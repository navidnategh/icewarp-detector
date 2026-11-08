#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
IceWarp Detector v4.3
Authorized security / asset-discovery / fingerprinting use only.

Usage:
  python3 iceWarp_Detector_v4_3.py -d example.com
  python3 iceWarp_Detector_v4_3.py -d example.com example.org -k -w 5 -t 10
  python3 iceWarp_Detector_v4_3.py -i domains.txt -k -w 5 -t 10 -o results.txt
"""

import argparse
import ipaddress
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

import requests
import urllib3

VERSION = "4.3"
DEFAULT_TIMEOUT = 10.0
DEFAULT_WORKERS = 5
MAX_REDIRECTS = 20
MAX_BODY_BYTES = 2_500_000

ICEWARP_PATH_TERMS = ("/webmail", "/webadmin", "/webmail/client")
ICEWARP_COOKIE_NAMES = ("login_sid", "icewarp", "webmail", "webadmin")


class Tee:
    def __init__(self, original, file_handle):
        self.original = original
        self.file_handle = file_handle

    def write(self, data):
        try:
            self.original.write(data)
        except Exception:
            pass
        try:
            if self.file_handle and not self.file_handle.closed:
                self.file_handle.write(data)
        except Exception:
            pass

    def flush(self):
        try:
            self.original.flush()
        except Exception:
            pass
        try:
            if self.file_handle and not self.file_handle.closed:
                self.file_handle.flush()
        except Exception:
            pass

    def isatty(self):
        try:
            return self.original.isatty()
        except Exception:
            return False


def setup_output(path):
    if not path:
        return None
    fh = open(path, "w", encoding="utf-8", buffering=1)
    sys.stdout = Tee(sys.stdout, fh)
    return fh


def close_output(fh):
    if fh is None:
        return
    try:
        sys.stdout.flush()
    except Exception:
        pass
    if isinstance(sys.stdout, Tee):
        sys.stdout = sys.__stdout__
    try:
        fh.flush()
    except Exception:
        pass
    try:
        fh.close()
    except Exception:
        pass


def normalize_target(raw):
    raw = raw.strip()
    if not raw or raw.startswith("#"):
        return None
    candidate = raw if "://" in raw else "//" + raw
    p = urlparse(candidate)
    host = p.hostname
    if not host:
        return None
    host_for_url = f"[{host}]" if ":" in host and not host.startswith("[") else host
    netloc = host_for_url
    try:
        port = p.port
    except ValueError:
        return None
    if port:
        netloc = f"{host_for_url}:{port}"
    return netloc


def build_initial_urls(target):
    return [f"https://{target}/", f"http://{target}/"]


def is_blocked_hostname(hostname):
    if not hostname:
        return True
    h = hostname.lower().rstrip(".")
    return h == "localhost" or h.endswith(".localhost") or h.endswith(".local")


def is_private_or_local_ip(hostname):
    try:
        ip = ipaddress.ip_address(hostname)
    except ValueError:
        return False
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_unspecified
        or ip.is_reserved
    )


def safe_redirect_url(current_url, location):
    if not location:
        return None
    new_url = urljoin(current_url, location)
    p = urlparse(new_url)
    if p.scheme.lower() not in {"http", "https"} or not p.hostname:
        return None
    if is_blocked_hostname(p.hostname) or is_private_or_local_ip(p.hostname):
        return None
    return new_url


class FingerprintParser(HTMLParser):
    def __init__(self, base_url):
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.text_chunks = []
        self.assets = []
        self.input_names = []

    def handle_data(self, data):
        if data:
            self.text_chunks.append(data)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        t = tag.lower()
        for attr in ("src", "href", "action"):
            value = attrs.get(attr)
            if not value:
                continue
            absolute = urljoin(self.base_url, value)
            low = absolute.lower()
            if any(x in low for x in ("icewarp", "/webmail/", "/webadmin/", "/client/", "favicon")):
                self.assets.append(absolute)
        if t == "input" and attrs.get("name"):
            self.input_names.append(attrs["name"])


def response_body(response):
    try:
        data = response.content[:MAX_BODY_BYTES]
        return data.decode(response.encoding or "utf-8", errors="replace")
    except Exception:
        try:
            return response.text[:MAX_BODY_BYTES]
        except Exception:
            return ""


def extract_version(server, x_version):
    m = re.search(r"IceWarp[/\s_-]*([0-9]+(?:\.[0-9]+){1,3})", server or "", re.I)
    if m:
        return m.group(1), "Server"
    m = re.search(r"\b([0-9]+(?:\.[0-9]+){1,3})\b", x_version or "")
    if m:
        return m.group(1), "X-Version"
    return None, None


def get_cookie_hits(response):
    hits = set()
    try:
        for cookie in response.cookies:
            low = cookie.name.lower()
            if low in ICEWARP_COOKIE_NAMES or "icewarp" in low:
                hits.add(cookie.name)
    except Exception:
        pass
    try:
        raw = response.headers.get("Set-Cookie", "")
        for part in raw.split(";"):
            name = part.split("=", 1)[0].strip()
            low = name.lower()
            if low in ICEWARP_COOKIE_NAMES or any(x in low for x in ("icewarp", "webmail", "webadmin")):
                hits.add(name)
    except Exception:
        pass
    return sorted(hits, key=str.lower)


def fingerprint_response(response):
    server = response.headers.get("Server", "").strip()
    x_version = response.headers.get("X-Version", "").strip()
    body = response_body(response)
    low = body.lower()

    parser = FingerprintParser(response.url)
    try:
        parser.feed(body)
        parser.close()
    except Exception:
        pass

    body_icewarp = "icewarp" in low
    app_terms = any(x in low for x in ("webclient", "webadmin", "webmail"))
    path_hit = any(x in urlparse(response.url).path.lower() for x in ICEWARP_PATH_TERMS)
    cookies = get_cookie_hits(response)
    assets = []
    seen = set()
    for asset in parser.assets:
        if asset not in seen:
            seen.add(asset)
            assets.append(asset)
    asset_hit = bool(assets)
    server_icewarp = "icewarp" in server.lower()
    x_version_present = bool(x_version)

    score = 0
    if server_icewarp:
        score += 5
    if x_version_present:
        score += 3
    if body_icewarp:
        score += 3
    if app_terms:
        score += 2
    if path_hit:
        score += 2
    if cookies:
        score += 2
    if asset_hit:
        score += 1

    version, version_via = extract_version(server, x_version)
    supporting_signal = app_terms or bool(cookies) or asset_hit or path_hit

    # Deliberately do NOT detect from body "IceWarp" alone.
    detected = (
        server_icewarp
        or (x_version_present and supporting_signal)
        or (body_icewarp and supporting_signal)
    )

    if detected:
        confidence = "HIGH" if server_icewarp or score >= 10 else ("MEDIUM" if score >= 7 else "LOW")
    else:
        confidence = "NONE"

    return {
        "detected": detected,
        "score": score,
        "max_score": 18,
        "confidence": confidence,
        "server": server or "N/A",
        "x_version": x_version or "N/A",
        "version": version or "N/A",
        "version_via": version_via or "N/A",
        "status_code": response.status_code,
        "url": response.url,
        "path": urlparse(response.url).path or "/",
        "cookies": cookies,
        "assets": assets,
        "inputs": sorted(set(parser.input_names), key=str.lower),
    }


def classify_request_error(exc):
    text = str(exc)
    low = text.lower()
    if isinstance(exc, requests.exceptions.SSLError):
        return "SSL_ERROR", "TLS/SSL negotiation or certificate error."
    if isinstance(exc, (requests.exceptions.ConnectTimeout, requests.exceptions.ReadTimeout, requests.exceptions.Timeout)):
        return "TIMEOUT", "No response within the configured timeout."
    if any(x in low for x in ("name or service not known", "name resolution", "failed to resolve", "temporary failure in name resolution", "nodename nor servname", "getaddrinfo failed")):
        return "DNS_FAILED", "Hostname could not be resolved."
    if isinstance(exc, requests.exceptions.ConnectionError):
        return "CONNECTION_FAILED", "Target rejected or could not establish the connection."
    return "ERROR", text[:220]


def is_blocked_http_status(statuses):
    return bool(statuses) and all(x in {401, 403, 407, 429} for x in statuses)


def scan_initial_url(session, initial_url, deadline, verify_tls):
    current = initial_url
    responses = []
    redirects = 0
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return responses, ("TIMEOUT", "Target time budget exhausted.")
        request_timeout = max(0.5, min(remaining, 10.0))
        try:
            resp = session.get(
                current,
                timeout=request_timeout,
                verify=verify_tls,
                allow_redirects=False,
                headers={
                    "User-Agent": "IceWarp-Detector/4.3",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                },
            )
        except requests.RequestException as exc:
            return responses, classify_request_error(exc)

        responses.append((resp, fingerprint_response(resp)))

        if resp.status_code not in {301, 302, 303, 307, 308}:
            return responses, None
        if redirects >= MAX_REDIRECTS:
            return responses, ("REDIRECT_LIMIT", "Redirect limit reached.")

        nxt = safe_redirect_url(current, resp.headers.get("Location"))
        if not nxt:
            return responses, ("REDIRECT_BLOCKED", "Redirect destination was rejected.")
        redirects += 1
        current = nxt


def scan_target(index, total, target, args):
    started = time.monotonic()
    result = {"index": index, "total": total, "target": target, "category": "NOT_DETECTED", "best": None, "error": None, "details": [], "duration": 0.0}
    session = requests.Session()
    session.trust_env = True
    deadline = started + max(0.5, args.timeout)
    errors = []
    statuses = []
    fps = []

    try:
        for initial_url in build_initial_urls(target):
            if time.monotonic() >= deadline:
                errors.append(("TIMEOUT", "Target time budget exhausted."))
                break
            responses, terminal_error = scan_initial_url(session, initial_url, deadline, not args.insecure)
            for resp, fp in responses:
                statuses.append(resp.status_code)
                fps.append(fp)
            if terminal_error:
                errors.append(terminal_error)

        if fps:
            best = max(fps, key=lambda x: (1 if x["detected"] else 0, x["score"], x["status_code"]))
            result["best"] = best
            result["details"] = fps
            if any(x["detected"] for x in fps):
                result["category"] = "DETECTED"
            elif is_blocked_http_status(statuses):
                result["category"] = "BLOCKED"
            elif any(x >= 500 for x in statuses):
                result["category"] = "HTTP_ERROR"
            else:
                result["category"] = "NOT_DETECTED"
        elif errors:
            priority = {"DNS_FAILED": 5, "TIMEOUT": 4, "CONNECTION_FAILED": 3, "SSL_ERROR": 2, "ERROR": 1}
            category, reason = max(errors, key=lambda x: priority.get(x[0], 0))
            result["category"] = category
            result["error"] = reason
        else:
            result["category"] = "ERROR"
            result["error"] = "No HTTP response."
    except Exception as exc:
        result["category"] = "ERROR"
        result["error"] = f"{type(exc).__name__}: {str(exc)[:220]}"
    finally:
        try:
            session.close()
        except Exception:
            pass
    result["duration"] = time.monotonic() - started
    return result


def print_target_result(r):
    labels = {
        "DETECTED": "ICEWARP FOUND",
        "NOT_DETECTED": "NOT DETECTED",
        "DNS_FAILED": "DNS FAILED",
        "TIMEOUT": "TIMEOUT",
        "CONNECTION_FAILED": "CONNECTION FAILED",
        "SSL_ERROR": "SSL ERROR",
        "BLOCKED": "INCONCLUSIVE / BLOCKED",
        "HTTP_ERROR": "HTTP ERROR",
        "REDIRECT_LIMIT": "REDIRECT LIMIT",
        "REDIRECT_BLOCKED": "REDIRECT BLOCKED",
        "ERROR": "ERROR",
    }
    print(f"[{r['index']:02d}/{r['total']}] {labels.get(r['category'], r['category']):<22} {r['target']}  ({r['duration']:.1f}s)")
    if r["category"] in {"DNS_FAILED", "TIMEOUT", "CONNECTION_FAILED", "SSL_ERROR", "ERROR"}:
        if r.get("error"):
            print(f"    Reason : {r['error']}")
        print()
        return
    best = r.get("best")
    if not best:
        print("    Reason : No usable HTTP response.")
        print()
        return
    print(f"    URL         : {best['url']}")
    print(f"    Path        : {best['path']}")
    print(f"    Status      : {best['status_code']}")
    print(f"    Server      : {best['server']}")
    print(f"    X-Version   : {best['x_version']}")
    print(f"    Version     : {best['version']}")
    print(f"    Version via : {best['version_via']}")
    print(f"    Confidence  : {best['confidence']} ({best['score']}/{best['max_score']})")
    if best["cookies"]:
        print("    Cookies     :")
        for x in best["cookies"]:
            print(f"                  {x}")
    if best["assets"]:
        print("    Assets      :")
        for x in best["assets"]:
            print(f"                  {x}")
    if best["inputs"]:
        print("    Inputs      :")
        for x in best["inputs"]:
            print(f"                  {x}")
    if r["category"] == "BLOCKED":
        print("    Note        : HTTP access may be restricted; detection is inconclusive.")
    print()


def load_targets(args):
    raw = []
    if args.input_file:
        with open(args.input_file, "r", encoding="utf-8", errors="ignore") as fh:
            raw.extend(line.strip() for line in fh)
    if args.domains:
        raw.extend(args.domains)
    out, seen = [], set()
    for x in raw:
        target = normalize_target(x)
        if target and target.lower() not in seen:
            seen.add(target.lower())
            out.append(target)
    return out


def print_banner(args, count):
    print("=" * 62)
    print(f"IceWarp Detector v{VERSION}")
    print("=" * 62)
    print(f"Targets        : {count}")
    print(f"Workers        : {args.workers}")
    print(f"Timeout        : {args.timeout:g}s per target")
    print(f"TLS verify     : {'OFF (-k)' if args.insecure else 'ON'}")
    print(f"Redirects      : ON (max {MAX_REDIRECTS})")
    print("=" * 62)
    print()


def build_parser():
    p = argparse.ArgumentParser(description="IceWarp HTTP/HTTPS fingerprinting detector.")
    p.add_argument("-i", "--input", dest="input_file", help="File with one domain/host per line.")
    p.add_argument("-d", "--domain", dest="domains", nargs="+", help="One or more domains/hosts.")
    p.add_argument("-k", "--insecure", action="store_true", help="Disable TLS certificate verification.")
    p.add_argument("-o", "--output", help="Tee terminal output to this file.")
    p.add_argument("-t", "--timeout", type=float, default=DEFAULT_TIMEOUT, help=f"Per-target time budget in seconds (default: {DEFAULT_TIMEOUT:g}).")
    p.add_argument("-w", "--workers", type=int, default=DEFAULT_WORKERS, help=f"Concurrent workers (default: {DEFAULT_WORKERS}).")
    return p


def print_summary(results, elapsed):
    counts = {}
    for r in results:
        counts[r["category"]] = counts.get(r["category"], 0) + 1
    total = len(results)
    print("=" * 62)
    print("SCAN SUMMARY")
    print("=" * 62)
    print(f"Total targets       : {total}")
    print(f"IceWarp detected    : {counts.get('DETECTED', 0)}")
    print(f"Not detected        : {counts.get('NOT_DETECTED', 0)}")
    print(f"DNS failed          : {counts.get('DNS_FAILED', 0)}")
    print(f"Timeout             : {counts.get('TIMEOUT', 0)}")
    print(f"Connection failed   : {counts.get('CONNECTION_FAILED', 0)}")
    print(f"SSL errors          : {counts.get('SSL_ERROR', 0)}")
    print(f"Blocked/inconclusive: {counts.get('BLOCKED', 0)}")
    print(f"HTTP errors         : {counts.get('HTTP_ERROR', 0)}")
    print(f"Other errors        : {sum(counts.get(x, 0) for x in ('ERROR', 'REDIRECT_LIMIT', 'REDIRECT_BLOCKED'))}")
    print(f"Completed           : {len(results)}/{total}")
    print("=" * 62)
    detected = [r for r in results if r["category"] == "DETECTED"]
    if detected:
        print("\nDETECTED TARGETS")
        print("-" * 62)
        for r in sorted(detected, key=lambda x: x["index"]):
            b = r["best"] or {}
            print(f"{r['target']:<35} {b.get('version', 'N/A'):<12} {b.get('confidence', 'N/A')}")
    print(f"\nTotal scan time: {elapsed:.1f}s")


def main():
    parser = build_parser()
    args = parser.parse_args()
    if not args.input_file and not args.domains:
        parser.print_help()
        return 0
    if args.timeout <= 0:
        parser.error("-t/--timeout must be greater than 0")
    if args.workers <= 0:
        parser.error("-w/--workers must be greater than 0")
    if args.insecure:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    try:
        targets = load_targets(args)
    except OSError as exc:
        print(f"[!] Failed to read input file: {exc}")
        return 1
    if not targets:
        print("[!] No valid targets found.")
        return 1

    output_file = None
    try:
        output_file = setup_output(args.output)
        print_banner(args, len(targets))
        start = time.monotonic()
        results = []
        workers = min(args.workers, len(targets))

        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {
                executor.submit(scan_target, i, len(targets), target, args): target
                for i, target in enumerate(targets, start=1)
            }
            completed = 0
            for future in as_completed(futures):
                try:
                    result = future.result()
                except Exception as exc:
                    target = futures[future]
                    result = {
                        "index": 0,
                        "total": len(targets),
                        "target": target,
                        "category": "ERROR",
                        "best": None,
                        "error": f"{type(exc).__name__}: {str(exc)[:220]}",
                        "details": [],
                        "duration": 0.0,
                    }
                results.append(result)
                completed += 1
                print_target_result(result)
                print(f"Progress: {completed}/{len(targets)} completed", flush=True)
                print()

        results.sort(key=lambda x: x["index"])
        print_summary(results, time.monotonic() - start)
        return 0

    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")
        return 130
    except Exception as exc:
        print(f"\n[!] Fatal error: {type(exc).__name__}: {exc}")
        return 1
    finally:
        close_output(output_file)


if __name__ == "__main__":
    sys.exit(main())
