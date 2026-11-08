# IceWarp Fingerprint Detector

A lightweight Python tool for identifying IceWarp webmail services through HTTP/HTTPS fingerprinting.

The tool analyzes HTTP response headers, HTML content, cookies, application paths, and asset references to identify potential IceWarp instances and extract version information when available.

## Features

- **HTTP & HTTPS:** Checks both protocols.
- **Redirect Handling:** Follows HTTP redirects, subject to the maximum redirect limit configured in the source code.
- **Version Detection:** Extracts version information from the `Server` and `X-Version` response headers.
- **Fingerprint Analysis:** Examines HTML content, cookies, input fields, and asset URLs.
- **Concurrent Scanning:** Scans multiple targets using configurable worker threads.
- **Error Classification:** Separates DNS failures, connection errors, TLS errors, timeouts, and inconclusive responses.
- **False-Positive Reduction:** Uses multiple indicators instead of relying solely on the presence of the word `IceWarp`.
- **Output Logging:** Displays results in the terminal and optionally saves them to a file.

## Requirements

- Python 3.8+
- `requests`
- `urllib3`

## Installation

Clone the repository:

```bash
git clone https://github.com/navidnategh/icewarp-detector.git
cd icewarp-detector
```

Install the dependencies:

```bash
python3 -m pip install -r requirements.txt
```

## Usage

### Scan a single domain

```bash
python3 iceWarp_Detector_v4_3.py -d mail.example.com
```

### Scan multiple domains

```bash
python3 iceWarp_Detector_v4_3.py -d mail1.example.com mail2.example.com
```

### Scan targets from a file

Create a `domains.txt` file containing one hostname per line:

```text
mail.example.com
webmail.example.org
mx.example.net
```

Run the scanner:

```bash
python3 iceWarp_Detector_v4_3.py -i domains.txt
```

### Configure timeout and concurrency

```bash
python3 iceWarp_Detector_v4_3.py -i domains.txt -w 5 -t 10
```

- `-w 5`: Use five concurrent workers.
- `-t 10`: Set the per-target time budget to 10 seconds.

### Disable TLS certificate verification

For authorized testing environments with invalid or self-signed certificates:

```bash
python3 iceWarp_Detector_v4_3.py -i domains.txt -k
```

**Note:** Disabling certificate verification reduces connection security. Use `-k` only when necessary.

### Save results to a file

```bash
python3 iceWarp_Detector_v4_3.py -i domains.txt -o results.txt
```

### Command-line options

| Option | Description |
| --- | --- |
| `-i FILE` | Read targets from a file |
| `-d DOMAIN [...]` | Scan one or more domains |
| `-k` | Disable TLS certificate verification |
| `-o FILE` | Save terminal output to a file |
| `-t SEC` | Configure the per-target time budget |
| `-w N` | Set the number of concurrent workers |
| `-h` | Display help |

## Example Output

```text
==============================================================
IceWarp Detector v4.3
==============================================================
Targets        : 3
Workers        : 5
Timeout        : 10s per target
TLS verify     : ON
Redirects      : ON (max 20)
==============================================================

[01/03] ICEWARP FOUND          mail.example.com (1.8s)
    URL         : https://mail.example.com/webmail/
    Status      : 200
    Server      : IceWarp/12.2.1.1 x64
    Version     : 12.2.1.1
    Version via : Server
    Confidence  : HIGH (example score)

[02/03] NOT DETECTED           webmail.example.org (0.9s)

[03/03] DNS FAILED             mx.example.net (0.4s)

==============================================================
SCAN SUMMARY
==============================================================
Total targets       : 3
IceWarp detected    : 1
Not detected        : 1
DNS failed          : 1
==============================================================
```

*Example output is illustrative; actual results depend on target responses. The redirect limit shown above reflects the current source code (`MAX_REDIRECTS = 20`).*

## Detection Methodology

The detector evaluates several indicators:

- `Server` header values identifying IceWarp.
- `X-Version` header values that may expose version information.
- HTML content containing IceWarp-related application identifiers.
- Relevant cookies and application asset references.
- Webmail and web administration paths.

Detection confidence is based on the available evidence. Missing version information does not necessarily mean the service is not IceWarp, and a negative result does not prove that IceWarp is absent.

## Security Research Context

This project is intended for service identification and asset inventory. It is not an exploit tool and does not independently confirm whether a target is vulnerable to **CVE-2025-14499** or any other vulnerability.

Version information obtained from HTTP headers may be incomplete, modified, or misleading. Confirm security status using authoritative vendor advisories and authorized validation procedures.

## Limitations

- Reverse proxies, WAFs, and custom headers may affect detection.
- Some services may conceal their product and version information.
- Redirects and network restrictions may prevent complete fingerprinting.
- Fingerprinting results are indicators, not proof of vulnerability.

## Responsible Use

Use this tool only against systems you own or have explicit authorization to assess.

The author is not responsible for unauthorized use or damage resulting from misuse of this software.

## License

This project is intended to be released under the MIT License. See the `LICENSE` file for details.
