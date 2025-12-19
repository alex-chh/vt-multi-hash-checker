# vt-multi-hash-checker

Command-line tool to batch query VirusTotal detections for multiple file hashes (MD5/SHA1/SHA256).

## Features
- Multiple hashes input via CLI or file (10+ supported)
- Vendor selection with case/spacing-insensitive matching (default: Trend Micro)
- Asynchronous concurrent requests with configurable concurrency
- Safe API key loading from env var or file
- Structured output: JSON or CSV, with optional output file

## Requirements
- Python 3.7+
- VirusTotal Python client library:

```powershell
pip install vt-py
```

## Usage (Windows PowerShell)

### 1) Provide API key via environment variable
```powershell
$env:VT_API_KEY="<YOUR_API_KEY>"
python check_hash.py --hash-file hashes.txt -c 5 --output csv --output-file out.csv
```

### 2) Provide API key via file
```powershell
Set-Content -Path apikey.txt -Value "<YOUR_API_KEY>"
Set-Content -Path hashes.txt -Value "c4bec46bfc6b42fa47641080f19577093f8591c7`n3395856ce81f2b7382dee72602f798b642f14140"
python check_hash.py --apikey-file apikey.txt --hash-file hashes.txt --vendor "trend micro" -c 5 --output json --output-file out.json
```

### 3) Pass multiple hashes on the command line
```powershell
$env:VT_API_KEY="<YOUR_API_KEY>"
python check_hash.py c4bec46bfc6b42fa47641080f19577093f8591c7 3395856ce81f2b7382dee72602f798b642f14140 --vendor "trend micro" -c 5 --output csv
```

## Arguments
- `hashes`: file hashes passed directly as positional arguments (supports multiple)
- `--hash-file <path>`: file containing hashes (one per line, `#` comments supported)
- `--vendor <name>`: security vendor to check (default `trend micro`)
- `--concurrency -c <n>`: number of concurrent requests (recommend 3–5)
- `--apikey`: provide API key via argument (not recommended)
- `--apikey-file <path>`: load API key from file (recommended)
- `VT_API_KEY`: environment variable for API key (recommended)
- `--output json|csv`: output format
- `--output-file <path>`: write output to file

## Output formats
- When vendor is specified:
  - JSON per item: `{ "hash", "vendor", "status", "result" }`
  - CSV columns: `hash,vendor,status,result,malicious,undetected,error`
- When vendor is not specified (default vendor Trend Micro is used):
  - Output uses unified columns; unused fields remain empty

## Example outputs
- JSON:
```json
[
  {"hash":"c4bec46bfc6b42fa47641080f19577093f8591c7","vendor":"TrendMicro","status":"malicious","result":"TROJ_FRS.VSNTKI25"},
  {"hash":"3395856ce81f2b7382dee72602f798b642f14140","vendor":"TrendMicro","status":"malicious","result":"Eicar_test_file"}
]
```

- CSV:
```
hash,vendor,status,result,malicious,undetected,error
c4bec46bfc6b42fa47641080f19577093f8591c7,TrendMicro,malicious,TROJ_FRS.VSNTKI25,,,
3395856ce81f2b7382dee72602f798b642f14140,TrendMicro,malicious,Eicar_test_file,,,
```

## How it works
- Fetches file objects via `vt.Client.get_object_async("/files/{hash}")` and compares `last_analysis_results` against the selected vendor; if no vendor is specified, Trend Micro is used by default.
- Uses `asyncio` with a semaphore to limit concurrency; final results are formatted as JSON or CSV.

## Security notes
- Prefer environment variable `VT_API_KEY` or `--apikey-file` over command-line arguments to avoid exposing secrets.
- Keep concurrency moderate to avoid hitting API rate limits; consider implementing backoff/retry if needed.
