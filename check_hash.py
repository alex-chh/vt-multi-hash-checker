import argparse
import asyncio
import sys
import os
import json
import csv
import vt

def normalize_vendor(name: str) -> str:
    return name.lower().replace(" ", "").replace("-", "")

def load_hashes(args) -> list[str]:
    hashes = []
    if args.hashes:
        hashes.extend(args.hashes)
    if args.hash_file:
        with open(args.hash_file, "r", encoding="utf-8") as f:
            for line in f:
                h = line.strip()
                if h and not h.startswith("#"):
                    hashes.append(h)
    uniq = []
    seen = set()
    for h in hashes:
        if h not in seen:
            uniq.append(h)
            seen.add(h)
    return uniq

async def query_one(client: vt.Client, file_hash: str, vendor: str | None):
    try:
        obj = await client.get_object_async(f"/files/{file_hash}")
    except vt.error.APIError as e:
        return {"hash": file_hash, "error": str(e)}
    results = getattr(obj, "last_analysis_results", None)
    if vendor:
        if not results:
            return {"hash": file_hash, "vendor": vendor, "status": "no_results"}
        target = normalize_vendor(vendor)
        for vn, res in results.items():
            if normalize_vendor(vn) == target:
                return {
                    "hash": file_hash,
                    "vendor": vn,
                    "status": res.get("category", "unknown"),
                    "result": res.get("result"),
                }
        return {"hash": file_hash, "vendor": vendor, "status": "vendor_not_found"}
    stats = getattr(obj, "last_analysis_stats", {}) or {}
    return {
        "hash": file_hash,
        "malicious": stats.get("malicious", 0),
        "undetected": stats.get("undetected", 0),
    }

async def run_async(apikey: str, hashes: list[str], vendor: str | None, concurrency: int):
    client = vt.Client(apikey)
    try:
        sem = asyncio.Semaphore(max(1, concurrency))
        async def wrapped(h):
            async with sem:
                return await query_one(client, h, vendor)
        tasks = [asyncio.create_task(wrapped(h)) for h in hashes]
        results = await asyncio.gather(*tasks)
    finally:
        await client.close_async()
    return results

def print_result(r):
    if "error" in r:
        print(f"{r['hash']} error: {r['error']}")
        return
    if "vendor" in r:
        print(f"{r['hash']} [{r['vendor']}] {r['status']}" + (f" {r['result']}" if r.get("result") else ""))
        return
    print(f"{r['hash']} malicious={r.get('malicious', 0)} undetected={r.get('undetected', 0)}")

def main():
    parser = argparse.ArgumentParser(description="Query VirusTotal for one or many file hashes.")
    parser.add_argument("hashes", nargs="*", help="File hashes (SHA1/SHA256/MD5)")
    parser.add_argument("--hash-file", help="Path to a file containing hashes, one per line")
    parser.add_argument("--vendor", "-v", help="Security vendor to check (case-insensitive)", default="trend micro")
    parser.add_argument("--concurrency", "-c", type=int, default=5, help="Number of concurrent requests")
    parser.add_argument("--apikey", help="VT API key (optional, prefer env or file)", default=None)
    parser.add_argument("--apikey-file", help="Path to file containing VT API key", default=None)
    parser.add_argument("--output", choices=["json", "csv"], help="Output format")
    parser.add_argument("--output-file", help="Write output to file")
    args = parser.parse_args()

    apikey = args.apikey or (open(args.apikey_file, "r", encoding="utf-8").read().strip() if args.apikey_file else os.environ.get("VT_API_KEY"))
    if not apikey:
        print("API key not provided. Use --apikey, --apikey-file or set VT_API_KEY env var.")
        sys.exit(1)

    hashes = load_hashes(args)
    if not hashes:
        print("No hashes provided")
        sys.exit(1)
    results = asyncio.run(run_async(apikey, hashes, args.vendor, args.concurrency))
    if args.output == "json":
        payload = json.dumps(results, ensure_ascii=False)
        if args.output_file:
            with open(args.output_file, "w", encoding="utf-8") as f:
                f.write(payload)
        else:
            print(payload)
    elif args.output == "csv":
        headers = ["hash", "vendor", "status", "result", "malicious", "undetected", "error"]
        if args.output_file:
            with open(args.output_file, "w", encoding="utf-8", newline="") as f:
                w = csv.DictWriter(f, fieldnames=headers, lineterminator="\n")
                w.writeheader()
                for r in results:
                    row = {
                        "hash": r.get("hash"),
                        "vendor": r.get("vendor"),
                        "status": r.get("status"),
                        "result": r.get("result"),
                        "malicious": r.get("malicious"),
                        "undetected": r.get("undetected"),
                        "error": r.get("error"),
                    }
                    w.writerow(row)
        else:
            w = csv.DictWriter(sys.stdout, fieldnames=headers, lineterminator="\n")
            w.writeheader()
            for r in results:
                row = {
                    "hash": r.get("hash"),
                    "vendor": r.get("vendor"),
                    "status": r.get("status"),
                    "result": r.get("result"),
                    "malicious": r.get("malicious"),
                    "undetected": r.get("undetected"),
                    "error": r.get("error"),
                }
                w.writerow(row)
    else:
        for r in results:
            print_result(r)

if __name__ == "__main__":
    main()
