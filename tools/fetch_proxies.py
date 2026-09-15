#!/usr/bin/env python3
"""Proxy Harvester and Validator for XSS Boss.

Fetches and consolidates free proxies from top active GitHub repositories,
deduplicates them, validates them concurrently with asyncio/aiohttp,
and outputs clean, working proxy lists or updates your .env configuration.

Sources included:
  - TheSpeedX/PROXY-List (HTTP, SOCKS4, SOCKS5)
  - monosans/proxy-list (HTTP, SOCKS4, SOCKS5)
  - clarketm/proxy-list
  - fate0/proxylist
  - hookzof/socks5_list
  - roosterkid/openproxylist
  - sunny9577/proxy-scraper
  - proxifly/free-proxy-list
  - ShiftyTR/Proxy-List
"""

import argparse
import asyncio
import json
import re
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

try:
    import aiohttp
    from aiohttp_socks import ProxyConnector
except ImportError:
    print("[!] Missing required packages. Run: pip install aiohttp aiohttp-socks")
    sys.exit(1)

# Regex for standard IP:PORT pattern
PROXY_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}:\d{2,5}\b")

# GitHub raw sources mapped by protocol category
SOURCES = [
    # TheSpeedX
    {"url": "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/http.txt", "protocol": "http", "name": "TheSpeedX (HTTP)"},
    {"url": "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks5.txt", "protocol": "socks5", "name": "TheSpeedX (SOCKS5)"},
    {"url": "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks4.txt", "protocol": "socks4", "name": "TheSpeedX (SOCKS4)"},
    # monosans
    {"url": "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt", "protocol": "http", "name": "monosans (HTTP)"},
    {"url": "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt", "protocol": "socks5", "name": "monosans (SOCKS5)"},
    {"url": "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks4.txt", "protocol": "socks4", "name": "monosans (SOCKS4)"},
    {"url": "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies_anonymous/http.txt", "protocol": "http", "name": "monosans (HTTP Anon)"},
    # clarketm
    {"url": "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt", "protocol": "http", "name": "clarketm"},
    # fate0 (JSON lines)
    {"url": "https://raw.githubusercontent.com/fate0/proxylist/master/proxy.list", "protocol": "json_fate0", "name": "fate0"},
    # hookzof
    {"url": "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt", "protocol": "socks5", "name": "hookzof (SOCKS5)"},
    # roosterkid
    {"url": "https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt", "protocol": "http", "name": "roosterkid (HTTPS)"},
    {"url": "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5_RAW.txt", "protocol": "socks5", "name": "roosterkid (SOCKS5)"},
    # sunny9577
    {"url": "https://raw.githubusercontent.com/sunny9577/proxy-scraper/master/proxies.txt", "protocol": "http", "name": "sunny9577 (HTTP)"},
    {"url": "https://raw.githubusercontent.com/sunny9577/proxy-scraper/master/generated/socks5_proxies.txt", "protocol": "socks5", "name": "sunny9577 (SOCKS5)"},
    # proxifly
    {"url": "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/http/data.txt", "protocol": "http", "name": "proxifly (HTTP)"},
    {"url": "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/socks5/data.txt", "protocol": "socks5", "name": "proxifly (SOCKS5)"},
    {"url": "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/socks4/data.txt", "protocol": "socks4", "name": "proxifly (SOCKS4)"},
    # ShiftyTR
    {"url": "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt", "protocol": "http", "name": "ShiftyTR (HTTP)"},
    {"url": "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks5.txt", "protocol": "socks5", "name": "ShiftyTR (SOCKS5)"},
    {"url": "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks4.txt", "protocol": "socks4", "name": "ShiftyTR (SOCKS4)"},
]


async def fetch_source(session: aiohttp.ClientSession, source: dict) -> List[Tuple[str, str]]:
    """Fetch raw text from source and return list of (protocol, ip:port)."""
    url = source["url"]
    proto = source["protocol"]
    name = source["name"]
    results = []

    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=8)) as resp:
            if resp.status == 200:
                text = await resp.text(errors="ignore")
                if proto == "json_fate0":
                    for line in text.splitlines():
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            item = json.loads(line)
                            ip = item.get("host")
                            port = item.get("port")
                            p_type = item.get("type", "http").lower()
                            if ip and port:
                                results.append((p_type, f"{ip}:{port}"))
                        except Exception:
                            continue
                else:
                    matches = PROXY_PATTERN.findall(text)
                    for match in matches:
                        results.append((proto, match))
                print(f"[+] Fetched {len(results):>5} proxies from {name}")
            else:
                pass  # Skip inactive source silently
    except Exception as exc:
        pass
    return results


async def harvest_all(allowed_protocols: Set[str]) -> Dict[str, Set[str]]:
    """Fetch all sources in parallel and categorize by protocol."""
    print("[*] Harvesting proxies from all GitHub repositories concurrently...")
    start_time = time.time()
    
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/125.0.0.0 Safari/537.36"}
    async with aiohttp.ClientSession(headers=headers) as session:
        tasks = [fetch_source(session, s) for s in SOURCES]
        all_results = await asyncio.gather(*tasks)

    categorized: Dict[str, Set[str]] = {"http": set(), "socks4": set(), "socks5": set()}
    total_raw = 0

    for res_list in all_results:
        for proto, proxy in res_list:
            total_raw += 1
            proto_key = "http" if "http" in proto else ("socks5" if "socks5" in proto else "socks4")
            if proto_key in allowed_protocols:
                categorized[proto_key].add(proxy)

    elapsed = time.time() - start_time
    total_deduped = sum(len(v) for v in categorized.values())
    print(f"\n[+] Harvest Complete in {elapsed:.2f}s!")
    print(f"    Raw entries collected: {total_raw}")
    print(f"    Unique HTTP(S):        {len(categorized['http'])}")
    print(f"    Unique SOCKS5:         {len(categorized['socks5'])}")
    print(f"    Unique SOCKS4:         {len(categorized['socks4'])}")
    print(f"    Total unique:          {total_deduped}")
    return categorized


async def check_proxy(
    sem: asyncio.Semaphore,
    proxy_url: str,
    target_url: str,
    timeout: float,
) -> Optional[Tuple[str, float]]:
    """Validate a single proxy and return (proxy_url, latency_ms) if live."""
    async with sem:
        start = time.time()
        try:
            connector = ProxyConnector.from_url(proxy_url)
            async with aiohttp.ClientSession(connector=connector) as session:
                async with session.get(
                    target_url,
                    timeout=aiohttp.ClientTimeout(total=timeout),
                    headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/125.0.0.0 Safari/537.36"}
                ) as resp:
                    if resp.status < 500:
                        latency_ms = (time.time() - start) * 1000
                        return proxy_url, latency_ms
        except Exception:
            return None
        return None


async def validate_proxies(
    proxies: List[str],
    target_url: str = "https://httpbin.org/ip",
    timeout: float = 4.0,
    concurrency: int = 150,
    limit: Optional[int] = None,
) -> List[Tuple[str, float]]:
    """Test proxies concurrently and return list of working ones sorted by latency."""
    print(f"\n[*] Validating {len(proxies)} proxies against {target_url} (Timeout: {timeout}s, Concurrency: {concurrency})...")
    sem = asyncio.Semaphore(concurrency)
    
    tasks = [asyncio.create_task(check_proxy(sem, p, target_url, timeout)) for p in proxies]
    working = []
    
    completed = 0
    total = len(tasks)
    
    for fut in asyncio.as_completed(tasks):
        res = await fut
        completed += 1
        if res:
            working.append(res)
            sys.stdout.write(f"\r[+] Progress: {completed}/{total} | Live found: {len(working)} (Last: {res[0]} - {res[1]:.0f}ms)   ")
            sys.stdout.flush()
            if limit and len(working) >= limit:
                print(f"\n[+] Target limit of {limit} working proxies reached! Cancelling remaining tests...")
                for t in tasks:
                    if not t.done():
                        t.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
                break
        elif completed % 50 == 0 or completed == total:
            sys.stdout.write(f"\r[*] Progress: {completed}/{total} | Live found: {len(working)}   ")
            sys.stdout.flush()

    print(f"\n[+] Validation finished! Found {len(working)} working proxies.")
    working.sort(key=lambda x: x[1])  # sort by latency
    return working


def update_env_proxy_list(working_proxies: List[str], env_path: Path) -> None:
    """Update PROXY_LIST inside the project .env file."""
    proxy_str = ",".join(working_proxies)
    if not env_path.exists():
        env_path.write_text(f"PROXY_LIST={proxy_str}\n", encoding="utf-8")
        print(f"[+] Created {env_path} with {len(working_proxies)} proxies.")
        return

    content = env_path.read_text(encoding="utf-8")
    if "PROXY_LIST=" in content:
        content = re.sub(r"PROXY_LIST=.*", f"PROXY_LIST={proxy_str}", content)
    else:
        content += f"\nPROXY_LIST={proxy_str}\n"
    env_path.write_text(content, encoding="utf-8")
    print(f"[+] Successfully updated PROXY_LIST in {env_path.name} ({len(working_proxies)} proxies)")


def main():
    parser = argparse.ArgumentParser(description="Fetch and validate free proxies from top GitHub repos.")
    parser.add_argument("--protocols", nargs="+", default=["http", "socks5", "socks4"], choices=["http", "socks5", "socks4"], help="Protocols to collect")
    parser.add_argument("--check", action="store_true", help="Perform live connectivity check on collected proxies")
    parser.add_argument("--target", default="https://httpbin.org/ip", help="Target URL for health checking (default: https://httpbin.org/ip)")
    parser.add_argument("--timeout", type=float, default=4.0, help="Check timeout in seconds (default: 4.0)")
    parser.add_argument("--concurrency", type=int, default=150, help="Concurrent check workers (default: 150)")
    parser.add_argument("--limit", type=int, default=None, help="Stop testing once this many working proxies are found")
    parser.add_argument("--out", default="proxies.txt", help="Output file path (default: proxies.txt)")
    parser.add_argument("--update-env", action="store_true", help="Automatically update PROXY_LIST in .env")
    parser.add_argument("--scheme", action="store_true", default=True, help="Prefix proxies with scheme (e.g. http:// or socks5://)")
    
    args = parser.parse_args()

    allowed_proto = set(args.protocols)
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    # 1. Harvest
    categorized = loop.run_until_complete(harvest_all(allowed_proto))

    # Build formatted list
    all_formatted: List[str] = []
    for proto, ips in categorized.items():
        for ip in ips:
            all_formatted.append(f"{proto}://{ip}" if args.scheme else ip)

    output_path = Path(args.out)

    # 2. Check if requested
    if args.check:
        working_results = loop.run_until_complete(
            validate_proxies(
                all_formatted,
                target_url=args.target,
                timeout=args.timeout,
                concurrency=args.concurrency,
                limit=args.limit
            )
        )
        final_list = [p[0] for p in working_results]
        
        # Save working list
        output_path.write_text("\n".join(final_list) + "\n", encoding="utf-8")
        print(f"[+] Saved {len(final_list)} verified working proxies to {output_path.resolve()}")
        
        if args.update_env:
            env_file = Path(__file__).parent.parent / ".env"
            update_env_proxy_list(final_list, env_file)
    else:
        # Save raw deduplicated
        output_path.write_text("\n".join(all_formatted) + "\n", encoding="utf-8")
        print(f"[+] Saved {len(all_formatted)} unique proxies (unverified) to {output_path.resolve()}")
        print("[i] To verify live connectivity, re-run with: python tools/fetch_proxies.py --check")


if __name__ == "__main__":
    main()
