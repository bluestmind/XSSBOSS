"""Automatic Background Proxy Harvester & Refresh Service for XSS Boss.

Ensures the proxy pool always contains thousands of fresh, validated proxies
by periodically harvesting from top repositories, pruning dead proxies,
and reloading the active memory rotation pools.
"""

import asyncio
import os
import re
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
import httpx

from backend_api.config import settings
from backend_api.utils.logger import logger
from backend_api.utils.stealth import (
    _init_proxy_pool,
    get_proxy_count,
    get_proxy_pool_status,
)

PROXY_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}:\d{2,5}\b")

# Top active and frequently updated public proxy sources across GitHub & APIs
PUBLIC_SOURCES = [
    # TheSpeedX
    {"url": "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/http.txt", "protocol": "http"},
    {"url": "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks5.txt", "protocol": "socks5"},
    {"url": "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks4.txt", "protocol": "socks4"},
    # monosans
    {"url": "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt", "protocol": "http"},
    {"url": "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt", "protocol": "socks5"},
    {"url": "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks4.txt", "protocol": "socks4"},
    {"url": "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies_anonymous/http.txt", "protocol": "http"},
    # sunny9577
    {"url": "https://raw.githubusercontent.com/sunny9577/proxy-scraper/master/proxies.txt", "protocol": "http"},
    {"url": "https://raw.githubusercontent.com/sunny9577/proxy-scraper/master/generated/socks5_proxies.txt", "protocol": "socks5"},
    # proxifly
    {"url": "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/http/data.txt", "protocol": "http"},
    {"url": "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/socks5/data.txt", "protocol": "socks5"},
    {"url": "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/socks4/data.txt", "protocol": "socks4"},
    # roosterkid
    {"url": "https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt", "protocol": "http"},
    {"url": "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5_RAW.txt", "protocol": "socks5"},
    {"url": "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS4_RAW.txt", "protocol": "socks4"},
    # hookzof
    {"url": "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt", "protocol": "socks5"},
    # ShiftyTR
    {"url": "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt", "protocol": "http"},
    {"url": "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks5.txt", "protocol": "socks5"},
    {"url": "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks4.txt", "protocol": "socks4"},
    # jetkai
    {"url": "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-http.txt", "protocol": "http"},
    {"url": "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-https.txt", "protocol": "http"},
    {"url": "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks5.txt", "protocol": "socks5"},
    {"url": "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks4.txt", "protocol": "socks4"},
    # MuRongPIG
    {"url": "https://raw.githubusercontent.com/MuRongPIG/Proxy-Master/main/http.txt", "protocol": "http"},
    {"url": "https://raw.githubusercontent.com/MuRongPIG/Proxy-Master/main/socks5.txt", "protocol": "socks5"},
    {"url": "https://raw.githubusercontent.com/MuRongPIG/Proxy-Master/main/socks4.txt", "protocol": "socks4"},
    # prxchk
    {"url": "https://raw.githubusercontent.com/prxchk/proxy-list/main/http.txt", "protocol": "http"},
    {"url": "https://raw.githubusercontent.com/prxchk/proxy-list/main/socks5.txt", "protocol": "socks5"},
    {"url": "https://raw.githubusercontent.com/prxchk/proxy-list/main/socks4.txt", "protocol": "socks4"},
    # ErcinDedeoglu
    {"url": "https://raw.githubusercontent.com/ErcinDedeoglu/proxies/main/proxies/http.txt", "protocol": "http"},
    {"url": "https://raw.githubusercontent.com/ErcinDedeoglu/proxies/main/proxies/socks5.txt", "protocol": "socks5"},
    {"url": "https://raw.githubusercontent.com/ErcinDedeoglu/proxies/main/proxies/socks4.txt", "protocol": "socks4"},
    # zevtyardt
    {"url": "https://raw.githubusercontent.com/zevtyardt/proxy-list/main/http.txt", "protocol": "http"},
    {"url": "https://raw.githubusercontent.com/zevtyardt/proxy-list/main/socks5.txt", "protocol": "socks5"},
    {"url": "https://raw.githubusercontent.com/zevtyardt/proxy-list/main/socks4.txt", "protocol": "socks4"},
    # Zaeem20
    {"url": "https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/http.txt", "protocol": "http"},
    {"url": "https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/https.txt", "protocol": "http"},
    {"url": "https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/socks5.txt", "protocol": "socks5"},
    {"url": "https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/socks4.txt", "protocol": "socks4"},
    # vakhov
    {"url": "https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/http.txt", "protocol": "http"},
    {"url": "https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/https.txt", "protocol": "http"},
    {"url": "https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/socks5.txt", "protocol": "socks5"},
    {"url": "https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/socks4.txt", "protocol": "socks4"},
    # officialputuid (KangProxy)
    {"url": "https://raw.githubusercontent.com/officialputuid/KangProxy/KangProxy/http/http.txt", "protocol": "http"},
    {"url": "https://raw.githubusercontent.com/officialputuid/KangProxy/KangProxy/https/https.txt", "protocol": "http"},
    {"url": "https://raw.githubusercontent.com/officialputuid/KangProxy/KangProxy/socks5/socks5.txt", "protocol": "socks5"},
    {"url": "https://raw.githubusercontent.com/officialputuid/KangProxy/KangProxy/socks4/socks4.txt", "protocol": "socks4"},
    # ProxyScrape API
    {"url": "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all", "protocol": "http"},
    {"url": "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&timeout=10000&country=all&ssl=all&anonymity=all", "protocol": "socks5"},
    {"url": "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks4&timeout=10000&country=all&ssl=all&anonymity=all", "protocol": "socks4"},
]


class ProxyHarvesterService:
    """Manages continuous harvesting and freshness of proxies.txt and active pool."""

    def __init__(self, interval_hours: float = 4.0, min_threshold: int = 500):
        self.interval_seconds = interval_hours * 3600
        self.min_threshold = min_threshold
        self._is_harvesting = False
        self._last_harvest_time: float = 0.0
        self._harvest_count = 0
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        """Start the background auto-harvester loop."""
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._background_loop,
            name="ProxyAutoHarvesterDaemon",
            daemon=True,
        )
        self._thread.start()
        logger.info("[ProxyHarvester] Automatic proxy refresh service started")

    def stop(self) -> None:
        """Stop background harvester thread."""
        self._stop_event.set()
        self._thread = None
        logger.info("[ProxyHarvester] Automatic proxy refresh service stopped")

    def _background_loop(self) -> None:
        """Periodic check loop."""
        # Initial short wait after app boot
        self._stop_event.wait(10.0)

        while not self._stop_event.is_set():
            try:
                current_count = get_proxy_count()
                time_since_harvest = time.time() - self._last_harvest_time

                # Trigger harvest if pool is depleted OR refresh interval elapsed
                if current_count < self.min_threshold or time_since_harvest >= self.interval_seconds:
                    logger.info(
                        f"[ProxyHarvester] Triggering proxy harvest: active={current_count}, "
                        f"interval_elapsed={time_since_harvest:.0f}s"
                    )
                    self.harvest_and_refresh()
            except Exception as err:
                logger.error(f"[ProxyHarvester] Error in background harvester loop: {err}")

            # Sleep in intervals of 60 seconds to allow responsive stop
            for _ in range(60):
                if self._stop_event.is_set():
                    break
                time.sleep(1)

    def harvest_and_refresh(self) -> Dict[str, Any]:
        """Fetch fresh proxies from sources, merge into proxies.txt, and reload memory pool."""
        with self._lock:
            if self._is_harvesting:
                return {"status": "in_progress", "message": "Harvest already running"}
            self._is_harvesting = True

        try:
            logger.info("[ProxyHarvester] Harvesting fresh proxies from public sources...")
            fresh_proxies: Set[str] = set()

            with httpx.Client(
                timeout=10.0,
                follow_redirects=True,
                verify=not settings.ALLOW_INSECURE_TLS,
            ) as client:
                for src in PUBLIC_SOURCES:
                    url = src["url"]
                    proto = src["protocol"]
                    try:
                        resp = client.get(url)
                        if resp.status_code == 200:
                            matches = PROXY_PATTERN.findall(resp.text)
                            for match in matches:
                                fresh_proxies.add(f"{proto}://{match}")
                    except Exception as e:
                        logger.debug(f"[ProxyHarvester] Source {url} failed: {e}")

            if not fresh_proxies:
                logger.warning("[ProxyHarvester] No fresh proxies fetched from remote sources")
                return {"status": "error", "message": "No proxies fetched"}

            # Load existing proxies to preserve working ones
            proxy_file = getattr(settings, "PROXY_LIST_FILE", "proxies.txt")
            existing: Set[str] = set()
            if os.path.exists(proxy_file):
                try:
                    with open(proxy_file, "r", encoding="utf-8") as f:
                        for line in f:
                            p = line.strip()
                            if p and not p.startswith("#"):
                                existing.add(p)
                except Exception:
                    pass

            merged = list(existing.union(fresh_proxies))
            with open(proxy_file, "w", encoding="utf-8") as f:
                f.write("\n".join(merged) + "\n")

            self._last_harvest_time = time.time()
            self._harvest_count = len(merged)

            # Reload memory pool
            _init_proxy_pool()

            logger.info(
                f"[ProxyHarvester] Successfully harvested {len(fresh_proxies)} proxies. "
                f"Total pool size: {len(merged)} active proxies."
            )
            return {
                "status": "success",
                "harvested_count": len(fresh_proxies),
                "total_pool_count": len(merged),
                "last_harvest_time": self._last_harvest_time,
            }
        except Exception as exc:
            logger.error(f"[ProxyHarvester] Harvest failed: {exc}")
            return {"status": "error", "error": str(exc)}
        finally:
            with self._lock:
                self._is_harvesting = False

    def get_status(self) -> Dict[str, Any]:
        """Return harvester metrics and freshness state."""
        return {
            "is_harvesting": self._is_harvesting,
            "last_harvest_time": self._last_harvest_time,
            "total_harvested": self._harvest_count,
            "active_pool_count": get_proxy_count(),
            "interval_hours": self.interval_seconds / 3600,
            "min_threshold": self.min_threshold,
        }


# Singleton instance
_proxy_harvester: Optional[ProxyHarvesterService] = None
_harvester_lock = threading.Lock()


def get_proxy_harvester_service() -> ProxyHarvesterService:
    """Return or create singleton ProxyHarvesterService."""
    global _proxy_harvester
    if _proxy_harvester is None:
        with _harvester_lock:
            if _proxy_harvester is None:
                _proxy_harvester = ProxyHarvesterService()
    return _proxy_harvester
