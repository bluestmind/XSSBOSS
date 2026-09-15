"""Self-improving learned parameter dictionary service.

Dynamically discovers, classifies, and persists parameter names across bug bounty programs
so that redirects, DOM sinks, JSONP callbacks, and debug flags are continuously learned
and shared across the entire scanning engine.
"""
from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set

from backend_api.utils.logger import logger


DATA_DIR = Path(__file__).resolve().parents[2] / "data"
DICT_FILE = DATA_DIR / "learned_param_dictionary.json"

DEFAULT_REDIRECT_PARAMS = [
    "url", "redirect", "redirect_uri", "redirecturl", "redirect_url",
    "originurl", "origin_url", "targeturl", "target_url", "dest", "destination",
    "goto", "return", "returnurl", "return_url", "r", "next", "continue", "continueurl",
    "relaystate", "forward", "referrer", "backurl", "checkouturl", "callbackurl",
    "callback_url", "auth_redirect", "login_redirect", "state", "target",
    "seoCallbackKey", "urlDynamic", "cartRedirectPayload", "viewUrl", "out", "link",
    "to", "nextUrl", "successUrl", "failUrl", "loginUrl", "oauthRedirect", "forwardUrl"
]

DEFAULT_SEARCH_PARAMS = [
    "q", "query", "search", "term", "keyword", "s", "filterViewID",
    "keywordDynamic", "find", "lookup", "key", "text", "queryText", "search_term"
]

DEFAULT_JSONP_PARAMS = [
    "callback", "cb", "jsonp", "call", "function", "handler", "jsonpCallback", "output"
]

DEFAULT_DEBUG_PARAMS = [
    "debug", "admin", "test", "dev", "preview", "enable", "mode", "view",
    "advancedHidden", "advancedQuick", "internal", "draft", "dryRun", "trace", "verbose"
]

DEFAULT_STATE_PARAMS = [
    "data", "payload", "state", "hash", "fragment", "dom", "template",
    "docPageID", "smart_page_id", "custom_fields", "workspaceID", "projectID"
]


class LearnedDictionaryService:
    """Self-improving learned parameter vocabulary engine."""

    _cache: Optional[Dict[str, Any]] = None

    @classmethod
    def _ensure_loaded(cls) -> Dict[str, Any]:
        """Load dictionary from disk or initialize with baseline entries."""
        if cls._cache is not None:
            return cls._cache

        DATA_DIR.mkdir(parents=True, exist_ok=True)
        if DICT_FILE.exists():
            try:
                with open(DICT_FILE, "r", encoding="utf-8") as f:
                    cls._cache = json.load(f)
                    return cls._cache
            except Exception as e:
                logger.warning(f"Failed to read {DICT_FILE}: {e}. Reinitializing.")

        # Initialize defaults
        items: Dict[str, Dict[str, Any]] = {}

        def add_defaults(params: List[str], cat: str):
            for p in params:
                items[p.lower()] = {
                    "param_name": p,
                    "category": cat,
                    "occurrence_count": 1,
                    "discovered_from": ["system_defaults"],
                    "is_custom": False,
                    "created_at": datetime.now(timezone.utc).isoformat(),
                    "updated_at": datetime.now(timezone.utc).isoformat(),
                }

        add_defaults(DEFAULT_REDIRECT_PARAMS, "redirect")
        add_defaults(DEFAULT_SEARCH_PARAMS, "search_query")
        add_defaults(DEFAULT_JSONP_PARAMS, "jsonp_callback")
        add_defaults(DEFAULT_DEBUG_PARAMS, "debug_privileged")
        add_defaults(DEFAULT_STATE_PARAMS, "dom_state")

        cls._cache = {
            "version": "1.0",
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "total_count": len(items),
            "items": items,
        }
        cls._save()
        return cls._cache

    @classmethod
    def _save(cls) -> None:
        """Persist in-memory cache to disk."""
        if cls._cache is None:
            return
        try:
            DATA_DIR.mkdir(parents=True, exist_ok=True)
            cls._cache["updated_at"] = datetime.now(timezone.utc).isoformat()
            cls._cache["total_count"] = len(cls._cache.get("items", {}))
            with open(DICT_FILE, "w", encoding="utf-8") as f:
                json.dump(cls._cache, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logger.error(f"Failed to save {DICT_FILE}: {e}")

    @classmethod
    def classify_param_name(cls, name: str) -> str:
        """Infer parameter category from name patterns."""
        n = name.lower()
        if any(w in n for w in ["redirect", "url", "dest", "return", "goto", "next", "forward", "link", "callback", "out", "target", "uri"]):
            return "redirect"
        if any(w in n for w in ["search", "query", "term", "find", "keyword", "filter", "key"]):
            return "search_query"
        if any(w in n for w in ["jsonp", "cb", "callback", "handler"]):
            return "jsonp_callback"
        if any(w in n for w in ["debug", "admin", "test", "dev", "mode", "preview", "dry", "trace"]):
            return "debug_privileged"
        if any(w in n for w in ["file", "path", "page", "doc", "template", "include", "src"]):
            return "file_path"
        return "general_parameter"

    @classmethod
    def register_parameter(
        cls,
        name: str,
        category: Optional[str] = None,
        source: Optional[str] = None,
        is_custom: bool = False
    ) -> Dict[str, Any]:
        """Register a newly discovered parameter into the self-improving dictionary."""
        data = cls._ensure_loaded()
        items = data.setdefault("items", {})

        clean_name = name.strip()
        if not clean_name or len(clean_name) > 80:
            return {}

        key = clean_name.lower()
        cat = category or cls.classify_param_name(clean_name)
        source_label = (source or "unknown").strip()

        now_iso = datetime.now(timezone.utc).isoformat()

        if key in items:
            item = items[key]
            item["occurrence_count"] = item.get("occurrence_count", 1) + 1
            item["updated_at"] = now_iso
            sources = item.setdefault("discovered_from", [])
            if source_label not in sources and len(sources) < 15:
                sources.append(source_label)
            if is_custom:
                item["is_custom"] = True
                item["category"] = cat
        else:
            item = {
                "param_name": clean_name,
                "category": cat,
                "occurrence_count": 1,
                "discovered_from": [source_label],
                "is_custom": is_custom,
                "created_at": now_iso,
                "updated_at": now_iso,
            }
            items[key] = item
            logger.info(f"[Learned Dictionary] Auto-learned new parameter: '{clean_name}' (category: {cat}) from {source_label}")

        cls._save()
        return item

    @classmethod
    def register_batch(cls, names: Iterable[str], source: Optional[str] = None) -> int:
        """Batch register discovered parameter names."""
        added = 0
        for name in names:
            if cls.register_parameter(name, source=source):
                added += 1
        return added

    @classmethod
    def get_redirect_param_names(cls) -> Set[str]:
        """Get full dynamic set of all redirect and navigation parameters."""
        data = cls._ensure_loaded()
        items = data.get("items", {})
        redirect_names = {p.lower() for p in DEFAULT_REDIRECT_PARAMS}

        for k, v in items.items():
            if v.get("category") == "redirect" or cls.classify_param_name(k) == "redirect":
                redirect_names.add(k)
                redirect_names.add(v.get("param_name", k))

        return redirect_names

    @classmethod
    def get_fuzzing_param_names(cls) -> List[str]:
        """Get prioritized list of all parameter names for probing."""
        data = cls._ensure_loaded()
        items = data.get("items", {})

        # Sort by occurrence count desc
        sorted_items = sorted(
            items.values(),
            key=lambda x: (x.get("is_custom", False), x.get("occurrence_count", 0)),
            reverse=True
        )
        return [item["param_name"] for item in sorted_items]

    @classmethod
    def get_all(cls, category: Optional[str] = None, query: Optional[str] = None) -> List[Dict[str, Any]]:
        """Return full list of dictionary items with optional filtering."""
        data = cls._ensure_loaded()
        items = list(data.get("items", {}).values())

        if category:
            items = [i for i in items if i.get("category") == category]

        if query:
            q = query.lower().strip()
            items = [i for i in items if q in i.get("param_name", "").lower() or any(q in s.lower() for s in i.get("discovered_from", []))]

        return sorted(items, key=lambda x: x.get("occurrence_count", 0), reverse=True)

    @classmethod
    def delete_param(cls, name: str) -> bool:
        """Delete parameter from dictionary."""
        data = cls._ensure_loaded()
        items = data.get("items", {})
        key = name.strip().lower()
        if key in items:
            del items[key]
            cls._save()
            return True
        return False
