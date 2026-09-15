import unittest
from datetime import datetime, timezone
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend_api.models.base import BaseModel
from backend_api.models.log_event import LogEvent
from backend_api.services.log_service import LogService, ring_buffer


class LogServiceTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine("sqlite:///:memory:")
        BaseModel.metadata.create_all(self.engine)
        self.db = sessionmaker(bind=self.engine)()

    def tearDown(self):
        self.db.close()

    def test_emit_and_retrieve_logs(self):
        # Emit multiple log levels and modules
        LogService.info("crawler", "Crawled https://example.test/home", detail="Found 5 links", db=self.db, experiment_id=1, target_id=10)
        LogService.warn("rate_limiter", "WAF rate limit backoff", detail="429 Too Many Requests", db=self.db, experiment_id=1, target_id=10)
        LogService.error("browser", "Browser timeout during CDP execution", db=self.db, experiment_id=1)
        LogService.hit("auditor", "🚨 Verified Stored XSS vulnerability confirmed", detail="Payload reflected in script tag", db=self.db, experiment_id=1, target_id=10)

        # Retrieve all logs
        res = LogService.get_logs(self.db)
        self.assertEqual(res["total"], 4)
        self.assertEqual(len(res["logs"]), 4)

        # Verify ordering (newest first)
        self.assertEqual(res["logs"][0]["level"], "HIT")
        self.assertEqual(res["logs"][0]["module"], "auditor")

        # Filter by level
        hits = LogService.get_logs(self.db, level="HIT")
        self.assertEqual(hits["total"], 1)
        self.assertEqual(hits["logs"][0]["level"], "HIT")

        # Filter by module
        crawler_logs = LogService.get_logs(self.db, module="crawler")
        self.assertEqual(crawler_logs["total"], 1)
        self.assertEqual(crawler_logs["logs"][0]["module"], "crawler")

        # Keyword search
        search_res = LogService.get_logs(self.db, search="timeout")
        self.assertEqual(search_res["total"], 1)
        self.assertIn("timeout", search_res["logs"][0]["message"].lower())

    def test_log_stats(self):
        LogService.info("fuzzer", "Generated 50 test cases", db=self.db, experiment_id=2)
        LogService.error("browser", "Navigation error", db=self.db, experiment_id=2)
        LogService.warn("profiler", "Sanitizer stripped script tag", db=self.db, experiment_id=2)
        LogService.hit("fuzzer", "XSS Alert triggered", db=self.db, experiment_id=2)

        stats = LogService.get_stats(self.db, experiment_id=2)
        self.assertEqual(stats["total"], 4)
        self.assertEqual(stats["hits"], 1)
        self.assertEqual(stats["errors"], 1)
        self.assertEqual(stats["warnings"], 1)
        self.assertEqual(stats["info"], 1)
        self.assertEqual(stats["modules"].get("fuzzer"), 2)
        self.assertEqual(stats["modules"].get("browser"), 1)

    def test_clear_logs(self):
        LogService.info("system", "Test message 1", db=self.db, experiment_id=5)
        LogService.info("system", "Test message 2", db=self.db, experiment_id=5)
        self.assertEqual(LogService.get_logs(self.db, experiment_id=5)["total"], 2)

        deleted = LogService.clear_logs(self.db, experiment_id=5)
        self.assertEqual(deleted, 2)
        self.assertEqual(LogService.get_logs(self.db, experiment_id=5)["total"], 0)

    def test_ring_buffer_integration(self):
        initial_count = len(ring_buffer.get_recent(500))
        LogService.info("orchestrator", "Ring buffer test event", db=self.db)
        recent = ring_buffer.get_recent(500)
        self.assertGreaterEqual(len(recent), initial_count + 1)
        self.assertEqual(recent[-1]["module"], "orchestrator")
        self.assertEqual(recent[-1]["message"], "Ring buffer test event")

    def test_credentials_are_redacted_but_payload_is_preserved(self):
        payload = "<img src=x onerror=alert(1)>"
        event = LogService.info(
            "browser.case",
            "Prepared request Authorization: Bearer should-not-leak",
            detail="Cookie: sid=secret-value",
            data={
                "payload": payload,
                "headers": {"Authorization": "Bearer secret-token", "X-Test": "visible"},
                "password": "hunter2",
            },
            db=self.db,
            experiment_id=8,
        )

        self.assertNotIn("should-not-leak", event["message"])
        self.assertNotIn("secret-value", event["detail"])
        self.assertEqual(event["data"]["headers"]["Authorization"], "[REDACTED]")
        self.assertEqual(event["data"]["password"], "[REDACTED]")
        self.assertEqual(event["data"]["payload"], payload)
