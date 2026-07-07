import unittest
from datetime import datetime
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend_api.models.base import BaseModel
from backend_api.models.test_case import TestCase
from backend_api.models.execution import Execution, OracleStatus
from oracle_server.main import oracle_callback


class OracleServerTests(unittest.TestCase):
    def setUp(self):
        # Setup in-memory SQLite DB
        self.engine = create_engine("sqlite:///:memory:")
        BaseModel.metadata.create_all(self.engine)
        SessionLocal = sessionmaker(bind=self.engine)
        self.db = SessionLocal()

        # Create dummy test case
        self.test_case = TestCase(
            experiment_id=1,
            endpoint_id=1,
            param_id=1,
            payload="<script>alert(1)</script>",
            token="test_unique_token_999"
        )
        self.db.add(self.test_case)
        self.db.commit()

    def tearDown(self):
        self.db.close()

    def test_oracle_callback_with_kind_execution(self):
        res = oracle_callback(
            token="test_unique_token_999",
            msg="SINK HIT: eval",
            sink="eval",
            kind="execution",
            data='{"filename":"test.js","line":1,"column":1}',
            db=self.db
        )

        self.assertEqual(res["status"], "ok")
        # Check execution record in DB
        execution = self.db.query(Execution).filter(Execution.test_case_id == self.test_case.id).first()
        self.assertIsNotNone(execution)
        self.assertEqual(execution.oracle_status, OracleStatus.HIT)
        self.assertEqual(execution.oracle_token, "test_unique_token_999")

    def test_oracle_callback_with_kind_taint(self):
        res = oracle_callback(
            token="test_unique_token_999",
            msg="SINK HIT: innerHTML",
            sink="innerHTML",
            kind="taint",
            data='{"filename":"test.js","line":1,"column":1}',
            db=self.db
        )

        self.assertEqual(res["status"], "ok")
        # Check execution record in DB
        execution = self.db.query(Execution).filter(Execution.test_case_id == self.test_case.id).first()
        self.assertIsNotNone(execution)
        self.assertEqual(execution.oracle_status, OracleStatus.MISSED)
        self.assertIsNone(execution.oracle_token)

    def test_oracle_callback_with_legacy_taint_is_not_a_hit(self):
        res = oracle_callback(
            token="test_unique_token_999",
            msg="SINK HIT: innerHTML",
            sink="innerHTML",
            kind=None,
            data='{"filename":"test.js","line":1,"column":1}',
            db=self.db
        )

        self.assertEqual(res["status"], "ok")
        execution = self.db.query(Execution).filter(Execution.test_case_id == self.test_case.id).first()
        self.assertIsNotNone(execution)
        self.assertEqual(execution.oracle_status, OracleStatus.MISSED)
        self.assertIsNone(execution.oracle_token)

    def test_oracle_callback_with_legacy_direct_beacon_is_a_hit(self):
        res = oracle_callback(
            token="test_unique_token_999",
            msg="direct payload beacon",
            sink="test_unique_token_999",
            kind=None,
            data='{"value":"test_unique_token_999"}',
            db=self.db
        )

        self.assertEqual(res["status"], "ok")
        execution = self.db.query(Execution).filter(Execution.test_case_id == self.test_case.id).first()
        self.assertIsNotNone(execution)
        self.assertEqual(execution.oracle_status, OracleStatus.HIT)
        self.assertEqual(execution.oracle_token, "test_unique_token_999")

    def test_oracle_callback_with_legacy_fallback_source_read_miss(self):
        res = oracle_callback(
            token="test_unique_token_999",
            msg="SINK HIT: DOMSourceRead:location.href",
            sink="DOMSourceRead:location.href",
            kind=None,
            data='{"filename":"test.js","line":1,"column":1}',
            db=self.db
        )

        self.assertEqual(res["status"], "ok")
        execution = self.db.query(Execution).filter(Execution.test_case_id == self.test_case.id).first()
        self.assertIsNotNone(execution)
        self.assertEqual(execution.oracle_status, OracleStatus.MISSED)


if __name__ == "__main__":
    unittest.main()
