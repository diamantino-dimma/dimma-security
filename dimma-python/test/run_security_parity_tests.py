"""Tests for Python security features shared with the Node.js runtime."""
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from flask import Flask


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from dimma.engine import DimmaEngine
from dimma.security.anomaly import RedisAnomalyDetector
from dimma.security import budget
from dimma.security.reputation import check_ip_reputation


class _FakeResponse:
    status = 200

    def __init__(self, payload):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, _limit):
        return self.payload


class _SharedRedis:
    def __init__(self):
        self.values = {}

    def eval(self, _script, _key_count, key, timestamp, window_size, _ttl):
        values = self.values.setdefault(key, [])
        values.append(timestamp)
        del values[:-int(window_size)]
        return list(values)

    def delete(self, key):
        self.values.pop(key, None)


class SecurityParityTests(unittest.TestCase):
    def setUp(self):
        budget._reset_for_testing()

    def tearDown(self):
        budget._reset_for_testing()

    def test_private_and_ipv4_mapped_private_addresses_are_not_sent(self):
        def fail_if_called(*_args, **_kwargs):
            raise AssertionError("private address must not reach external API")

        for ip in ("127.0.0.1", "10.1.2.3", "::ffff:192.168.1.2"):
            result = check_ip_reputation(ip, api_key="test-key", urlopen=fail_if_called)
            self.assertFalse(result["checked"], ip)

    def test_invalid_ip_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "IP invalido"):
            check_ip_reputation("not-an-ip", api_key="test-key")

    def test_abuseipdb_request_is_bounded_and_response_is_validated(self):
        captured = {}
        body = (
            b'{"data":{"ipAddress":"8.8.8.8","abuseConfidenceScore":92,'
            b'"totalReports":18,"countryCode":"US","isWhitelisted":false}}'
        )

        def fake_urlopen(request, timeout):
            captured["url"] = request.full_url
            captured["key"] = request.get_header("Key")
            captured["timeout"] = timeout
            return _FakeResponse(body)

        result = check_ip_reputation(
            "8.8.8.8",
            api_key="secret-test-key",
            timeout=2,
            urlopen=fake_urlopen,
        )

        self.assertTrue(result["checked"])
        self.assertEqual(result["abuseConfidenceScore"], 92)
        self.assertEqual(captured["key"], "secret-test-key")
        self.assertEqual(captured["timeout"], 2)
        self.assertIn("ipAddress=8.8.8.8", captured["url"])
        self.assertNotIn("secret-test-key", captured["url"])

    def test_exhausted_budget_skips_external_request(self):
        def fail_if_called(*_args, **_kwargs):
            raise AssertionError("exhausted budget must not call external API")

        result = check_ip_reputation(
            "8.8.8.8",
            api_key="test-key",
            daily_budget=0,
            urlopen=fail_if_called,
        )

        self.assertFalse(result["checked"])
        self.assertIn("esgotado", result["reason"])

    def test_external_reputation_blocks_only_after_local_anomaly(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "security.dimma"
            config_path.write_text(
                "@auto_protect: false\n"
                "@security_headers: false\n"
                "@csrf_protection: false\n"
                "@anomaly_detection: true\n"
                "@ip_reputation_check: true\n",
                encoding="utf-8",
            )
            app = Flask(__name__)
            app.config["TESTING"] = True
            engine = DimmaEngine(str(config_path), auto_create=False)
            engine._anomaly_detector.observe = lambda *_args: {
                "anomalous": True,
                "score": 4.5,
                "reason": "burst",
            }
            reputation = {
                "checked": True,
                "abuseConfidenceScore": 90,
                "totalReports": 7,
                "isWhitelisted": False,
            }
            app.config["SECRET_KEY"] = "test-secret-key"
            with patch("dimma.engine.check_ip_reputation", return_value=reputation) as check:
                engine.protect(app)

                @app.get("/protected")
                def protected():
                    return "ok"

                response = app.test_client().get("/protected")

            self.assertEqual(response.status_code, 403)
            self.assertEqual(response.json["abuseConfidenceScore"], 90)
            check.assert_called_once()

    def test_shared_budget_uses_atomic_redis_script_when_configured(self):
        counts = {}

        class FakeRedis:
            def eval(self, _script, _key_count, key, _ttl):
                counts[key] = counts.get(key, 0) + 1
                return counts[key]

        with patch.dict(os.environ, {"REDIS_URL": "redis://test.invalid"}):
            with patch("dimma.security.budget._get_redis_client", return_value=FakeRedis()):
                first = budget.consume_daily_budget("test-service", 1)
                second = budget.consume_daily_budget("test-service", 1)

        self.assertEqual(first["allowed"], 1)
        self.assertEqual(second["allowed"], 0)
        self.assertEqual(second["count"], 2)

    def test_redis_budget_failure_fails_closed_for_external_calls(self):
        from redis.exceptions import ConnectionError

        with patch.dict(os.environ, {"REDIS_URL": "redis://test.invalid"}):
            with patch(
                "dimma.security.budget._get_redis_client",
                side_effect=ConnectionError("connection details"),
            ):
                result = budget.consume_daily_budget("test-service", 100)

        self.assertEqual(result["allowed"], 0)
        self.assertEqual(result["remaining"], 0)

    def test_budget_rejects_boolean_or_negative_limits(self):
        for limit in (True, -1):
            with self.assertRaises(ValueError):
                budget.consume_daily_budget("test-service", limit)

    def test_redis_anomaly_history_is_shared_and_window_bounded(self):
        shared_redis = _SharedRedis()
        first = RedisAnomalyDetector(shared_redis, window_size=10, z_score_threshold=2)
        second = RedisAnomalyDetector(shared_redis, window_size=10, z_score_threshold=2)
        start = 1_000_000

        for index in range(15):
            detector = first if index % 2 == 0 else second
            detector.observe("client-a", start + index * 1000)
        result = second.observe("client-a", start + 14 * 1000 + 5)

        self.assertTrue(result["anomalous"])
        self.assertEqual(len(shared_redis.values["dimma:anomaly:client-a"]), 10)
        self.assertFalse(first.observe("client-b", start)["anomalous"])

    def test_redis_anomaly_failure_does_not_create_external_reputation_signal(self):
        class BrokenRedis:
            def eval(self, *_args):
                from redis.exceptions import ConnectionError

                raise ConnectionError("connection details")

        detector = RedisAnomalyDetector(BrokenRedis())
        result = detector.observe("client-a")

        self.assertFalse(result["anomalous"])
        self.assertEqual(result["reason"], "redis indisponivel")


if __name__ == "__main__":
    unittest.main()
