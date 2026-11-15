# -*- coding: utf-8 -*-
"""cloudflare_adpp.py 的本地验证：mock Cloudflare API，不联网、不使用真实凭据。

运行：python3 -m unittest discover -s examples/dns-providers/tests
"""

import importlib.util
import json
import subprocess
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

SCRIPT_PATH = Path(__file__).resolve().parents[1] / "cloudflare_adpp.py"
SPEC = importlib.util.spec_from_file_location("cloudflare_adpp", SCRIPT_PATH)
cloudflare_adpp = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(cloudflare_adpp)

TEST_TOKEN = "test-token-sentinel"
ZONE_EXAMPLE = {"id": "zone-example", "name": "example.com", "status": "active"}
ZONE_NET = {"id": "zone-net", "name": "validation.net", "status": "active"}

RESPONSE_KEYS = {"provider_name", "provider_version", "protocol", "version",
                 "request_id", "action", "results", "error"}
ERROR_KEYS = {"code", "message", "side_effect", "retry_after_seconds", "provider_code"}


class MockCloudflareHandler(BaseHTTPRequestHandler):
    """最小 Cloudflare v4 兼容面：zones 列表 + dns_records CRUD。"""

    server_version = "MockCloudflare/1"

    def log_message(self, fmt, *args):  # 安静模式
        pass

    # ---- 工具 ----

    def _send(self, status, payload, extra_headers=None):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def _authorized(self):
        return self.headers.get("Authorization") == "Bearer " + TEST_TOKEN

    def _body(self):
        length = int(self.headers.get("Content-Length", "0"))
        return json.loads(self.rfile.read(length).decode("utf-8")) if length else {}

    def _segments(self):
        # /client/v4/zones/{zone}/dns_records[/{id}]
        return [s for s in self.path.split("?")[0].split("/") if s]

    def _query(self):
        fragment = self.path.split("?", 1)
        if len(fragment) < 2:
            return {}
        return dict(pair.split("=", 1) for pair in fragment[1].split("&") if "=" in pair)

    # ---- 路由 ----

    def do_GET(self):
        state = self.server.state
        if not self._authorized():
            return self._send(401, {"success": False, "errors": [
                {"code": 9109, "message": "Unauthorized to access requested resource"}]})
        segments = self._segments()
        query = self._query()
        if segments[:3] == ["client", "v4", "zones"] and len(segments) == 3:
            name = query.get("name", "")
            matched = state.zones.get(name, [])
            state.requests.append(("zones", name))
            if state.ambiguous_zone_names.get(name):
                matched = matched * 2
            return self._send(200, {"success": True, "result": matched})
        # 形如 /client/v4/zones/{zone}/dns_records[/{id}]
        if (segments[:3] == ["client", "v4", "zones"] and len(segments) == 5
                and segments[4] == "dns_records"):
            zone_id = segments[3]
            records = [dict(record) for record in state.records.get(zone_id, {}).values()
                       if record.get("type") == query.get("type")
                       and record.get("name") == query.get("name")]
            page = int(query.get("page", "1"))
            return self._send(200, {
                "success": True, "result": records,
                "result_info": {"page": page, "total_pages": 1, "count": len(records)}})
        if (segments[:3] == ["client", "v4", "zones"] and len(segments) == 6
                and segments[4] == "dns_records"):
            zone_id, record_id = segments[3], segments[5]
            record = state.records.get(zone_id, {}).get(record_id)
            if record is None:
                return self._send(404, {"success": False, "errors": [
                    {"code": 81044, "message": "Record does not exist."}]})
            return self._send(200, {"success": True, "result": dict(record)})
        return self._send(404, {"success": False, "errors": [
            {"code": 7000, "message": "No route for that URI"}]})

    def do_POST(self):
        state = self.server.state
        if not self._authorized():
            return self._send(401, {"success": False, "errors": [
                {"code": 9109, "message": "Unauthorized"}]})
        segments = self._segments()
        if (segments[:3] == ["client", "v4", "zones"] and len(segments) == 5
                and segments[4] == "dns_records"):
            zone_id = segments[3]
            if zone_id not in state.records:
                return self._send(403, {"success": False, "errors": [
                    {"code": 9109, "message": "Unknown zone"}]})
            if state.fail_next_create:
                state.fail_next_create = False
                return self._send(429, {"success": False, "errors": [
                    {"code": 813, "message": "Rate limit exceeded"}]},
                    extra_headers={"Retry-After": "30"})
            body = self._body()
            state.create_counter += 1
            record_id = "cf-record-{0}".format(state.create_counter)
            record = {"id": record_id, "type": body.get("type"),
                      "name": body.get("name"), "content": body.get("content"),
                      "ttl": body.get("ttl"), "comment": body.get("comment")}
            state.records.setdefault(zone_id, {})[record_id] = record
            return self._send(200, {"success": True, "result": dict(record)})
        return self._send(404, {"success": False, "errors": [
            {"code": 7000, "message": "No route for that URI"}]})

    def do_DELETE(self):
        state = self.server.state
        if not self._authorized():
            return self._send(401, {"success": False, "errors": [
                {"code": 9109, "message": "Unauthorized"}]})
        segments = self._segments()
        if (segments[:3] == ["client", "v4", "zones"] and len(segments) == 6
                and segments[4] == "dns_records"):
            zone_id, record_id = segments[3], segments[5]
            record = state.records.get(zone_id, {}).pop(record_id, None)
            if record is None:
                return self._send(404, {"success": False, "errors": [
                    {"code": 81044, "message": "Record does not exist."}]})
            return self._send(200, {"success": True, "result": {"id": record_id}})
        return self._send(404, {"success": False, "errors": [
            {"code": 7000, "message": "No route for that URI"}]})


class MockState:
    def __init__(self):
        self.zones = {"example.com": [ZONE_EXAMPLE], "validation.net": [ZONE_NET]}
        self.records = {"zone-example": {}, "zone-net": {}}
        self.create_counter = 0
        self.fail_next_create = False
        self.ambiguous_zone_names = {}
        self.requests = []


class CloudflareAdppTest(unittest.TestCase):
    def setUp(self):
        self.state = MockState()
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), MockCloudflareHandler)
        self.server.state = self.state
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.api_base = "http://127.0.0.1:{0}/client/v4".format(self.server.server_port)

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()

    # ---- 请求/响应构造 ----

    def custom(self, **overrides):
        values = {"api_token": TEST_TOKEN, "api_base": self.api_base}
        values.update(overrides)
        for key, value in list(values.items()):
            if value is None:
                values.pop(key)
        return values

    def context(self, **overrides):
        return {
            "provider_instance_id": "cf-test",
            "provider_profile_version": 1,
            "provider_custom": self.custom(**overrides),
        }

    def entry(self, publication_id, name="_acme-challenge.example.com.",
              value="digest-value", ttl=120, record_id=None, ownership=None):
        item = {"publication_id": publication_id, "challenge_name": name,
                "cname_chain": [name],
                "record": {"type": "TXT", "name": name, "value": value,
                           "ttl_seconds": ttl}}
        if record_id is not None:
            item["record_id"] = record_id
        if ownership is not None:
            item["ownership"] = ownership
        return item

    def run_request(self, request):
        raw = json.dumps(request).encode("utf-8")
        response, exit_code = cloudflare_adpp.handle_request_bytes(raw)
        self.assertEqual(exit_code, 0)
        self.assertIsInstance(response, dict)
        self.validate_response_shape(request, response)
        return response

    def validate_response_shape(self, request, response):
        # 镜像 host 侧 wire.rs 的 deny_unknown_fields/关联校验。
        self.assertTrue(set(response.keys()) <= RESPONSE_KEYS, response.keys())
        self.assertIn("error", response)
        self.assertEqual(response.get("protocol"), "com.astercosm.acme.adpp")
        self.assertEqual(response.get("version"), 1)
        self.assertEqual(response.get("request_id"), request.get("request_id"))
        self.assertEqual(response.get("action"), request.get("action"))
        if response.get("error") is not None:
            self.assertEqual(response["results"], [])
            self.assertTrue(set(response["error"].keys()) <= ERROR_KEYS)
            self.assertEqual(response["error"]["side_effect"], "none")
            return
        publication_ids = [entry["publication_id"] for entry in request["records"]]
        self.assertEqual(sorted(item["publication_id"] for item in response["results"]),
                         sorted(publication_ids))
        self.assertEqual(len(response["results"]), len(publication_ids))
        for item in response["results"]:
            if item["status"] == "present":
                self.assertEqual(set(item.keys()),
                                 {"publication_id", "status", "record_id", "ownership"})
                self.assertTrue(item["record_id"])
                self.assertIn(item["ownership"], ("created", "preexisting"))
            elif item["status"] in ("removed", "retained", "already_absent"):
                self.assertEqual(set(item.keys()), {"publication_id", "status"})
            elif item["status"] == "error":
                self.assertEqual(set(item.keys()),
                                 {"publication_id", "status", "error"})
                self.assertTrue(set(item["error"].keys()) <= ERROR_KEYS)
            else:
                self.fail("unknown status: {0}".format(item["status"]))

    def cleanup_request(self, entry):
        return {"protocol": "com.astercosm.acme.adpp", "version": 1,
                "request_id": "req-" + entry["publication_id"],
                "action": "cleanup", "context": self.context(),
                "records": [entry]}

    def records_by_id(self):
        merged = {}
        for records in self.state.records.values():
            merged.update(records)
        return merged

    # ---- 用例 ----

    def test_present_create_then_cleanup_removes(self):
        request = {"protocol": "com.astercosm.acme.adpp", "version": 1,
                   "request_id": "req-1", "action": "present",
                   "context": self.context(),
                   "records": [self.entry("pub-one")]}
        response = self.run_request(request)
        self.assertIsNone(response["error"])
        result = response["results"][0]
        self.assertEqual(result["status"], "present")
        self.assertEqual(result["ownership"], "created")
        record = self.records_by_id()[result["record_id"]]
        self.assertEqual(record["comment"], "pub-one")
        self.assertEqual(record["content"], "digest-value")
        self.assertEqual(record["ttl"], 120)

        entry = request["records"][0]
        entry["record_id"] = result["record_id"]
        entry["ownership"] = result["ownership"]
        cleanup = self.run_request(self.cleanup_request(entry))
        self.assertEqual(cleanup["results"][0]["status"], "removed")
        self.assertEqual(self.records_by_id(), {})

        cleanup_again = self.run_request(self.cleanup_request(entry))
        self.assertEqual(cleanup_again["results"][0]["status"], "already_absent")

    def test_present_retries_reuse_same_record(self):
        entry = self.entry("pub-retry")
        first = self.run_request({"protocol": "com.astercosm.acme.adpp", "version": 1,
                                  "request_id": "req-r1", "action": "present",
                                  "context": self.context(), "records": [entry]})
        second = self.run_request({"protocol": "com.astercosm.acme.adpp", "version": 1,
                                   "request_id": "req-r2", "action": "present",
                                   "context": self.context(), "records": [entry]})
        self.assertEqual(first["results"][0]["record_id"],
                         second["results"][0]["record_id"])
        self.assertEqual(second["results"][0]["ownership"], "created")
        self.assertEqual(len(self.records_by_id()), 1)

    def test_preexisting_value_is_flagged_and_retained(self):
        self.state.records["zone-example"]["user-record"] = {
            "id": "user-record", "type": "TXT", "name": "_acme-challenge.example.com",
            "content": "digest-value", "ttl": 300, "comment": "user owns this"}
        entry = self.entry("pub-pre")
        response = self.run_request({"protocol": "com.astercosm.acme.adpp",
                                     "version": 1, "request_id": "req-p1",
                                     "action": "present", "context": self.context(),
                                     "records": [entry]})
        self.assertEqual(response["results"][0]["ownership"], "preexisting")
        entry["record_id"] = response["results"][0]["record_id"]
        entry["ownership"] = "preexisting"
        cleanup = self.run_request(self.cleanup_request(entry))
        self.assertEqual(cleanup["results"][0]["status"], "retained")
        self.assertIn("user-record", self.records_by_id())

    def test_batch_partial_failure_keeps_successful_results(self):
        good = self.entry("pub-good")
        bad = self.entry("pub-bad", name="_acme-challenge.nowhere.invalid.")
        response = self.run_request({"protocol": "com.astercosm.acme.adpp",
                                     "version": 1, "request_id": "req-b1",
                                     "action": "present", "context": self.context(),
                                     "records": [good, bad]})
        self.assertIsNone(response["error"])
        statuses = {item["publication_id"]: item for item in response["results"]}
        self.assertEqual(statuses["pub-good"]["status"], "present")
        self.assertEqual(statuses["pub-bad"]["status"], "error")
        self.assertEqual(statuses["pub-bad"]["error"]["code"], "zone_not_found")

    def test_request_level_errors(self):
        base = {"records": [self.entry("pub-x")]}
        cases = [
            ({"protocol": "other.protocol", "version": 1, "request_id": "r",
              "action": "present", "context": self.context(),
              "records": base["records"]},
             "invalid_request"),
            ({"protocol": "com.astercosm.acme.adpp", "version": 2, "request_id": "r",
              "action": "present", "context": self.context(),
              "records": base["records"]},
             "unsupported_version"),
            ({"protocol": "com.astercosm.acme.adpp", "version": 1, "request_id": "r",
              "action": "renew", "context": self.context(),
              "records": base["records"]},
             "unsupported_action"),
            ({"protocol": "com.astercosm.acme.adpp", "version": 1, "request_id": "r",
              "action": "present",
              "context": self.context(api_token=None), "records": base["records"]},
             "credentials_unavailable"),
            ({"protocol": "com.astercosm.acme.adpp", "version": 1, "request_id": "r",
              "action": "present",
              "context": self.context(api_token=None,
                                      token_file="/nonexistent/token"),
              "records": base["records"]},
             "credentials_unavailable"),
        ]
        for request, expected in cases:
            response = self.run_request(request)
            self.assertIsNotNone(response["error"])
            self.assertEqual(response["error"]["code"], expected)
            self.assertEqual(response["results"], [])

    def test_rate_limited_carries_retry_hint(self):
        self.state.fail_next_create = True
        response = self.run_request({"protocol": "com.astercosm.acme.adpp",
                                     "version": 1, "request_id": "req-rl",
                                     "action": "present", "context": self.context(),
                                     "records": [self.entry("pub-rl")]})
        error = response["results"][0]["error"]
        self.assertEqual(error["code"], "rate_limited")
        self.assertEqual(error["retry_after_seconds"], 30)
        # 被明确拒绝，未产生写入：side_effect 为 none。
        self.assertEqual(error["side_effect"], "none")

    def test_record_semantics_are_rejected_per_record(self):
        bad_type = self.entry("pub-a")
        bad_type["record"]["type"] = "A"
        bad_ttl = self.entry("pub-ttl")
        bad_ttl["record"]["ttl_seconds"] = 0
        response = self.run_request({"protocol": "com.astercosm.acme.adpp",
                                     "version": 1, "request_id": "req-v",
                                     "action": "present", "context": self.context(),
                                     "records": [bad_type, bad_ttl]})
        errors = {item["publication_id"]: item["error"]["code"]
                  for item in response["results"]}
        self.assertEqual(errors, {"pub-a": "invalid_request",
                                  "pub-ttl": "invalid_request"})
        self.assertEqual(self.records_by_id(), {})

    def test_cleanup_fail_closed_on_value_mismatch(self):
        entry = self.entry("pub-own")
        response = self.run_request({"protocol": "com.astercosm.acme.adpp",
                                     "version": 1, "request_id": "req-o1",
                                     "action": "present", "context": self.context(),
                                     "records": [entry]})
        record_id = response["results"][0]["record_id"]
        # 篡改记录内容：所有权不再可证明，必须失败且不删除。
        self.state.records["zone-example"][record_id]["content"] = "someone-else"
        entry["record_id"] = record_id
        entry["ownership"] = "created"
        cleanup = self.run_request(self.cleanup_request(entry))
        self.assertEqual(cleanup["results"][0]["status"], "error")
        self.assertEqual(cleanup["results"][0]["error"]["code"], "record_not_owned")
        self.assertIn(record_id, self.state.records["zone-example"])

    def test_zone_ambiguous_fails_closed(self):
        self.state.ambiguous_zone_names["example.com"] = True
        response = self.run_request({"protocol": "com.astercosm.acme.adpp",
                                     "version": 1, "request_id": "req-am",
                                     "action": "present", "context": self.context(),
                                     "records": [self.entry("pub-am")]})
        error = response["results"][0]["error"]
        self.assertEqual(error["code"], "zone_ambiguous")
        self.assertEqual(self.records_by_id(), {})

    def test_error_messages_never_contain_the_token(self):
        response = self.run_request({"protocol": "com.astercosm.acme.adpp",
                                     "version": 1, "request_id": "req-s",
                                     "action": "present",
                                     "context": self.context(
                                         api_token="wrong-token"),
                                     "records": [self.entry("pub-s")]})
        rendered = json.dumps(response)
        self.assertNotIn("wrong-token", rendered)
        self.assertNotIn(TEST_TOKEN, rendered)
        self.assertIsNone(response["error"])
        error = response["results"][0]["error"]
        self.assertEqual(error["code"], "authentication_failed")
        self.assertEqual(error["side_effect"], "none")


class SubprocessSmokeTest(unittest.TestCase):
    """以子进程方式验证完整的 stdin/stdout 管道契约（mock API，不联网）。"""

    @unittest.skipUnless(SCRIPT_PATH.exists(), "script missing")
    def test_script_roundtrip(self):
        # 起 mock server、喂请求、断言单行 JSON + 换行 + 退出码 0。
        state = MockState()
        server = ThreadingHTTPServer(("127.0.0.1", 0), MockCloudflareHandler)
        server.state = state
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            api_base = "http://127.0.0.1:{0}/client/v4".format(server.server_port)
            request = {
                "protocol": "com.astercosm.acme.adpp", "version": 1,
                "request_id": "req-sub", "action": "present",
                "context": {"provider_instance_id": "cf-sub",
                            "provider_profile_version": 1,
                            "provider_custom": {"api_token": TEST_TOKEN,
                                                "api_base": api_base}},
                "records": [{"publication_id": "pub-sub",
                             "challenge_name": "_acme-challenge.example.com.",
                             "cname_chain": ["_acme-challenge.example.com."],
                             "record": {"type": "TXT",
                                        "name": "_acme-challenge.example.com.",
                                        "value": "subprocess-value",
                                        "ttl_seconds": 120}}],
            }
            interpreter = sys.executable
            proc = subprocess.run(
                [interpreter, str(SCRIPT_PATH)],
                input=json.dumps(request).encode("utf-8"),
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertTrue(proc.stdout.endswith(b"\n"))
            self.assertEqual(proc.stdout.count(b"\n"), 1)
            response = json.loads(proc.stdout.decode("utf-8"))
            self.assertEqual(response["request_id"], "req-sub")
            self.assertIsNone(response["error"])
            self.assertEqual(response["results"][0]["ownership"], "created")
        finally:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    unittest.main()
