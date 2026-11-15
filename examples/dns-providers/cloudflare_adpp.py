#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""AsterACME ADPP v1 外部 DNS provider：Cloudflare。

协议契约见 docs/rfc/dns-provider-protocol/0001-asteracme-dns-provider-protocol.md。

调用形态：一次进程调用，stdin 收一个 ADPP v1 JSON 请求，stdout 回一个 JSON
响应并以换行结尾；诊断只写 stderr。AsterACME 以清空 ENV 的方式启动本脚本，
所以凭据只从请求 context.provider_custom 读取，不读环境变量。

provider_custom 支持的键：
- api_token:  Cloudflare API token（直接存入 provider profile，敏感）。
- token_file: 保存 token 的文件绝对路径；读取整个文件并去除首尾空白。
- zone_id:    可选；固定使用的 Cloudflare zone ID，跳过 zone 发现。
- api_base:   可选；覆盖 API 根地址，仅供本地 mock 测试使用。

仅依赖 Python 3.9+ 标准库；退出码 0 表示已输出结构化响应（含错误响应）。
"""

import json
import sys
import urllib.error
import urllib.parse
import urllib.request

PROTOCOL_ID = "com.astercosm.acme.adpp"
PROTOCOL_VERSION = 1
PROVIDER_NAME = "cloudflare-adpp"
PROVIDER_VERSION = "0.1.0"

DEFAULT_API_BASE = "https://api.cloudflare.com/client/v4"
MAX_INPUT_BYTES = 1024 * 1024
MAX_RESPONSE_BYTES = 1024 * 1024
MAX_RECORDS = 100
MAX_VALUE_BYTES = 255
MAX_RECORD_ID_BYTES = 1024
MAX_TTL = 2147483647
MAX_MESSAGE_CHARS = 500

DEFAULT_TTL = 120
CLOUDFLARE_MIN_TTL = 60
CLOUDFLARE_MAX_TTL = 86400
COMMENT_MAX_CHARS = 100
REQUEST_TIMEOUT_SECONDS = 10.0
LIST_PAGE_SIZE = 100
LIST_MAX_PAGES = 5
ZONE_MAX_LABELS = 10

# Cloudflare 在并发/竞态下对同值记录会返回"已存在"类错误码。
CLOUDFLARE_DUPLICATE_CODES = {"81053", "81057", "9106", "81044"}


class ProviderError(Exception):
    """携带 ADPP 稳定错误码的失败；side_effect 说明 DNS 是否可能已改变。"""

    def __init__(self, message, code, side_effect="none",
                 retry_after_seconds=None, provider_code=None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.side_effect = side_effect
        self.retry_after_seconds = retry_after_seconds
        self.provider_code = provider_code

    def to_wire(self):
        wire = {
            "code": self.code,
            "message": sanitize_text(self.message, MAX_MESSAGE_CHARS),
            "side_effect": self.side_effect,
        }
        if (self.code == "rate_limited"
                and isinstance(self.retry_after_seconds, int)
                and not isinstance(self.retry_after_seconds, bool)
                and 1 <= self.retry_after_seconds <= 86400):
            wire["retry_after_seconds"] = self.retry_after_seconds
        code = self.provider_code
        if isinstance(code, str) and code and len(code) <= 128 and code.isascii() \
                and all(c.isprintable() and not c.isspace() for c in code):
            wire["provider_code"] = code
        return wire


class CloudflareApiError(ProviderError):
    """保留 HTTP 状态与 Cloudflare 错误码，供 404 之类的流程分支使用。"""

    def __init__(self, code, message, status, side_effect="none",
                 retry_after_seconds=None, provider_code=None):
        super().__init__(message, code, side_effect=side_effect,
                         retry_after_seconds=retry_after_seconds,
                         provider_code=provider_code)
        self.status = status


def sanitize_text(text, limit):
    """单行、去空白噪声并截断的错误文本；不承载凭据。"""
    collapsed = " ".join(str(text).split())
    return collapsed[:limit]


def log(message):
    sys.stderr.write(f"[{PROVIDER_NAME}] {message}\n")
    sys.stderr.flush()


def is_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def valid_record_id(value):
    control = any(ord(c) < 32 or ord(c) == 127 for c in value)
    return (isinstance(value, str) and value
            and len(value) <= MAX_RECORD_ID_BYTES and not control)


class CloudflareClient:
    """Cloudflare API v4 的最小客户端；一次进程调用内复用 zone 缓存。"""

    def __init__(self, token, api_base):
        self._token = token
        self._api_base = api_base.rstrip("/")
        self._zone_candidates = {}
        self._zones_for_record = {}

    def call(self, method, path, params=None, body=None, may_mutate=False):
        """一次 API 调用；返回成功 payload，失败抛 ProviderError。

        may_mutate 决定传输层失败（网络断开、响应丢失）的 side_effect：
        可能已触达写操作的按 unknown 上报，只读操作按 none 上报。
        服务端返回结构化错误时视为明确拒绝，副作用可证明为 none。
        """
        url = self._api_base + path
        if params:
            url += "?" + urllib.parse.urlencode(params)
        data = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")
        request = urllib.request.Request(url, data=data, method=method)
        request.add_header("Authorization", "Bearer " + self._token)
        if data is not None:
            request.add_header("Content-Type", "application/json")
        request.add_header("User-Agent", f"{PROVIDER_NAME}/{PROVIDER_VERSION}")
        try:
            with urllib.request.urlopen(
                    request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
                status = response.status
                raw = response.read(MAX_RESPONSE_BYTES + 1)
                headers = response.headers
        except urllib.error.HTTPError as error:
            status = error.code
            raw = error.read(MAX_RESPONSE_BYTES + 1)
            headers = error.headers
        except Exception as error:  # 传输层失败：连接、TLS、超时
            raise ProviderError(
                f"Cloudflare API unreachable: {error}",
                code="provider_unavailable",
                side_effect="unknown" if may_mutate else "none")
        if len(raw) > MAX_RESPONSE_BYTES:
            raise ProviderError(
                "Cloudflare API response too large",
                code="provider_unavailable",
                side_effect="unknown" if may_mutate else "none")
        retry_after = None
        if status == 429 and headers is not None:
            retry_after = parse_retry_after(headers.get("Retry-After"))
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            raise ProviderError(
                "Cloudflare API returned an unreadable response",
                code="provider_unavailable",
                side_effect="unknown" if may_mutate else "none")
        if not isinstance(payload, dict) or payload.get("success") is not True:
            errors = payload.get("errors") if isinstance(payload, dict) else None
            detail, cf_code = summarize_cf_errors(errors)
            code, message = map_http_failure(status, detail)
            # 服务端返回了结构化错误：本次请求被明确拒绝，可证明无副作用。
            raise CloudflareApiError(
                code, message, status, side_effect="none",
                retry_after_seconds=retry_after, provider_code=cf_code)
        return payload

    def resolve_zone(self, record_name, pinned_zone_id=None):
        """按最长后缀找到权威 zone；pinned_zone_id 跳过发现。"""
        if pinned_zone_id:
            return pinned_zone_id
        name = record_name.rstrip(".").lower()
        if name in self._zones_for_record:
            zone_id = self._zones_for_record[name]
            if zone_id is None:
                raise ProviderError(f"no Cloudflare zone matched {name}",
                                    code="zone_not_found")
            return zone_id
        labels = name.split(".")
        if len(labels) < 2 or len(labels) > ZONE_MAX_LABELS:
            raise ProviderError(f"no Cloudflare zone matched {name}",
                                code="zone_not_found")
        for index in range(len(labels) - 1):
            candidate = ".".join(labels[index:])
            if candidate in self._zone_candidates:
                zone_id = self._zone_candidates[candidate]
            else:
                zone_id = self._query_zone(candidate)
                self._zone_candidates[candidate] = zone_id
            if zone_id is not None:
                self._zones_for_record[name] = zone_id
                return zone_id
        self._zones_for_record[name] = None
        raise ProviderError(f"no Cloudflare zone matched {name}",
                            code="zone_not_found")

    def _query_zone(self, candidate):
        payload = self.call("GET", "/zones", params={
            "name": candidate, "status": "active", "per_page": "50"})
        zones = payload.get("result")
        if not isinstance(zones, list) or not zones:
            return None
        zone_ids = []
        for zone in zones:
            if isinstance(zone, dict) and isinstance(zone.get("id"), str):
                zone_ids.append(zone["id"])
        if len(zone_ids) != 1:
            raise ProviderError(
                f"{len(zone_ids)} Cloudflare zones matched {candidate}",
                code="zone_ambiguous")
        return zone_ids[0]

    def list_txt(self, zone_id, name_no_dot):
        """分页列出该 owner 的 TXT 记录。"""
        records = []
        page = 1
        while page <= LIST_MAX_PAGES:
            payload = self.call(
                "GET", f"/zones/{zone_id}/dns_records",
                params={"type": "TXT", "name": name_no_dot,
                        "per_page": str(LIST_PAGE_SIZE), "page": str(page)})
            batch = payload.get("result")
            if not isinstance(batch, list):
                raise ProviderError(
                    "Cloudflare list returned no result array",
                    code="internal_error")
            records.extend(item for item in batch if isinstance(item, dict))
            info = payload.get("result_info")
            total_pages = info.get("total_pages") if isinstance(info, dict) else None
            if not batch or not is_int(total_pages) or page >= total_pages:
                break
            page += 1
        return records

    def create_txt(self, zone_id, name_no_dot, value, ttl, comment):
        body = {"type": "TXT", "name": name_no_dot, "content": value,
                "ttl": ttl, "comment": comment}
        payload = self.call("POST", f"/zones/{zone_id}/dns_records",
                            body=body, may_mutate=True)
        record = payload.get("result")
        record_id = record.get("id") if isinstance(record, dict) else None
        if not isinstance(record_id, str) or not record_id:
            raise ProviderError(
                "Cloudflare create returned no record ID",
                code="internal_error", side_effect="unknown")
        return record_id

    def get_record(self, zone_id, record_id):
        """按 ID 读取记录；不存在返回 None。"""
        try:
            payload = self.call(
                "GET", f"/zones/{zone_id}/dns_records/{record_id}")
        except CloudflareApiError as error:
            if error.status == 404 or error.provider_code in CLOUDFLARE_DUPLICATE_CODES:
                return None
            raise
        record = payload.get("result")
        if not isinstance(record, dict):
            raise ProviderError(
                "Cloudflare get returned no result object", code="internal_error")
        return record

    def delete_record(self, zone_id, record_id):
        self.call("DELETE", f"/zones/{zone_id}/dns_records/{record_id}",
                  may_mutate=True)


def parse_retry_after(header_value):
    if not isinstance(header_value, str):
        return None
    try:
        seconds = int(header_value.strip())
    except ValueError:
        return None
    return max(1, min(seconds, 86400))


def summarize_cf_errors(errors):
    """提取首个 Cloudflare 错误码与消息；不回传完整响应体。"""
    if isinstance(errors, list) and errors and isinstance(errors[0], dict):
        code = errors[0].get("code")
        message = errors[0].get("message")
        code_text = str(code) if is_int(code) or isinstance(code, str) else None
        if isinstance(message, str) and message:
            return message, code_text
        return "Cloudflare API rejected the request", code_text
    return "Cloudflare API rejected the request", None


def map_http_failure(status, detail):
    if status == 401:
        return "authentication_failed", f"Cloudflare rejected the API token: {detail}"
    if status == 403:
        return "authorization_denied", f"Cloudflare token lacks permission: {detail}"
    if status == 429:
        return "rate_limited", f"Cloudflare rate limit reached: {detail}"
    if isinstance(status, int) and 500 <= status <= 599:
        return "provider_unavailable", f"Cloudflare service error: {detail}"
    return "internal_error", f"Cloudflare request failed: {detail}"


def load_settings(context):
    """从 provider_custom 解析凭据与选项；ENV 被清空，这里没有环境变量可用。"""
    custom = context.get("provider_custom")
    if not isinstance(custom, dict):
        custom = {}
    api_base = custom.get("api_base")
    if api_base is None:
        api_base = DEFAULT_API_BASE
    if not isinstance(api_base, str) or not api_base.startswith(("http://", "https://")):
        raise ProviderError("provider_custom.api_base must be an http(s) URL",
                            code="invalid_request")
    token = custom.get("api_token")
    if isinstance(token, str) and token.strip():
        token = token.strip()
    else:
        token = None
        token_file = custom.get("token_file")
        if isinstance(token_file, str) and token_file.strip():
            try:
                with open(token_file.strip(), "r", encoding="utf-8") as handle:
                    token = handle.read().strip()
            except OSError as error:
                raise ProviderError(
                    f"cannot read provider_custom.token_file: {error}",
                    code="credentials_unavailable")
            if not token:
                raise ProviderError("provider_custom.token_file is empty",
                                    code="credentials_unavailable")
    if not token:
        raise ProviderError("provider_custom needs api_token or token_file",
                            code="credentials_unavailable")
    zone_id = custom.get("zone_id")
    if zone_id is not None and not (isinstance(zone_id, str) and zone_id.strip()):
        raise ProviderError("provider_custom.zone_id must be a nonempty string",
                            code="invalid_request")
    return token, api_base, zone_id.strip() if zone_id else None


def validate_envelope(request):
    """校验请求信封；结构性问题抛请求级错误（未开始任何记录操作）。"""
    if not isinstance(request, dict):
        raise ProviderError("request is not a JSON object", code="invalid_request")
    if request.get("protocol") != PROTOCOL_ID:
        raise ProviderError(
            "unknown protocol identifier, expected com.astercosm.acme.adpp",
            code="invalid_request")
    version = request.get("version")
    if not is_int(version) or version != PROTOCOL_VERSION:
        raise ProviderError("provider supports ADPP version 1 only",
                            code="unsupported_version")
    action = request.get("action")
    if action not in ("present", "cleanup"):
        raise ProviderError("unknown action, expected present or cleanup",
                            code="unsupported_action")
    context = request.get("context")
    if not isinstance(context, dict) or not isinstance(context.get("provider_instance_id"), str):
        raise ProviderError("request context is invalid", code="invalid_request")
    records = request.get("records")
    if not isinstance(records, list) or not records or len(records) > MAX_RECORDS:
        raise ProviderError("request must carry 1-100 records", code="invalid_request")
    seen = set()
    for record in records:
        if not isinstance(record, dict):
            raise ProviderError("record entry is not an object", code="invalid_request")
        publication_id = record.get("publication_id")
        if not isinstance(publication_id, str) or not publication_id:
            raise ProviderError("record is missing a publication ID",
                                code="invalid_request")
        if publication_id in seen:
            raise ProviderError(f"duplicate publication ID {publication_id}",
                                code="invalid_request")
        seen.add(publication_id)
    return action, context, records


def validate_record_data(record):
    """校验 record 字段语义；语义问题按记录级 invalid_request 上报。"""
    data = record.get("record")
    if not isinstance(data, dict):
        raise ProviderError("record is missing DNS record data", code="invalid_request")
    if data.get("type") != "TXT":
        raise ProviderError("only TXT records are supported", code="invalid_request")
    name = data.get("name")
    if not isinstance(name, str) or not name.endswith("."):
        raise ProviderError(
            "record name must be absolute with a trailing dot", code="invalid_request")
    value = data.get("value")
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > MAX_VALUE_BYTES:
        raise ProviderError("TXT value must be 1-255 bytes", code="invalid_request")
    ttl = data.get("ttl_seconds")
    if ttl is not None and (not is_int(ttl) or ttl < 1 or ttl > MAX_TTL):
        raise ProviderError("ttl_seconds is out of range", code="invalid_request")
    return name, value, ttl


def request_level(request_id, action, error):
    return {
        "protocol": PROTOCOL_ID,
        "version": PROTOCOL_VERSION,
        "request_id": request_id,
        "action": action,
        "results": [],
        "error": error,
    }


def present_one(client, entry, pinned_zone_id):
    publication_id = entry["publication_id"]
    name, value, ttl = validate_record_data(entry)
    name_no_dot = name.rstrip(".")
    zone_id = client.resolve_zone(name, pinned_zone_id)
    existing = find_exact_value(client, zone_id, name_no_dot, value)
    if existing is not None:
        comment = existing.get("comment")
        ours = (isinstance(comment, str)
                and comment == publication_id[:COMMENT_MAX_CHARS])
        ownership = "created" if ours else "preexisting"
        record_id = existing.get("id")
        if not valid_record_id(record_id):
            raise ProviderError(
                "Cloudflare list returned a record without a usable ID",
                code="internal_error", side_effect="unknown")
        log(f"present {name_no_dot}: found existing record {record_id} ({ownership})")
    else:
        effective_ttl = max(CLOUDFLARE_MIN_TTL,
                            min(ttl if ttl is not None else DEFAULT_TTL,
                                CLOUDFLARE_MAX_TTL))
        record_id, ownership = create_with_reconcile(
            client, zone_id, name_no_dot, value, effective_ttl, publication_id)
        log(f"present {name_no_dot}: created record {record_id}")
    return {
        "publication_id": publication_id,
        "status": "present",
        "record_id": record_id,
        "ownership": ownership,
    }


def find_exact_value(client, zone_id, name_no_dot, value):
    for record in client.list_txt(zone_id, name_no_dot):
        if record.get("type") == "TXT" and record.get("content") == value \
                and isinstance(record.get("id"), str):
            return record
    return None


def create_with_reconcile(client, zone_id, name_no_dot, value, ttl, publication_id):
    """创建；竞态下 Cloudflare 报"已存在"时改为对账既有记录。"""
    try:
        return client.create_txt(zone_id, name_no_dot, value, ttl,
                                 publication_id[:COMMENT_MAX_CHARS]), "created"
    except CloudflareApiError as error:
        if error.provider_code not in CLOUDFLARE_DUPLICATE_CODES \
                and "already exist" not in error.message.lower():
            raise
    existing = find_exact_value(client, zone_id, name_no_dot, value)
    if existing is None or not valid_record_id(existing.get("id")):
        raise ProviderError(
            "Cloudflare reports a conflicting record that cannot be reconciled",
            code="record_conflict")
    comment = existing.get("comment")
    ours = isinstance(comment, str) and comment == publication_id[:COMMENT_MAX_CHARS]
    log(f"present {name_no_dot}: reconciled duplicate create to record {existing['id']}")
    return existing["id"], "created" if ours else "preexisting"


def cleanup_one(client, entry, pinned_zone_id):
    publication_id = entry["publication_id"]
    ownership = entry.get("ownership")
    if ownership == "preexisting":
        # 事先存在的同值记录不是本次创建的；清理必须保留它。
        record_name = entry.get("record", {}).get("name", "?")
        log(f"cleanup {record_name}: preexisting value retained")
        return {"publication_id": publication_id, "status": "retained"}
    if ownership != "created":
        raise ProviderError("cleanup ownership must be created or preexisting",
                            code="invalid_request")
    name, value, _ = validate_record_data(entry)
    record_id = entry.get("record_id")
    if not valid_record_id(record_id):
        raise ProviderError("cleanup is missing a valid record ID",
                            code="invalid_request")
    zone_id = client.resolve_zone(name, pinned_zone_id)
    current = client.get_record(zone_id, record_id)
    if current is None:
        log(f"cleanup {name.rstrip('.')}: record {record_id} already absent")
        return {"publication_id": publication_id, "status": "already_absent"}
    content = current.get("content")
    current_name = current.get("name")
    if current.get("type") != "TXT" or content != value \
            or not isinstance(current_name, str) \
            or current_name.rstrip(".").lower() != name.rstrip(".").lower():
        # 所有权无法证明时按 fail closed 处理，保留记录。
        raise ProviderError(
            f"record {record_id} no longer holds this publication's exact value",
            code="record_not_owned")
    client.delete_record(zone_id, record_id)
    log(f"cleanup {name.rstrip('.')}: removed record {record_id}")
    return {"publication_id": publication_id, "status": "removed"}


def handle_request_bytes(raw):
    """ADPP 入口：返回 (response_dict, exit_code)。始终尽量回结构化响应。"""
    if len(raw) > MAX_INPUT_BYTES:
        log("request exceeds the 1 MiB ADPP bound; refusing")
        return None, 2
    try:
        request = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as error:
        log(f"stdin is not valid UTF-8 JSON: {error}")
        return None, 2
    request_id = request.get("request_id") if isinstance(request, dict) else None
    if not isinstance(request_id, str):
        request_id = ""
    action = request.get("action") if isinstance(request, dict) else None
    action = action if isinstance(action, str) else ""
    try:
        action, context, records = validate_envelope(request)
        token, api_base, pinned_zone_id = load_settings(context)
        client = CloudflareClient(token, api_base)
        handler = present_one if action == "present" else cleanup_one
        results = []
        for entry in records:
            try:
                results.append(handler(client, entry, pinned_zone_id))
            except ProviderError as error:
                log(f"record {entry.get('publication_id')} failed: "
                    f"{error.code} ({error.side_effect})")
                results.append({
                    "publication_id": entry["publication_id"],
                    "status": "error",
                    "error": error.to_wire(),
                })
            except Exception as error:  # 未预期缺陷：副作用状态未知
                log(f"record {entry.get('publication_id')} failed unexpectedly: {error}")
                results.append({
                    "publication_id": entry["publication_id"],
                    "status": "error",
                    "error": ProviderError("unexpected provider failure",
                                           code="internal_error",
                                           side_effect="unknown").to_wire(),
                })
        response = {
            "provider_name": PROVIDER_NAME,
            "provider_version": PROVIDER_VERSION,
            "protocol": PROTOCOL_ID,
            "version": PROTOCOL_VERSION,
            "request_id": request_id,
            "action": action,
            "results": results,
            "error": None,
        }
    except ProviderError as error:
        if error.side_effect != "none":
            # 请求级错误按协议必须 none；到这里的路径都未开始记录操作。
            error = ProviderError(error.message, code=error.code, side_effect="none",
                                  retry_after_seconds=error.retry_after_seconds,
                                  provider_code=error.provider_code)
        response = request_level(request_id, action, error.to_wire())
    return response, 0


def main():
    raw = sys.stdin.buffer.read()
    response, exit_code = handle_request_bytes(raw)
    if response is None:
        return exit_code
    sys.stdout.write(json.dumps(response) + "\n")
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
