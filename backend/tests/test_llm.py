"""LLM 分析服务测试。

全部使用假客户端或 ``httpx.MockTransport``，**不发起真实网络请求，
也不依赖真实 API key**。覆盖四层：

1. 客户端：请求构造、重试、超时、错误映射、响应上限；
2. 提示词：行号、上下文截断、不可信数据声明、key 不出现在消息里；
3. 解析：JSON 容错、逐条校验、行号核对、证据取自源码；
4. 编排与扫描集成：缺配置降级、失败不抹掉其他分析器、跨分析器去重。
"""

from __future__ import annotations

import json

import httpx
import pytest
from pydantic import SecretStr, ValidationError

from app.analyzers.line_index import LineIndex
from app.analyzers.llm import (
    ALLOWED_VULNERABILITY_TYPES,
    SYSTEM_PROMPT,
    build_prompt,
    detect_llm_findings,
    parse_llm_output,
)
from app.analyzers.llm.parser import LlmOutputError
from app.core.config import Settings, settings as app_settings
from app.llm.client import MAX_RESPONSE_BYTES, LlmClient, missing_settings
from app.llm.errors import (
    LlmConfigurationError,
    LlmNetworkError,
    LlmRateLimitError,
    LlmResponseFormatError,
    LlmResponseTooLargeError,
    LlmServerError,
    LlmTimeoutError,
)
from app.schemas.enums import AnalyzerName, AnalyzerState, FindingSource
from app.schemas.finding import Finding
from app.schemas.scan import DEFAULT_DISCLAIMER, ScanRequest
from app.services.scan_service import run_scan

SOURCE = """from flask import Flask, request
import os

app = Flask(__name__)

@app.route("/run")
def run():
    cmd = request.args.get("cmd")
    os.system("echo " + cmd)
"""

LLM_ONLY_SOURCE = """def handler(request):
    uid = request.args.get("id")
    return "Hello " + uid
"""


# ---------------------------------------------------------------------------
# 辅助
# ---------------------------------------------------------------------------


def _finding(**overrides: object) -> Finding:
    data: dict[str, object] = {
        "id": "0123456789abcdef",
        "title": "疑似 SQL 注入",
        "vulnerability_type": "sql_injection",
        "severity": "medium",
        "description": "说明",
        "evidence": "",
        "line_start": 8,
        "line_end": 8,
        "recommendation": "修复建议",
        "confidence": 0.5,
        "source": FindingSource.STATIC_RULE,
        "rule_id": "ARGUS-SQL-001",
    }
    data.update(overrides)
    return Finding(**data)


def _item(**overrides: object) -> dict[str, object]:
    data: dict[str, object] = {
        "title": "疑似命令注入",
        "vulnerability_type": "command_injection",
        "severity": "high",
        "description": "外部输入进入系统命令",
        "evidence": "os.system(EVIL)",
        "line_start": 9,
        "line_end": 9,
        "recommendation": "改用参数列表调用",
        "confidence": 0.7,
        "cwe_id": "CWE-78",
    }
    data.update(overrides)
    return data


def _raw(items: list[dict[str, object]]) -> str:
    return json.dumps({"findings": items}, ensure_ascii=False)


def _settings(**overrides: object) -> Settings:
    values: dict[str, object] = {
        "_env_file": None,
        "llm_enabled": True,
        "llm_base_url": "https://llm.test/v1",
        "llm_api_key": SecretStr("test-key"),
        "llm_model": "test-model",
        "llm_max_retries": 2,
    }
    values.update(overrides)
    return Settings(**values)


class _FakeCompleter:
    """记录调用参数、按预设返回或抛异常的假客户端。"""

    def __init__(self, reply: str | Exception) -> None:
        self.reply = reply
        self.calls: list[tuple[str, str]] = []

    def complete(self, system: str, user: str) -> str:
        self.calls.append((system, user))
        if isinstance(self.reply, Exception):
            raise self.reply
        return self.reply


def _client(
    handler,
    *,
    max_retries: int = 0,
    sleeps: list[float] | None = None,
) -> LlmClient:
    recorded = sleeps if sleeps is not None else []

    def _sleep(seconds: float) -> None:
        recorded.append(seconds)

    return LlmClient(
        base_url="https://llm.test/v1",
        api_key=SecretStr("test-key"),
        model="test-model",
        timeout_seconds=5,
        max_output_tokens=100,
        max_retries=max_retries,
        transport=httpx.MockTransport(handler),
        sleep=_sleep,
    )


def _ok(content: str = '{"findings": []}') -> httpx.Response:
    return httpx.Response(
        200, json={"choices": [{"message": {"role": "assistant", "content": content}}]}
    )


def _status(response, name: AnalyzerName):
    return next(item for item in response.analyzer_status if item.name == name)


# ---------------------------------------------------------------------------
# 客户端
# ---------------------------------------------------------------------------


def test_client_sends_openai_compatible_request() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return _ok()

    with _client(handler) as client:
        assert client.complete("sys", "user") == '{"findings": []}'

    request = seen[0]
    assert request.method == "POST"
    assert request.url.path == "/v1/chat/completions"
    assert request.headers["Authorization"] == "Bearer test-key"
    body = json.loads(request.content)
    assert body["model"] == "test-model"
    assert body["messages"] == [
        {"role": "system", "content": "sys"},
        {"role": "user", "content": "user"},
    ]
    assert body["max_tokens"] == 100
    assert body["temperature"] == 0


def test_client_rejects_non_http_base_url() -> None:
    with pytest.raises(LlmConfigurationError):
        LlmClient(
            base_url="file:///etc/passwd",
            api_key="k",
            model="m",
            timeout_seconds=1,
            max_output_tokens=10,
            max_retries=0,
        )


def test_client_retries_429_then_succeeds() -> None:
    responses = [httpx.Response(429), _ok()]

    def handler(request: httpx.Request) -> httpx.Response:
        return responses.pop(0)

    sleeps: list[float] = []
    with _client(handler, max_retries=1, sleeps=sleeps) as client:
        assert client.complete("s", "u") == '{"findings": []}'
    assert sleeps == [0.5]


def test_client_retries_5xx() -> None:
    responses = [httpx.Response(502), _ok()]

    def handler(request: httpx.Request) -> httpx.Response:
        return responses.pop(0)

    with _client(handler, max_retries=1) as client:
        assert client.complete("s", "u") == '{"findings": []}'


def test_client_does_not_retry_400() -> None:
    calls: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(1)
        return httpx.Response(400, json={"error": "bad"})

    sleeps: list[float] = []
    with _client(handler, max_retries=3, sleeps=sleeps) as client:
        with pytest.raises(LlmResponseFormatError):
            client.complete("s", "u")
    assert len(calls) == 1
    assert sleeps == []


def test_client_raises_rate_limit_after_retries_exhausted() -> None:
    calls: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(1)
        return httpx.Response(429)

    with _client(handler, max_retries=2) as client:
        with pytest.raises(LlmRateLimitError):
            client.complete("s", "u")
    assert len(calls) == 3


def test_client_maps_timeout() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("boom", request=request)

    with _client(handler) as client:
        with pytest.raises(LlmTimeoutError):
            client.complete("s", "u")


def test_client_maps_network_error_without_leaking_details() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("internal-host-1234", request=request)

    with _client(handler) as client:
        with pytest.raises(LlmNetworkError) as caught:
            client.complete("s", "u")
    assert "internal-host-1234" not in str(caught.value)


def test_client_does_not_follow_redirect() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"Location": "https://evil.test/"})

    with _client(handler) as client:
        with pytest.raises(LlmResponseFormatError) as caught:
            client.complete("s", "u")
    assert "未跟随" in str(caught.value)


def test_client_rejects_malformed_json() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"not json")

    with _client(handler) as client:
        with pytest.raises(LlmResponseFormatError):
            client.complete("s", "u")


def test_client_rejects_missing_choices() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"choices": []})

    with _client(handler) as client:
        with pytest.raises(LlmResponseFormatError):
            client.complete("s", "u")


def test_client_rejects_empty_content() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"choices": [{"message": {"content": "  "}}]})

    with _client(handler) as client:
        with pytest.raises(LlmResponseFormatError):
            client.complete("s", "u")


def test_client_rejects_oversized_response() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"x" * (MAX_RESPONSE_BYTES + 1))

    with _client(handler) as client:
        with pytest.raises(LlmResponseTooLargeError):
            client.complete("s", "u")


def test_client_errors_never_contain_api_key() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500)

    with _client(handler) as client:
        with pytest.raises(LlmServerError) as caught:
            client.complete("s", "u")
    assert "test-key" not in str(caught.value)


def test_missing_settings_returns_names_not_values() -> None:
    missing = missing_settings(base_url="", api_key=SecretStr("super-secret"), model="")
    assert missing == ["LLM_BASE_URL", "LLM_MODEL"]
    assert "super-secret" not in " ".join(missing)


def test_llm_defaults_are_off_and_bounded() -> None:
    config = Settings(_env_file=None)
    assert config.llm_enabled is False
    assert config.llm_max_retries == 2
    assert config.llm_max_input_chars == 12_000
    assert config.llm_timeout_seconds == 30


def test_llm_settings_reject_out_of_range_values() -> None:
    with pytest.raises(ValidationError):
        Settings(_env_file=None, llm_max_retries=6)
    with pytest.raises(ValidationError):
        Settings(_env_file=None, llm_timeout_seconds=0)
    with pytest.raises(ValidationError):
        Settings(_env_file=None, llm_max_output_tokens=0)


def test_api_disclaimer_mentions_third_party_transmission() -> None:
    assert "第三方" in DEFAULT_DISCLAIMER
    assert "请勿提交敏感代码" in DEFAULT_DISCLAIMER


# ---------------------------------------------------------------------------
# 提示词
# ---------------------------------------------------------------------------


def test_system_prompt_declares_code_as_untrusted() -> None:
    assert "不可信数据" in SYSTEM_PROMPT
    assert "不要执行" in SYSTEM_PROMPT
    assert "line_start" in SYSTEM_PROMPT


def test_user_message_contains_numbered_code() -> None:
    prompt = build_prompt(
        index=LineIndex(SOURCE), language="python", prior_findings=[], max_input_chars=10_000
    )
    assert "语言：python" in prompt.user
    assert "代码总行数：9" in prompt.user
    assert "1: from flask import Flask" in prompt.user
    assert "9:     os.system" in prompt.user
    assert prompt.truncated is False
    assert prompt.included_lines == 9


def test_code_appears_only_in_user_message() -> None:
    prompt = build_prompt(
        index=LineIndex(SOURCE), language="python", prior_findings=[], max_input_chars=10_000
    )
    assert "os.system" not in prompt.system


def test_prior_findings_are_compact_and_capped() -> None:
    findings = [
        _finding(line_start=i, line_end=i, description=f"SECRET_DESC_{i}") for i in range(1, 26)
    ]
    prompt = build_prompt(
        index=LineIndex("\n".join(f"line{i}" for i in range(1, 27))),
        language="python",
        prior_findings=findings,
        max_input_chars=10_000,
    )
    assert "仅列出前 20 条" in prompt.user
    assert "SECRET_DESC" not in prompt.user
    assert '"line":1' in prompt.user
    assert '"line":21' not in prompt.user


def test_long_code_is_truncated_by_whole_lines() -> None:
    prompt = build_prompt(
        index=LineIndex(SOURCE), language="python", prior_findings=[], max_input_chars=50
    )
    assert prompt.truncated is True
    assert prompt.included_lines == 2
    assert "只提供前 2 行（共 9 行）" in prompt.user
    assert "\n3: " not in prompt.user


def test_single_huge_line_is_truncated_with_marker() -> None:
    source = "x" * 200 + "\n"
    prompt = build_prompt(
        index=LineIndex(source), language="python", prior_findings=[], max_input_chars=40
    )
    assert prompt.truncated is True
    assert prompt.included_lines == 1
    assert "（本行已截断）" in prompt.user


def test_build_prompt_rejects_non_positive_limit() -> None:
    with pytest.raises(ValueError):
        build_prompt(
            index=LineIndex(SOURCE), language="python", prior_findings=[], max_input_chars=0
        )


def test_allowed_types_match_dto() -> None:
    assert set(ALLOWED_VULNERABILITY_TYPES) == {
        "sql_injection",
        "command_injection",
        "xss",
        "unsafe_dynamic_execution",
        "unsafe_deserialization",
    }


# ---------------------------------------------------------------------------
# 解析
# ---------------------------------------------------------------------------


def _parse(items: list[dict[str, object]]):
    return parse_llm_output(_raw(items), LineIndex(SOURCE))


def test_valid_output_becomes_llm_finding() -> None:
    result = _parse([_item()])
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.source is FindingSource.LLM
    assert finding.rule_id == "llm.command_injection"
    assert finding.vulnerability_type == "command_injection"
    assert finding.severity.value == "high"
    assert finding.confidence == 0.7
    assert finding.cwe_id == "CWE-78"
    assert finding.line_start == 9
    assert finding.line_end == 9
    assert result.dropped == 0


def test_model_evidence_is_not_trusted() -> None:
    finding = _parse([_item(evidence="os.system(EVIL)")]).findings[0]
    assert "EVIL" not in finding.evidence
    assert finding.evidence.startswith("os.system(")


def test_code_fence_is_tolerated() -> None:
    raw = "```json\n" + _raw([_item()]) + "\n```"
    assert len(parse_llm_output(raw, LineIndex(SOURCE)).findings) == 1


def test_surrounding_text_is_tolerated() -> None:
    raw = "分析结果如下：\n" + _raw([_item()]) + "\n以上。"
    assert len(parse_llm_output(raw, LineIndex(SOURCE)).findings) == 1


def test_invalid_json_raises() -> None:
    with pytest.raises(LlmOutputError):
        parse_llm_output("这不是 JSON", LineIndex(SOURCE))


def test_empty_output_raises() -> None:
    with pytest.raises(LlmOutputError):
        parse_llm_output("   ", LineIndex(SOURCE))


def test_missing_findings_list_raises() -> None:
    with pytest.raises(LlmOutputError):
        parse_llm_output('{"result": []}', LineIndex(SOURCE))


def test_empty_findings_is_valid() -> None:
    result = parse_llm_output('{"findings": []}', LineIndex(SOURCE))
    assert result.findings == []
    assert result.total_items == 0


def test_unknown_vulnerability_type_is_dropped() -> None:
    result = _parse([_item(vulnerability_type="other"), _item(line_start=8, line_end=8)])
    assert len(result.findings) == 1
    assert result.findings[0].line_start == 8
    assert result.dropped == 1


def test_invalid_severity_is_dropped() -> None:
    result = _parse([_item(severity="Moderate"), _item(line_start=8, line_end=8)])
    assert len(result.findings) == 1
    assert result.dropped == 1


def test_confidence_out_of_range_is_dropped() -> None:
    result = _parse([_item(confidence=1.5), _item(line_start=8, line_end=8)])
    assert len(result.findings) == 1
    assert result.dropped == 1


def test_extra_field_is_dropped_not_guessed() -> None:
    result = _parse([_item(reasoning="额外字段"), _item(line_start=8, line_end=8)])
    assert len(result.findings) == 1
    assert result.dropped == 1


def test_out_of_range_line_is_dropped() -> None:
    result = _parse([_item(line_start=99, line_end=99), _item(line_start=8, line_end=8)])
    assert len(result.findings) == 1
    assert result.findings[0].line_start == 8
    assert result.dropped == 1


def test_line_end_before_start_is_dropped() -> None:
    result = _parse([_item(line_start=9, line_end=8), _item(line_start=8, line_end=8)])
    assert len(result.findings) == 1
    assert result.dropped == 1


def test_line_end_out_of_range_is_dropped() -> None:
    result = _parse([_item(line_start=8, line_end=99), _item(line_start=8, line_end=8)])
    assert len(result.findings) == 1
    assert result.dropped == 1


def test_end_without_start_is_dropped() -> None:
    result = _parse([_item(line_start=None, line_end=9), _item(line_start=8, line_end=8)])
    assert len(result.findings) == 1
    assert result.dropped == 1


def test_no_location_is_kept_without_evidence() -> None:
    finding = _parse([_item(line_start=None, line_end=None)]).findings[0]
    assert finding.line_start is None
    assert finding.line_end is None
    assert finding.evidence == ""


def test_boolean_line_is_dropped() -> None:
    result = _parse([_item(line_start=True, line_end=True), _item(line_start=8, line_end=8)])
    assert len(result.findings) == 1
    assert result.dropped == 1


def test_description_carries_qualifier() -> None:
    finding = _parse([_item()]).findings[0]
    assert finding.description.startswith("外部输入进入系统命令")
    assert "仍需人工确认" in finding.description


def test_cwe_is_extracted_from_free_text() -> None:
    finding = _parse([_item(cwe_id="CWE-78: OS Command Injection")]).findings[0]
    assert finding.cwe_id == "CWE-78"


def test_invalid_cwe_is_left_empty() -> None:
    finding = _parse([_item(cwe_id="78")]).findings[0]
    assert finding.cwe_id is None


def test_duplicate_type_and_line_is_deduped() -> None:
    result = _parse([_item(title="第一条"), _item(title="第二条")])
    assert len(result.findings) == 1
    assert result.findings[0].title == "第一条"
    assert result.dropped == 1


def test_all_items_dropped_raises() -> None:
    with pytest.raises(LlmOutputError) as caught:
        _parse([_item(vulnerability_type="invented")])
    assert "没有一条通过" in str(caught.value)


def test_partial_drop_still_succeeds() -> None:
    result = _parse([_item(vulnerability_type="invented"), _item(line_start=8, line_end=8)])
    assert len(result.findings) == 1
    assert result.dropped == 1


def test_findings_are_capped() -> None:
    source = "\n".join(f"line{i}" for i in range(1, 56))
    items = [
        _item(
            title=f"问题 {i}",
            vulnerability_type="sql_injection",
            line_start=i,
            line_end=i,
        )
        for i in range(1, 56)
    ]
    result = parse_llm_output(_raw(items), LineIndex(source))
    assert result.total_items == 50
    assert len(result.findings) == 50
    assert result.dropped == 5


def test_finding_id_is_stable_across_runs() -> None:
    first = _parse([_item()]).findings[0]
    second = _parse([_item()]).findings[0]
    assert first.id == second.id


# ---------------------------------------------------------------------------
# 检测器
# ---------------------------------------------------------------------------


def test_detector_skips_when_globally_disabled() -> None:
    client = _FakeCompleter(_raw([_item()]))
    outcome = detect_llm_findings(
        SOURCE, "python", client=client, config=_settings(llm_enabled=False)
    )
    assert outcome.state is AnalyzerState.SKIPPED
    assert "LLM_ENABLED" in (outcome.reason or "")
    assert client.calls == []


def test_detector_reports_missing_key_without_calling() -> None:
    client = _FakeCompleter(_raw([_item()]))
    outcome = detect_llm_findings(
        SOURCE, "python", client=client, config=_settings(llm_api_key="")
    )
    assert outcome.state is AnalyzerState.UNAVAILABLE
    assert "LLM_API_KEY" in (outcome.reason or "")
    assert client.calls == []


def test_detector_reports_all_missing_settings() -> None:
    outcome = detect_llm_findings(
        SOURCE,
        "python",
        client=_FakeCompleter(""),
        config=_settings(llm_base_url="", llm_api_key="", llm_model=""),
    )
    reason = outcome.reason or ""
    assert "LLM_BASE_URL" in reason
    assert "LLM_API_KEY" in reason
    assert "LLM_MODEL" in reason


def test_detector_rejects_invalid_base_url() -> None:
    outcome = detect_llm_findings(
        SOURCE,
        "python",
        client=None,
        config=_settings(llm_base_url="ftp://example.com"),
    )
    assert outcome.state is AnalyzerState.UNAVAILABLE
    assert "http" in (outcome.reason or "")


def test_detector_success_returns_findings() -> None:
    client = _FakeCompleter(_raw([_item()]))
    outcome = detect_llm_findings(SOURCE, "python", client=client, config=_settings())
    assert outcome.state is AnalyzerState.SUCCESS
    assert outcome.reason is None
    assert len(outcome.findings) == 1
    assert outcome.findings[0].source is FindingSource.LLM


def test_detector_prompt_contains_code_and_prior_hints() -> None:
    client = _FakeCompleter(_raw([_item()]))
    outcome = detect_llm_findings(
        SOURCE,
        "python",
        prior_findings=[_finding(line_start=9, line_end=9)],
        client=client,
        config=_settings(),
    )
    assert outcome.state is AnalyzerState.SUCCESS
    system, user = client.calls[0]
    assert "不可信数据" in system
    assert "os.system" in user
    assert '"line":9' in user
    assert "test-key" not in system
    assert "test-key" not in user


def test_detector_maps_timeout() -> None:
    outcome = detect_llm_findings(
        SOURCE,
        "python",
        client=_FakeCompleter(LlmTimeoutError("timeout")),
        config=_settings(),
    )
    assert outcome.state is AnalyzerState.FAILED
    assert "超时" in (outcome.reason or "")
    assert "已重试 2 次" in (outcome.reason or "")


def test_detector_maps_rate_limit() -> None:
    outcome = detect_llm_findings(
        SOURCE,
        "python",
        client=_FakeCompleter(LlmRateLimitError("429")),
        config=_settings(),
    )
    assert outcome.state is AnalyzerState.FAILED
    assert "429" in (outcome.reason or "")


def test_detector_maps_server_and_network_errors() -> None:
    server = detect_llm_findings(
        SOURCE,
        "python",
        client=_FakeCompleter(LlmServerError("模型服务返回 502，属于服务端错误。")),
        config=_settings(llm_max_retries=0),
    )
    assert server.state is AnalyzerState.FAILED
    assert "未重试" in (server.reason or "")

    network = detect_llm_findings(
        SOURCE,
        "python",
        client=_FakeCompleter(LlmNetworkError("无法连接模型服务。")),
        config=_settings(llm_max_retries=0),
    )
    assert network.state is AnalyzerState.FAILED
    assert "无法连接" in (network.reason or "")


def test_detector_marks_invalid_output_as_failure() -> None:
    outcome = detect_llm_findings(
        SOURCE,
        "python",
        client=_FakeCompleter("not json"),
        config=_settings(),
    )
    assert outcome.state is AnalyzerState.FAILED
    assert "模型输出不可用" in (outcome.reason or "")


def test_detector_success_with_no_findings() -> None:
    outcome = detect_llm_findings(
        SOURCE,
        "python",
        client=_FakeCompleter('{"findings": []}'),
        config=_settings(),
    )
    assert outcome.state is AnalyzerState.SUCCESS
    assert outcome.findings == []


# ---------------------------------------------------------------------------
# 扫描集成
# ---------------------------------------------------------------------------


def _enable_llm(monkeypatch: pytest.MonkeyPatch, **overrides: object) -> None:
    """把全局配置切到"已启用且配置完整"，测试结束后自动还原。"""
    values: dict[str, object] = {
        "llm_enabled": True,
        "llm_base_url": "https://llm.test/v1",
        "llm_api_key": SecretStr("test-key"),
        "llm_model": "test-model",
    }
    values.update(overrides)
    for key, value in values.items():
        monkeypatch.setattr(app_settings, key, value)


def test_scan_without_llm_reports_skipped(monkeypatch: pytest.MonkeyPatch) -> None:
    # 固定总开关，避免本机环境变量让测试意外发起真实请求。
    monkeypatch.setattr(app_settings, "llm_enabled", False)
    request = ScanRequest(source_code=SOURCE, language="python")
    response = run_scan(request)
    status = _status(response, AnalyzerName.LLM)
    assert status.state is AnalyzerState.SKIPPED
    assert status.reason


def test_scan_with_llm_requested_but_server_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(app_settings, "llm_enabled", False)
    request = ScanRequest(
        source_code=SOURCE,
        language="python",
        analysis_options={"enable_llm": True},
    )
    response = run_scan(request, llm_client=_FakeCompleter(_raw([_item()])))
    status = _status(response, AnalyzerName.LLM)
    assert status.state is AnalyzerState.SKIPPED
    assert "LLM_ENABLED" in (status.reason or "")
    # 规则层照常执行。
    assert _status(response, AnalyzerName.RULES).state is AnalyzerState.SUCCESS


def test_scan_with_llm_missing_key_keeps_rules(monkeypatch: pytest.MonkeyPatch) -> None:
    _enable_llm(monkeypatch, llm_api_key=SecretStr(""))
    request = ScanRequest(
        source_code=SOURCE,
        language="python",
        analysis_options={"enable_llm": True},
    )
    response = run_scan(request, llm_client=_FakeCompleter(_raw([_item()])))
    status = _status(response, AnalyzerName.LLM)
    assert status.state is AnalyzerState.UNAVAILABLE
    assert "LLM_API_KEY" in (status.reason or "")
    assert _status(response, AnalyzerName.RULES).state is AnalyzerState.SUCCESS
    assert response.status.value == "partial"


def test_scan_adds_llm_only_finding(monkeypatch: pytest.MonkeyPatch) -> None:
    _enable_llm(monkeypatch)
    client = _FakeCompleter(
        _raw(
            [
                _item(
                    vulnerability_type="xss",
                    severity="medium",
                    line_start=3,
                    line_end=3,
                    cwe_id="CWE-79",
                )
            ]
        )
    )
    request = ScanRequest(
        source_code=LLM_ONLY_SOURCE,
        language="python",
        analysis_options={"enable_llm": True},
    )
    response = run_scan(request, llm_client=client)

    status = _status(response, AnalyzerName.LLM)
    assert status.state is AnalyzerState.SUCCESS
    assert status.findings_count == 1
    assert status.duration_ms is not None

    llm_findings = [item for item in response.findings if item.source is FindingSource.LLM]
    assert len(llm_findings) == 1
    assert llm_findings[0].line_start == 3
    assert llm_findings[0].evidence == 'return "Hello " + uid'


def test_scan_merges_llm_duplicate_without_losing_rule_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _enable_llm(monkeypatch)
    client = _FakeCompleter(_raw([_item(line_start=9, line_end=9)]))
    request = ScanRequest(
        source_code=SOURCE,
        language="python",
        analysis_options={"enable_llm": True},
    )
    response = run_scan(request, llm_client=client)

    line9 = [item for item in response.findings if item.line_start == 9]
    assert len(line9) == 1
    assert line9[0].source is FindingSource.STATIC_RULE
    assert "LLM 在同一位置也给出判断" in line9[0].description
    assert _status(response, AnalyzerName.LLM).findings_count == 0

    counts = sum(item.findings_count for item in response.analyzer_status)
    assert counts == response.summary.total_findings


def test_scan_llm_failure_does_not_remove_other_findings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _enable_llm(monkeypatch)
    request = ScanRequest(
        source_code=SOURCE,
        language="python",
        analysis_options={"enable_llm": True},
    )
    response = run_scan(request, llm_client=_FakeCompleter(LlmTimeoutError("timeout")))

    status = _status(response, AnalyzerName.LLM)
    assert status.state is AnalyzerState.FAILED
    assert status.findings_count == 0
    assert any(item.source is FindingSource.STATIC_RULE for item in response.findings)
    assert _status(response, AnalyzerName.RULES).state is AnalyzerState.SUCCESS
    assert response.status.value == "partial"


def test_scan_llm_never_sees_api_key_in_prompt(monkeypatch: pytest.MonkeyPatch) -> None:
    _enable_llm(monkeypatch)
    client = _FakeCompleter('{"findings": []}')
    request = ScanRequest(
        source_code=SOURCE,
        language="python",
        analysis_options={"enable_llm": True},
    )
    run_scan(request, llm_client=client)
    system, user = client.calls[0]
    assert "test-key" not in system
    assert "test-key" not in user
