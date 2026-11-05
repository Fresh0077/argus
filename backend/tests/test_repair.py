"""修复建议（阶段 16）的测试。

覆盖四层：

1. 上下文裁剪：只发送目标行附近内容，且不裁掉目标行；
2. 模型输出校验：坏 JSON、缺字段、空代码、未修改、带行号；
3. 编排：LLM 关闭/缺配置、调用失败、提示词不含密钥；
4. HTTP 接口：成功与各类错误的状态码、错误码与文案安全。

所有模型调用都使用假客户端，不会发起真实网络请求，也不依赖真实 API key。
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

from app.analyzers.line_index import LineIndex
from app.analyzers.repair import (
    RepairContextError,
    RepairModelError,
    RepairOutputError,
    RepairUnavailableError,
    build_repair_context,
    generate_repair,
    parse_repair_output,
)
from app.analyzers.repair import detector as repair_detector
from app.core.config import Settings, settings
from app.llm.errors import LlmRateLimitError, LlmTimeoutError
from app.main import app
from app.schemas.enums import ErrorCode, FindingSource, Severity
from app.schemas.finding import Finding
from app.schemas.repair import RepairRequest

client = TestClient(app)

REPAIR_URL = "/api/v1/repair"

SOURCE = "\n".join(
    [
        "def handler(user_id):",  # 1
        "    conn = connect()",  # 2
        "    sql = 'SELECT * FROM users WHERE id = ' + user_id",  # 3
        "    return conn.execute(sql)",  # 4
        *(f"    filler_{index} = {index}" for index in range(5, 41)),
    ]
)

ORIGINAL_CODE = (
    "    sql = 'SELECT * FROM users WHERE id = ' + user_id\n"
    "    return conn.execute(sql)"
)

FIXED_CODE = (
    "    sql = 'SELECT * FROM users WHERE id = ?'\n"
    "    return conn.execute(sql, (user_id,))"
)

MODEL_OK: dict[str, Any] = {
    "repair_idea": "使用参数化查询，把用户输入作为参数传入。",
    "fixed_code": FIXED_CODE,
    "explanation": "原代码把 user_id 拼进 SQL；改为占位符后，输入不再改变语句结构。",
    "compatibility_impact": "需要数据库驱动支持参数占位符；不同驱动的占位符写法可能不同。",
    "unconfirmed_premises": ["上下文中没有给出 conn 的具体类型与 SQL 方言。"],
}


class FakeCompleter:
    """记录调用的假客户端。"""

    def __init__(self, raw: str) -> None:
        self.raw = raw
        self.calls: list[tuple[str, str]] = []

    def complete(self, system: str, user: str) -> str:
        self.calls.append((system, user))
        return self.raw


class RaisingCompleter:
    """直接抛出指定异常的假客户端。"""

    def __init__(self, error: Exception) -> None:
        self.error = error

    def complete(self, system: str, user: str) -> str:
        raise self.error


def make_finding(
    *,
    line_start: int | None = 3,
    line_end: int | None = 4,
    **overrides: object,
) -> Finding:
    values: dict[str, object] = {
        "id": "finding-1",
        "title": "SQL 注入",
        "vulnerability_type": "sql_injection",
        "severity": Severity.HIGH,
        "description": "用户输入被直接拼接到 SQL 语句中。",
        "evidence": "sql = 'SELECT * FROM users WHERE id = ' + user_id",
        "line_start": line_start,
        "line_end": line_end,
        "recommendation": "使用参数化查询。",
        "confidence": 0.8,
        "source": FindingSource.STATIC_RULE,
        "rule_id": "ARGUS-SQL-001",
        "cwe_id": "CWE-89",
    }
    values.update(overrides)
    return Finding(**values)


def make_request(**overrides: object) -> RepairRequest:
    values: dict[str, object] = {
        "source_code": SOURCE,
        "language": "python",
        "filename": "views.py",
        "finding": make_finding(),
    }
    values.update(overrides)
    return RepairRequest(**values)


def make_config(**overrides: object) -> Settings:
    values: dict[str, object] = {
        "llm_enabled": True,
        "llm_base_url": "https://llm.test/v1",
        "llm_api_key": SecretStr("test-key"),
        "llm_model": "test-model",
    }
    values.update(overrides)
    return Settings(**values)


def model_raw(**overrides: object) -> str:
    payload = dict(MODEL_OK)
    payload.update(overrides)
    return json.dumps(payload, ensure_ascii=False)


# ---------------------------------------------------------------------------
# 上下文裁剪
# ---------------------------------------------------------------------------


def test_context_window_has_ten_lines_on_each_side() -> None:
    source = "\n".join(f"line_{index} = {index}" for index in range(1, 41))
    finding = make_finding(line_start=20, line_end=20)

    context = build_repair_context(LineIndex(source), finding, max_chars=10_000)

    assert context.excerpt_line_start == 20
    assert context.excerpt_line_end == 20
    assert context.context_line_start == 10
    assert context.context_line_end == 30
    assert "20: line_20 = 20" in context.context_code
    # 行号由系统提供，模型不需要自己数。
    assert "10: line_10 = 10" in context.context_code


def test_context_shrinks_to_character_limit_without_cutting_target() -> None:
    source = "\n".join(f"line_{index} = {index}" for index in range(1, 41))
    finding = make_finding(line_start=20, line_end=21)

    context = build_repair_context(LineIndex(source), finding, max_chars=180)

    assert len(context.context_code) <= 180
    assert context.context_line_start <= 20
    assert context.context_line_end >= 21
    assert "20: line_20 = 20" in context.context_code
    assert "21: line_21 = 21" in context.context_code


def test_target_longer_than_limit_is_rejected() -> None:
    finding = make_finding(line_start=3, line_end=4)
    with pytest.raises(RepairContextError, match="过长"):
        build_repair_context(LineIndex(SOURCE), finding, max_chars=5)


def test_finding_without_line_number_is_rejected() -> None:
    finding = make_finding(line_start=None, line_end=None)
    with pytest.raises(RepairContextError, match="行号"):
        build_repair_context(LineIndex(SOURCE), finding, max_chars=10_000)


def test_line_out_of_range_is_rejected() -> None:
    finding = make_finding(line_start=999, line_end=999)
    with pytest.raises(RepairContextError, match="超出"):
        build_repair_context(LineIndex(SOURCE), finding, max_chars=10_000)


def test_line_end_defaults_to_line_start() -> None:
    finding = make_finding(line_start=3, line_end=None)
    context = build_repair_context(LineIndex(SOURCE), finding, max_chars=10_000)
    assert context.excerpt_line_start == 3
    assert context.excerpt_line_end == 3
    assert context.original_code == "    sql = 'SELECT * FROM users WHERE id = ' + user_id"


# ---------------------------------------------------------------------------
# 模型输出校验
# ---------------------------------------------------------------------------


def test_parse_accepts_valid_output() -> None:
    parsed = parse_repair_output(model_raw(), original_code=ORIGINAL_CODE)
    assert parsed.fixed_code == FIXED_CODE
    assert parsed.unconfirmed_premises


def test_parse_rejects_invalid_json() -> None:
    with pytest.raises(RepairOutputError, match="JSON"):
        parse_repair_output("这不是 JSON", original_code=ORIGINAL_CODE)


def test_parse_rejects_missing_field() -> None:
    payload = dict(MODEL_OK)
    payload.pop("compatibility_impact")
    with pytest.raises(RepairOutputError):
        parse_repair_output(json.dumps(payload), original_code=ORIGINAL_CODE)


def test_parse_rejects_extra_field() -> None:
    with pytest.raises(RepairOutputError):
        parse_repair_output(
            model_raw(unexpected="额外字段"), original_code=ORIGINAL_CODE
        )


def test_parse_rejects_empty_fixed_code() -> None:
    with pytest.raises(RepairOutputError, match="未能给出"):
        parse_repair_output(model_raw(fixed_code=""), original_code=ORIGINAL_CODE)
    with pytest.raises(RepairOutputError, match="未能给出"):
        parse_repair_output(model_raw(fixed_code="   \n  "), original_code=ORIGINAL_CODE)


def test_parse_rejects_unchanged_code() -> None:
    with pytest.raises(RepairOutputError, match="相同"):
        parse_repair_output(
            model_raw(fixed_code=ORIGINAL_CODE), original_code=ORIGINAL_CODE
        )


def test_parse_rejects_code_with_line_numbers() -> None:
    numbered = "\n".join(
        f"{index}: {line}"
        for index, line in enumerate(FIXED_CODE.splitlines(), start=3)
    )
    with pytest.raises(RepairOutputError, match="行号"):
        parse_repair_output(model_raw(fixed_code=numbered), original_code=ORIGINAL_CODE)


def test_parse_strips_markdown_fence_inside_fixed_code() -> None:
    fenced = f"```python\n{FIXED_CODE}\n```"
    parsed = parse_repair_output(
        model_raw(fixed_code=fenced), original_code=ORIGINAL_CODE
    )
    assert parsed.fixed_code == FIXED_CODE


# ---------------------------------------------------------------------------
# 编排
# ---------------------------------------------------------------------------


def test_generate_repair_returns_patch_and_diff() -> None:
    fake = FakeCompleter(model_raw())

    suggestion = generate_repair(
        make_request(), client=fake, config=make_config()
    )

    assert suggestion.finding_id == "finding-1"
    assert suggestion.original_code == ORIGINAL_CODE
    assert suggestion.fixed_code == FIXED_CODE
    assert suggestion.excerpt_line_start == 3
    assert suggestion.excerpt_line_end == 4
    assert suggestion.context_line_start == 1
    assert suggestion.context_line_end == 14
    assert "--- 原始代码" in suggestion.diff
    assert "+++ 候选补丁" in suggestion.diff
    assert "-    sql = 'SELECT * FROM users WHERE id = ' + user_id" in suggestion.diff
    assert "+    sql = 'SELECT * FROM users WHERE id = ?'" in suggestion.diff
    assert "未经编译" in suggestion.disclaimer


def test_prompt_only_contains_context_window_and_no_api_key() -> None:
    fake = FakeCompleter(model_raw())

    generate_repair(make_request(), client=fake, config=make_config())

    system, user = fake.calls[0]
    assert "不可信数据" in system
    # 目标在第 3–4 行，窗口到第 14 行；第 40 行的内容不应出现。
    assert "filler_39" not in user
    assert "14:     filler_14 = 14" in user
    assert "test-key" not in system
    assert "test-key" not in user
    assert "SQL 注入" in user


def test_llm_disabled_raises_unavailable() -> None:
    with pytest.raises(RepairUnavailableError, match="LLM_ENABLED"):
        generate_repair(
            make_request(),
            client=FakeCompleter(model_raw()),
            config=make_config(llm_enabled=False),
        )


def test_missing_key_raises_unavailable_without_leaking_value() -> None:
    with pytest.raises(RepairUnavailableError) as exc_info:
        generate_repair(
            make_request(),
            client=FakeCompleter(model_raw()),
            config=make_config(llm_api_key=SecretStr("")),
        )
    assert "LLM_API_KEY" in str(exc_info.value)


def test_model_failure_is_reported_as_model_error() -> None:
    with pytest.raises(RepairModelError, match="超时"):
        generate_repair(
            make_request(),
            client=RaisingCompleter(LlmTimeoutError("timeout")),
            config=make_config(),
        )

    with pytest.raises(RepairModelError, match="429"):
        generate_repair(
            make_request(),
            client=RaisingCompleter(LlmRateLimitError("rate limited")),
            config=make_config(),
        )


# ---------------------------------------------------------------------------
# HTTP 接口
# ---------------------------------------------------------------------------


def _enable_llm(monkeypatch: pytest.MonkeyPatch) -> None:
    values: dict[str, object] = {
        "llm_enabled": True,
        "llm_base_url": "https://llm.test/v1",
        "llm_api_key": SecretStr("test-key"),
        "llm_model": "test-model",
    }
    for key, value in values.items():
        monkeypatch.setattr(settings, key, value)


def _repair_payload(**overrides: object) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "source_code": SOURCE,
        "language": "python",
        "filename": "views.py",
        "finding": make_finding().model_dump(mode="json"),
    }
    payload.update(overrides)
    return payload


def test_repair_api_returns_suggestion(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _enable_llm(monkeypatch)
    fake = FakeCompleter(model_raw())
    monkeypatch.setattr(repair_detector, "_create_client", lambda cfg: fake)

    response = client.post(REPAIR_URL, json=_repair_payload())

    assert response.status_code == 200
    body = response.json()
    assert body["finding_id"] == "finding-1"
    assert body["fixed_code"] == FIXED_CODE
    assert body["diff"]
    assert "test-key" not in response.text
    # 只返回目标片段，不返回完整源码。
    assert "filler_39" not in response.text


def test_repair_api_when_llm_disabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "llm_enabled", False)

    response = client.post(REPAIR_URL, json=_repair_payload())

    assert response.status_code == 503
    error = response.json()["error"]
    assert error["code"] == ErrorCode.REPAIR_UNAVAILABLE.value
    assert "LLM_ENABLED" in error["message"]


def test_repair_api_without_reliable_line(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _enable_llm(monkeypatch)

    payload = _repair_payload(
        finding=make_finding(line_start=None, line_end=None).model_dump(mode="json")
    )
    response = client.post(REPAIR_URL, json=payload)

    assert response.status_code == 422
    assert (
        response.json()["error"]["code"]
        == ErrorCode.REPAIR_CONTEXT_UNAVAILABLE.value
    )


def test_repair_api_invalid_model_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _enable_llm(monkeypatch)
    monkeypatch.setattr(
        repair_detector, "_create_client", lambda cfg: FakeCompleter("not json")
    )

    response = client.post(REPAIR_URL, json=_repair_payload())

    assert response.status_code == 502
    assert response.json()["error"]["code"] == ErrorCode.LLM_OUTPUT_INVALID.value


def test_repair_api_model_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _enable_llm(monkeypatch)
    monkeypatch.setattr(
        repair_detector,
        "_create_client",
        lambda cfg: RaisingCompleter(LlmTimeoutError("timeout")),
    )

    response = client.post(REPAIR_URL, json=_repair_payload())

    assert response.status_code == 502
    assert response.json()["error"]["code"] == ErrorCode.REPAIR_FAILED.value
    # 不回显异常类型或底层消息（配置名 LLM_TIMEOUT_SECONDS 属于我们自己的文案）。
    assert "LlmTimeoutError" not in response.text
    assert "Traceback" not in response.text
    assert "test-key" not in response.text


def test_repair_api_rejects_invalid_request() -> None:
    response = client.post(
        REPAIR_URL,
        json={"source_code": "   ", "finding": make_finding().model_dump(mode="json")},
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == ErrorCode.VALIDATION_ERROR.value
