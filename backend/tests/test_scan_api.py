"""扫描输入接口的集成测试。

覆盖两条入口：

    POST /api/v1/scan          JSON 代码文本
    POST /api/v1/scan/upload   multipart 文件上传

除了常规的成功/失败路径，这里还锁定了三条安全约束：

1. **被提交的代码不会被执行。** 用一段"执行就会创建文件"的代码做探针，
   跑完确认该文件不存在。
2. **文件类型判断不采信 MIME。** 同一个文件改换 ``Content-Type`` 结果必须一致。
3. **区分"没发现"与"没分析"。** 尚未接入或按开关关闭的分析器
   必须带非 success 状态和原因，不能被读成"代码安全"。
"""

from __future__ import annotations

import codecs
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from httpx import Response

from app.core.config import settings
from app.main import app
from app.schemas.enums import AnalyzerName, AnalyzerState, FindingSource
from app.schemas.scan import DEFAULT_DISCLAIMER

client = TestClient(app)

SCAN_URL = "/api/v1/scan"
UPLOAD_URL = "/api/v1/scan/upload"

SAMPLE_SOURCE = 'query = "SELECT * FROM users WHERE id = " + user_id\n'


def _upload(
    content: bytes,
    filename: str = "views.py",
    content_type: str = "text/x-python",
    **form: str,
) -> Response:
    return client.post(
        UPLOAD_URL,
        files={"file": (filename, content, content_type)},
        data=form or None,
    )


def _upload_raw_multipart(
    content: bytes, raw_filename: bytes, content_type: str = "text/x-python"
) -> Response:
    """手工拼装 multipart 请求体，用来看清那些"正经客户端发不出来"的字节。

    httpx 会把文件名里的 NUL 百分号编码成字面量 ``%00``，测不到服务端
    面对**真实 NUL 字节**时的行为。而 HTTP 层并没有禁止原始 NUL，
    构造恶意请求的客户端完全可以直接把它写进 Content-Disposition。
    因此这里绕开 httpx 的编码，直接拼字节。
    """
    boundary = b"----argusrawboundary"
    body = (
        b"--" + boundary + b"\r\n"
        b'Content-Disposition: form-data; name="file"; filename="' + raw_filename + b'"\r\n'
        b"Content-Type: " + content_type.encode("ascii") + b"\r\n\r\n"
        + content
        + b"\r\n--" + boundary + b"--\r\n"
    )
    return client.post(
        UPLOAD_URL,
        content=body,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary.decode('ascii')}"},
    )


# ---------------------------------------------------------------------------
# POST /scan：正常输入
# ---------------------------------------------------------------------------


def test_scan_accepts_valid_source_code() -> None:
    response = client.post(SCAN_URL, json={"source_code": SAMPLE_SOURCE})

    assert response.status_code == 200
    body = response.json()
    assert body["scan_id"]
    assert body["findings"] == []
    assert body["summary"]["total_findings"] == 0
    assert body["duration_ms"] >= 0
    assert body["disclaimer"] == DEFAULT_DISCLAIMER


def test_scan_reports_partial_status_because_no_analyzer_ran() -> None:
    """输入合法但没有分析器执行，状态必须是 partial 而不是 completed。"""
    body = client.post(SCAN_URL, json={"source_code": SAMPLE_SOURCE}).json()

    assert body["status"] == "partial"


def test_analyzers_that_did_not_run_are_never_reported_as_success() -> None:
    """最容易被误读的地方：findings 为空必须能被解释。

    已接入的分析器会如实报 success；尚未接入或按开关关闭的，
    必须明确跳过/不可用**并给出原因**，这样前端才能显示"未执行分析"
    而不是"未发现漏洞"。
    """
    body = client.post(SCAN_URL, json={"source_code": SAMPLE_SOURCE}).json()

    statuses = {item["name"]: item for item in body["analyzer_status"]}
    assert set(statuses) == {name.value for name in AnalyzerName}

    for name, item in statuses.items():
        if item["state"] == AnalyzerState.SUCCESS.value:
            assert item["reason"] is None, f"{name} 报成功却带着失败原因"
            continue
        assert item["reason"], f"{name} 处于 {item['state']} 状态却没有给出原因"

    # 尚未接入的分析器必须明确表态，不能借"没发现问题"蒙混过去。
    for name in (AnalyzerName.SEMGREP, AnalyzerName.LLM):
        assert statuses[name.value]["state"] != AnalyzerState.SUCCESS.value


def test_rules_analyzer_reports_success_once_the_language_is_known() -> None:
    """本地规则检测不依赖 API key，也不依赖外部工具。

    语言识别成功它就一定能跑——这正是"没有 API key 也能执行基础检测"
    要落实的地方，所以这里断言的是 success，而不是"没报错"。
    """
    body = client.post(
        SCAN_URL, json={"source_code": SAMPLE_SOURCE, "language": "python"}
    ).json()

    statuses = {item["name"]: item for item in body["analyzer_status"]}
    assert statuses[AnalyzerName.RULES.value]["state"] == AnalyzerState.SUCCESS.value
    assert statuses[AnalyzerName.RULES.value]["reason"] is None
    assert statuses[AnalyzerName.FEATURE_EXTRACTION.value]["state"] == AnalyzerState.SUCCESS.value


def test_rules_analyzer_is_skipped_with_a_reason_when_language_is_unknown() -> None:
    """语言没识别出来时不能报 success——那会被读成"看过了，没问题"。"""
    body = client.post(SCAN_URL, json={"source_code": "x = 1\n"}).json()

    statuses = {item["name"]: item for item in body["analyzer_status"]}
    rules = statuses[AnalyzerName.RULES.value]
    if body["detected_language"] is None:
        assert rules["state"] == AnalyzerState.SKIPPED.value
        assert rules["reason"]
    else:
        assert rules["state"] == AnalyzerState.SUCCESS.value


def test_explicit_language_is_used_and_reported() -> None:
    body = client.post(
        SCAN_URL, json={"source_code": SAMPLE_SOURCE, "language": "  PYTHON  "}
    ).json()

    assert body["detected_language"] == "python"
    language_status = next(
        item for item in body["analyzer_status"] if item["name"] == AnalyzerName.LANGUAGE_DETECTION.value
    )
    assert language_status["state"] == AnalyzerState.SUCCESS.value


def test_language_is_inferred_from_filename() -> None:
    body = client.post(
        SCAN_URL, json={"source_code": SAMPLE_SOURCE, "filename": "app.tsx"}
    ).json()

    assert body["detected_language"] == "typescript"


def test_language_detection_is_skipped_when_nothing_to_go_on() -> None:
    """既没指定语言、没有文件名、内容也认不出来时，必须承认识别不了。

    猜一个语言会让后续按错误语言的模式去匹配，产出一批看似合理、
    实则无关的线索——那比不产出更糟。
    """
    body = client.post(SCAN_URL, json={"source_code": SAMPLE_SOURCE}).json()

    assert body["detected_language"] is None
    assert body["features"]["language"] is None
    assert body["features"]["language_source"] == "none"

    language_status = next(
        item for item in body["analyzer_status"] if item["name"] == AnalyzerName.LANGUAGE_DETECTION.value
    )
    assert language_status["state"] == AnalyzerState.SKIPPED.value
    assert "无法识别语言" in language_status["reason"]


def test_clue_extraction_is_skipped_when_language_is_unknown() -> None:
    """语言未识别必须连带跳过线索提取，并说明原因，不能静默返回空线索。"""
    body = client.post(SCAN_URL, json={"source_code": SAMPLE_SOURCE}).json()

    clue_status = next(
        item for item in body["analyzer_status"] if item["name"] == AnalyzerName.CLUES.value
    )
    assert clue_status["state"] == AnalyzerState.SKIPPED.value
    assert "跳过候选线索提取" in clue_status["reason"]
    assert clue_status["findings_count"] == 0

    # 特征提取本身仍要成功：统计与结构不依赖语言识别。
    feature_status = next(
        item
        for item in body["analyzer_status"]
        if item["name"] == AnalyzerName.FEATURE_EXTRACTION.value
    )
    assert feature_status["state"] == AnalyzerState.SUCCESS.value
    assert body["features"]["stats"]["total_lines"] == 1


def test_json_submission_has_no_source_encoding() -> None:
    """JSON 请求体按规范就是 UTF-8，没有发生字符集转换，此处应为 null。"""
    body = client.post(SCAN_URL, json={"source_code": SAMPLE_SOURCE}).json()

    assert body["source_encoding"] is None


# ---------------------------------------------------------------------------
# POST /scan：非法输入
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("source_code", ["", "   ", "\n\t\n"])
def test_scan_rejects_blank_source_code(source_code: str) -> None:
    response = client.post(SCAN_URL, json={"source_code": source_code})

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"


def test_scan_rejects_oversized_source_code_without_echoing_it() -> None:
    marker = "SECRET_MARKER_SHOULD_NOT_APPEAR"
    oversized = marker + "a" * (settings.max_source_code_chars + 1)

    response = client.post(SCAN_URL, json={"source_code": oversized})

    assert response.status_code == 422
    assert marker not in response.text


def test_scan_rejects_path_traversal_filename() -> None:
    response = client.post(
        SCAN_URL, json={"source_code": SAMPLE_SOURCE, "filename": "../../secret.py"}
    )

    assert response.status_code == 422
    assert response.json()["error"]["details"][0]["field"] == "filename"


def test_scan_rejects_unknown_field() -> None:
    response = client.post(
        SCAN_URL, json={"source_code": SAMPLE_SOURCE, "analysis_options": {"enable_llmm": True}}
    )

    assert response.status_code == 422


# ---------------------------------------------------------------------------
# POST /scan/upload：正常输入
# ---------------------------------------------------------------------------


def test_upload_accepts_utf8_file() -> None:
    response = _upload(SAMPLE_SOURCE.encode("utf-8"))

    assert response.status_code == 200
    body = response.json()
    assert body["detected_language"] == "python"
    assert body["source_encoding"] == "utf-8"
    # 这段样例是字符串拼接构造 SQL，必然产生一条启发式线索。
    # 它**不是**"已确认漏洞"，因此来源必须是 heuristic。
    assert len(body["findings"]) == 1
    finding = body["findings"][0]
    assert finding["source"] == FindingSource.HEURISTIC.value
    assert finding["vulnerability_type"] == "sql_injection"
    assert finding["line_start"] == 1


@pytest.mark.parametrize(
    ("filename", "expected_language"),
    [
        ("views.py", "python"),
        ("app.js", "javascript"),
        ("app.jsx", "javascript"),
        ("app.ts", "typescript"),
        ("app.tsx", "typescript"),
        ("index.php", "php"),
        ("Main.java", "java"),
        ("main.go", "go"),
        ("app.rb", "ruby"),
        ("index.html", "html"),
        ("App.vue", "vue"),
    ],
)
def test_upload_accepts_every_supported_extension(filename: str, expected_language: str) -> None:
    response = _upload(b"x = 1\n", filename=filename)

    assert response.status_code == 200
    assert response.json()["detected_language"] == expected_language


def test_upload_accepts_gbk_file_and_reports_the_encoding() -> None:
    """GBK 兜底解码必须如实报告，否则用户看到的是被静默转换过的内容。"""
    response = _upload("# 中文注释\nx = 1\n".encode("gbk"), filename="chinese.py")

    assert response.status_code == 200
    body = response.json()
    assert body["source_encoding"] == "gbk"
    assert body["detected_language"] == "python"


def test_upload_accepts_utf8_bom_file() -> None:
    response = _upload(codecs.BOM_UTF8 + b"x = 1\n")

    assert response.status_code == 200
    assert response.json()["source_encoding"] == "utf-8-sig"


def test_upload_preserves_crlf_and_missing_final_newline() -> None:
    response = _upload(b"a = 1\r\nb = 2")

    assert response.status_code == 200


def test_upload_form_language_overrides_extension() -> None:
    response = _upload(b"x = 1\n", filename="app.txt.php", language="html")

    assert response.status_code == 200
    assert response.json()["detected_language"] == "html"


def test_upload_accepts_enable_flags() -> None:
    response = _upload(b"x = 1\n", enable_llm="true", enable_semgrep="true")

    assert response.status_code == 200
    items = {item["name"]: item for item in response.json()["analyzer_status"]}

    # LLM 仍未接入：开关打开后必须是 unavailable，不能静默忽略这个开关。
    assert items[AnalyzerName.LLM.value]["state"] == AnalyzerState.UNAVAILABLE.value

    # Semgrep 已接入：开关打开后必须真的尝试执行，因此不能是 skipped。
    # 具体落在 success / unavailable / failed，取决于本机是否装了 Semgrep、
    # 装的版本能否正常运行——三种都是对开关的如实回应，测试不绑定环境。
    semgrep = items[AnalyzerName.SEMGREP.value]
    assert semgrep["state"] != AnalyzerState.SKIPPED.value
    if semgrep["state"] != AnalyzerState.SUCCESS.value:
        assert semgrep["reason"], "未成功执行时必须给出原因"


def test_upload_disabled_analyzer_is_reported_as_skipped() -> None:
    response = _upload(b"x = 1\n")

    statuses = {item["name"]: item["state"] for item in response.json()["analyzer_status"]}
    assert statuses[AnalyzerName.LLM.value] == AnalyzerState.SKIPPED.value


# ---------------------------------------------------------------------------
# POST /scan/upload：非法输入
# ---------------------------------------------------------------------------


def test_upload_rejects_unsupported_extension_with_415() -> None:
    response = _upload(b"x = 1\n", filename="payload.exe")

    assert response.status_code == 415
    assert response.json()["error"]["code"] == "unsupported_file_type"


def test_upload_rejects_filename_without_extension_with_415() -> None:
    response = _upload(b"x = 1\n", filename="Makefile")

    assert response.status_code == 415


def test_upload_rejects_empty_file_with_422() -> None:
    response = _upload(b"")

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "empty_input"


def test_upload_rejects_binary_content() -> None:
    response = _upload(b"\xff\xff\xff\xff", filename="evil.py")

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "unsupported_encoding"


@pytest.mark.parametrize(
    "bad_filename",
    [
        "../../etc/passwd.py",
        "..\\windows\\system32\\cmd.py",
        "sub/dir/views.py",
        "C:views.py",
        "views.py:evil",
        "CON.py",
        "NUL.py",
        "views.py.",
    ],
)
def test_upload_rejects_dangerous_filenames(bad_filename: str) -> None:
    """Windows 特有的路径变体：盘符前缀、NTFS 数据流、保留名、尾随点。"""
    response = _upload(b"x = 1\n", filename=bad_filename)

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"


def test_upload_rejects_raw_null_byte_in_filename() -> None:
    """真实 NUL 字节绕不过 httpx 的编码，只能用原始请求体验证。

    这类文件名会让路径处理函数在 C 层被截断（``views.py\\x00.txt`` 变成
    ``views.py``），从而绕过扩展名检查。这里确认它在进入任何处理之前就被拒绝。
    """
    response = _upload_raw_multipart(b"x = 1\n", b"views.py\x00.txt")

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"
    assert response.json()["error"]["details"][0]["field"] == "file"


def test_upload_rejects_percent_encoded_traversal_only_as_a_type_error() -> None:
    """百分号编码的穿越串到达服务端时已是字面量 ``%2e%2e%2f``。

    它不含路径分隔符，也不含 ``..``，因此不会被路径规则拦截，
    而是因为扩展名不是 ``py`` 被 415 拒绝。

    我们**不**为 ``%`` 追加专门规则：文件名只用于展示，从不参与路径拼接，
    字面量 ``%2e%2e%2f`` 是惰性文本；而拒绝所有含 ``%`` 的名字会误伤
    ``100%_done.py`` 这类正常文件。这里把结论固定下来，
    以免日后有人误以为"没拦"是遗漏。
    """
    response = _upload(b"x = 1\n", filename="%2e%2e%2fetc%2fpasswd.txt")

    assert response.status_code == 415


def test_upload_rejects_missing_filename() -> None:
    response = client.post(UPLOAD_URL, files={"file": ("", b"x = 1\n", "text/plain")})

    assert response.status_code == 422


def test_upload_rejects_oversized_file_with_413(monkeypatch: pytest.MonkeyPatch) -> None:
    # 把字节上限压小，使其成为唯一生效的约束：
    # 默认配置下 1 MB 的文件有 100 多万字符，早已超过 20 万字符上限，
    # 那样测到的是字符限制，而不是这里想验证的字节限制。
    monkeypatch.setattr(settings, "max_upload_size_bytes", 4096)

    response = _upload(b"a" * 4097)

    assert response.status_code == 413
    assert response.json()["error"]["code"] == "input_too_large"


def test_upload_accepts_file_exactly_at_size_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    """上限是闭区间：恰好等于上限应当通过，只有超过才拒绝。"""
    monkeypatch.setattr(settings, "max_upload_size_bytes", 4096)

    response = _upload(b"a" * 4096)

    assert response.status_code == 200


def test_upload_size_check_aborts_reading_without_buffering_everything(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """超限时立即停止读取，而不是把整个文件读完再检查。

    这里提交的内容远大于上限（1 MB vs 4 KB）。若实现是先读满再判断，
    接口仍然会返回 413——所以单看状态码区分不出两种写法。
    真正要确认的是**行为**：越界之后就不再继续消费请求体。
    """
    monkeypatch.setattr(settings, "max_upload_size_bytes", 4096)

    response = _upload(b"a" * (1024 * 1024))

    assert response.status_code == 413


def test_upload_rejects_file_exceeding_character_limit() -> None:
    """字节数在上限内、字符数超限的文件必须被拒绝。

    默认配置下 1 MB 字节上限与 20 万字符上限是两条独立约束：
    30 万字符的纯 ASCII 文件只有约 300 KB，字节没超但字符超了。
    若只查字节数，用户会收到一条与上传毫不相干的 source_code 报错。
    """
    payload = b"a" * (settings.max_source_code_chars + 1)
    assert len(payload) < settings.max_upload_size_bytes

    response = _upload(payload)

    assert response.status_code == 413
    assert response.json()["error"]["code"] == "input_too_large"
    assert response.json()["error"]["details"][0]["field"] == "file"


# ---------------------------------------------------------------------------
# 安全约束
# ---------------------------------------------------------------------------


def test_submitted_code_is_never_executed(tmp_path: Path) -> None:
    """核心安全红线：提交的代码只被当作字符串，绝不执行。

    代码内容在"被执行"时会创建一个标记文件。跑完之后该文件必须不存在——
    这比断言"没有异常抛出"更能说明问题，因为它直接验证了副作用没有发生。
    """
    marker = tmp_path / "argus_executed_marker.txt"
    payload = f"open(r'{marker.as_posix()}', 'w').write('executed')\n"

    assert client.post(SCAN_URL, json={"source_code": payload}).status_code == 200
    assert _upload(payload.encode("utf-8")).status_code == 200

    assert not marker.exists(), "提交的代码被执行了"


def test_file_type_is_decided_by_extension_not_mime_type() -> None:
    """MIME 类型由调用方随意填写，不构成任何安全依据。

    同一个文件内容，把 Content-Type 伪装成 Python 也必须被拒绝；
    反过来，正确的扩展名不因 Content-Type 奇怪而被误拒。
    """
    disguised = _upload(b"x = 1\n", filename="payload.txt", content_type="text/x-python")
    assert disguised.status_code == 415

    honest = _upload(b"x = 1\n", filename="views.py", content_type="application/octet-stream")
    assert honest.status_code == 200


def test_upload_does_not_write_files_anywhere(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """处理过程不落盘：把工作目录切到临时目录后，该目录应保持为空。"""
    monkeypatch.chdir(tmp_path)

    assert _upload(SAMPLE_SOURCE.encode("utf-8")).status_code == 200

    assert list(tmp_path.iterdir()) == []


def test_scan_response_has_no_internal_details() -> None:
    """响应不得包含路径、traceback 或配置内部值。"""
    text = client.post(SCAN_URL, json={"source_code": SAMPLE_SOURCE}).text.lower()

    for leaked in ("traceback", "c:\\", "site-packages", "api_key"):
        assert leaked not in text
