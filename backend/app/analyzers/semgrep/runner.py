"""调用 Semgrep CLI 并把原始 JSON 取回来。

这一层只负责"安全地把代码交给外部工具、再把结果拿回来"，不解释结果
（解释在 ``parser``）。它需要处理的失败情形很多，每一种都必须与
"没有发现问题"区分开：

    可执行文件找不到       unavailable
    进程超时               failed
    退出码非零             failed
    输出文件缺失 / 过大     failed
    JSON 无法解析          failed

**安全要点**

- 用参数列表调用子进程，``shell=False``，用户代码只经临时文件传递。
  临时文件名由语言决定（``input.py``），**绝不取自上传文件名**。
- 临时目录用 ``tempfile.mkdtemp`` 创建，退出时无条件删除。
- ``--metrics=off`` 关闭遥测，``--disable-version-check`` 禁止联网检查更新。
- 从子进程环境里删除 ``SEMGREP_APP_TOKEN``：它会让 Semgrep 把结果上传到
  Semgrep AppSec Platform。本项目的分析必须留在本机。
- 设置 ``PYTHONUTF8=1``。中文 Windows 的系统默认编码是 GBK，而 Semgrep
  用默认编码读取含中文的规则文件，不设置它会在启动阶段直接崩溃。
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

from app.analyzers.semgrep.catalog import (
    INNER_TIMEOUT_SECONDS,
    MAX_OUTPUT_BYTES,
    MAX_TARGET_BYTES,
    RULES_PATH,
    SemgrepLanguage,
)
from app.schemas.enums import AnalyzerState

#: 失败原因里最多保留多少个字符的 stderr。
#:
#: 只取一小段：Semgrep 的报错本身就长，而且原文可能带临时路径与内部细节。
#: 截断后再去掉换行，保证它适合放在一行 ``analyzer_status.reason`` 里。
_MAX_STDERR_CHARS = 240

#: 不该传给子进程的环境变量。
#:
#: ``SEMGREP_APP_TOKEN`` 一旦存在，Semgrep 会把扫描结果上传到其 SaaS 平台；
#: 本项目的定位是本地分析，代码与结论都不应离开本机。
_DROP_ENV = ("SEMGREP_APP_TOKEN",)


@dataclass(frozen=True)
class SemgrepRun:
    """一次 CLI 调用的结果。

    ``state`` 只有三种取值：``success`` / ``unavailable`` / ``failed``。
    "语言不支持"由调用方在更早一步判断，不会走到这里。
    """

    state: AnalyzerState
    payload: dict[str, object] | None = None
    reason: str | None = None


def run_semgrep(
    source_code: str,
    language: SemgrepLanguage,
    *,
    command: str = "semgrep",
    timeout_seconds: float = 30.0,
) -> SemgrepRun:
    """在临时目录中对源码执行一次 Semgrep 扫描。

    参数：
        source_code: 待分析源码。只写入临时文件，**不执行、不导入**。
        language: ``catalog.SEMGREP_LANGUAGES`` 中的配置。
        command: 可执行文件名或路径；找不到时会尝试虚拟环境同目录下的可执行文件。
        timeout_seconds: 整个子进程的超时时间。

    返回：
        ``SemgrepRun``。本函数不抛异常——外部工具的任何失败都应变成
        一个带原因的 ``failed``，而不是让整次扫描 500。
    """
    executable = locate_executable(command)
    if executable is None:
        return SemgrepRun(
            state=AnalyzerState.UNAVAILABLE,
            reason=(
                "未找到 Semgrep 可执行文件。未安装时其余分析器仍会照常运行；"
                "需要该分析器时请按 backend/README.md 的说明单独安装。"
            ),
        )

    try:
        with tempfile.TemporaryDirectory(prefix="argus-semgrep-") as directory:
            return _scan_in_directory(
                Path(directory),
                executable,
                source_code,
                language,
                timeout_seconds,
            )
    except OSError as exc:
        # 临时目录创建失败、可执行文件权限问题等。错误信息只保留类型与简短说明，
        # 不把完整路径与堆栈暴露给调用方。
        return SemgrepRun(
            state=AnalyzerState.FAILED,
            reason=f"Semgrep 调用失败：{type(exc).__name__}。",
        )


def _scan_in_directory(
    directory: Path,
    executable: str,
    source_code: str,
    language: SemgrepLanguage,
    timeout_seconds: float,
) -> SemgrepRun:
    """在给定临时目录中写入源码、调用 CLI、读回 JSON。"""
    target = directory / f"input{language.suffix}"
    output = directory / "result.json"

    # newline="" 保持源码原有的换行风格（CRLF 不被改写），
    # 这样 Semgrep 报出的行号与用户编辑器里的行号一致。
    with open(target, "w", encoding="utf-8", newline="") as handle:
        handle.write(source_code)

    argv = [
        executable,
        "scan",
        "--config",
        str(RULES_PATH),
        # 不按配置文件的路径给规则 ID 加前缀：默认情况下 Semgrep 会把
        # `<绝对路径>.argus.semgrep.python-sqli` 当作 check_id，
        # 这个值随机器而变，会破坏发现 ID 的稳定性。
        "--no-rewrite-rule-ids",
        "--json",
        f"--json-output={output}",
        "--metrics=off",
        "--disable-version-check",
        "--no-git-ignore",
        "--quiet",
        "--timeout",
        str(INNER_TIMEOUT_SECONDS),
        "--max-target-bytes",
        str(MAX_TARGET_BYTES),
        str(target),
    ]

    try:
        completed = subprocess.run(
            argv,
            cwd=str(directory),
            capture_output=True,
            timeout=timeout_seconds,
            check=False,
            shell=False,
            env=_subprocess_env(),
            encoding="utf-8",
            errors="replace",
        )
    except subprocess.TimeoutExpired:
        return SemgrepRun(
            state=AnalyzerState.FAILED,
            reason=(
                f"Semgrep 执行超过 {timeout_seconds:g} 秒被终止，"
                "本次扫描不包含它的结果。可以缩小文件或调大 SEMGREP_TIMEOUT_SECONDS。"
            ),
        )
    except OSError as exc:
        return SemgrepRun(
            state=AnalyzerState.FAILED,
            reason=f"Semgrep 无法启动：{type(exc).__name__}。",
        )

    if completed.returncode != 0:
        return SemgrepRun(
            state=AnalyzerState.FAILED,
            reason=_failure_reason(completed.returncode, completed.stderr),
        )

    if not output.is_file():
        return SemgrepRun(
            state=AnalyzerState.FAILED,
            reason="Semgrep 未产出 JSON 结果文件，无法判断本次是否完成分析。",
        )

    size = output.stat().st_size
    if size > MAX_OUTPUT_BYTES:
        return SemgrepRun(
            state=AnalyzerState.FAILED,
            reason=f"Semgrep 输出过大（{size} 字节，上限 {MAX_OUTPUT_BYTES}），已拒绝解析。",
        )

    # 显式指定 UTF-8：Semgrep 输出的是 UTF-8，而中文 Windows 的默认编码是 GBK。
    with open(output, encoding="utf-8") as handle:
        raw = handle.read()

    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return SemgrepRun(
            state=AnalyzerState.FAILED,
            reason="Semgrep 的 JSON 输出无法解析，已丢弃本次结果。",
        )

    if not isinstance(payload, dict):
        return SemgrepRun(
            state=AnalyzerState.FAILED,
            reason="Semgrep 的输出不是一个 JSON 对象，已丢弃本次结果。",
        )

    return SemgrepRun(state=AnalyzerState.SUCCESS, payload=payload)


def locate_executable(command: str) -> str | None:
    """找到 Semgrep 可执行文件。

    先按配置的名字在 PATH 中查找；找不到时再看当前解释器所在目录。
    后一步是为了覆盖"没有激活虚拟环境、但 semgrep 装在 venv 里"这种
    很常见的情况——否则用户明明装了，系统却报告未安装。
    """
    found = shutil.which(command)
    if found is not None:
        return found

    interpreter_dir = Path(sys.executable).resolve().parent
    for name in ("semgrep.exe", "semgrep"):
        candidate = interpreter_dir / name
        if candidate.is_file():
            return str(candidate)
    return None


def _subprocess_env() -> dict[str, str]:
    """构造子进程环境：强制 UTF-8、关闭遥测、剔除会外传数据的变量。"""
    env = dict(os.environ)
    for name in _DROP_ENV:
        env.pop(name, None)
    env["PYTHONUTF8"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    env["SEMGREP_SEND_METRICS"] = "off"
    env["SEMGREP_ENABLE_VERSION_CHECK"] = "0"
    return env


def _failure_reason(returncode: int, stderr: str) -> str:
    """把非零退出码与 stderr 摘要拼成一条可读的原因。"""
    detail = " ".join(stderr.split())[:_MAX_STDERR_CHARS]
    if not detail:
        return f"Semgrep 以退出码 {returncode} 结束，且未给出错误信息。"
    return f"Semgrep 以退出码 {returncode} 结束：{detail}"
