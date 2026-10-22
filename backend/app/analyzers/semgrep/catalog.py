"""Semgrep 适配层的固定映射表。

这里集中回答三个问题，避免它们散落在调用代码里：

1. **哪些语言交给 Semgrep 分析**，以及临时文件该用什么扩展名；
2. Semgrep 的 ``ERROR`` / ``WARNING`` / ``INFO`` 各自对应本项目的哪个等级；
3. 内置规则集放在哪里。

映射必须是显式的：Semgrep 对不认识的文件扩展名**不报错，直接跳过**
（``results`` 为空、``paths.scanned`` 为空、退出码 0）。若不在这里先拦住，
一次"什么都没扫"的调用看起来会和"扫了、没问题"完全一样。
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from app.schemas.enums import Severity

#: 内置规则集。随仓库分发，不访问 Semgrep Registry，因此不依赖网络，
#: 也不会因为线上规则更新而让同一份代码两次扫描结论不同。
RULES_PATH = Path(__file__).resolve().parent / "rules" / "argus.yml"

#: Semgrep 原始输出的读取上限。
#:
#: 我们让它把 JSON 写进文件再读，而不是直接收 stdout，就是为了能在**读之前**
#: 先看大小。正常输出与输入规模成正比（每条发现不到 1 KB），4 MB 足够宽松。
MAX_OUTPUT_BYTES = 4 * 1024 * 1024

#: Semgrep 单条规则的内部超时（秒）。外层还由 subprocess 的超时兜底，
#: 这个值更小，是为了让"某条规则太慢"表现为 Semgrep 自己跳过它，
#: 而不是让整次扫描被外层超时杀掉、连其他规则的结果一起丢掉。
INNER_TIMEOUT_SECONDS = 5

#: 交给 Semgrep 的文件大小上限。本项目的源码长度上限是 20 万字符，
#: UTF-8 下最多约 600 KB，这里留出余量即可。
MAX_TARGET_BYTES = 2 * 1024 * 1024


@dataclass(frozen=True)
class SemgrepLanguage:
    """一种语言在 Semgrep 侧的名字与临时文件扩展名。"""

    #: 传给 Semgrep 的语言标识（只写在规则文件里，这里用于文档与断言）。
    name: str
    #: 临时文件的扩展名。**由语言决定，绝不取自用户提交的文件名**。
    suffix: str


#: ARGUS 语言标识 → Semgrep 侧的配置。
#:
#: 刻意不含 ``html`` 与 ``vue``：Semgrep 不解析这两种目标（实测传 .vue 文件
#: 时它静默跳过、退出码 0），因此调用方应当在**调用前**就报 ``skipped``，
#: 而不是传进去等一个空结果。
SEMGREP_LANGUAGES: dict[str, SemgrepLanguage] = {
    "python": SemgrepLanguage("python", ".py"),
    "javascript": SemgrepLanguage("javascript", ".js"),
    "typescript": SemgrepLanguage("typescript", ".ts"),
    "php": SemgrepLanguage("php", ".php"),
    "java": SemgrepLanguage("java", ".java"),
    "go": SemgrepLanguage("go", ".go"),
    "ruby": SemgrepLanguage("ruby", ".rb"),
}

#: Semgrep 的等级 → 本项目的等级。
#:
#: 内置规则集全部使用 taint 模式，命中即意味着"外部输入确实流到了这个位置"，
#: 因此 ``ERROR`` 对应 ``high`` 是有依据的，不是照抄厂商等级。
#: 仍然不给 ``critical``：那需要人工确认可利用性，静态工具给不了。
SEVERITY_MAP: dict[str, Severity] = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.LOW,
}

#: 每个等级对应的置信度。
#:
#: 与本地正则规则（0.45–0.8）相比，Semgrep 的高等级发现置信度略低（0.75）：
#: 它看到了数据流，但不理解业务语义——例如这个"外部输入"是否已经被上游
#: 的白名单校验过。数值是约定的估计值，不是算出来的概率。
CONFIDENCE_BY_SEVERITY: dict[Severity, float] = {
    Severity.HIGH: 0.75,
    Severity.MEDIUM: 0.6,
    Severity.LOW: 0.5,
}

#: 规则元数据缺失时的兜底漏洞类别。使用通用值而不是猜一个具体类别：
#: 猜错会让用户按错误的类别去排查。
FALLBACK_VULNERABILITY_TYPE = "semgrep_finding"

#: 规则没有给出修复建议时的兜底文案。
FALLBACK_RECOMMENDATION = (
    "请人工确认该位置的数据来源与净化方式。Semgrep 只报告了「外部输入流到这里」"
    "这条路径，是否可被利用取决于上下文。"
)


def semgrep_language(language: str | None) -> SemgrepLanguage | None:
    """返回该语言在 Semgrep 侧的配置；不支持时返回 ``None``。"""
    if not language:
        return None
    return SEMGREP_LANGUAGES.get(language.lower())
