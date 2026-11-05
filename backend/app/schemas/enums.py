"""契约层的枚举定义。

统一使用小写英文取值。所有面向外部输入的枚举都需要容错：
- 大小写、首尾空白会被归一化（例如 ``"HIGH"``、``" High "`` → ``"high"``）。
- 各分析器特有的取值（例如 Semgrep 的 ``ERROR``/``WARNING``、
  LLM 可能返回的 ``"Moderate"``）**不在此处做同义词映射**，
  而应由对应适配器显式转换成本枚举，避免把厂商细节泄漏进公共契约。
"""

from __future__ import annotations

from enum import Enum


class Severity(str, Enum):
    """漏洞严重等级。

    取值统一为小写，输入时不区分大小写。
    """

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @classmethod
    def _missing_(cls, value: object) -> "Severity | None":
        """容忍大小写与首尾空白差异，返回归一化后的成员。

        未识别的取值返回 ``None``，由 Pydantic 抛出校验错误，
        而不是猜测一个等级（猜测会伪造严重程度）。
        """
        if isinstance(value, str):
            normalized = value.strip().lower()
            for member in cls:
                if member.value == normalized:
                    return member
        return None


#: 严重等级从高到低的排序权重，数字越小越严重。
#: 供结果排序使用（阶段 13），避免各处重复推导顺序。
SEVERITY_RANK: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


class FindingSource(str, Enum):
    """发现来源。

    必须如实标注，便于用户区分「可解释的规则证据」与「模型的辅助判断」。
    """

    #: 本地规则匹配（阶段 7）
    STATIC_RULE = "static_rule"
    #: 基于语言特征提取的候选线索，置信度更低，仅作为提示（阶段 6）
    HEURISTIC = "heuristic"
    #: 外部静态分析工具 Semgrep（阶段 8）
    SEMGREP = "semgrep"
    #: 大语言模型判断（阶段 9）
    LLM = "llm"


class ScanStatus(str, Enum):
    """一次扫描的整体状态。"""

    #: 所有启用的分析器都成功执行
    COMPLETED = "completed"
    #: 部分分析器被跳过或失败，但仍有分析结果返回
    PARTIAL = "partial"
    #: 无法产出任何结果（例如输入不合法之后的内部错误）
    FAILED = "failed"


class AnalyzerState(str, Enum):
    """单个分析器的执行状态。

    必须区分这几种情况，不能把「分析失败」报告成「未发现漏洞」。
    """

    #: 执行成功（无论是否找到问题）
    SUCCESS = "success"
    #: 按配置或输入主动跳过（例如语言不受支持）
    SKIPPED = "skipped"
    #: 依赖不可用（例如未安装 Semgrep、未配置 LLM API key）
    UNAVAILABLE = "unavailable"
    #: 执行过程中出错（超时、解析失败、网络错误等）
    FAILED = "failed"


class AnalyzerName(str, Enum):
    """分析器标识，用于 ``analyzer_status`` 中逐项报告状态。"""

    LANGUAGE_DETECTION = "language_detection"
    #: 代码统计与结构特征（行数、函数/类数量、导入）。只要拿到输入就一定能执行。
    FEATURE_EXTRACTION = "feature_extraction"
    #: 候选线索提取。依赖语言识别结果：语言未知时会跳过（见 LanguageSource.NONE）。
    #: 与 feature_extraction 分开报告，是因为"统计做了、线索没做"是一种真实状态，
    #: 合在一起会导致要么误报成成功、要么误报成失败，两者都是误导。
    CLUES = "clue_extraction"
    RULES = "rules"
    SEMGREP = "semgrep"
    LLM = "llm"


class LanguageSource(str, Enum):
    """``detected_language`` 是怎么得出来的。

    必须如实标注：调用方显式指定的语言与从内容推断的语言，
    可信程度完全不同，前端应当区别展示。
    """

    #: 调用方在请求里显式指定
    EXPLICIT = "explicit"
    #: 由文件扩展名确定（确定性查表，不是猜测）
    EXTENSION = "extension"
    #: 由代码内容特征推断（shebang、语法标记等），可能出错
    HEURISTIC = "heuristic"
    #: 未能识别。此时 ``detected_language`` 为 None
    NONE = "none"


class ErrorCode(str, Enum):
    """机器可读的错误码。

    面向用户的 ``message`` 使用中文说明，本枚举供前端做分支判断。
    """

    INVALID_REQUEST = "invalid_request"
    VALIDATION_ERROR = "validation_error"
    EMPTY_INPUT = "empty_input"
    INPUT_TOO_LARGE = "input_too_large"
    UNSUPPORTED_FILE_TYPE = "unsupported_file_type"
    #: 文件内容无法按受支持的编码解码（阶段 5 上传接口）。
    #: 与 ``unsupported_file_type`` 区分开：前者是"扩展名不在白名单"，
    #: 后者是"扩展名合法但字节不是可识别的文本"，用户需要采取的动作不同。
    UNSUPPORTED_ENCODING = "unsupported_encoding"
    UNSUPPORTED_LANGUAGE = "unsupported_language"
    NOT_FOUND = "not_found"
    #: 扫描历史相关状态（阶段 15）。
    #: 与普通 404 区分开：前端可以据此提示"记录已删除"，而不是"接口不存在"。
    HISTORY_NOT_FOUND = "history_not_found"
    #: 服务端通过 HISTORY_ENABLED=false 关闭了历史功能。
    HISTORY_DISABLED = "history_disabled"
    #: 历史数据库无法打开、版本不兼容或记录损坏。
    HISTORY_UNAVAILABLE = "history_unavailable"
    METHOD_NOT_ALLOWED = "method_not_allowed"
    ANALYZER_FAILED = "analyzer_failed"
    LLM_UNAVAILABLE = "llm_unavailable"
    LLM_OUTPUT_INVALID = "llm_output_invalid"
    INTERNAL_ERROR = "internal_error"
