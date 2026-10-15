"""``Finding`` 模型：所有分析器输出的统一收敛格式。

规则检测（阶段 7）、特征提取（阶段 6）、Semgrep（阶段 8）与 LLM（阶段 9）
的输出都会转换成 ``Finding``，并保留 ``source`` 以标明来源。

**重要定位说明：** 一条 ``Finding`` 是「值得人工复核的候选发现」，
不等于已确认的漏洞。单条正则命中尤其如此。
"""

from __future__ import annotations

import hashlib
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

from app.schemas.enums import FindingSource, Severity

#: 证据片段长度上限。证据只保留最小必要上下文，
#: 避免把整个源代码文件塞进响应或日志。
MAX_EVIDENCE_CHARS = 2_000

#: CWE 编号格式，例如 ``CWE-89``。
CweId = Annotated[str, StringConstraints(pattern=r"^CWE-\d{1,5}$")]


def make_finding_id(
    *,
    source: FindingSource,
    rule_key: str,
    line_start: int | None,
    line_end: int | None,
    evidence: str,
    extra: str = "",
) -> str:
    """生成稳定、可复现的发现标识符。

    同一个问题在多次扫描中应得到相同的 ``id``，这样：
    - 结果去重可以直接按 ``id`` 处理（阶段 7、阶段 10）；
    - 前端列表的 React key 稳定，不会因重新扫描而整表重渲染。

    参数中的 ``rule_key`` 由各分析器提供，需能唯一标识「哪条规则/哪次判断」，
    例如规则 ID、Semgrep 的 ``check_id``、或 LLM 使用的类别标识。

    注意：``id`` 只用于标识「同一条发现」，**不表达严重程度或漏洞身份**，
    因此不要把 ``severity``、``confidence`` 纳入计算，
    否则同一问题在两次分析中置信度略有变化就会被当成两条不同发现。
    """
    payload = "\x1f".join(
        [
            source.value,
            rule_key.strip().lower(),
            "" if line_start is None else str(line_start),
            "" if line_end is None else str(line_end),
            evidence.strip(),
            extra.strip().lower(),
        ]
    )
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    return digest[:16]


class Finding(BaseModel):
    """一条候选发现。

    字段设计说明（对应提问中「对不确定的字段设计做出说明」的要求）：

    - ``line_start`` / ``line_end``：**无法可靠定位时为 ``None``**，
      不使用 0 或 -1 这类哨兵值。哨兵值在类型上与真实行号无法区分，
      前端一旦漏判就会把 -1 渲染成行号，违背「不得编造行号」的要求。
      单行发现只填 ``line_start`` 即可。
    - ``evidence``：允许为空字符串。某些结构性发现确实没有可展示的代码片段，
      此时**宁可留空，也不编造证据**。
    - ``confidence``：分析置信度，见字段说明。它**不是**漏洞真实发生概率。
    - 未知字段默认忽略而非报错：同一个模型需要同时承接我们自己分析器的输出
      和 LLM 的返回，后者常带有额外字段，因此不宜使用 ``extra="forbid"``
      而让整条发现有价值信息被丢弃。若需严格校验 LLM 返回，
      应在阶段 9 用单独的传输对象（DTO）承接后再转换成本模型。
    """

    model_config = ConfigDict(extra="ignore")

    #: 稳定标识符，由 ``make_finding_id()`` 生成或分析器自行保证稳定。
    id: Annotated[str, StringConstraints(min_length=1, max_length=64)]

    #: 简短标题，用于列表展示。
    title: Annotated[str, StringConstraints(min_length=1, max_length=200)]

    #: 漏洞类别标识。使用受控词表（由各分析器定义），不要填入自由描述。
    vulnerability_type: Annotated[str, StringConstraints(min_length=1, max_length=100)]

    #: 严重等级。输入不区分大小写。
    severity: Severity

    #: 面向用户的风险说明。
    description: Annotated[str, StringConstraints(min_length=1, max_length=4_000)]

    #: 支持该发现的代码片段或上下文。可为空，表示没有可展示的证据片段。
    evidence: Annotated[str, StringConstraints(max_length=MAX_EVIDENCE_CHARS)] = ""

    #: 起始行号（1 起）。无法可靠定位时为 None。
    line_start: int | None = Field(default=None, ge=1)

    #: 结束行号（1 起）。无法可靠定位时为 None。
    line_end: int | None = Field(default=None, ge=1)

    #: 修复建议。可以是「建议人工复核」这类保守表述。
    recommendation: Annotated[str, StringConstraints(min_length=1, max_length=4_000)]

    #: 分析置信度，取值 0.0–1.0。
    #: **它是分析器对自身判断的估计，不是漏洞真实发生的概率。**
    #: 不同来源的置信度含义不同（规则命中 vs LLM 自评），不可跨来源直接比较或相加。
    confidence: float = Field(ge=0.0, le=1.0)

    #: 发现来源，必须如实标注。
    source: FindingSource

    #: 触发本次发现的规则标识，例如 ``ARGUS-SQL-001``。
    #:
    #: **只有规则类分析器才填**：本层规则填 ``rule_id``，Semgrep 填它的
    #: ``check_id``，LLM 填所使用的判断类别。启发式线索不是规则，
    #: 因此留空——填一个看着像规则名的值会让人以为它经过了规则那样明确的定义。
    #:
    #: 它的作用是让发现**可解释、可查**：用户看到这条发现之后，
    #: 应该能据此查到它是由什么条件触发、覆盖哪些语言。
    rule_id: Annotated[str, StringConstraints(min_length=1, max_length=120)] | None = None

    #: 关联的 CWE 编号，例如 ``CWE-89``。没有明确对应关系时留空，不要硬套。
    cwe_id: CweId | None = None

    @model_validator(mode="after")
    def _validate_line_range(self) -> "Finding":
        """校验行号区间的自洽性。

        只在两端都给出时比较大小；允许只给出 ``line_start`` 表示单行发现。
        """
        if self.line_end is not None and self.line_start is None:
            raise ValueError(
                "line_end 已提供但 line_start 为空：只允许「仅有起始行」或「同时给出起止行」"
            )
        if (
            self.line_start is not None
            and self.line_end is not None
            and self.line_end < self.line_start
        ):
            raise ValueError("line_end 不能小于 line_start")
        return self

    @property
    def has_reliable_location(self) -> bool:
        """是否具备可展示的行号。

        前端应据此显示行号或「未能可靠定位」，不要显示 0 或虚构值。
        """
        return self.line_start is not None
