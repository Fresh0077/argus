"""加载并校验测试样例清单。

标签只来自手写的 ``test_samples/manifest.json``。评估脚本**不根据分析结果
反推标签**，否则 precision / recall 会变成自证。清单里每个样例都记录语言、
类别、风险原因与预期分析行为，说明文档同步在 ``test_samples/README.md``。
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from app.core.uploads import EXTENSION_LANGUAGE_MAP, extension_of, language_for_extension

#: 参与指标计算的漏洞类别。``untrusted_input_source`` 是线索而不是漏洞判定，
#: 因此不进入 precision / recall；它仍会在正常扫描结果里出现。
EVALUATED_TYPES: tuple[str, ...] = (
    "sql_injection",
    "command_injection",
    "xss",
    "unsafe_dynamic_execution",
    "unsafe_deserialization",
)

SAMPLE_KINDS = ("vulnerable", "secure", "benign")


class ManifestError(ValueError):
    """清单或样例文件不合法。调用方应原样展示这条信息，不要吞掉。"""


class ExpectedFindingSpec(BaseModel):
    """一条人工标注的预期发现：类别 + 危险调用所在行。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    vulnerability_type: str
    line: int = Field(gt=0)

    @field_validator("vulnerability_type")
    @classmethod
    def _known_type(cls, value: str) -> str:
        if value not in EVALUATED_TYPES:
            raise ValueError(f"未知的评估类别：{value}")
        return value


class SampleSpec(BaseModel):
    """清单中的一个样例及其全部人工标签。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]*$")
    path: str
    language: str
    kind: Literal["vulnerable", "secure", "benign"]
    category: str
    expected: tuple[ExpectedFindingSpec, ...] = ()
    description: str
    risk_reason: str
    expected_behavior: str

    @field_validator("path")
    @classmethod
    def _safe_relative_path(cls, value: str) -> str:
        candidate = PurePosixPath(value)
        if candidate.is_absolute() or ".." in candidate.parts or not candidate.parts:
            raise ValueError("样例路径必须是 test_samples/ 下的相对路径")
        return value

    @field_validator("language")
    @classmethod
    def _supported_language(cls, value: str) -> str:
        if value not in set(EXTENSION_LANGUAGE_MAP.values()):
            raise ValueError(f"未知语言：{value}")
        return value

    @field_validator("description", "risk_reason", "expected_behavior")
    @classmethod
    def _non_empty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("说明字段不能为空")
        return value

    @model_validator(mode="after")
    def _kind_and_expected_agree(self) -> "SampleSpec":
        if self.kind == "vulnerable" and not self.expected:
            raise ValueError("风险样例必须至少有一条预期发现")
        if self.kind != "vulnerable" and self.expected:
            raise ValueError("安全/普通样例不应声明预期发现")
        keys = [(item.vulnerability_type, item.line) for item in self.expected]
        if len(keys) != len(set(keys)):
            raise ValueError("同一类别与行号的预期发现重复")
        return self


class Manifest(BaseModel):
    """清单根结构。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int
    description: str
    line_tolerance: int = Field(ge=0, le=10)
    evaluated_types: tuple[str, ...]
    samples: tuple[SampleSpec, ...]

    @field_validator("evaluated_types")
    @classmethod
    def _all_types(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if set(value) != set(EVALUATED_TYPES):
            raise ValueError("evaluated_types 必须覆盖项目约定的五类风险")
        return value

    @model_validator(mode="after")
    def _unique_ids(self) -> "Manifest":
        ids = [sample.id for sample in self.samples]
        if len(ids) != len(set(ids)):
            raise ValueError("样例 id 重复")
        paths = [sample.path for sample in self.samples]
        if len(paths) != len(set(paths)):
            raise ValueError("样例 path 重复")
        return self


@dataclass(frozen=True)
class LoadedSample:
    """已读入内存的样例。``source_code`` 只被当作文本，不执行。"""

    spec: SampleSpec
    absolute_path: Path
    source_code: str
    line_count: int

    @property
    def id(self) -> str:
        return self.spec.id

    @property
    def language(self) -> str:
        return self.spec.language

    @property
    def expected(self) -> tuple[ExpectedFindingSpec, ...]:
        return self.spec.expected


def load_manifest(path: Path) -> Manifest:
    """读取并校验清单；失败时抛出带具体原因的 ``ManifestError``。"""
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ManifestError(f"无法读取样例清单 {path}：{exc}") from exc
    except UnicodeDecodeError as exc:
        raise ManifestError(f"样例清单不是 UTF-8 编码：{path}") from exc

    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ManifestError(f"样例清单不是合法 JSON：{exc}") from exc

    try:
        return Manifest.model_validate(payload)
    except ValidationError as exc:
        raise ManifestError(f"样例清单校验失败：{exc}") from exc


def load_samples(samples_root: Path, manifest: Manifest) -> tuple[LoadedSample, ...]:
    """按清单读取全部样例，并校验路径、编码、扩展名与行号范围。"""
    root = samples_root.resolve()
    loaded: list[LoadedSample] = []

    for spec in manifest.samples:
        absolute = (root / spec.path).resolve()
        if not absolute.is_relative_to(root):
            raise ManifestError(f"{spec.id}：路径越出样例目录")
        if not absolute.is_file():
            raise ManifestError(f"{spec.id}：文件不存在 {spec.path}")

        extension_language = language_for_extension(extension_of(absolute.name))
        if extension_language != spec.language:
            raise ManifestError(
                f"{spec.id}：扩展名对应的语言是 {extension_language}，清单写的是 {spec.language}"
            )

        try:
            source_code = absolute.read_text(encoding="utf-8")
        except UnicodeDecodeError as exc:
            raise ManifestError(f"{spec.id}：样例不是 UTF-8 编码") from exc
        except OSError as exc:
            raise ManifestError(f"{spec.id}：无法读取样例：{exc}") from exc

        line_count = max(1, len(source_code.splitlines()))
        for expected in spec.expected:
            if expected.line > line_count:
                raise ManifestError(
                    f"{spec.id}：预期行号 {expected.line} 超出文件行数 {line_count}"
                )

        loaded.append(
            LoadedSample(
                spec=spec,
                absolute_path=absolute,
                source_code=source_code,
                line_count=line_count,
            )
        )

    return tuple(loaded)
