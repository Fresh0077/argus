"""运行 ARGUS 样例集评估。

用法（在 backend/ 下）：

    ./.venv/Scripts/python.exe -m scripts.evaluate
    ./.venv/Scripts/python.exe -m scripts.evaluate --no-semgrep
    ./.venv/Scripts/python.exe -m scripts.evaluate --enable-llm --json result.json

样例代码**只被当作文本分析，不执行、不编译、不导入**。默认不调用 LLM；
传入 --enable-llm 且配置齐全时，样例代码会发送到所配置的第三方服务商。
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from scripts.argus_eval.manifest import (  # noqa: E402
    EVALUATED_TYPES,
    ManifestError,
    load_manifest,
    load_samples,
)
from scripts.argus_eval.matching import (  # noqa: E402
    Counts,
    SampleOutcome,
    aggregate,
    aggregate_by_type,
)
from scripts.argus_eval.runner import (  # noqa: E402
    AnalyzerRun,
    run_combined,
    run_llm,
    run_rules,
    run_semgrep,
)

DEFAULT_SAMPLES_DIR = BACKEND_DIR.parent / "test_samples"


def _metric(value: float | None) -> str:
    return "—" if value is None else f"{value:.3f}"


def _counts_line(counts: Counts) -> str:
    return (
        f"TP={counts.true_positives}  FP={counts.false_positives}  "
        f"FN={counts.false_negatives}  |  "
        f"precision={_metric(counts.precision)}  "
        f"recall={_metric(counts.recall)}  "
        f"F1={_metric(counts.f1)}"
    )


def _state_text(run: AnalyzerRun, total: int) -> str:
    if run.state in {"disabled", "unavailable"} and not run.outcomes:
        return f"{run.state}（未参与指标）"
    return f"{run.state}，评估 {run.evaluated_count}/{total} 个样例"


def _print_analyzer(run: AnalyzerRun, total_samples: int) -> None:
    print()
    print(f"【{run.label}】")
    print(f"  状态：{_state_text(run, total_samples)}")
    if run.reason:
        print(f"  说明：{run.reason}")
    if run.notes:
        for note in run.notes:
            print(f"  注：{note}")

    if not run.outcomes:
        print("  指标：不计算（没有成功分析的样例）。")
        return

    ordered = [run.outcomes[sample_id] for sample_id in sorted(run.outcomes)]
    counts = aggregate(ordered)
    print(f"  总体：{_counts_line(counts)}")

    print("  按类型：")
    by_type = aggregate_by_type(ordered)
    for vulnerability_type in EVALUATED_TYPES:
        type_counts = by_type[vulnerability_type]
        print(
            f"    {vulnerability_type:<26} "
            f"P={_metric(type_counts.precision)} "
            f"R={_metric(type_counts.recall)} "
            f"F1={_metric(type_counts.f1)}  "
            f"(TP={type_counts.true_positives} "
            f"FP={type_counts.false_positives} "
            f"FN={type_counts.false_negatives})"
        )

    missed = [
        f"{outcome.sample_id}: {item.describe()}"
        for outcome in ordered
        for item in outcome.missed
    ]
    unexpected = [
        f"{outcome.sample_id}: {item.describe()}"
        for outcome in ordered
        for item in outcome.unexpected
    ]
    if missed:
        print("  漏报：")
        for item in missed:
            print(f"    - {item}")
    if unexpected:
        print("  误报：")
        for item in unexpected:
            print(f"    - {item}")
    if not missed and not unexpected:
        print("  漏报/误报：无")

    if run.not_evaluated:
        expected_skips = {
            sample_id: reason
            for sample_id, reason in run.not_evaluated.items()
            if reason.startswith("skipped：")
        }
        real_skips = {
            sample_id: reason
            for sample_id, reason in run.not_evaluated.items()
            if not reason.startswith("skipped：")
        }
        if expected_skips:
            print(f"  语言不适用（{len(expected_skips)} 个，未计入分母）：")
            for sample_id, reason in sorted(expected_skips.items()):
                print(f"    - {sample_id}: {reason}")
        if real_skips:
            print(f"  未执行（{len(real_skips)} 个，未计入分母）：")
            for sample_id, reason in sorted(real_skips.items()):
                print(f"    - {sample_id}: {reason}")
    if run.out_of_scope:
        print(f"  评估范围外的发现：{run.out_of_scope} 条（未计入指标）")


def _outcome_json(outcome: SampleOutcome) -> dict[str, object]:
    return {
        "sample_id": outcome.sample_id,
        "expected": [item.describe() for item in outcome.expected],
        "predicted": [item.describe() for item in outcome.predicted],
        "true_positives": outcome.true_positives,
        "false_positives": outcome.false_positives,
        "false_negatives": outcome.false_negatives,
        "missed": [item.describe() for item in outcome.missed],
        "unexpected": [item.describe() for item in outcome.unexpected],
    }


def _run_json(run: AnalyzerRun, total_samples: int) -> dict[str, object]:
    ordered = [run.outcomes[sample_id] for sample_id in sorted(run.outcomes)]
    counts = aggregate(ordered)
    by_type = aggregate_by_type(ordered)
    return {
        "label": run.label,
        "state": run.state,
        "reason": run.reason,
        "evaluated_samples": run.evaluated_count,
        "total_samples": total_samples,
        "not_evaluated": run.not_evaluated,
        "out_of_scope": run.out_of_scope,
        "counts": {
            "true_positives": counts.true_positives,
            "false_positives": counts.false_positives,
            "false_negatives": counts.false_negatives,
        },
        "metrics": {
            "precision": counts.precision,
            "recall": counts.recall,
            "f1": counts.f1,
        },
        "by_type": {
            name: {
                "true_positives": value.true_positives,
                "false_positives": value.false_positives,
                "false_negatives": value.false_negatives,
                "precision": value.precision,
                "recall": value.recall,
                "f1": value.f1,
            }
            for name, value in by_type.items()
        },
        "samples": [_outcome_json(outcome) for outcome in ordered],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="运行 ARGUS 测试样例集评估")
    parser.add_argument(
        "--samples-dir",
        type=Path,
        default=DEFAULT_SAMPLES_DIR,
        help="样例目录（默认：项目根目录下的 test_samples/）",
    )
    parser.add_argument(
        "--no-semgrep",
        action="store_true",
        help="不运行 Semgrep；其余分析器照常评估",
    )
    parser.add_argument(
        "--enable-llm",
        action="store_true",
        help="显式启用 LLM 评估；需要 LLM_* 配置，样例代码会发送到第三方服务商",
    )
    parser.add_argument(
        "--json",
        type=Path,
        default=None,
        help="把完整结果写入指定 JSON 文件",
    )
    args = parser.parse_args(argv)

    samples_dir: Path = args.samples_dir
    manifest_path = samples_dir / "manifest.json"

    try:
        manifest = load_manifest(manifest_path)
        samples = load_samples(samples_dir, manifest)
    except ManifestError as exc:
        print(f"样例集校验失败：{exc}", file=sys.stderr)
        return 2

    kinds = {kind: sum(1 for sample in samples if sample.spec.kind == kind) for kind in ("vulnerable", "secure", "benign")}

    print("ARGUS 样例集评估")
    print(f"  样例目录：{samples_dir.resolve()}")
    print(
        f"  样例数量：{len(samples)}"
        f"（风险 {kinds['vulnerable']} / 安全 {kinds['secure']} / 普通 {kinds['benign']}）"
    )
    print(
        f"  评估类别：{', '.join(EVALUATED_TYPES)}"
    )
    print(
        f"  匹配规则：类别相同且行号差 ≤ {manifest.line_tolerance}；"
        "线索（untrusted_input_source）不计入指标"
    )

    if args.enable_llm:
        print(
            "  注意：已请求 LLM 评估。若配置齐全，样例代码会发送到 LLM_BASE_URL "
            "所配置的第三方服务商。"
        )

    # Semgrep 需要逐个样例启动子进程，可能要几十秒；逐条打印进度，
    # 避免长时间没有输出被误认为脚本卡住。
    def progress(message: str) -> None:
        print(f"  {message}", flush=True)

    print("\n运行本地规则…", flush=True)
    rules = run_rules(samples, manifest.line_tolerance)
    if not args.no_semgrep:
        print("运行 Semgrep（逐个样例启动子进程，请稍候）…", flush=True)
    semgrep = run_semgrep(
        samples,
        manifest.line_tolerance,
        enabled=not args.no_semgrep,
        progress=progress,
    )
    if args.enable_llm:
        print("运行 LLM…", flush=True)
    llm = run_llm(
        samples,
        manifest.line_tolerance,
        enabled=args.enable_llm,
        progress=progress,
    )
    print("汇总组合分析…", flush=True)
    combined = run_combined(
        samples,
        rules=rules,
        semgrep=semgrep,
        llm=llm,
        tolerance=manifest.line_tolerance,
    )

    print()
    print("分析器状态")
    for run in (rules, semgrep, llm, combined):
        print(f"  {run.label:<8} {_state_text(run, len(samples))}")
        if run.reason and run.state in {"disabled", "unavailable"}:
            print(f"            {run.reason}")

    for run in (rules, semgrep, llm, combined):
        _print_analyzer(run, len(samples))

    print()
    print("说明")
    print("  - 指标只反映这组最小样例，不代表真实项目上的检出率。")
    print("  - 安全/普通样例的误报也计入 precision；样例规模小，单个样本影响较大。")
    print("  - Semgrep / LLM 未成功分析的样例不进入各自的分母，不等于“没发现问题”。")
    print("  - 标签、匹配规则与局限详见 docs/evaluation.md。")

    if args.json is not None:
        payload = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "samples_dir": str(samples_dir.resolve()),
            "sample_count": len(samples),
            "kinds": kinds,
            "line_tolerance": manifest.line_tolerance,
            "evaluated_types": list(EVALUATED_TYPES),
            "analyzers": {
                run.name: _run_json(run, len(samples))
                for run in (rules, semgrep, llm, combined)
            },
        }
        args.json.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        print(f"\nJSON 结果已写入：{args.json.resolve()}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
