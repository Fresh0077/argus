import { useEffect, useRef, useState } from 'react';
import { ApiError, generateRepair } from '../services/apiClient';
import type { RepairContext, RepairSuggestion } from '../types/repair';
import type { Finding } from '../types/scan';

export interface RepairSuggestionController {
  target: Finding | null;
  suggestion: RepairSuggestion | null;
  loading: boolean;
  error: string | null;
  generate: (finding: Finding) => void;
  close: () => void;
  retry: () => void;
}

/**
 * 候选补丁的请求状态管理。
 *
 * 源码扫描与请求包审计共用：两者都把当前文本作为 `source_code` 传给
 * 同一个修复接口，行号含义由调用方保证。
 */
export function useRepairSuggestion(
  repairContext: RepairContext | null,
): RepairSuggestionController {
  const [target, setTarget] = useState<Finding | null>(null);
  const [suggestion, setSuggestion] = useState<RepairSuggestion | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const abortRef = useRef<AbortController | null>(null);

  useEffect(
    () => () => {
      abortRef.current?.abort();
    },
    [],
  );

  const generate = (finding: Finding) => {
    if (!repairContext) {
      return;
    }

    abortRef.current?.abort();
    const controller = new AbortController();
    abortRef.current = controller;

    setTarget(finding);
    setSuggestion(null);
    setError(null);
    setLoading(true);

    void generateRepair(
      {
        source_code: repairContext.sourceCode,
        language: repairContext.language,
        filename: repairContext.filename,
        finding,
      },
      { signal: controller.signal },
    )
      .then((next) => {
        if (abortRef.current === controller) {
          setSuggestion(next);
        }
      })
      .catch((requestError: unknown) => {
        if (requestError instanceof ApiError && requestError.kind === 'aborted') {
          return;
        }
        if (abortRef.current === controller) {
          setError(
            requestError instanceof ApiError
              ? requestError.message
              : '生成候选补丁失败，请稍后重试。',
          );
        }
      })
      .finally(() => {
        if (abortRef.current === controller) {
          setLoading(false);
        }
      });
  };

  const close = () => {
    abortRef.current?.abort();
    abortRef.current = null;
    setTarget(null);
    setSuggestion(null);
    setError(null);
    setLoading(false);
  };

  const retry = () => {
    if (target) {
      generate(target);
    }
  };

  return { target, suggestion, loading, error, generate, close, retry };
}
