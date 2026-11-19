import { Col, Row } from 'antd';
import { useEffect, useRef, useState } from 'react';
import RequestAuditPanel from '../components/RequestAuditPanel';
import RequestAuditResultPanel from '../components/RequestAuditResultPanel';
import {
  ApiError,
  auditHttpRequest,
  previewRequestAudit,
} from '../services/apiClient';
import { toScanErrorInfo } from '../services/scanErrors';
import type { RequestAuditResponse } from '../types/requestAudit';
import type { ScanErrorInfo } from '../types/ui';
import { sha256Hex } from '../utils/hash';

/**
 * 请求包审计工作区。
 *
 * 两阶段交互：
 * 1. “预览脱敏结果”只做解析与脱敏，不调用 LLM，也不产生审计发现；
 * 2. 用户必须查看预览、勾选确认，才会把脱敏后的报文发送给 LLM。
 *
 * 任何输入变化都会让旧预览/旧结果失效，避免展示与当前报文不对应的结论。
 */
export default function RequestAuditPage() {
  const [rawRequest, setRawRequest] = useState('');
  const [preview, setPreview] = useState<RequestAuditResponse | null>(null);
  const [previewText, setPreviewText] = useState('');
  const [result, setResult] = useState<RequestAuditResponse | null>(null);
  const [loading, setLoading] = useState<'preview' | 'audit' | null>(null);
  const [error, setError] = useState<ScanErrorInfo | null>(null);
  const [enableLlm, setEnableLlm] = useState(false);

  const abortRef = useRef<AbortController | null>(null);
  const mountedRef = useRef(true);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      abortRef.current?.abort();
      abortRef.current = null;
    };
  }, []);

  const canPreview = rawRequest.trim().length > 0;
  const response = result ?? preview;

  const invalidate = () => {
    abortRef.current?.abort();
    abortRef.current = null;
    setPreview(null);
    setPreviewText('');
    setResult(null);
    setError(null);
    setLoading(null);
  };

  const handleRawRequestChange = (value: string) => {
    setRawRequest(value);
    invalidate();
  };

  const handleEnableLlmChange = (enabled: boolean) => {
    setEnableLlm(enabled);
    // 已执行的 LLM 结果与当前授权状态不再对应，回到预览/空状态。
    setResult(null);
    setError(null);
  };

  const handlePreview = async () => {
    if (!canPreview || loading) {
      return;
    }

    abortRef.current?.abort();
    const controller = new AbortController();
    abortRef.current = controller;

    setLoading('preview');
    setPreview(null);
    setResult(null);
    setError(null);

    try {
      const next = await previewRequestAudit(rawRequest, { signal: controller.signal });
      if (!mountedRef.current || abortRef.current !== controller) {
        return;
      }
      setPreview(next);
      setPreviewText(next.redacted_request);
    } catch (requestError) {
      if (requestError instanceof ApiError && requestError.kind === 'aborted') {
        return;
      }
      if (abortRef.current === controller) {
        setError(
          toScanErrorInfo(requestError, {
            fallback: '请求审计失败',
            server: '后端审计失败',
          }),
        );
      }
    } finally {
      if (abortRef.current === controller) {
        abortRef.current = null;
        setLoading(null);
      }
    }
  };

  const handleAudit = async () => {
    if (!enableLlm || !preview || loading || !previewText.trim()) {
      return;
    }

    abortRef.current?.abort();
    const controller = new AbortController();
    abortRef.current = controller;

    setLoading('audit');
    setError(null);

    let fingerprint: string;
    try {
      fingerprint = await sha256Hex(previewText);
    } catch (fingerprintError) {
      abortRef.current = null;
      setLoading(null);
      setError({
        title: '无法确认预览内容',
        message:
          fingerprintError instanceof Error
            ? fingerprintError.message
            : '无法计算预览指纹，请刷新页面后重试。',
        details: [],
      });
      return;
    }

    if (!mountedRef.current || abortRef.current !== controller) {
      return;
    }

    try {
      const next = await auditHttpRequest(
        {
          raw_request: rawRequest,
          redacted_request: previewText,
          confirm_send: true,
          preview_fingerprint: fingerprint,
        },
        { signal: controller.signal },
      );
      if (!mountedRef.current || abortRef.current !== controller) {
        return;
      }
      setResult(next);
      setPreviewText(next.redacted_request);
    } catch (requestError) {
      if (requestError instanceof ApiError && requestError.kind === 'aborted') {
        return;
      }
      if (abortRef.current === controller) {
        // 409 表示预览与当前报文不一致；旧预览不能再用于确认。
        if (requestError instanceof ApiError && requestError.status === 409) {
          setPreview(null);
          setPreviewText('');
        }
        setError(
          toScanErrorInfo(requestError, {
            fallback: '请求审计失败',
            server: '后端审计失败',
          }),
        );
      }
    } finally {
      if (abortRef.current === controller) {
        abortRef.current = null;
        setLoading(null);
      }
    }
  };

  const handleClear = () => {
    invalidate();
    setRawRequest('');
  };

  return (
    <Row gutter={[20, 20]} className="scan-page request-audit-page">
      <Col xs={24} xl={10}>
        <RequestAuditPanel
          rawRequest={rawRequest}
          onRawRequestChange={handleRawRequestChange}
          enableLlm={enableLlm}
          onEnableLlmChange={handleEnableLlmChange}
          canPreview={canPreview}
          loading={loading !== null}
          onPreview={() => {
            void handlePreview();
          }}
          onClear={handleClear}
        />
      </Col>
      <Col xs={24} xl={14}>
        <RequestAuditResultPanel
          response={response}
          previewText={previewText}
          onPreviewTextChange={setPreviewText}
          loading={loading}
          error={error}
          enableLlm={enableLlm}
          onAudit={() => {
            void handleAudit();
          }}
          onRetry={() => {
            void handlePreview();
          }}
        />
      </Col>
    </Row>
  );
}
