/** 页脚：固定展示工具定位、隐私边界与使用限制。 */
export default function AppFooter() {
  return (
    <footer className="app-footer">
      <div className="app-footer__inner">
        <p>
          ARGUS 是代码安全分析的<strong>辅助工具</strong>，不是安全证明工具。特征提取与 LLM 判断均可能误报或漏报，
          <strong>未发现候选问题不代表代码绝对安全</strong>。
        </p>
        <p>
          提交的代码只做静态分析，不会被执行或编译；修复建议必须由人工确认，不会自动改写入你的代码。
          请求包审计只读取报文文本，不会重放请求或访问目标；启用 LLM 时，
          代码或脱敏后的报文会发送到所配置的第三方模型服务商，请勿提交敏感内容。
        </p>
        <p>本工具不提供“总体安全分数”，也不会把不同来源的置信度相加。</p>
      </div>
    </footer>
  );
}
