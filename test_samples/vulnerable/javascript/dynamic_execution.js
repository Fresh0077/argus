/**
 * ARGUS 测试样例：不安全动态执行（仅用于静态分析，切勿执行）。
 *
 * 预期类别：unsafe_dynamic_execution
 * 风险原因：请求体中的文本被 eval 当作代码执行。
 * 预期行为：本地规则与 Semgrep 都应报告该执行位置。
 */

const express = require('express');

const app = express();

app.post('/run', (req, res) => {
  const code = req.body.code;
  const result = eval(code);
  res.send(String(result));
});
