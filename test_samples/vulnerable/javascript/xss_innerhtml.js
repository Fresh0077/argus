/**
 * ARGUS 测试样例：XSS 风险（仅用于静态分析，切勿执行）。
 *
 * 预期类别：xss
 * 风险原因：请求参数被写入 innerHTML。
 * 预期行为：本地规则与 Semgrep 都应报告该赋值位置。
 */

const express = require('express');

const app = express();

app.get('/hello', (req, res) => {
  const name = req.query.name;
  const output = document.getElementById('output');
  output.innerHTML = name;
  res.send('ok');
});
