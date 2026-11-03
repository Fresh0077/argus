/**
 * ARGUS 测试样例：安全的 DOM 文本写入（仅用于静态分析，切勿执行）。
 *
 * 预期类别：无
 * 安全原因：使用 textContent 写入纯文本，不解析 HTML。
 * 预期行为：不应报告 xss。
 */

const express = require('express');

const app = express();

app.get('/hello', (req, res) => {
  const name = req.query.name ?? '';
  const output = document.getElementById('output');
  output.textContent = name;
  res.send('ok');
});
