/**
 * ARGUS 测试样例：命令注入风险（仅用于静态分析，切勿执行）。
 *
 * 预期类别：command_injection
 * 风险原因：shell 命令由请求参数拼接后交给 child_process.exec。
 * 预期行为：本地规则应报告该调用位置；内置 Semgrep 规则集未覆盖 JavaScript 命令注入。
 */

const express = require('express');
const { exec } = require('child_process');

const app = express();

app.get('/ping', (req, res) => {
  const host = req.query.host;
  exec('ping -c 1 ' + host, (error, stdout) => {
    res.send(error ? 'failed' : stdout);
  });
});
