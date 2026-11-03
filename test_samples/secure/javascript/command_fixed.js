/**
 * ARGUS 测试样例：固定命令与参数数组（仅用于静态分析，切勿执行）。
 *
 * 预期类别：无
 * 安全原因：使用 execFile 并以数组传入固定命令与参数，不经过 shell。
 * 预期行为：不应报告 command_injection。
 */

const express = require('express');
const { execFile } = require('child_process');

const app = express();

app.get('/date', (req, res) => {
  execFile('date', ['+%Y-%m-%d'], (error, stdout) => {
    res.send(error ? 'failed' : stdout);
  });
});
