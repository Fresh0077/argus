/**
 * ARGUS 测试样例：普通 Web 代码（仅用于静态分析，切勿执行）。
 *
 * 预期类别：无
 * 安全说明：没有 DOM HTML 写入、命令执行或动态求值。
 * 预期行为：不应报告五类风险之一。
 */

const express = require('express');

const app = express();

const articles = {
  intro: { title: '介绍', body: '这是示例文章。' },
};

app.get('/articles/:slug', (req, res) => {
  const article = articles[req.params.slug];
  if (!article) {
    res.status(404).json({ error: 'not found' });
    return;
  }
  res.json(article);
});
