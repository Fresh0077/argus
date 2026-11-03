<?php
declare(strict_types=1);

/**
 * ARGUS 测试样例：反射型 XSS 风险（仅用于静态分析，切勿执行）。
 *
 * 预期类别：xss
 * 风险原因：同一行的输出语句直接拼接了 $_GET 的内容，没有 HTML 转义。
 * 预期行为：本地规则应报告该输出位置；内置 Semgrep 规则集未覆盖 PHP XSS。
 */

echo '<h1>' . $_GET['name'] . '</h1>';
