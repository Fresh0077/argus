<?php
declare(strict_types=1);

/**
 * ARGUS 测试样例：普通 Web 代码（仅用于静态分析，切勿执行）。
 *
 * 预期类别：无
 * 安全说明：页面名只用于固定白名单查找，输出前做了 HTML 转义。
 * 预期行为：不应报告五类风险之一。
 */

$page = $_GET['page'] ?? 'home';
$pages = ['home' => '首页', 'about' => '关于'];
echo htmlspecialchars($pages[$page] ?? '未找到', ENT_QUOTES, 'UTF-8');
