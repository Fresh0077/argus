<?php
declare(strict_types=1);

/**
 * ARGUS 测试样例：预处理语句安全写法（仅用于静态分析，切勿执行）。
 *
 * 预期类别：无
 * 安全原因：SQL 文本固定，取值通过 PDO 占位符绑定。
 * 预期行为：不应报告 sql_injection。
 */

$pdo = new PDO('sqlite::memory:');
$id = $_GET['id'] ?? '';
$statement = $pdo->prepare('SELECT * FROM users WHERE id = ?');
$statement->execute([$id]);

echo htmlspecialchars((string) $statement->fetchColumn(), ENT_QUOTES, 'UTF-8');
