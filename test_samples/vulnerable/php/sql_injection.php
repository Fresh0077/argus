<?php
declare(strict_types=1);

/**
 * ARGUS 测试样例：SQL 注入风险（仅用于静态分析，切勿执行）。
 *
 * 预期类别：sql_injection
 * 风险原因：查询语句由 $_GET 拼接后交给 PDO 执行。
 * 预期行为：本地规则与 Semgrep 都应报告该执行位置。
 */

$pdo = new PDO('sqlite::memory:');
$id = $_GET['id'] ?? '';
$sql = "SELECT * FROM users WHERE id = '" . $id . "'";
$rows = $pdo->query($sql);

echo htmlspecialchars((string) count($rows->fetchAll()), ENT_QUOTES, 'UTF-8');
