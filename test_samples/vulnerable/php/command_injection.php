<?php
declare(strict_types=1);

/**
 * ARGUS 测试样例：命令注入风险（仅用于静态分析，切勿执行）。
 *
 * 预期类别：command_injection
 * 风险原因：shell 命令由 $_GET 拼接后交给 system 执行。
 * 预期行为：本地规则与 Semgrep 都应报告该执行位置。
 */

$dir = $_GET['dir'] ?? '.';
system('ls ' . $dir);

echo 'done';
