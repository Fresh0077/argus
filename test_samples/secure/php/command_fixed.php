<?php
declare(strict_types=1);

/**
 * ARGUS 测试样例：固定命令（仅用于静态分析，切勿执行）。
 *
 * 预期类别：无
 * 安全原因：命令与参数完全写死，不含任何外部输入。
 * 预期行为：不应报告 command_injection。
 */

system('ls -la /var/www');

echo 'done';
