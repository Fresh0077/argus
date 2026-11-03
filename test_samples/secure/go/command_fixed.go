package main

/**
 * ARGUS 测试样例：固定命令与参数（仅用于静态分析，切勿执行）。
 *
 * 预期类别：无
 * 安全原因：exec.Command 的程序名与参数均写死，不含外部输入。
 * 预期行为：不应报告 command_injection。
 */

import (
	"os/exec"
)

func listFiles() ([]byte, error) {
	return exec.Command("ls", "-la", "/var/www").Output()
}
