package main

/**
 * ARGUS 测试样例：命令注入风险（仅用于静态分析，切勿执行）。
 *
 * 预期类别：command_injection
 * 风险原因：要执行的程序名由请求参数决定。
 * 预期行为：本地规则与 Semgrep 都应报告该调用位置。
 */

import (
	"net/http"
	"os/exec"
)

func runTool(r *http.Request) ([]byte, error) {
	tool := r.URL.Query().Get("tool")
	return exec.Command(tool, "--list").Output()
}
