package main

/**
 * ARGUS 测试样例：SQL 注入风险（仅用于静态分析，切勿执行）。
 *
 * 预期类别：sql_injection
 * 风险原因：查询语句由请求参数拼接后交给 database/sql 执行。
 * 预期行为：本地规则应报告该执行位置；内置 Semgrep 规则集未覆盖 Go SQL 注入。
 */

import (
	"database/sql"
	"net/http"
)

func findUser(db *sql.DB, r *http.Request) *sql.Row {
	id := r.URL.Query().Get("id")
	query := "SELECT * FROM users WHERE id = '" + id + "'"
	return db.QueryRow(query)
}
