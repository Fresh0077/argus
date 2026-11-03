"""ARGUS 测试样例：SQL 注入风险（仅用于静态分析，切勿执行）。

预期类别：sql_injection
风险原因：查询语句由请求参数拼接后交给 sqlite3 执行。
预期行为：本地规则与 Semgrep 都应报告该执行位置。
"""

import sqlite3

from flask import Flask, request

app = Flask(__name__)
db = sqlite3.connect(":memory:")


@app.route("/users")
def find_user():
    user_id = request.args.get("id", "")
    sql = "SELECT * FROM users WHERE id = '" + user_id + "'"
    cursor = db.execute(sql)
    return str(cursor.fetchall())
