"""ARGUS 测试样例：参数化 SQL 安全写法（仅用于静态分析，切勿执行）。

预期类别：无
安全原因：查询文本固定，取值通过占位符绑定。
预期行为：不应报告 sql_injection。
"""

import sqlite3

from flask import Flask, request

app = Flask(__name__)
db = sqlite3.connect(":memory:")


@app.route("/users")
def find_user():
    user_id = request.args.get("id", "")
    cursor = db.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return str(cursor.fetchall())
