"""ARGUS 测试样例：同一文件中的多个风险（仅用于静态分析，切勿执行）。

预期类别：command_injection、unsafe_dynamic_execution
风险原因：一条命令由外部输入拼接；另一条直接执行外部表达式。
预期行为：规则与 Semgrep 都应分别报告这两个位置。
"""

import os

from flask import Flask, request

app = Flask(__name__)


@app.route("/admin")
def admin():
    action = request.args.get("action", "")
    os.system("backup " + action)
    expression = request.args.get("expr", "1 + 1")
    return str(eval(expression))
