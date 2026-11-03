"""ARGUS 测试样例：命令注入风险（仅用于静态分析，切勿执行）。

预期类别：command_injection
风险原因：shell 命令由请求参数拼接后交给 os.system。
预期行为：本地规则与 Semgrep 都应报告该执行位置。
"""

import os

from flask import Flask, request

app = Flask(__name__)


@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    os.system("ping -c 1 " + host)
    return "ok"
