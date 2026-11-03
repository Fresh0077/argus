"""ARGUS 测试样例：受限的动态求值（仅用于静态分析，切勿执行）。

预期类别：无
安全原因：使用 ast.literal_eval，只解析字面量，不执行任意代码。
预期行为：不应报告 unsafe_dynamic_execution。
"""

import ast

from flask import Flask, request

app = Flask(__name__)


@app.route("/literal")
def literal():
    text = request.args.get("value", "0")
    return str(ast.literal_eval(text))
