"""ARGUS 测试样例：不安全动态执行（仅用于静态分析，切勿执行）。

预期类别：unsafe_dynamic_execution
风险原因：eval 执行了请求参数中的文本。
预期行为：本地规则与 Semgrep 都应报告该执行位置。
"""

from flask import Flask, request

app = Flask(__name__)


@app.route("/calc")
def calc():
    expression = request.args.get("expr", "")
    return str(eval(expression))
