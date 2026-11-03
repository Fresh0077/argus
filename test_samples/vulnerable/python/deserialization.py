"""ARGUS 测试样例：不安全反序列化（仅用于静态分析，切勿执行）。

预期类别：unsafe_deserialization
风险原因：pickle.loads 处理了请求体。
预期行为：本地规则与 Semgrep 都应报告该调用位置。
"""

import pickle

from flask import Flask, request

app = Flask(__name__)


@app.route("/restore", methods=["POST"])
def restore():
    payload = request.data
    return str(pickle.loads(payload))
