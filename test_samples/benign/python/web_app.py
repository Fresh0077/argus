"""ARGUS 测试样例：普通 Web 代码（仅用于静态分析，切勿执行）。

预期类别：无
安全说明：没有数据库查询、命令执行或动态求值。
预期行为：不应报告五类风险之一；请求参数只作为纯文本返回。
"""

from flask import Flask, jsonify, request

app = Flask(__name__)

ARTICLES = {
    "intro": {"title": "介绍", "body": "这是示例文章。"},
}


@app.get("/articles/<slug>")
def article(slug: str):
    item = ARTICLES.get(slug)
    if item is None:
        return jsonify({"error": "not found"}), 404
    return jsonify(item)


@app.get("/search")
def search():
    keyword = request.args.get("q", "")
    return jsonify({"keyword": keyword, "count": 0})
