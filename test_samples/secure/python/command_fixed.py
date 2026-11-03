"""ARGUS 测试样例：固定命令与安全参数处理（仅用于静态分析，切勿执行）。

预期类别：无
安全原因：命令名与参数以列表形式传入，不经过 shell；外部内容只作为独立参数。
预期行为：不应报告 command_injection。
"""

import shutil
import subprocess

from flask import Flask, request

app = Flask(__name__)


@app.route("/disk")
def disk_usage():
    directory = request.args.get("dir", "/var/www")
    # 程序路径固定；外部内容只进入独立参数位置，不参与命令字符串拼接。
    target = shutil.which("du") or "/usr/bin/du"
    result = subprocess.run([target, "-sh", directory], capture_output=True, check=False)
    return result.stdout.decode("utf-8", errors="replace")
