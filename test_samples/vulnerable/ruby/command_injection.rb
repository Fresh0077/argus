# ARGUS 测试样例：命令注入风险（仅用于静态分析，切勿执行）。
#
# 预期类别：command_injection
# 风险原因：请求参数被插值进 shell 命令。
# 预期行为：本地规则与 Semgrep 都应报告该执行位置。

def list_directory(params)
  dir = params[:dir]
  system("ls -la #{dir}")
end
