# ARGUS 测试样例：固定命令与参数数组（仅用于静态分析，切勿执行）。
#
# 预期类别：无
# 安全原因：命令与参数均写死，不含外部输入。
# 预期行为：不应报告 command_injection。

def list_files
  system('ls', '-la', '/var/www')
end
