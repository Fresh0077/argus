/**
 * ARGUS 测试样例：固定进程命令（仅用于静态分析，切勿执行）。
 *
 * 预期类别：无
 * 安全原因：ProcessBuilder 的命令与参数完全写死，不含外部输入。
 * 预期行为：不应报告 command_injection。
 */

public class FixedCommandDemo {
    public Process ping() throws Exception {
        return new ProcessBuilder("ping", "-c", "1", "127.0.0.1").start();
    }
}
