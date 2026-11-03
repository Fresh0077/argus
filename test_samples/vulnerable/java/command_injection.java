/**
 * ARGUS 测试样例：命令注入风险（仅用于静态分析，切勿执行）。
 *
 * 预期类别：command_injection
 * 风险原因：进程命令由请求参数拼接后交给 Runtime.exec。
 * 预期行为：本地规则与 Semgrep 都应报告该执行位置。
 */

import java.io.IOException;
import javax.servlet.http.HttpServletRequest;

public class CommandInjectionDemo {
    public Process ping(HttpServletRequest request) throws IOException {
        String host = request.getParameter("host");
        return Runtime.getRuntime().exec("ping -c 1 " + host);
    }
}
