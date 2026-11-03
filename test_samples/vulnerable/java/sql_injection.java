/**
 * ARGUS 测试样例：SQL 注入风险（仅用于静态分析，切勿执行）。
 *
 * 预期类别：sql_injection
 * 风险原因：查询语句由请求参数拼接后交给 Statement 执行。
 * 预期行为：本地规则与 Semgrep 都应报告该执行位置。
 */

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import javax.servlet.http.HttpServletRequest;

public class SqlInjectionDemo {
    public ResultSet findUser(Connection connection, HttpServletRequest request) throws Exception {
        String id = request.getParameter("id");
        Statement statement = connection.createStatement();
        String sql = "SELECT * FROM users WHERE id = '" + id + "'";
        return statement.executeQuery(sql);
    }
}
