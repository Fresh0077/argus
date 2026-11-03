/**
 * ARGUS 测试样例：预处理语句安全写法（仅用于静态分析，切勿执行）。
 *
 * 预期类别：无
 * 安全原因：SQL 文本固定，取值通过 PreparedStatement 参数绑定。
 * 预期行为：不应报告 sql_injection。
 */

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import javax.servlet.http.HttpServletRequest;

public class PreparedSqlDemo {
    public ResultSet findUser(Connection connection, HttpServletRequest request) throws Exception {
        String id = request.getParameter("id");
        PreparedStatement statement = connection.prepareStatement("SELECT * FROM users WHERE id = ?");
        statement.setString(1, id);
        return statement.executeQuery();
    }
}
