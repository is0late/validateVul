package plugins

import (
	"database/sql"
	"fmt"
	"net"
	"validateVul/core"

	_ "github.com/go-sql-driver/mysql"
)

type MySQLPlugin struct {
	user     string
	password string
}

func (p *MySQLPlugin) Name() string {
	return "MySQL弱口令验证插件"
}

func (p *MySQLPlugin) Description() string {
	return "用于检测MySQL服务是否存在弱口令漏洞"
}

// // SetUser 设置用户名 (for MySQL Plugin)
// func (p *MySQLPlugin) SetUser(user string) {
// 	p.user = user
// }

// // SetPassword 设置密码 (for MySQL Plugin)
// func (p *MySQLPlugin) SetPassword(password string) {
// 	p.password = password
// }

func (p *MySQLPlugin) SetUserAndPassword(user, password string) {
	p.user = user
	p.password = password
}

func (p *MySQLPlugin) Run(target string) core.ValidationResult {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return core.ValidationResult{
			Target:     target,
			PluginName: p.Name(),
			Success:    false,
			Message:    fmt.Sprintf("目标格式错误: %v", err),
		}
	}

	if port == "" {
		port = "3306" // 默认 MySQL 端口
	}
	var passwords []string
	if p.password != "" {
		// 如果指定了密码，则只使用指定的密码进行验证
		passwords = []string{p.password}
	} else {
		passwords = []string{"root", "admin", "password", "123456", "test", "mysql"} // TOP 6 弱口令
	}
	for _, password := range passwords {
		dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/mysql", p.user, password, host, port)
		db, err := sql.Open("mysql", dsn)
		if err != nil {
			continue //  连接失败，尝试下一个密码
		}
		defer db.Close()

		err = db.Ping()
		if err == nil {
			return core.ValidationResult{
				Target:     target,
				PluginName: p.Name(),
				Success:    true,
				Message:    fmt.Sprintf("MySQL 弱口令验证成功，用户名: %s, 密码: %s", p.user, password),
			}
		}
	}

	return core.ValidationResult{
		Target:     target,
		PluginName: p.Name(),
		Success:    false,
		Message:    "MySQL 弱口令验证失败",
	}
}

func NewMySQLPlugin() *MySQLPlugin {
	return &MySQLPlugin{
		user:     "root", // 默认用户名
		password: "",     // 默认密码为空
	}
}
