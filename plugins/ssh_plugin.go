package plugins

import (
	"fmt"
	"net"
	"time"
	"validateVul/core"

	"golang.org/x/crypto/ssh"
)

type SSHPlugin struct {
	user     string
	password string
}

func (p *SSHPlugin) Name() string {
	return "SSH弱口令验证插件"
}

func (p *SSHPlugin) Description() string {
	return "用于检测SSH服务是否存在弱口令漏洞"
}

// SetUserAndPassword 设置用户名和密码
func (p *SSHPlugin) SetUserAndPassword(user, password string) {
	p.user = user
	p.password = password
}

func (p *SSHPlugin) Run(target string) core.ValidationResult {
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
		port = "22" // 默认 SSH 端口
	}

	var passwords []string
	if p.password != "" {
		// 如果指定了密码，则只使用指定的密码进行验证
		passwords = []string{p.password}
	} else {
		// 否则使用弱口令字典
		passwords = []string{"root", "admin", "password", "123456", "test"} // TOP 5 弱口令
	}

	for _, password := range passwords {
		authMethod := ssh.Password(password)
		config := &ssh.ClientConfig{
			User:            p.user, // 使用设置的用户名
			Auth:            []ssh.AuthMethod{authMethod},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(), // 忽略 HostKey 检查
			Timeout:         5 * time.Second,
		}

		client, err := ssh.Dial("tcp", net.JoinHostPort(host, port), config)
		if err == nil {
			defer client.Close()
			return core.ValidationResult{
				Target:     target,
				PluginName: p.Name(),
				Success:    true,
				Message:    fmt.Sprintf("弱口令验证成功，用户名: %s, 密码: %s", p.user, password),
			}
		}
	}

	return core.ValidationResult{
		Target:     target,
		PluginName: p.Name(),
		Success:    false,
		Message:    "弱口令验证失败",
	}
}

func NewSSHPlugin() *SSHPlugin {
	return &SSHPlugin{
		user:     "root", // 默认用户名
		password: "",     // 默认密码为空，使用弱口令字典
	}
}
