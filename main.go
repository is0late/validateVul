package main

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"validateVul/core"
	"validateVul/plugins"

	"github.com/spf13/cobra"
)

var (
	host       string
	ports      string //  端口参数，支持单个端口和端口范围
	threads    int
	file       string
	pluginName string
	User       string
	password   string //  统一密码参数
	version    string = "0.1"
)

var rootCmd = &cobra.Command{
	Use:   "validateVul",
	Short: "validateVul is a vulnerability validation tool",
	Long: `validateVul 漏洞验证工具 (v` + version + `)
  * 支持 SSH、Redis、Mysql 弱口令/未授权访问检测
  * 支持单个目标、IP 段、文件批量目标检测

Example:
  validateVul -m ssh -H 192.168.1.1 -P 22 -u test -p 123456 # 单IP模式
  validateVul -m ssh -H 192.168.1.0/24 -P 22,23 -t 20  # IP段模式，多端口，20线程
  validateVul -m redis -f targets.txt  -p 123456 -t 20 # 文件模式，每行形如：192.168.1.1:6379
  validateVul -m mysql -f targets.txt -u test -p 123456 -t 20 
  `,
	Run: func(cmd *cobra.Command, args []string) {
		pluginManager := &core.PluginManager{}
		pluginManager.RegisterPlugin(plugins.NewSSHPlugin())
		pluginManager.RegisterPlugin(plugins.NewRedisPlugin())
		pluginManager.RegisterPlugin(plugins.NewMySQLPlugin())

		var selectedPlugins []core.Plugin
		if pluginName != "" {
			// 选择指定插件
			switch pluginName {
			case "ssh":
				selectedPlugins = []core.Plugin{plugins.NewSSHPlugin()}
			case "redis":
				selectedPlugins = []core.Plugin{plugins.NewRedisPlugin()}
			case "mysql":
				selectedPlugins = []core.Plugin{plugins.NewMySQLPlugin()}
			default:
				fmt.Printf("未知的插件名称: %s\n", pluginName)
				return
			}
		} else {
			// 默认运行所有插件
			selectedPlugins = pluginManager.GetPlugins()
		}

		if host != "" {
			//  处理 IP 段
			hosts := expandHost(host)
			for _, h := range hosts {
				fmt.Printf("开始检测 Host: %s, Ports: %s\n", h, ports) // 打印 host 和 ports
				targetPorts := expandPorts(ports)
				for _, port := range targetPorts {
					target := fmt.Sprintf("%s:%s", h, port) //  构建 target 字符串
					var results []core.ValidationResult
					for _, plugin := range selectedPlugins {
						switch p := plugin.(type) {
						case *plugins.SSHPlugin:
							p.SetUserAndPassword(User, password)
							results = append(results, pluginManager.ValidateTargetWithPlugin(target, threads, p)...)
						case *plugins.RedisPlugin:
							p.SetPassword(password)
							results = append(results, pluginManager.ValidateTargetWithPlugin(target, threads, p)...)
						case *plugins.MySQLPlugin:
							p.SetUserAndPassword(User, password)
							results = append(results, pluginManager.ValidateTargetWithPlugin(target, threads, p)...)
						default:
							results = append(results, pluginManager.ValidateTargetWithPlugin(target, threads, plugin)...)
						}
					}
					core.PrintValidationResults(results)
				}
			}

		} else if file != "" {
			//  批量文件检测
			targets, err := readTargetsFromFile(file)
			if err != nil {
				fmt.Printf("读取目标文件失败: %v\n", err)
				return
			}
			for _, target := range targets {
				fmt.Printf("开始检测目标: %s\n", target)
				var results []core.ValidationResult
				for _, plugin := range selectedPlugins {
					switch p := plugin.(type) {
					case *plugins.SSHPlugin:
						p.SetUserAndPassword(User, password)
						results = append(results, pluginManager.ValidateTargetWithPlugin(target, threads, p)...)
					case *plugins.RedisPlugin:
						p.SetPassword(password)
						results = append(results, pluginManager.ValidateTargetWithPlugin(target, threads, p)...)
					case *plugins.MySQLPlugin:
						p.SetUserAndPassword(User, password)
						results = append(results, pluginManager.ValidateTargetWithPlugin(target, threads, p)...)
					default:
						results = append(results, pluginManager.ValidateTargetWithPlugin(target, threads, plugin)...)
					}
				}
				core.PrintValidationResults(results)
			}

		} else {
			fmt.Println("请指定 Host 或 目标文件") //  修改提示信息
		}
	},
}

// 扩展 IP 段
func expandHost(host string) []string {
	if strings.Contains(host, "/") {
		mask := strings.Split(host, "/")[1]
		if _, err := strconv.Atoi(mask); err == nil {
			return expandCIDR(host) // 调用 CIDR 扩展函数
		}
	}
	return []string{host} //  非 IP 段，直接返回
}

// CIDR 扩展函数
func expandCIDR(cidr string) []string {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		fmt.Printf("Error parsing CIDR: %v\n", err)
		return []string{} //  Return empty slice on error
	}

	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
	}
	// remove network address and broadcast address
	if len(ips) > 2 {
		return ips[1 : len(ips)-1]
	}
	return ips
}

// IP increment function
func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// 扩展端口范围
func expandPorts(ports string) []string {
	if strings.Contains(ports, ",") {
		return strings.Split(ports, ",") // 逗号分隔的端口
	} else if strings.Contains(ports, "-") {
		portRange := strings.Split(ports, "-")
		startPort, _ := strconv.Atoi(portRange[0])
		endPort, _ := strconv.Atoi(portRange[1])
		var expandedPorts []string
		for port := startPort; port <= endPort; port++ {
			expandedPorts = append(expandedPorts, strconv.Itoa(port))
		}
		return expandedPorts //  范围端口
	}
	return []string{ports} //  单个端口
}

func readTargetsFromFile(filepath string) ([]string, error) {
	content, err := os.ReadFile(filepath)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(content), "\n")
	var targets []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			targets = append(targets, line)
		}
	}
	return targets, nil
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&host, "host", "H", "", "目标Host (IP/域名/IP段)")                          //  host 参数
	rootCmd.PersistentFlags().StringVarP(&ports, "ports", "P", "22,3306,6379", "端口 (e.g., 22,3306,6379,80-88)") //  端口参数，默认值修改
	rootCmd.PersistentFlags().IntVarP(&threads, "threads", "t", 10, "并发线程数 (default: 10)")
	rootCmd.PersistentFlags().StringVarP(&file, "file", "f", "", "目标文件，每行一个目标")
	rootCmd.PersistentFlags().StringVarP(&pluginName, "module", "m", "", "指定插件名称 (ssh, redis, mysql)")
	rootCmd.PersistentFlags().StringVarP(&User, "user", "u", "root", "")
	rootCmd.PersistentFlags().StringVarP(&password, "password", "p", "", "密码 ( 默认: 弱口令字典)")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
