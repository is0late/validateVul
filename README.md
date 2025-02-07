# validateVul

## 简介

`validateVul` 是一个漏洞验证工具，支持 SSH、Redis 和 MySQL 服务的弱口令/未授权访问检测。它支持单个目标、IP 段和文件批量目标检测。用户可以指定用户名和密码，或者使用默认的弱口令字典进行检测。

## 功能

*   **支持多种服务：** SSH, Redis, MySQL
*   **多种目标格式：** 单个目标, IP 段 (CIDR), 文件批量目标
*   **弱口令检测：** 使用内置弱口令字典或自定义密码
*   **未授权访问检测：**  检测 Redis 未授权访问漏洞
*   **多线程支持：**  通过 `-t` 参数设置并发线程数

## 使用方法

```
validateVul -m <module> -H <host> -P <port> -u <user> -p <password> -t <threads> -f <file>
```

### 参数说明

*   `-m, --module`:  指定插件名称 (ssh, redis, mysql)
*   `-H, --host`:  目标 Host (IP/域名/IP段)
*   `-P, --ports`:  端口 (e.g., 22,3306,6379,80-88)
*   `-u, --user`:  用户名 (default: root)
*   `-p, --password`:  密码 ( 默认: 弱口令字典)
*   `-t, --threads`:  并发线程数 (default: 10)
*   `-f, --file`:  目标文件，每行一个目标

### 示例

```
validateVul -m ssh -H 192.168.1.1 -P 22 -u test -p 123456 # 单IP模式
validateVul -m ssh -H 192.168.1.0/24 -P 22,23 -t 20  # IP段模式，多端口，20线程
validateVul -m redis -f targets.txt  -p 123456 -t 20 # 文件模式，每行形如：192.168.1.1:6379
validateVul -m mysql -f targets.txt -u test -p 123456 -t 20
```

## 安装

1.  安装 Go 环境
2.  `git clone https://github.com/your-username/validateVul.git`
3.  `cd validateVul`
4.  `go build .`

## 注意事项

*   请在授权情况下使用本工具，禁止用于非法用途。
