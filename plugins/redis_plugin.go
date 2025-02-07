package plugins

import (
	"fmt"
	"net"
	"time"
	"validateVul/core"

	"context"

	"github.com/go-redis/redis/v8"
)

type RedisPlugin struct {
	password string // 新增 password 字段
}

func (p *RedisPlugin) Name() string {
	return "Redis 弱口令/未授权访问验证插件"
}

func (p *RedisPlugin) Description() string {
	return "用于检测Redis服务是否存在弱口令或未授权访问漏洞"
}

// SetPassword 设置密码
func (p *RedisPlugin) SetPassword(password string) {
	p.password = password
}

func (p *RedisPlugin) Run(target string) core.ValidationResult {
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
		port = "6379" // 默认 Redis 端口
	}

	var passwords []string
	if p.password != "" {
		// 如果指定了密码，则只使用指定的密码进行验证 (不进行弱口令检测)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		rdb := redis.NewClient(&redis.Options{
			Addr:     net.JoinHostPort(host, port),
			Password: p.password,
			DB:       0,
		})

		_, err := rdb.Ping(ctx).Result()
		if err == nil {
			rdb.Close()
			return core.ValidationResult{
				Target:     target,
				PluginName: p.Name(),
				Success:    true,
				Message:    fmt.Sprintf("Redis 密码验证成功，密码: %s", p.password),
			}
		} else {
			return core.ValidationResult{
				Target:     target,
				PluginName: p.Name(),
				Success:    false,
				Message:    fmt.Sprintf("Redis 密码验证失败，密码: %s, 错误: %v", p.password, err),
			}
		}

	} else {
		// 未指定密码，进行未授权访问和弱口令检测
		// 未授权访问检测
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		rdb := redis.NewClient(&redis.Options{
			Addr:     net.JoinHostPort(host, port),
			Password: "", // no password by default
			DB:       0,  // default DB
		})

		_, err = rdb.Ping(ctx).Result()
		if err == nil {
			rdb.Close()
			return core.ValidationResult{
				Target:     target,
				PluginName: p.Name(),
				Success:    true,
				Message:    "Redis 未授权访问漏洞",
			}
		}

		// 弱口令检测
		passwords = []string{"root", "admin", "password", "123456", "test", "redis"} // TOP 6 弱口令
		for _, password := range passwords {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			rdb := redis.NewClient(&redis.Options{
				Addr:     net.JoinHostPort(host, port),
				Password: password,
				DB:       0,
			})

			_, err := rdb.Ping(ctx).Result()
			if err == nil {
				rdb.Close()
				return core.ValidationResult{
					Target:     target,
					PluginName: p.Name(),
					Success:    true,
					Message:    fmt.Sprintf("Redis 弱口令验证成功，密码: %s", password),
				}
			}
		}
	}

	return core.ValidationResult{
		Target:     target,
		PluginName: p.Name(),
		Success:    false,
		Message:    "Redis 弱口令/未授权访问验证失败",
	}
}

func NewRedisPlugin() *RedisPlugin {
	return &RedisPlugin{
		password: "", // 默认密码为空
	}
}
