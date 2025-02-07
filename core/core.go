package core

import (
	"fmt"
	"sync"
)

// Plugin 插件接口
type Plugin interface {
	Name() string                       // 插件名称
	Description() string                // 插件描述
	Run(target string) ValidationResult // 插件执行方法
}

// ValidationResult 验证结果
type ValidationResult struct {
	Target     string
	PluginName string
	Success    bool
	Message    string
}

// 插件管理器
type PluginManager struct {
	plugins []Plugin
}

// 注册插件
func (pm *PluginManager) RegisterPlugin(plugin Plugin) {
	pm.plugins = append(pm.plugins, plugin)
}

// 获取所有插件
func (pm *PluginManager) GetPlugins() []Plugin {
	return pm.plugins
}

// ValidateTargetWithPlugin 使用指定插件验证目标
func (pm *PluginManager) ValidateTargetWithPlugin(target string, threads int, plugin Plugin) []ValidationResult {
	var results []ValidationResult
	var wg sync.WaitGroup
	var resultChan = make(chan ValidationResult, 1) //  changed from len(pm.plugins) to 1

	// 控制并发线程数
	semaphore := make(chan struct{}, threads)

	wg.Add(1)
	semaphore <- struct{}{} // 获取信号量
	go func(p Plugin) {
		defer func() {
			<-semaphore // 释放信号量
			wg.Done()
		}()
		result := p.Run(target)
		resultChan <- result
	}(plugin)

	wg.Wait()
	close(resultChan)

	for result := range resultChan {
		results = append(results, result)
	}
	return results
}

// 验证目标
func (pm *PluginManager) ValidateTarget(target string, threads int) []ValidationResult {
	var results []ValidationResult
	var wg sync.WaitGroup
	var resultChan = make(chan ValidationResult, len(pm.plugins))

	// 控制并发线程数
	semaphore := make(chan struct{}, threads)

	for _, plugin := range pm.plugins {
		wg.Add(1)
		semaphore <- struct{}{} // 获取信号量
		go func(p Plugin) {
			defer func() {
				<-semaphore // 释放信号量
				wg.Done()
			}()
			result := p.Run(target)
			resultChan <- result
		}(plugin)
	}

	wg.Wait()
	close(resultChan)

	for result := range resultChan {
		results = append(results, result)
	}
	return results
}

// 打印验证结果
func PrintValidationResults(results []ValidationResult) {
	for _, result := range results {
		if result.Success {
			fmt.Printf("[+] Target: %s, Plugin: %s, Status: Vulnerable, Message: %s\n", result.Target, result.PluginName, result.Message)
		} else {
			fmt.Printf("[-] Target: %s, Plugin: %s, Status: Not Vulnerable, Message: %s\n", result.Target, result.PluginName, result.Message)
		}
	}
}
