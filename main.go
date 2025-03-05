package main

import (
	"encoding/json"
	"fmt"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"
)

func main() {
	go startPrometheusServer()

	// 创建一个 ticker 定时读取 map 数据
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	// 等待中断信号以终止程序
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	fmt.Println("开始监控进程执行信息...")

	go func() {
		for {
			select {
			case <-ticker.C:
				// 使用 bpftool 读取 map
				readMapUsingBpftool()
			}
		}
	}()

	<-sig
	fmt.Println("\n程序终止")
}

// 使用 bpftool 读取 map
func readMapUsingBpftool() {
	fmt.Println("\n当前进程执行信息:")

	// 执行 bpftool 命令读取 map
	cmd := exec.Command("bpftool", "map", "dump", "pinned", "/sys/fs/bpf/sys_execve/proc_execve")
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("执行 bpftool 失败: %v\n", err)
		return
	}

	// 解析输出并格式化显示
	processMapOutput(string(output))
}

// 解析并格式化 bpftool 的输出，按进程名称统计调用次数
func processMapOutput(output string) {
	// 清理输出，删除杂项字符
	cleanOutput := strings.ReplaceAll(output, "------------------------------------------", "")

	// 尝试将输出作为JSON解析
	var entries []struct {
		Key   int `json:"key"`
		Value struct {
			Comm  string `json:"comm"`
			Pid   int    `json:"pid"`
			Count int    `json:"count"`
		} `json:"value"`
	}

	err := json.Unmarshal([]byte(cleanOutput), &entries)
	if err != nil {
		fmt.Printf("JSON解析错误: %v\n", err)
		return
	}

	// 按进程名称统计调用次数
	processStats := make(map[string]struct {
		TotalCount int
		Executions int
		ProcessIDs []int
	})

	for _, entry := range entries {
		procName := entry.Value.Comm
		stats := processStats[procName]
		stats.TotalCount += entry.Value.Count
		stats.Executions++
		stats.ProcessIDs = append(stats.ProcessIDs, entry.Value.Pid)
		processStats[procName] = stats
	}

	var statsList []ProcessStat

	for name, stats := range processStats {
		statsList = append(statsList, ProcessStat{
			Name:       name,
			TotalCount: stats.TotalCount,
			Executions: stats.Executions,
			ProcessIDs: stats.ProcessIDs,
		})
	}

	// 按总调用次数降序排序
	sort.Slice(statsList, func(i, j int) bool {
		return statsList[i].TotalCount > statsList[j].TotalCount
	})

	// 显示统计结果
	fmt.Printf("\n%-20s %-15s %-15s %-20s\n", "进程名", "总调用次数", "执行进程数", "PID列表(部分)")
	fmt.Println(strings.Repeat("-", 75))

	for _, stat := range statsList {
		// 只显示前5个PID，如果超过5个则显示"等"
		pidDisplay := ""
		if len(stat.ProcessIDs) <= 5 {
			for i, pid := range stat.ProcessIDs {
				if i > 0 {
					pidDisplay += ", "
				}
				pidDisplay += fmt.Sprintf("%d", pid)
			}
		} else {
			for i := 0; i < 5; i++ {
				if i > 0 {
					pidDisplay += ", "
				}
				pidDisplay += fmt.Sprintf("%d", stat.ProcessIDs[i])
			}
			pidDisplay += fmt.Sprintf(" 等%d个", len(stat.ProcessIDs))
		}

		fmt.Printf("%-20s %-15d %-15d %-20s\n",
			stat.Name, stat.TotalCount, stat.Executions, pidDisplay)
	}

	// 显示统计总数
	fmt.Printf("\n共发现 %d 个不同进程，总调用次数: %d\n",
		len(statsList), sumTotalCounts(statsList))

	// 在显示统计总数后更新 Prometheus 指标
	updatePrometheusMetrics(statsList)
}

// ProcessStat 转换为切片以便排序
type ProcessStat struct {
	Name       string
	TotalCount int
	Executions int
	ProcessIDs []int
}

// 计算总调用次数
func sumTotalCounts(stats []ProcessStat) int {
	total := 0
	for _, stat := range stats {
		total += stat.TotalCount
	}
	return total
}

// 定义 Prometheus 指标
var (
	// 进程总调用次数
	execveCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "execve_total_calls",
			Help: "Total number of execve calls by process name",
		},
		[]string{"process_name"},
	)

	// 进程执行实例数
	execveInstancesGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "execve_instances",
			Help: "Number of process instances by process name",
		},
		[]string{"process_name"},
	)

	// 所有进程总调用次数
	execveTotalCounter = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "execve_all_calls_total",
			Help: "Total number of execve calls across all processes",
		},
	)
)

func init() {
	// 注册指标到 Prometheus
	prometheus.MustRegister(execveCounter)
	prometheus.MustRegister(execveInstancesGauge)
	prometheus.MustRegister(execveTotalCounter)
}

// 启动 Prometheus HTTP 服务
func startPrometheusServer() {
	// 注册 Prometheus 指标处理器
	http.Handle("/metrics", promhttp.Handler())

	// 启动 HTTP 服务器
	fmt.Println("启动 Prometheus 指标服务在 :9093/metrics")
	if err := http.ListenAndServe(":9093", nil); err != nil {
		fmt.Printf("启动 Prometheus 服务失败: %v\n", err)
	}
}

// 跟踪上一次的总调用次数
var lastTotalCalls float64 = 0

// 更新 Prometheus 指标
func updatePrometheusMetrics(stats []ProcessStat) {
	// 清除旧的指标值
	execveCounter.Reset()
	execveInstancesGauge.Reset()

	// 更新进程级别的指标
	for _, stat := range stats {
		execveCounter.WithLabelValues(stat.Name).Add(float64(stat.TotalCount))
		execveInstancesGauge.WithLabelValues(stat.Name).Set(float64(stat.Executions))
	}

	// 更新总调用次数
	total := sumTotalCounts(stats)
	currentTotal := float64(total)

	// 计算增量并更新
	if currentTotal > lastTotalCalls {
		execveTotalCounter.Add(currentTotal - lastTotalCalls)
	}

	// 保存当前总数用于下次比较
	lastTotalCalls = currentTotal
}
