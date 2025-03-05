package main

import (
	"fmt"
	"github.com/cilium/ebpf"
	"os"
	"strings"
)

const TaskCommLen = 16

// ProcInfo 对应BPF程序中的struct proc_info
type ProcInfo struct {
	Comm  [TaskCommLen]byte // 进程名
	Pid   uint32            // 进程ID
	Count uint64            // 执行次数计数
}

// DumpEbpfMap 从指定路径读取pinned eBPF map并解析其内容
func DumpEbpfMap(mapPath string) error {
	// 打开pinned的eBPF map
	m, err := ebpf.LoadPinnedMap(mapPath, &ebpf.LoadPinOptions{})
	if err != nil {
		return fmt.Errorf("failed to load pinned map: %w", err)
	}
	defer m.Close()

	// 获取map的信息
	mapInfo, err := m.Info()
	if err != nil {
		return fmt.Errorf("failed to get map info: %w", err)
	}

	fmt.Printf("Map名称: %s\n", mapInfo.Name)
	fmt.Printf("键大小: %d 字节\n", mapInfo.KeySize)
	fmt.Printf("值大小: %d 字节\n", mapInfo.ValueSize)
	fmt.Printf("最大条目数: %d\n", mapInfo.MaxEntries)
	fmt.Println("Map内容:")
	fmt.Println("----------------------------")

	// 遍历map中的所有键值对
	var (
		key   uint32
		value ProcInfo
		iter  = m.Iterate()
	)

	for iter.Next(&key, &value) {
		// 将进程名转换为字符串并去除空字符
		commStr := string(value.Comm[:])
		commStr = strings.TrimRight(commStr, "\x00")

		// 以JSON格式输出
		fmt.Printf("{ \"key\": %d, \"value\": { \"comm\": \"%s\", \"pid\": %d, \"count\": %d } }\n",
			key, commStr, value.Pid, value.Count)
	}

	if err := iter.Err(); err != nil {
		return fmt.Errorf("迭代过程中出错: %w", err)
	}

	return nil
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "用法: %s <ebpf-map-路径>\n", os.Args[0])
		os.Exit(1)
	}

	mapPath := os.Args[1]
	if err := DumpEbpfMap(mapPath); err != nil {
		fmt.Fprintf(os.Stderr, "错误: %s\n", err)
		os.Exit(1)
	}
}
