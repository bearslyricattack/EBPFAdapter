package main

import (
	"fmt"
	"github.com/cilium/ebpf"
	"os"
)

// ExecveEvent 对应eBPF map中的值结构
type ExecveEvent struct {
	Comm  [16]byte // 进程名称，通常是16字节的固定长度数组
	Pid   uint32   // 进程ID
	Count uint32   // 计数
}

// DumpEbpfMap 从指定路径读取pinned eBPF map并打印其内容
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

	fmt.Printf("Map Name: %s\n", mapInfo.Name)
	fmt.Printf("Key Size: %d bytes\n", mapInfo.KeySize)
	fmt.Printf("Value Size: %d bytes\n", mapInfo.ValueSize)
	fmt.Printf("Max Entries: %d\n", mapInfo.MaxEntries)
	fmt.Println("Map Contents:")
	fmt.Println("----------------------------")

	// 遍历map中的所有键值对
	var (
		key   uint32
		value ExecveEvent
		iter  = m.Iterate()
	)

	for iter.Next(&key, &value) {
		commStr := string(value.Comm[:])
		// 移除可能的空字符
		for i := 0; i < len(commStr); i++ {
			if commStr[i] == 0 {
				commStr = commStr[:i]
				break
			}
		}

		fmt.Printf("{ \"key\": %d, \"value\": { \"comm\": \"%s\", \"pid\": %d, \"count\": %d } }\n",
			key, commStr, value.Pid, value.Count)
	}

	if err := iter.Err(); err != nil {
		return fmt.Errorf("error during iteration: %w", err)
	}

	return nil
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <pinned-map-path>\n", os.Args[0])
		os.Exit(1)
	}

	mapPath := os.Args[1]
	if err := DumpEbpfMap(mapPath); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		os.Exit(1)
	}
}
