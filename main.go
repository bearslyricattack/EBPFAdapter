package main

import (
	"encoding/hex"
	"fmt"
	"github.com/cilium/ebpf"
	"os"
	"strings"
	"unsafe"
)

const TaskCommLen = 16

// ProcInfo 对应BPF程序中的struct proc_info
type ProcInfo struct {
	Comm  [TaskCommLen]byte // 进程名
	Pid   uint32            // 进程ID
	Count uint64            // 执行次数计数
	// 可能还有额外的填充或字段
}

// DumpEbpfMap 从指定路径读取pinned eBPF map并解析其内容
func DumpEbpfMap(mapPath string, rawMode bool) error {
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

	// 打印结构体信息用于调试
	procInfoSize := int(unsafe.Sizeof(ProcInfo{}))
	fmt.Printf("ProcInfo结构体大小: %d 字节\n", procInfoSize)
	fmt.Printf("结构体字段大小: Comm=%d字节, Pid=%d字节, Count=%d字节\n",
		unsafe.Sizeof([TaskCommLen]byte{}),
		unsafe.Sizeof(uint32(0)),
		unsafe.Sizeof(uint64(0)))

	if procInfoSize != int(mapInfo.ValueSize) {
		fmt.Printf("警告: 结构体大小(%d)与Map值大小(%d)不匹配!\n",
			procInfoSize, mapInfo.ValueSize)
	}

	fmt.Println("Map内容:")
	fmt.Println("----------------------------")

	if rawMode {
		// 原始模式: 读取原始字节并显示
		var (
			keyBytes   = make([]byte, mapInfo.KeySize)
			valueBytes = make([]byte, mapInfo.ValueSize)
			iter       = m.Iterate()
		)

		for iter.Next(keyBytes, valueBytes) {
			// 解析key (uint32)
			key := *(*uint32)(unsafe.Pointer(&keyBytes[0]))

			// 显示原始字节和尝试解析
			fmt.Printf("键: %d\n", key)
			fmt.Printf("值(原始十六进制): %s\n", hex.EncodeToString(valueBytes))

			// 尝试解析前面的字段
			if len(valueBytes) >= 16+4+8 {
				commBytes := valueBytes[:16]
				commStr := strings.TrimRight(string(commBytes), "\x00")
				pid := *(*uint32)(unsafe.Pointer(&valueBytes[16]))
				count := *(*uint64)(unsafe.Pointer(&valueBytes[20]))

				fmt.Printf("解析字段: comm=\"%s\", pid=%d, count=%d\n",
					commStr, pid, count)

				// 显示剩余字节
				if len(valueBytes) > 28 {
					fmt.Printf("剩余字节: %s\n",
						hex.EncodeToString(valueBytes[28:]))
				}
			}
			fmt.Println()
		}
	} else {
		// 结构体模式: 尝试使用结构体解析
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

	}
	return nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "用法: %s <ebpf-map-路径> [--raw]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  --raw: 以原始字节模式显示数据\n")
		os.Exit(1)
	}

	mapPath := os.Args[1]
	rawMode := false

	// 检查是否有--raw参数
	if len(os.Args) > 2 && os.Args[2] == "--raw" {
		rawMode = true
	}

	if err := DumpEbpfMap(mapPath, rawMode); err != nil {
		fmt.Fprintf(os.Stderr, "错误: %s\n", err)
		os.Exit(1)
	}
}
