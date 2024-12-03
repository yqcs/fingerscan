package main

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

func init() {
	//初始化指纹信息
	InitFinger()
}
func main() {
	if len(os.Args) < 3 {
		fmt.Println("example: fingerscan 127.0.0.1 22")
		return
	}
	port, err := strconv.Atoi(os.Args[2])
	if err != nil {
		fmt.Println("example: fingerscan 127.0.0.1 22")
		return
	}
	result := ScanFingerprint(os.Args[1], port, 30*time.Second)
	//开始扫描
	fmt.Println(result)
}
