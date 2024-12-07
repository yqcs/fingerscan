package main

import (
	"fmt"
	"github.com/yqcs/fingerscan"
	"os"
	"strconv"
	"time"
)

func init() {
	//初始化指纹信息
	fingerscan.InitFinger()
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
	result := fingerscan.ScanFingerprint(os.Args[1], port, 20*time.Second)
	//开始扫描
	fmt.Println(result)
}
