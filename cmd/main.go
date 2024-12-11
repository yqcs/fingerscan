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

	fmt.Println("URI: ", result.Uri)
	fmt.Println("Server: ", result.Service)
	fmt.Println("WebFinger: ", result.WebApp.App)
	fmt.Println("Web Title: ", result.WebApp.Title)
	//fmt.Println("WebIcon: ", result.WebApp.Icon)
	fmt.Println("SSL Cert: ", result.WebApp.Cert)
}
