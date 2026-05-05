package main

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/yqcs/fingerscan"
	"github.com/yqcs/fingerscan/utils/netUtils"
)

func init() {
	//初始化指纹信息
	fingerscan.InitFinger()
}
func main() {

	//request, err := http.NewRequest("GET", "https://60.172.145.140:444", nil)
	//if err != nil {
	//	return
	//}
	//request.Header.Add("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36")
	//sendHttp, err := netUtils.SendHttp(request, 20*time.Second)
	//if err != nil {
	//	fmt.Println(err)
	//	return
	//}
	//fmt.Println(string(sendHttp.Body))

	send, err := netUtils.Send("tcp", "qq.com:80", []byte("GET / HTTP/1.1\r\nHost: qq.com:80\r\nConnection: close\r\n\r\n"), 20*time.Second)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(string(send))

	return
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
