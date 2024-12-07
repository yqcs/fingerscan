package fingerscan

import (
	"context"
	"embed"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

var (
	initProbe InitProbe //nmap指纹数据
)

//go:embed data/nmap-service-probes data/nmap-services  data/web-finger.json
var temp embed.FS

func InitFinger() {
	//解析NMAP
	initProbe.initNmap()

	//加载web指纹
	initProbe.initWappalyze()
}

// ScanFingerprint 扫描
func ScanFingerprint(ip string, port int, timeout time.Duration) *AppFinger {

	//检测tcp指纹
	finger := probeCheck(ip, port, false, timeout)
	//扫描到服务是ssl，再深入识别
	if finger != nil && finger.Service == "ssl" {
		sslFinger := probeCheck(ip, port, true, timeout)
		if sslFinger != nil {
			finger.Service += "/" + sslFinger.Service
			finger.Version = sslFinger.Version
			finger.Response = sslFinger.Response
		} else {
			if portFinger := initProbe.portToServer(ip, port); portFinger != nil {
				finger.Service += "/" + portFinger.Service //BUG处理
			}
		}
	} else if finger == nil {
		//通过端口解析服务
		finger = initProbe.portToServer(ip, port)
	}

	//识别web指纹
	if finger != nil && strings.Contains(finger.Service, "http") {
		if strings.Contains(finger.Service, "ssl/http") {
			finger.Service = "https"
		}
		//获取web指纹
		if res := initProbe.webFinger(fmt.Sprintf("%s://%s", finger.Service, net.JoinHostPort(ip, strconv.Itoa(port))), timeout); res != nil {
			finger.WebApp = *res
			finger.Response = []byte(fmt.Sprintf("%s\n%s", res.Header, res.Body))
		}
	} else if finger != nil && finger.Service == "ssl" {
		if subFinger := initProbe.portToServer(ip, port); subFinger != nil {
			finger.Service += "/" + subFinger.Service //BUG处理
		}
	}

	finger = makeTcpFinger(finger)
	finger.Uri = net.JoinHostPort(ip, strconv.Itoa(port))
	finger.IP = ip
	finger.Port = port

	//web响应大于500k则不保存
	if utf8.RuneCountInString(string(finger.Response)) > 500*1024 {
		finger.Response = []byte("The data is too large to display, please visit the URL yourself.")
	}
	if finger.Version.VendorProductName != "unknown" {
		//移除重复
		finger.WebApp.App = DeleteSliceValueToLower(finger.WebApp.App, finger.Version.VendorProductName)
		//如果检测到了version，将其拼接进appName里，组成 nginx 1.18.2
		if finger.Version.Version != "unknown" {
			finger.WebApp.App = append(finger.WebApp.App, finger.Version.VendorProductName+" "+finger.Version.Version)
		} else {
			finger.WebApp.App = append(finger.WebApp.App, finger.Version.VendorProductName)
		}
	}
	return finger
}

func probeCheck(ip string, port int, ssl bool, timeout time.Duration) (finger *AppFinger) {

	ctx, cancel := context.WithTimeout(context.Background(), timeout*3)
	defer cancel()

	//第一步，先匹配匹配port指定端口的探针`
	for _, item := range initProbe.probeList {
		if ctx.Err() != nil {
			return
		}
		if ((item.ProbeName != "NULL" && (!IntSliceContains(item.Ports, port) || item.Rarity > 7)) && !ssl) || item.Protocol == "UDP" {
			continue
		}
		if finger = initProbe.regxResponse(ip, port, item, ssl); finger != nil {
			return
		}
		time.Sleep(time.Duration(item.TcpWrappedMS) * time.Millisecond)
	}

	//第二步，匹配sslPort指定端口的探针
	for _, item := range initProbe.probeList {
		if ctx.Err() != nil {
			return
		}
		//是否ssl检测
		if !IntSliceContains(item.SSLPorts, port) || item.Rarity > 7 {
			continue
		}
		if finger = initProbe.regxResponse(ip, port, item, true); finger != nil {
			return
		}
		time.Sleep(time.Duration(item.TcpWrappedMS) * time.Millisecond)

	}
	//第三步，依次从低到高进行匹配TCP
	for _, item := range initProbe.probeList {
		if ctx.Err() != nil {
			return
		}
		//过滤以下探针：包含port/sslPort、Name = NULL
		if item.ProbeName == "NULL" || IntSliceContains(item.Ports, port) || IntSliceContains(item.SSLPorts, port) || item.Protocol == "UDP" || item.Rarity > 7 {
			continue
		}
		//检测
		if finger = initProbe.regxResponse(ip, port, item, ssl); finger != nil {
			return
		}
		time.Sleep(time.Duration(item.TcpWrappedMS) * time.Millisecond)

	}
	//第四步，匹配全部UDP
	for _, item := range initProbe.probeList {
		if ctx.Err() != nil {
			return
		}
		if item.Protocol == "TCP" {
			continue
		}
		if finger = initProbe.regxResponse(ip, port, item, ssl); finger != nil {
			return
		}
		time.Sleep(time.Duration(item.TcpWrappedMS) * time.Millisecond)
	}
	return
}
