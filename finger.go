package fingerscan

import (
	"context"
	"embed"
	"fmt"
	"github.com/yqcs/fingerscan/utils/arr"
	"net"
	"strconv"
	"strings"
	"time"
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

	return finger
}

func probeCheck(ip string, port int, ssl bool, timeout time.Duration) (finger *AppFinger) {

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	//第一步，先匹配匹配port指定端口的探针`
	for _, item := range initProbe.probeList {
		if ctx.Err() != nil {
			return
		}
		if ((item.ProbeName != "NULL" && (!arr.IntSliceContains(item.Ports, port) || item.Rarity > 7)) && !ssl) || item.Protocol == "UDP" {
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
		if !arr.IntSliceContains(item.SSLPorts, port) || item.Rarity > 7 {
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
		if item.ProbeName == "NULL" || arr.IntSliceContains(item.Ports, port) || arr.IntSliceContains(item.SSLPorts, port) || item.Protocol == "UDP" || item.Rarity > 7 {
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

// GetWebAppList 获取全部WebApp列表
func GetWebAppList() (list []string) {
	for k, _ := range initProbe.wappalyze.Apps {
		if k != "" {
			list = append(list, k)
		}
	}
	return
}
func GetNmapAppList() (list []string) {
	for _, item := range initProbe.probeList {
		for _, subItem := range item.Matches {
			list = append(list, subItem.Service)
		}
	}
	return
}
