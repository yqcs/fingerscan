package main

import (
	"crypto/rsa"
	"crypto/tls"
	"encoding/pem"
	netUtils2 "fingerscan/netUtils"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

type InitProbe struct {
	wappalyze  Wappalyze //wappalyze指纹数据
	probeList  []Probe   //nmap探针数据
	serverList []struct {
		Port   string
		Server string
	}
}

// Probe 探针基本结构
type Probe struct {
	Protocol     string // 协议
	ProbeName    string // 探针名
	ProbeString  []byte // 发送的数据包
	Ports        []int  //告诉Nmap探针所要发送数据的端口，仅使用一次，在每个探针的下面
	SSLPorts     []int
	Fallback     []string        // 此指令用于指定哪个探针作为回退，如果当前探针没有匹配项；由于前一个探针可能返回数据很慢，因此可以开启新的探针，将新探针的结果与前面的匹配
	TotalWaitMS  int             // 这个很少必要的指令指定了Nmap在放弃针对特定服务定义的最新定义之前应等待的时间量。Nmap默认值通常很好
	TcpWrappedMS int             //此指令仅用于 Null 探测器。如果某个服务在此计时器用完之前关闭 TCP 连接，则该服务将标记为 。否则，匹配将照常继续
	Rarity       int             //用于控制使用探针
	Exclude      string          //排除的端口
	Matches      []ProbesMatches //匹配规则
}

// ProbesMatches 规则结构
type ProbesMatches struct {
	IsSoft      bool   //是否为软规则
	Service     string // 服务名
	Pattern     string // 匹配正则
	PatternFlag string //目前opts支持“i”，代表的含义是匹配不区分大小写；“s”：代表在‘.’字符后面有新行
	VersionInfo Version
}

// Version 版本信息结构
type Version struct {
	CpeName           string `json:"cpe_name"`            // nmap通用的指纹格式
	DeviceType        string `json:"device_type"`         // 服务运行的设备类型
	Hostname          string `json:"hostname"`            // 主机名
	Info              string `json:"info"`                // 其他详细信息
	OperatingSystem   string `json:"operating_system"`    // 运行的操作系统
	VendorProductName string `json:"vendor_product_name"` // 供应商或者服务名
	Version           string `json:"version"`             // 应用的版本信息，$1的意思由match指令中第一个()的内容替换
}

// Certificate SSL证书
// 暂时不用
type Certificate struct {
	Version            int    `json:"version"`             //版本信息
	Issuer             string `json:"issuer"`              //颁发者
	IssuerCountry      string `json:"issuer_country"`      //颁发国家
	IssuerOrganization string `json:"issuer_organization"` //颁发机构
	Subject            string `json:"subject"`             //使用人
	SubOrganization    string `json:"sub_organization"`    //组织机构
	SubCountry         string `json:"sub_country"`         //使用国家
	NotBefore          string `json:"not_before"`          //颁发日期
	NotAfter           string `json:"not_after"`           //失效日期
}

// WebApp web结果
type WebApp struct {
	Icon   string
	Title  string
	Header string
	Body   string
	App    []string
	Cert   string
}

// AppFinger 指纹信息
type AppFinger struct {
	IP       string
	Port     int
	Uri      string //IP+PORT
	Service  string //服务名
	Response []byte //响应信息
	Version  Version
	WebApp   WebApp
}

func (init *InitProbe) initNmap() {
	nmapServiceProbes, _ := temp.ReadFile("data/nmap-service-probes")
	data := string(nmapServiceProbes) + customizeProbes
	init.parseProbe(strings.Split(data, "\n"))
	nmapServicesPort, _ := temp.ReadFile("data/nmap-services")
	init.parsePort(strings.Split(string(nmapServicesPort), "\n"))
}

// regxResponse 解析响应
func (init *InitProbe) regxResponse(ip string, port int, probe Probe, ssl bool) (finger *AppFinger) {

	var (
		err      error
		response []byte
	)

	if probe.TotalWaitMS == 0 {
		probe.TotalWaitMS = 5000
	}
	if probe.TcpWrappedMS == 0 {
		probe.TcpWrappedMS = 10
	}

	if ssl {
		response, err = tlsSend(probe.Protocol, net.JoinHostPort(ip, strconv.Itoa(port)), probe.ProbeString, time.Duration(probe.TotalWaitMS)*time.Millisecond)
	} else {
		response, err = tcpSend(probe.Protocol, net.JoinHostPort(ip, strconv.Itoa(port)), probe.ProbeString, time.Duration(probe.TotalWaitMS)*time.Millisecond)
	}

	if err != nil || response == nil {
		return
	}

	// 循环匹配该协议中的正则表达式
	for _, item := range probe.Matches {

		//如果不等于空说明是soft，此时只排查相同服务的探针
		if finger != nil && finger.Service != item.Service {
			continue
		}
		//转义response
		data := ConvResponse(response)
		//进行硬匹配和软匹配
		if reg := init.getPatternRegexp(item.Pattern, item.PatternFlag); reg != nil && reg.MatchString(data) {
			if finger == nil {
				finger = &AppFinger{}
				finger.Service = item.Service
			}
			finger.Response = response
			//解析版本
			item.parseVersionInfo(data, &finger.Version, reg.String())
			//软匹配，继续下一个
			if item.IsSoft {
				continue
			}
			return finger
		}
	}

	//匹配空探针的规则
	for _, item := range init.probeList {
		if item.ProbeName != "NULL" {
			continue
		}
		for _, subItem := range item.Matches {
			//如果不等于空说明是soft，此时只排查相同服务的探针
			if finger != nil && finger.Service != subItem.Service {
				continue
			}
			//转义response
			data := ConvResponse(response)
			//进行硬匹配和软匹配
			if reg := init.getPatternRegexp(subItem.Pattern, subItem.PatternFlag); reg != nil && reg.MatchString(data) {
				if finger == nil {
					finger = &AppFinger{}
					finger.Service = subItem.Service
				}
				finger.Response = response
				//解析版本
				subItem.parseVersionInfo(data, &finger.Version, reg.String())
				//软匹配，继续下一个
				if subItem.IsSoft {
					continue
				}
				return finger
			}
		}

	}

	//此可选指令指定在当前“探测器”部分中没有匹配项时应将哪些探测器用作回退。
	//对于没有回退指令的 TCP 探测器，Nmap 首先尝试探测本身中的匹配行，然后执行到 NULL 探测器的隐式回退。
	//如果存在回退指令，Nmap 首先尝试匹配探测器本身的行，然后尝试匹配回退指令中指定的探测器中的行（从左到右）。
	//最后，Nmap 将尝试空探测。对于 UDP，行为是相同的，只是从不尝试 NULL 探测。
	for _, fallback := range probe.Fallback {
		for _, fallbackProbe := range init.probeList {
			if fallbackProbe.ProbeName != fallback {
				continue
			}
			// 循环匹配该协议中的正则表达式
			for _, item := range fallbackProbe.Matches {
				//如果不等于空说明是soft，此时只排查相同服务的探针
				if finger != nil && finger.Service != item.Service {
					continue
				}
				//转义response
				data := ConvResponse(response)
				//进行硬匹配和软匹配
				if reg := init.getPatternRegexp(item.Pattern, item.PatternFlag); reg != nil && reg.MatchString(data) {
					if finger == nil {
						finger = &AppFinger{}
						finger.Service = item.Service
					}
					finger.Response = response
					//解析版本
					item.parseVersionInfo(data, &finger.Version, reg.String())
					//软匹配，继续下一个
					if item.IsSoft {
						continue
					}
					return finger
				}
			}
		}
	}
	return finger
}

// portToServer 根据端口获取服务信息
func (init *InitProbe) portToServer(ip string, port int) (finger *AppFinger) {
	for _, item := range init.serverList {
		if item.Port == strconv.Itoa(port) && item.Server != "unknown" {
			finger = &AppFinger{}
			finger.Service = item.Server + "?"
			finger.IP = ip
			finger.Port = port
			finger.Uri = net.JoinHostPort(ip, strconv.Itoa(port))
			return finger
		}
	}
	return nil
}

func makeTcpFinger(finger *AppFinger) *AppFinger {
	if finger == nil {
		finger = &AppFinger{}
	}
	if finger.Service == "" {
		finger.Service = "unknown"
	}
	if finger.Version.CpeName == "" {
		finger.Version.CpeName = "unknown"
	}
	if finger.Version.DeviceType == "" {
		finger.Version.DeviceType = "unknown"
	}
	if finger.Version.Info == "" {
		finger.Version.Info = "unknown"
	}
	if finger.Version.Hostname == "" {
		finger.Version.Hostname = "unknown"
	}
	if finger.Version.OperatingSystem == "" {
		finger.Version.OperatingSystem = "unknown"
	}
	if finger.Version.VendorProductName == "" {
		finger.Version.VendorProductName = "unknown"
	}
	if finger.Version.Version == "" {
		finger.Version.Version = "unknown"
	}
	return finger
}

// addProbe 添加自定义规则
// 单独的匹配语句必须要以|结尾
func (init *InitProbe) addProbe(s, m string) {
	for i := 0; i < len(init.probeList); i++ {
		if init.probeList[i].ProbeName == s {
			init.probeList[i].Matches = append(init.probeList[i].Matches, init.parseProbe([]string{m}).Matches...)
		}
	}
}

// parseProbe 解析探针
func (init *InitProbe) parseProbe(list []string) (probe Probe) {
	for _, line := range list {

		//过滤换行和注释
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "Exclude ") {
			slice := strings.Split(line, " ")
			probe.Exclude = slice[1]
		}

		if strings.HasPrefix(line, "Probe ") {
			//解析探针基本信息
			if probe.ProbeName != "" && probe.Protocol != "" {
				init.probeList = append(init.probeList, probe)
				//添加完之后置空
				probe = Probe{}
			}
			slice := strings.Split(line, " ")
			//解析协议
			probe.Protocol = slice[1]
			//解析探针名称
			probe.ProbeName = slice[2]
			//将之后的数据全都赋给probeString
			probeString := strings.Join(slice[3:], " ")
			//移除开头和结尾的|
			if probeString != "" {
				probeString = probeString[strings.Index(probeString, "|")+1 : strings.LastIndex(probeString, "|")]
				probeString = strings.ReplaceAll(probeString, `\0`, `\x00`)
				probeString = strings.ReplaceAll(probeString, `"`, `${-x-}`)
				probeString = `"` + probeString + `"`
				probeString, _ = strconv.Unquote(probeString)
				probeString = strings.ReplaceAll(probeString, `${-x-}`, `"`)
				probe.ProbeString = []byte(probeString)
			}
		}
		if strings.HasPrefix(line, "match ") {
			line = strings.Replace(line, "match ", "", 1)
			slice := init.rangeMatch(line)
			if slice == nil {
				return
			}
			probe.Matches = append(probe.Matches, ProbesMatches{
				Service:     slice[1],
				Pattern:     slice[2],
				PatternFlag: slice[3],
				VersionInfo: rangeVersion(slice[4]),
				IsSoft:      false,
			})
		}
		if strings.HasPrefix(line, "softmatch ") {
			line = strings.Replace(line, "softmatch ", "", 1)
			slice := init.rangeMatch(line)
			if slice == nil {
				return
			}
			probe.Matches = append(probe.Matches, ProbesMatches{
				Service:     slice[1],
				Pattern:     slice[2],
				PatternFlag: slice[3],
				IsSoft:      true,
				VersionInfo: rangeVersion(slice[4]),
			})
		}
		if strings.HasPrefix(line, "ports ") {
			slice := strings.Split(line, " ")
			probe.Ports = ParsePort(slice[1])
		}
		if strings.HasPrefix(line, "sslports ") {
			slice := strings.Split(line, " ")
			probe.SSLPorts = ParsePort(slice[1])
		}
		if strings.HasPrefix(line, "totalwaitms ") {
			slice := strings.Split(line, " ")
			atoi, _ := strconv.Atoi(slice[1])
			probe.TotalWaitMS = atoi
		}
		if strings.HasPrefix(line, "tcpwrappedms ") {
			slice := strings.Split(line, " ")
			atoi, _ := strconv.Atoi(slice[1])
			probe.TcpWrappedMS = atoi
		}
		if strings.HasPrefix(line, "rarity ") {
			slice := strings.Split(line, " ")
			atoi, _ := strconv.Atoi(slice[1])
			probe.Rarity = atoi
		}
		if strings.HasPrefix(line, "fallback ") {
			slice := strings.Split(line, " ")
			fallback := slice[1]
			if fallback != "" {
				probe.Fallback = strings.Split(fallback, ",")
			}
			strings.Split(line, " ")
		}
	}
	if probe.ProbeName != "" && probe.Protocol != "" {
		init.probeList = append(init.probeList, probe)
	}
	return
}

// parsePort 加载内置端口集
func (init *InitProbe) parsePort(slice []string) {
	for _, line := range slice {
		if line == "" || strings.HasPrefix(line, "#") || !strings.Contains(line, "/tcp") {
			continue
		}
		line = strings.ReplaceAll(line, "\t", " ")
		list := strings.Split(line, " ")
		port := list[1]
		if strings.Contains(port, "/") {
			port = port[0:strings.Index(port, "/")]
		}
		init.serverList = append(init.serverList, struct {
			Port   string
			Server string
		}{Port: port, Server: list[0]})
	}
}

// parseVersionInfo 解析版本信息
func (m *ProbesMatches) parseVersionInfo(s string, f *Version, pattern string) {
	f.Version = m.parseItemHelper(s, m.VersionInfo.Version, pattern)
	f.Info = m.parseItemHelper(s, m.VersionInfo.Info, pattern)
	f.DeviceType = m.parseItemHelper(s, m.VersionInfo.DeviceType, pattern)
	f.Hostname = m.parseItemHelper(s, m.VersionInfo.Hostname, pattern)
	f.OperatingSystem = m.parseItemHelper(s, m.VersionInfo.OperatingSystem, pattern)
	f.VendorProductName = m.parseItemHelper(s, m.VersionInfo.VendorProductName, pattern)
}

// parseItemHelper 解析version信息
func (m *ProbesMatches) parseItemHelper(s string, pattern string, ss string) string {

	reg := regexp.MustCompile(ss)

	if len(reg.FindStringSubmatch(s)) == 1 || pattern == "" {
		return pattern
	}

	if subReg := regexp.MustCompile(`\$P\((\d)\)`); subReg.MatchString(pattern) {
		pattern = subReg.ReplaceAllStringFunc(pattern, func(repl string) string {
			a := subReg.FindStringSubmatch(repl)[1]
			return "$" + a
		})
	}

	if subReg := regexp.MustCompile(`\$(\d)`); subReg.MatchString(pattern) {
		pattern = subReg.ReplaceAllStringFunc(pattern, func(repl string) string {
			i, _ := strconv.Atoi(subReg.FindStringSubmatch(repl)[1])
			return reg.FindStringSubmatch(s)[i]
		})
	}
	pattern = strings.ReplaceAll(pattern, "\n", "")
	pattern = strings.ReplaceAll(pattern, "\r", "")
	return pattern
}

// rangeMatch 解析match
func (init *InitProbe) rangeMatch(s string) (matches []string) {
	for _, item := range []string{
		"^([a-zA-Z0-9-_./]+) m\\|([^|]+)\\|([is]{0,2})(?: (.*))?$",
		"^([a-zA-Z0-9-_./]+) m=([^=]+)=([is]{0,2})(?: (.*))?$",
		"^([a-zA-Z0-9-_./]+) m%([^%]+)%([is]{0,2})(?: (.*))?$",
		"^([a-zA-Z0-9-_./]+) m@([^@]+)@([is]{0,2})(?: (.*))?$"} {
		reg := regexp.MustCompile(item)
		if reg.MatchString(s) {
			matches = append(matches, reg.FindStringSubmatch(s)...)
		}
	}
	return matches
}

// getPatternRegexp 处理Pattern
func (init *InitProbe) getPatternRegexp(pattern string, opt string) *regexp.Regexp {

	pattern = strings.ReplaceAll(pattern, `\0`, `\x00`)

	if opt != "" {
		if strings.Contains(opt, "i") == false {
			opt += "i"
		}
		if pattern[:1] == "^" {
			pattern = fmt.Sprintf("^(?%s:%s", opt, pattern[1:])
		} else {
			pattern = fmt.Sprintf("(?%s:%s", opt, pattern)
		}
		if pattern[len(pattern)-1:] == "$" {
			pattern = fmt.Sprintf("%s)$", pattern[:len(pattern)-1])
		} else {
			pattern = fmt.Sprintf("%s)", pattern)
		}
	}

	if compile, err := regexp.Compile(pattern); err == nil {
		return compile
	}
	return nil
}

// rangeVersion 解析Version
func rangeVersion(s string) (versionInfo Version) {
	if s == "" {
		return
	}
	list := []string{`p/([^/]+)/`, `v/([^/]+)/`, `i/([^/]+)/`, `h/([^/]+)/`, `o/([^/]+)/`, `d/([^/]+)/`,
		`cpe:/([^/]+)/`, `p\|([^\|]+)\|`, `v\|([^\|]+)\|`, `i\|([^\|]+)\|`, `h\|([^\|]+)\|`, `o\|([^\|]+)\|`, `d\|([^\|]+)\|`, `cpe:\|([^\|]+)\|`}
	for _, item := range list {
		reg := regexp.MustCompile(item)
		if reg.MatchString(s) {
			match := reg.FindStringSubmatch(s)
			if len(match) < 2 {
				continue
			}
			switch item {
			case `p/([^/]+)/`:
				versionInfo.VendorProductName = match[1]
			case `p\|([^\|]+)\|`:
				versionInfo.VendorProductName = match[1]
			case `v/([^/]+)/`:
				versionInfo.Version = match[1]
			case `v\|([^\|]+)\|`:
				versionInfo.Version = match[1]
			case `i/([^/]+)/`:
				versionInfo.Info = match[1]
			case `i\|([^\|]+)\|`:
				versionInfo.Info = match[1]
			case `h/([^/]+)/`:
				versionInfo.Hostname = match[1]
			case `h\|([^\|]+)\|`:
				versionInfo.Hostname = match[1]
			case `o/([^/]+)/`:
				versionInfo.OperatingSystem = match[1]
			case `o\|([^\|]+)\|`:
				versionInfo.OperatingSystem = match[1]
			case `d/([^/]+)/`:
				versionInfo.DeviceType = match[1]
			case `d\|([^\|]+)\|`:
				versionInfo.DeviceType = match[1]
			case `cpe:/([^/]+)/`:
				versionInfo.CpeName = match[1]
			case `cpe:\|([^\|]+)\|`:
				versionInfo.CpeName = match[1]
			}
		}
	}
	return
}

func tlsSend(protocol string, ip string, data []byte, duration time.Duration) (response []byte, err error) {

	conn, err := net.DialTimeout(strings.ToLower(protocol), ip, duration)
	if err != nil {
		return nil, err
	}

	defer conn.Close()

	tlsConn := tls.Client(conn, &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
		CurvePreferences: []tls.CurveID{
			tls.CurveP256,
			tls.CurveP384,
			tls.CurveP521,
			tls.X25519,
		},
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,

			// Kept for backwards compatibility with some clients
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		},
	})

	//设置读取超时Deadline
	_ = tlsConn.SetDeadline(time.Now().Add(duration))

	_, err = tlsConn.Write(data)
	if err != nil {
		return nil, err
	}
	for {
		buff := make([]byte, 4096)
		n, err := tlsConn.Read(buff)
		if err != nil {
			if len(response) > 0 {
				break
			}
			return nil, err
		}
		if n > 0 {
			response = append(response, buff[:n]...)
		}
	}
	return response, nil
}

func tcpSend(protocol string, ip string, data []byte, duration time.Duration) (response []byte, err error) {
	conn, err := net.DialTimeout(strings.ToLower(protocol), ip, duration)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	//设置读取超时Deadline
	_ = conn.SetDeadline(time.Now().Add(duration))

	// 发送指纹探测数据
	_, err = conn.Write(data)
	if err != nil {
		return nil, err
	}

	//等待回复时长
	for {
		buff := make([]byte, 4096)
		n, err := conn.Read(buff)
		if err != nil {
			if len(response) > 0 {
				break
			}
			return nil, err
		}
		if n > 0 {
			response = append(response, buff[:n]...)
			break
		}
	}
	return response, nil
}

// WebFinger 运行web指纹枚举
func (init *InitProbe) webFinger(target string, timeout time.Duration) *WebApp {

	req, _ := http.NewRequest("GET", target, nil)

	req.AddCookie(&http.Cookie{Name: "rememberMe", Value: RandomString(5)})

	response, err := netUtils2.SendHttp(req, timeout, true)
	if err != nil {
		return nil
	}

	defer func() {
		if response.Other.Body != nil {
			response.Other.Body.Close()
		}
	}()

	res := WebApp{}

	for m := range init.wappalyze.Fingerprint(response.Other.Header, response.Body) {
		res.App = append(res.App, m)
	}

	if len(res.App) > 0 {
		res.App = SliceRemoveDuplicates(res.App)
		sort.Strings(res.App)
	}

	res.Body = string(response.Body)

	//保存header
	res.Header = response.Header

	//保存证书
	if response.Other.TLS != nil && len(response.Other.TLS.PeerCertificates) > 0 {
		cert := response.Other.TLS.PeerCertificates[0]
		res.Cert += "Subject: "
		res.Cert += "\n  Common Name: " + cert.Subject.CommonName
		if cert.Subject.Organization != nil && len(cert.Subject.Organization) > 0 {
			res.Cert += "\n  Organization: " + cert.Subject.Organization[0]
		}
		if cert.Subject.OrganizationalUnit != nil && len(cert.Subject.OrganizationalUnit) > 0 {
			res.Cert += "\n  Organizational Unit: " + cert.Subject.OrganizationalUnit[0]
		}
		if cert.Subject.Locality != nil && len(cert.Subject.Locality) > 0 {
			res.Cert += "\n  Locality: " + cert.Subject.Locality[0]
		}
		if cert.Subject.Province != nil && len(cert.Subject.Province) > 0 {
			res.Cert += "\n  Province: " + cert.Subject.Province[0]
		}
		if cert.Subject.Country != nil && len(cert.Subject.Country) > 0 {
			res.Cert += "\n  Country: " + cert.Subject.Country[0]
		}
		res.Cert += "\n\nIssuer: "
		res.Cert += "\n  Common Name: " + cert.Issuer.CommonName
		if cert.Issuer.Organization != nil && len(cert.Issuer.Organization) > 0 {
			res.Cert += "\n  Organization: " + cert.Issuer.Organization[0]
		}
		if cert.Issuer.OrganizationalUnit != nil && len(cert.Issuer.OrganizationalUnit) > 0 {
			res.Cert += "\n  Organizational Unit: " + cert.Issuer.OrganizationalUnit[0]
		}
		if cert.Issuer.Locality != nil && len(cert.Issuer.Locality) > 0 {
			res.Cert += "\n  Locality: " + cert.Issuer.Locality[0]
		}
		if cert.Issuer.Province != nil && len(cert.Issuer.Province) > 0 {
			res.Cert += "\n  Province: " + cert.Issuer.Province[0]
		}
		if cert.Issuer.Country != nil && len(cert.Issuer.Country) > 0 {
			res.Cert += "\n  Country: " + cert.Issuer.Country[0]
		}
		res.Cert += "\n\nValidity Period"
		res.Cert += "\n  Not Before: " + cert.NotBefore.String()
		res.Cert += "\n  Not After: " + cert.NotAfter.String()
		res.Cert += "\n\nSerial: " + cert.SerialNumber.String()
		res.Cert += "\nVersion: " + strconv.Itoa(cert.Version)
		res.Cert += "\nSignature: "
		res.Cert += "\n  Algorithm: " + cert.SignatureAlgorithm.String()
		res.Cert += "\n\nPublic Key: "
		res.Cert += " \n Algorithm: " + cert.PublicKeyAlgorithm.String()
		if cert.PublicKey != nil {

			if rsaPublicKey, ok := cert.PublicKey.(*rsa.PublicKey); ok {
				res.Cert += "\n  Public Exponent: " + strconv.Itoa(rsaPublicKey.E)
				res.Cert += "\n  Key Size: " + strconv.Itoa(rsaPublicKey.N.BitLen())
			} else {
				res.Cert += "\n  Public Exponent: Unknown public key type"
				res.Cert += "\n  Key Size: Unknown public key size"
			}
		}
		res.Cert += "\n\nExtension: Key Usage"
		res.Cert += "\n  - SSL/TLS Web Server Authentication\n\n"
		res.Cert += string(pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}))
	}

	//获取ICON和Title
	if scr := netUtils2.Scrape(response, timeout); scr != nil {
		res.Title = strings.ReplaceAll(scr.Title, "\r", " ")
		res.Title = strings.ReplaceAll(scr.Title, "\n", " ")
		res.Title = strings.ReplaceAll(scr.Title, "  ", " ")
		res.Icon = scr.Icon
	}
	return &res
}
