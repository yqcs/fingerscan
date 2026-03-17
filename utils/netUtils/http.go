package netUtils

import (
	"crypto/tls"
	"net"
	"net/http"

	"github.com/saintfish/chardet"

	"net/http/httputil"
	"strings"
	"time"

	"github.com/tjfoc/gmsm/gmtls"
)

// Result 封装的http返回包
type Result struct {
	Other      *http.Response
	RequestRaw string
	Body       []byte
	Header     string
}

var client = http.Client{
	Transport: &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10},
		DisableKeepAlives:   true,
		MaxIdleConnsPerHost: 10, //每个host最大空闲连接
	},
}

func newGMClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialTLS: func(network, addr string) (net.Conn, error) {
				conn, err := net.DialTimeout(network, addr, 10*time.Second)
				if err != nil {
					return nil, err
				}
				config := &gmtls.Config{
					InsecureSkipVerify: true,
				}
				tlsConn := gmtls.Client(conn, config)
				if err = tlsConn.Handshake(); err != nil {
					conn.Close()
					return nil, err
				}
				return tlsConn, nil
			},
		},
		Timeout: 30 * time.Second,
	}
}

// isTLSError 检查是否为TLS相关错误，提高检测准确性和性能
func isTLSError(errStr string) bool {
	// 预编译常见的TLS错误关键词，避免重复字符串匹配
	tlsErrors := []string{
		"unsupported elliptic curve",
		"failed to parse certificate",
		"certificate verify failed",
		"handshake failure",
		"unknown certificate authority",
		"no supported cipher suite",
	}

	for _, tlsErr := range tlsErrors {
		if strings.Contains(errStr, tlsErr) {
			return true
		}
	}
	return false
}

// SendHttp 自定义Http包，redirect默认为true
func SendHttp(request *http.Request, timeout time.Duration) (result Result, err error) {

	client.Timeout = timeout
	//获取请求Raw
	if requestOut, err := httputil.DumpRequestOut(request, true); err == nil {
		result.RequestRaw = string(requestOut)
	}

	result.Other, err = client.Do(request)
	if err != nil {
		errStr := err.Error()
		// 使用更精确的错误类型检测，避免字符串匹配的误判
		if isTLSError(errStr) {
			gmcClient := newGMClient()
			gmcClient.Timeout = timeout
			result.Other, err = gmcClient.Do(request)
		}
		return result, err
	}

	if result.Other != nil {
		//无损取body
		result.Body = CopyRespBody(result.Other)
		//获取Header Raw
		headerOut, err := httputil.DumpResponse(result.Other, false)
		if err == nil {
			result.Header = string(headerOut)
		}
		var encoding string
		detectorStr, err := chardet.NewTextDetector().DetectBest(result.Body)
		if err != nil {
			encoding = GetEncoding(result.Other.Header.Get("Content-Type"), result.Body)
		} else {
			encoding = detectorStr.Charset
		}
		if strings.ToLower(encoding) != "utf-8" {
			result.Body = []byte(TransCode(result.Body, encoding))
		}
	}

	return result, err
}
