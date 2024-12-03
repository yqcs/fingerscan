package netUtils

import (
	"crypto/tls"
	"github.com/saintfish/chardet"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"
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

// SendHttp 自定义Http包
func SendHttp(request *http.Request, timeout time.Duration, redirect bool) (result Result, err error) {

	client.Timeout = timeout
	//获取请求Raw
	if requestOut, err := httputil.DumpRequestOut(request, true); err == nil {
		result.RequestRaw = string(requestOut)
	}

	result.Other, err = client.Do(request)
	if err != nil {
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
