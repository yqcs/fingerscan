package netUtils

import (
	"bytes"
	"encoding/base64"
	"golang.org/x/text/encoding/charmap"
	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"golang.org/x/net/html"
)

type DocumentPreview struct {
	Title    string
	iconPath string
	Icon     string
}

func parseDocument(body []byte) (doc DocumentPreview) {

	// 初始化变量来保存标题和图标地址
	tokenizer := html.NewTokenizer(strings.NewReader(string(body)))

	for {
		tokenType := tokenizer.Next()

		switch tokenType {
		case html.ErrorToken:
			return doc
		case html.SelfClosingTagToken, html.StartTagToken:
			token := tokenizer.Token()

			if token.Data == "link" {
				rel := ""
				href := ""
				for _, attr := range token.Attr {
					if attr.Key == "rel" {
						rel = attr.Val
					}
					if attr.Key == "href" {
						href = attr.Val
					}
				}
				if strings.Contains(rel, "icon") && doc.iconPath == "" {
					doc.iconPath = href
				}
			} else if token.Data == "title" {
				if tokenizer.Next() == html.TextToken {
					doc.Title = strings.ReplaceAll(tokenizer.Token().Data, "  ", "")
					doc.Title = strings.ReplaceAll(doc.Title, "\r", "")
					doc.Title = strings.ReplaceAll(doc.Title, "\n", "")
				}
			}
		}
	}
}

func Scrape(resp Result, timeout time.Duration) *DocumentPreview {
	doc := parseDocument(resp.Body)
	if doc == (DocumentPreview{}) {
		return nil
	}
	url := resp.Other.Request.URL.Scheme + "://" + resp.Other.Request.URL.Host + doc.iconPath
	//如果是独立地址
	if strings.HasPrefix(doc.iconPath, "http") {
		url = doc.iconPath
	} else if strings.HasPrefix(doc.iconPath, "//") {
		//如果是//exp.com地址
		url = resp.Other.Request.URL.Scheme + ":" + doc.iconPath
	} else if !strings.HasPrefix(doc.iconPath, "/") {
		// 如果是img.ico 则使用这种拼接
		url = resp.Other.Request.URL.Scheme + "://" + resp.Other.Request.URL.Host + "/" + doc.iconPath
	}
	request, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return &doc
	}
	sendHttp, err := SendHttp(request, timeout, true)
	if err != nil {
		return &doc
	}
	if sendHttp.Other.Body != nil {
		sendHttp.Other.Body.Close()
	}
	if sendHttp.Other.StatusCode != http.StatusOK {
		return &doc
	}
	iconType := http.DetectContentType(sendHttp.Body)
	if strings.HasSuffix(doc.iconPath, ".svg") {
		doc.Icon = "data:image/svg+xml;base64," + base64.StdEncoding.EncodeToString(sendHttp.Body)
	} else if strings.Contains(iconType, "image/") {
		doc.Icon = "data:" + iconType + ";base64," + base64.StdEncoding.EncodeToString(sendHttp.Body)
	}
	return &doc
}

var (
	charsets = []string{"utf-8", "gbk", "gb2312", "latin1", "iso-8859-1"}
)

// TransCode 转码
func TransCode(body []byte, encode string) string {
	if strings.Contains(strings.ToLower(encode), "gb") {
		O := transform.NewReader(bytes.NewReader(body), simplifiedchinese.GBK.NewDecoder())
		decoder, err := io.ReadAll(O)
		if err == nil {
			body = decoder
		}
	} else if strings.Contains(strings.ToLower(encode), "iso-8859-1") || strings.Contains(strings.ToLower(encode), "latin1") {
		decoder, _, err := transform.Bytes(charmap.Windows1252.NewEncoder(), body)
		if err == nil {
			body = decoder
		}
	}
	return html.UnescapeString(string(body))
}

func GetEncoding(contentType string, body []byte) string {
	r1, err := regexp.Compile(`(?im)charset=\s*?([\w-]+)`)
	if err != nil {
		return ""
	}
	headerCharset := r1.FindString(contentType)
	if headerCharset != "" {
		for _, v := range charsets {
			if strings.Contains(strings.ToLower(headerCharset), v) {
				return v
			}
		}
	}

	r2, err := regexp.Compile(`(?im)<meta.*?charset=['"]?([\w-]+)["']?.*?>`)
	if err != nil {
		return ""
	}
	htmlCharset := r2.FindString(string(body))
	if htmlCharset != "" {
		for _, v := range charsets {
			if strings.Contains(strings.ToLower(htmlCharset), v) {
				return v
			}
		}
	}
	return "utf-8"
}
