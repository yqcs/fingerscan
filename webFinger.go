package fingerscan

import (
	"bytes"
	"encoding/json"
	"golang.org/x/net/html"
	"regexp"
	"strings"
	"unsafe"
)

type Wappalyze struct {
	Apps map[string]*Fingerprint `json:"apps"`
}

// Fingerprint is a single piece of information about a tech validated and normalized
type Fingerprint struct {
	Cookies map[string]string   `json:"cookies"`
	Headers map[string]string   `json:"headers"`
	HTML    []string            `json:"html"`
	Script  []string            `json:"scripts"`
	Meta    map[string][]string `json:"meta"`
	Implies []string            `json:"implies"`
	// Precompiled patterns
	CompiledCookies map[string]*regexp.Regexp
	CompiledHeaders map[string]*regexp.Regexp
	CompiledHTML    []*regexp.Regexp
	CompiledScript  []*regexp.Regexp
	CompiledMeta    map[string][]*regexp.Regexp
}

// part is the part of the fingerprint to match
type part int

// parts that can be matched
const (
	cookiesPart part = iota + 1
	jsPart
	headersPart
	htmlPart
	scriptPart
	metaPart
)

// matchString 匹配指纹的字符串
func (s *Wappalyze) matchString(data string, part part) []string {
	var matched bool
	var technologies []string

	for app, fingerprint := range s.Apps {
		switch part {
		case scriptPart:
			for _, reg := range fingerprint.CompiledScript {
				if reg != nil && reg.MatchString(data) {
					matched = true
				}
			}
		case htmlPart:
			for _, reg := range fingerprint.CompiledHTML {
				if reg != nil && reg.MatchString(data) {
					matched = true
				}
			}
		}

		if !matched {
			continue
		}

		technologies = append(technologies, app)
		if len(fingerprint.Implies) > 0 {
			technologies = append(technologies, fingerprint.Implies...)
		}
		matched = false
	}
	return technologies
}

// matchKeyValue matches a key-value store map for the fingerprints
func (s *Wappalyze) matchKeyValueString(key, value string, part part) []string {
	var matched bool
	var technologies []string

	for app, fingerprint := range s.Apps {
		switch part {
		case cookiesPart:
			if reg, ok := fingerprint.CompiledCookies[key]; ok && reg != nil && reg.MatchString(value) {
				matched = true
			}
		case headersPart:
			if reg, ok := fingerprint.CompiledHeaders[key]; ok && reg != nil && reg.MatchString(value) {
				matched = true
			}
		case metaPart:
			if regList, ok := fingerprint.CompiledMeta[key]; ok {
				for _, reg := range regList {
					if reg != nil && reg.MatchString(value) {
						matched = true
						break
					}
				}
			}
		}

		if !matched {
			continue
		}
		technologies = append(technologies, app)
		technologies = append(technologies, fingerprint.Implies...)
		matched = false
	}
	return technologies
}

// matchMapString matches a key-value store map for the fingerprints
func (s *Wappalyze) matchMapString(keyValue map[string]string, part part) []string {
	var matched bool
	var technologies []string
	for app, fingerprint := range s.Apps {
		switch part {
		case cookiesPart:
			for key, reg := range fingerprint.CompiledCookies {
				if value, ok := keyValue[key]; ok && reg != nil && reg.MatchString(value) {
					matched = true
					break
				}
			}
		case headersPart:
			for key, reg := range fingerprint.CompiledHeaders {
				if value, ok := keyValue[strings.ToLower(key)]; ok && reg != nil && reg.MatchString(value) {
					matched = true
					break
				}
			}
		case metaPart:
			for key, regList := range fingerprint.CompiledMeta {
				if value, ok := keyValue[key]; ok {
					for _, reg := range regList {
						if reg != nil && reg.MatchString(value) {
							matched = true
							break
						}
					}
				}
			}
		}

		if !matched {
			continue
		}

		technologies = append(technologies, app)
		if len(fingerprint.Implies) > 0 {
			technologies = append(technologies, fingerprint.Implies...)
		}
		matched = false
	}
	return technologies
}

func (s *Wappalyze) checkBody(body []byte) []string {
	var technologies []string

	bodyString := unsafeToString(body)

	technologies = append(
		technologies,
		s.matchString(bodyString, htmlPart)...,
	)

	tokenizer := html.NewTokenizer(bytes.NewReader(body))

	for {
		tt := tokenizer.Next()
		switch tt {
		case html.ErrorToken:
			return technologies
		case html.StartTagToken:
			token := tokenizer.Token()
			switch token.Data {
			case "meta":
				name, content, found := getMetaNameAndContent(token)
				if !found {
					continue
				}
				technologies = append(
					technologies,
					s.matchKeyValueString(name, content, metaPart)...,
				)
			}
		case html.SelfClosingTagToken:
			token := tokenizer.Token()
			if token.Data != "meta" {
				continue
			}

			name, content, found := getMetaNameAndContent(token)
			if !found {
				continue
			}
			technologies = append(
				technologies,
				s.matchKeyValueString(name, content, metaPart)...,
			)
		}
	}
}

// getMetaNameAndContent gets name and content attributes from meta html token
func getMetaNameAndContent(token html.Token) (string, string, bool) {
	if len(token.Attr) < keyValuePairLength {
		return "", "", false
	}

	var name, content string
	for _, attr := range token.Attr {
		switch attr.Key {
		case "name":
			name = attr.Val
		case "content":
			content = attr.Val
		}
	}
	return name, content, true
}

func unsafeToString(data []byte) string {
	return *(*string)(unsafe.Pointer(&data))
}

const keyValuePairLength = 2

func (s *Wappalyze) normalizeCookies(cookies []string) map[string]string {
	normalized := make(map[string]string)

	for _, part := range cookies {
		parts := strings.SplitN(strings.Trim(part, " "), "=", keyValuePairLength)
		if len(parts) < keyValuePairLength {
			continue
		}
		normalized[parts[0]] = parts[1]
	}
	return normalized
}

// findSetCookie finds the set cookie header from the normalized headers
func (s *Wappalyze) findSetCookie(headers map[string]string) []string {
	value, ok := headers["set-cookie"]
	if !ok {
		return nil
	}
	cookies := strings.Split(value, ";")
	return cookies
}

// normalizeHeaders 对标头上的技术发现的标头进行规范化
func (s *Wappalyze) normalizeHeaders(headers map[string][]string) map[string]string {
	normalized := make(map[string]string, len(headers))
	for header, value := range getHeadersMap(headers) {
		normalized[strings.ToLower(header)] = value
	}
	return normalized
}

// getHeadersMap 获取响应头的header
func getHeadersMap(headersArray map[string][]string) map[string]string {
	headers := make(map[string]string, len(headersArray))
	builder := &strings.Builder{}
	for key, value := range headersArray {
		for i, v := range value {
			builder.WriteString(v)
			if i != len(value)-1 {
				builder.WriteString(", ")
			}
		}
		headers[key] = builder.String()
		builder.Reset()
	}
	return headers
}

// initWappalyze
func (init *InitProbe) initWappalyze() {
	webapp := &Wappalyze{
		Apps: make(map[string]*Fingerprint),
	}
	if err := webapp.loadFingerprints(); err == nil {
		init.wappalyze = *webapp
	}
}

func stripVersionSuffix(pattern string) string {
	if idx := strings.Index(pattern, `\;version:`); idx != -1 {
		return pattern[:idx]
	}
	return pattern
}

func compilePatternMap(patterns map[string]string) map[string]*regexp.Regexp {
	compiled := make(map[string]*regexp.Regexp, len(patterns))
	for key, pattern := range patterns {
		pattern = stripVersionSuffix(pattern)
		if reg, err := regexp.Compile(pattern); err == nil {
			compiled[key] = reg
		}
	}
	return compiled
}

func compilePatternSlice(patterns []string) []*regexp.Regexp {
	compiled := make([]*regexp.Regexp, 0, len(patterns))
	for _, pattern := range patterns {
		pattern = stripVersionSuffix(pattern)
		if reg, err := regexp.Compile(pattern); err == nil {
			compiled = append(compiled, reg)
		}
	}
	return compiled
}

func compilePatternMapSlice(patterns map[string][]string) map[string][]*regexp.Regexp {
	compiled := make(map[string][]*regexp.Regexp, len(patterns))
	for key, patternList := range patterns {
		compiled[key] = compilePatternSlice(patternList)
	}
	return compiled
}

func (s *Wappalyze) loadFingerprints() error {
	fingerprintsStruct := Wappalyze{}
	data, _ := temp.ReadFile("data/web-finger.json")
	err := json.Unmarshal(data, &fingerprintsStruct)
	if err != nil {
		return err
	}
	for i, fingerprint := range fingerprintsStruct.Apps {
		s.Apps[i] = fingerprint
		s.Apps[i].CompiledCookies = compilePatternMap(fingerprint.Cookies)
		s.Apps[i].CompiledHeaders = compilePatternMap(fingerprint.Headers)
		s.Apps[i].CompiledHTML = compilePatternSlice(fingerprint.HTML)
		s.Apps[i].CompiledScript = compilePatternSlice(fingerprint.Script)
		s.Apps[i].CompiledMeta = compilePatternMapSlice(fingerprint.Meta)
	}
	return nil
}

func (s *Wappalyze) Fingerprint(headers map[string][]string, body []byte) map[string]struct{} {
	apps := make(map[string]struct{})
	headerList := s.normalizeHeaders(headers)
	for _, application := range s.matchMapString(headerList, headersPart) {
		if _, ok := apps[application]; !ok {
			apps[application] = struct{}{}
		}
	}
	cookies := s.findSetCookie(headerList)
	if len(cookies) > 0 {
		for _, application := range s.matchMapString(s.normalizeCookies(cookies), cookiesPart) {
			if _, ok := apps[application]; !ok {
				apps[application] = struct{}{}
			}
		}
	}
	for _, application := range s.checkBody(body) {
		if _, ok := apps[application]; !ok {
			apps[application] = struct{}{}
		}
	}
	return apps
}
