package fingerscan

import (
	"math/rand"
	"strconv"
	"strings"
	"time"
)

func ParsePort(ports string) (scanPorts []int) {
	if ports == "" {
		return
	}
	slices := strings.Split(ports, ",")
	for _, port := range slices {
		port = strings.Trim(port, " ")
		upper := port
		if strings.Contains(port, "-") {
			ranges := strings.Split(port, "-")
			if len(ranges) < 2 {
				continue
			}

			startPort, _ := strconv.Atoi(ranges[0])
			endPort, _ := strconv.Atoi(ranges[1])
			if startPort < endPort {
				port = ranges[0]
				upper = ranges[1]
			} else {
				port = ranges[1]
				upper = ranges[0]
			}

		}
		start, _ := strconv.Atoi(port)
		end, _ := strconv.Atoi(upper)
		for i := start; i <= end; i++ {
			scanPorts = append(scanPorts, i)
		}
	}
	scanPorts = IntSliceRemoveDuplicates(scanPorts)
	return scanPorts
}

func IntSliceRemoveDuplicates(slice []int) (result []int) {
	tempData := map[int]struct{}{}
	for _, item := range slice {
		if _, ok := tempData[item]; !ok {
			tempData[item] = struct{}{}
			result = append(result, item)
		}
	}
	return result
}
func IntSliceContains(sl []int, v int) bool {
	for _, vv := range sl {
		if vv == v {
			return true
		}
	}
	return false
}
func ConvResponse(b []byte) string {
	var r1 []rune
	for _, i := range b {
		r1 = append(r1, rune(i))
	}
	return string(r1)
}

func RandomString(n int) string {
	randSource := rand.New(rand.NewSource(time.Now().Unix()))
	const (
		letterIdxBits = 6
		letterIdxMask = 1<<letterIdxBits - 1
		letterIdxMax  = 63 / letterIdxBits
		letterBytes   = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	)
	randBytes := make([]byte, n)
	for i, cache, remain := n-1, randSource.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = randSource.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			randBytes[i] = letterBytes[idx]
			i--
		}
		cache >>= letterIdxBits
		remain--
	}
	return string(randBytes)
}
func SliceRemoveDuplicates(slice []string) (result []string) {
	tempData := map[string]struct{}{}
	for _, item := range slice {
		if _, ok := tempData[item]; !ok {
			tempData[item] = struct{}{}
			result = append(result, item)
		}
	}
	return result
}
func DeleteSliceValueToLower(list []string, value string) []string {
	for i := 0; i < len(list); i++ {
		if strings.ToLower(list[i]) == strings.ToLower(value) {
			list = append(list[:i], list[i+1:]...)
		}
	}
	return list
}
