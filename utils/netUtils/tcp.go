package netUtils

import (
	"crypto/tls"
	"io"
	"net"
	"strings"
	"time"

	"github.com/hxx258456/ccgo/gmtls"
)

func Send(protocol string, addr string, data []byte, duration time.Duration) ([]byte, error) {

	protocol = strings.ToLower(protocol)

	var conn net.Conn
	var err error

	// ===== 1. 建立连接层 =====
	if protocol == "ssl" {
		conn, err = gmtls.Dial("tcp", addr, &gmtls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS13})
	} else {
		conn, err = net.DialTimeout(protocol, addr, duration)
	}
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(duration))

	// ===== 2. write =====
	if _, err = conn.Write(data); err != nil {
		return nil, err
	}

	// ===== 3. read =====
	buf := make([]byte, 4096)
	var response []byte

	for {
		_ = conn.SetReadDeadline(time.Now().Add(duration))
		n, err := conn.Read(buf)

		if n > 0 {
			response = append(response, buf[:n]...)
		}

		if err != nil {
			if err == io.EOF {
				break
			}

			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				if len(response) > 0 {
					break
				}
			}

			return response, err
		}
	}

	return response, nil
}
