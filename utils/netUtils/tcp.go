package netUtils

import (
	"io"
	"net"
	"strings"
	"time"

	"github.com/tjfoc/gmsm/gmtls"
)

func TlsSend(addr string, data []byte, duration time.Duration) ([]byte, error) {

	cfg := &gmtls.Config{InsecureSkipVerify: true}

	conn, err := gmtls.Dial("tcp", addr, cfg)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(duration))

	// ===== write =====
	if _, err = conn.Write(data); err != nil {
		return nil, err
	}

	// ===== read =====
	buff := make([]byte, 4096)
	var response []byte

	for {
		_ = conn.SetReadDeadline(time.Now().Add(duration))
		n, err := conn.Read(buff)

		if n > 0 {
			response = append(response, buff[:n]...)
		}

		if err != nil {
			if err == io.EOF {
				break
			}

			// 超时但已有数据 → 直接返回
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

func TcpSend(protocol string, ip string, data []byte, duration time.Duration) ([]byte, error) {
	conn, err := net.DialTimeout(strings.ToLower(protocol), ip, duration)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// 写超时
	_ = conn.SetWriteDeadline(time.Now().Add(duration))

	// 发送
	if _, err = conn.Write(data); err != nil {
		return nil, err
	}

	// 读超时（滚动）
	buf := make([]byte, 4096)
	var response []byte

	for {
		_ = conn.SetReadDeadline(time.Now().Add(duration))
		n, err := conn.Read(buf)

		if n > 0 {
			response = append(response, buf[:n]...)
		}

		if err != nil {
			// 正常结束
			if err == io.EOF {
				break
			}
			// 超时：如果已经有数据，就认为读完了
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

func Send(protocol string, addr string, data []byte, duration time.Duration) ([]byte, error) {

	protocol = strings.ToLower(protocol)

	var conn net.Conn
	var err error

	// ===== 1. 建立连接层 =====
	if protocol == "ssl" {
		conn, err = gmtls.Dial("tcp", addr, &gmtls.Config{InsecureSkipVerify: true})
		if err != nil {
			return nil, err
		}
	} else {
		conn, err = net.DialTimeout(protocol, addr, duration)
		if err != nil {
			return nil, err
		}
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
