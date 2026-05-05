package netUtils

import (
	"io"
	"net"
	"strings"
	"time"

	"github.com/tjfoc/gmsm/gmtls"
)

func TlsSend(protocol string, ip string, data []byte, duration time.Duration) (response []byte, err error) {

	conn, err := net.DialTimeout(strings.ToLower(protocol), ip, duration)
	if err != nil {
		return nil, err
	}

	gmConn := gmtls.Client(conn, &gmtls.Config{
		InsecureSkipVerify: true, ServerName: "60.172.145.140",
	})

	_ = gmConn.SetDeadline(time.Now().Add(duration))

	err = gmConn.Handshake()
	if err != nil {
		conn.Close()
		return nil, err
	}

	defer gmConn.Close()
	return tlsReadWrite(gmConn, data)
}

// tlsReadWrite 通过TLS连接发送数据并读取响应
func tlsReadWrite(conn net.Conn, data []byte) (response []byte, err error) {
	_, err = conn.Write(data)
	if err != nil {
		return nil, err
	}

	buff := make([]byte, 4096)

	for {
		n, err := conn.Read(buff)

		if n > 0 {
			response = append(response, buff[:n]...)
		}

		if err != nil {
			if err == io.EOF {
				break
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

	// 👉 尝试半关闭（对部分协议很关键，比如HTTP/1.0风格）
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		_ = tcpConn.CloseWrite()
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
