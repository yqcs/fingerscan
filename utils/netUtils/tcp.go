package netUtils

import (
	"crypto/tls"
	"net"
	"strings"
	"time"

	"github.com/tjfoc/gmsm/gmtls"
)

// newGMTLSConn 创建国密TLS连接（必须新建TCP连接，不能复用标准TLS失败后的脏连接）
func newGMTLSConn(protocol string, ip string, duration time.Duration) (net.Conn, error) {
	conn, err := net.DialTimeout(strings.ToLower(protocol), ip, duration)
	if err != nil {
		return nil, err
	}
	tlsConn := gmtls.Client(conn, &gmtls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
		CurvePreferences: []gmtls.CurveID{
			gmtls.CurveP256,
			gmtls.CurveP384,
			gmtls.CurveP521,
			gmtls.X25519,
		},
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		},
	})
	if err = tlsConn.Handshake(); err != nil {
		conn.Close()
		return nil, err
	}
	return tlsConn, nil
}

func TlsSend(protocol string, ip string, data []byte, duration time.Duration) (response []byte, err error) {

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
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		},
	})

	_ = tlsConn.SetDeadline(time.Now().Add(duration))
	response, err = tlsReadWrite(tlsConn, data)

	if err != nil && isTLSError(err.Error()) {
		//标准TLS失败，关闭旧连接，新建国密TLS连接重试
		conn.Close()
		gmConn, gmErr := newGMTLSConn(protocol, ip, duration)
		if gmErr != nil {
			return nil, err
		}
		defer gmConn.Close()
		_ = gmConn.SetDeadline(time.Now().Add(duration))
		response, err = tlsReadWrite(gmConn, data)
	}
	return
}

// tlsReadWrite 通过TLS连接发送数据并读取响应
func tlsReadWrite(conn net.Conn, data []byte) (response []byte, err error) {
	_, err = conn.Write(data)
	if err != nil {
		return nil, err
	}
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
		}
	}
	return response, nil
}

func TcpSend(protocol string, ip string, data []byte, duration time.Duration) (response []byte, err error) {
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
