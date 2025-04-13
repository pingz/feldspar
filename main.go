package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/kevinburke/ssh_config"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// SSHConfig 保存 SSH 连接的配置
type SSHConfig struct {
	User           string
	Host           string
	Port           string
	PrivateKey     string
	PrivateKeyPath string // 新增私钥路径字段
	ProxyJump      string
}

type ForwardConfig struct {
	Forwards []ForwardRule `toml:"forward"`
}

type ForwardRule struct {
	RemoteHost string `toml:"remote_host"`
	RemotePort string `toml:"remote_port"`
	LocalPort  string `toml:"local_port"`
	SshHost    string `toml:"ssh_host"`
	Timeout    int    `toml:"timeout"`
}

// GetPort 从配置中获取指定主机的端口号
func GetPort(cfg *ssh_config.Config, host string) (string, error) {
	port, err := cfg.Get(host, "Port")
	if err != nil {
		return "", fmt.Errorf("failed to get port for host %s: %v", host, err)
	}

	if port == "" {
		port = "22"
	}

	portNum, err := strconv.Atoi(port)
	if err != nil {
		return "", fmt.Errorf("invalid port: %s", port)
	}

	if portNum < 22 || portNum > 65535 {
		return "", fmt.Errorf("port number out of range: %d", portNum)
	}

	return port, nil
}

// getSSHConfigValue 从配置中获取指定键的值
func getSSHConfigValue(cfg *ssh_config.Config, host, key string) (string, error) {
	value, err := cfg.Get(host, key)
	if err != nil {
		return "", fmt.Errorf("failed to get %s for host %s: %v", key, host, err)
	}
	if value == "" {
		return "", fmt.Errorf("%s for host %s is empty", key, host)
	}
	return value, nil
}

// validatePrivateKeyFile 检查私钥文件是否存在且可读
func validatePrivateKeyFile(path string) error {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return fmt.Errorf("file does not exist: %s", path)
	}
	if err != nil {
		return fmt.Errorf("error accessing file: %v", err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("file is not a regular file: %s", path)
	}
	if info.Mode().Perm()&(1<<(uint(7))) == 0 {
		return fmt.Errorf("file is not readable: %s", path)
	}
	return nil
}

// getKeyPath 获取私钥文件的路径
func getKeyPath(cfg *ssh_config.Config, host string) (string, error) {
	privateKey, err := getSSHConfigValue(cfg, host, "IdentityFile")
	if err != nil {
		return "", err
	}
	cleanedPrivateKeyPath := filepath.Clean(privateKey)
	absPrivateKeyPath, err := filepath.Abs(cleanedPrivateKeyPath)
	if err != nil {
		return "", fmt.Errorf("failed to get absolute path: %v", err)
	}
	if err := validatePrivateKeyFile(absPrivateKeyPath); err != nil {
		return "", fmt.Errorf("failed to validate private key: %v", err)
	}
	return privateKey, nil
}

// getPassphrase 通过 ssh-askpass 获取加密密钥密码
func getPassphrase() (string, error) {
	askpass := os.Getenv("SSH_ASKPASS")
	if askpass == "" {
		return "", fmt.Errorf("SSH_ASKPASS 环境变量未设置")
	}
	cmd := exec.Command(askpass, "Enter passphrase for private key:")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("执行 ssh-askpass 失败: %v", err)
	}
	passphrase := strings.TrimSpace(string(output))
	log.Printf("成功从 ssh-askpass 获取密码")
	return passphrase, nil
}

// LoadSSHConfig 从 ~/.ssh/config 加载指定主机的 SSH 配置
func LoadSSHConfig(host string) (*SSHConfig, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get user home directory: %v", err)
	}

	configFile := filepath.Join(homeDir, ".ssh", "config")
	file, err := os.Open(configFile)
	if err != nil {
		return nil, fmt.Errorf("failed to open SSH config file: %v", err)
	}
	defer file.Close()

	cfg, err := ssh_config.Decode(file)
	if err != nil {
		return nil, fmt.Errorf("failed to decode SSH config file: %v", err)
	}
	log.Printf("Loaded SSH config file: %s", configFile)

	sshConfig := &SSHConfig{
		Port: "22",
	}

	user, err := getSSHConfigValue(cfg, host, "User")
	if err != nil {
		return nil, err
	}
	log.Printf("Using user: %s", user)
	sshConfig.User = user

	hostname, err := getSSHConfigValue(cfg, host, "Hostname")
	if err != nil {
		return nil, err
	}
	log.Printf("Using hostname: %s", hostname)

	sshConfig.Host = hostname

	port, err := GetPort(cfg, host)
	if err != nil {
		return nil, err
	}
	log.Printf("Using port: %s", port)
	sshConfig.Port = port

	privateKeyPath, err := getKeyPath(cfg, host)
	if err != nil {
		return nil, err
	}
	log.Printf("Using private key: %s", privateKeyPath)
	privateKeyBytes, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file: %v", err)
	}
	sshConfig.PrivateKey = string(privateKeyBytes)
	sshConfig.PrivateKeyPath = privateKeyPath // 保存私钥路径
	privateKeyBytes = nil

	proxyJump, err := getSSHConfigValue(cfg, host, "ProxyJump")
	if err == nil {
		sshConfig.ProxyJump = proxyJump
	}

	return sshConfig, nil
}

// getPublicKey 获取私钥对应的公钥
func getPublicKey(privateKeyPath string) (ssh.PublicKey, error) {
	// 尝试读取同名的.pub文件
	pubKeyPath := privateKeyPath + ".pub"
	pubKeyBytes, err := os.ReadFile(pubKeyPath)
	if err == nil {
		pubKey, _, _, _, err := ssh.ParseAuthorizedKey(pubKeyBytes)
		if err != nil {
			return nil, fmt.Errorf("解析公钥文件失败: %v", err)
		}
		return pubKey, nil
	}

	// 从私钥内容解析公钥
	privateKeyBytes, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("读取私钥失败: %v", err)
	}

	// 尝试解析未加密的私钥
	signer, err := ssh.ParsePrivateKey(privateKeyBytes)
	if err == nil {
		return signer.PublicKey(), nil
	}

	// 处理加密私钥
	if strings.Contains(err.Error(), "passphrase") {
		// 尝试环境变量密码
		passcode := os.Getenv("SSH_PASSCODE")
		if passcode != "" {
			signer, err := ssh.ParsePrivateKeyWithPassphrase(privateKeyBytes, []byte(passcode))
			if err == nil {
				return signer.PublicKey(), nil
			}
		}

		// 尝试通过ssh-askpass获取密码
		passphrase, err := getPassphrase()
		if err == nil {
			signer, err := ssh.ParsePrivateKeyWithPassphrase(privateKeyBytes, []byte(passphrase))
			if err == nil {
				return signer.PublicKey(), nil
			}
		}
	}

	return nil, fmt.Errorf("无法获取公钥: %v", err)
}

// getAgentSigners 从SSH Agent获取匹配的签名器
func getAgentSigners(privateKeyPath string) ([]ssh.Signer, error) {
	agentConn, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK"))
	if err != nil {
		return nil, fmt.Errorf("连接SSH Agent失败: %v", err)
	}
	// defer agentConn.Close()

	agentClient := agent.NewClient(agentConn)
	agentSigners, err := agentClient.Signers()
	if err != nil {
		return nil, fmt.Errorf("获取Agent签名器失败: %v", err)
	}

	// 获取目标公钥
	targetPubKey, err := getPublicKey(privateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("无法获取目标公钥: %v", err)
	}

	// 匹配公钥
	var matched []ssh.Signer
	for _, s := range agentSigners {
		if bytes.Equal(s.PublicKey().Marshal(), targetPubKey.Marshal()) {
			matched = append(matched, s)
		}
	}
	if len(matched) == 0 {
		return nil, fmt.Errorf("Agent中未找到匹配的公钥")
	}
	return matched, nil
}

// createSigners 创建 SSH 签名器（优先使用Agent）
func createSigners(sshConfig *SSHConfig) ([]ssh.Signer, error) {
	// 1. 优先尝试从SSH Agent获取匹配的签名器
	if agentSigners, err := getAgentSigners(sshConfig.PrivateKeyPath); err == nil {
		log.Printf("从SSH Agent获取到%d个匹配的签名器", len(agentSigners))
		return agentSigners, nil
	} else {
		log.Printf("SSH Agent未提供匹配签名器: %v", err)
	}

	// 2. 回退到加载私钥文件
	privateKeyBytes := []byte(sshConfig.PrivateKey)

	// 尝试无密码解析
	parsedKey, err := ssh.ParseRawPrivateKey(privateKeyBytes)
	if err == nil {
		signer, err := ssh.NewSignerFromKey(parsedKey)
		if err != nil {
			log.Printf("无法创建签名器: %v", err)
		} else {
			log.Printf("成功加载未加密私钥")
			return []ssh.Signer{signer}, nil
		}
	}

	// 处理加密私钥
	if strings.Contains(err.Error(), "passphrase") {
		// 尝试环境变量密码
		if passcode := os.Getenv("SSH_PASSCODE"); passcode != "" {
			parsedKey, err := ssh.ParseRawPrivateKeyWithPassphrase(privateKeyBytes, []byte(passcode))
			if err == nil {
				signer, _ := ssh.NewSignerFromKey(parsedKey)
				return []ssh.Signer{signer}, nil
			}
		}

		// 尝试ssh-askpass
		passphrase, err := getPassphrase()
		if err == nil {
			parsedKey, err := ssh.ParseRawPrivateKeyWithPassphrase(privateKeyBytes, []byte(passphrase))
			if err == nil {
				signer, _ := ssh.NewSignerFromKey(parsedKey)
				return []ssh.Signer{signer}, nil
			}
		}
	}

	// 所有方式失败
	return nil, fmt.Errorf("无法加载私钥")
}

// createSSHClient 创建 SSH 客户端
func createSSHClient(sshConfig *SSHConfig, timeout time.Duration) (*ssh.Client, error) {
	signers, err := createSigners(sshConfig) // 此处改为传入整个配置
	if err != nil {
		return nil, fmt.Errorf("failed to create signers: %v", err)
	}

	config := &ssh.ClientConfig{
		User: sshConfig.User,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signers...),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         timeout,
	}

	dialer := &net.Dialer{Timeout: timeout}
	tcpConn, err := dialer.Dial("tcp", net.JoinHostPort(sshConfig.Host, sshConfig.Port))
	if err != nil {
		return nil, fmt.Errorf("SSH dial failed (%s:%s): %v", sshConfig.Host, sshConfig.Port, err)
	}

	sshConn, chans, reqs, err := ssh.NewClientConn(tcpConn, net.JoinHostPort(sshConfig.Host, sshConfig.Port), config)
	if err != nil {
		tcpConn.Close() // 关闭连接以防止资源泄漏
		return nil, fmt.Errorf("SSH handshake failed: %v", err)
	}

	return ssh.NewClient(sshConn, chans, reqs), nil
}

// createSSHClientRecursive 递归创建 SSH 客户端，支持多层 ProxyJump
func createSSHClientRecursive(sshConfig *SSHConfig, timeout time.Duration, depth int) (*ssh.Client, error) {
	if depth > 3 {
		return nil, fmt.Errorf("maximum proxy jump depth exceeded")
	}

	if sshConfig.ProxyJump == "" {
		return createSSHClient(sshConfig, timeout)
	}

	proxyConfig, err := LoadSSHConfig(sshConfig.ProxyJump)
	if err != nil {
		return nil, fmt.Errorf("failed to load proxy jump config: %v", err)
	}

	proxyClient, err := createSSHClientRecursive(proxyConfig, timeout, depth+1)
	if err != nil {
		return nil, fmt.Errorf("failed to create proxy jump client: %v", err)
	}

	conn, err := proxyClient.Dial("tcp", net.JoinHostPort(sshConfig.Host, sshConfig.Port))
	if err != nil {
		return nil, fmt.Errorf("failed to dial through proxy jump: %v", err)
	}
	// TODO need to release?
	// defer conn.Close()

	signers, err := createSigners(sshConfig) // 此处改为传入整个配置
	if err != nil {
		return nil, fmt.Errorf("failed to create signers: %v", err)
	}

	sshConn, chans, reqs, err := ssh.NewClientConn(
		conn, net.JoinHostPort(sshConfig.Host, sshConfig.Port),
		&ssh.ClientConfig{
			User: sshConfig.User,
			Auth: []ssh.AuthMethod{
				ssh.PublicKeys(signers...),
			},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Timeout:         timeout,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to establish SSH connection through proxy jump: %v", err)
	}

	client := ssh.NewClient(sshConn, chans, reqs)
	// // 包装客户端以保持代理连接存活
	// return &ssh.Client{
	// 	Conn: client.Conn,
	// 	Channel: client.Channel,
	// 	Channels: client.Channels,
	// 	Requests: client.Requests,
	// }, nil
	return client, nil
}

// ForwardProxy 启动本地代理，通过 SSH 将流量转发到远程服务器
func ForwardProxy(localPort, remoteHost, remotePort string, sshConfig *SSHConfig, timeout time.Duration) error {
	sshClient, err := createSSHClientRecursive(sshConfig, timeout, 0)
	if err != nil {
		return err
	}
	defer sshClient.Close()

	listener, err := net.Listen("tcp", ":"+localPort)
	if err != nil {
		return fmt.Errorf("failed to listen on local port %s: %v", localPort, err)
	}
	defer func() {
		if err := listener.Close(); err != nil {
			log.Printf("Error closing listener (port %s): %v", localPort, err)
		}
	}()

	log.Printf("Forwarding started: localhost:%s -> %s:%s via %s",
		localPort, remoteHost, remotePort, sshConfig.Host)

	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			if _, _, err := sshClient.SendRequest("keepalive@feldspar", true, nil); err != nil {
				log.Printf("Health check failed, attempting to reconnect: %v", err)
				sshClient.Close()
				sshClient, err = createSSHClientRecursive(sshConfig, timeout, 0)
				if sshClient == nil {
					log.Printf("Reconnect failed: cannot create new client")
					continue
				}
				if err != nil {
					log.Printf("Reconnect failed: %v", err)
					continue
				}
				log.Printf("Reconnected successfully")
			}
		}
		// 防止goroutine泄漏
		return
	}()

	for {
		localConn, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				// listener已关闭，正常退出
				return nil
			}
			log.Printf("Accept error (port %s): %v", localPort, err)
			continue
		}

		go func(localConn net.Conn) {
			defer localConn.Close()

			remoteConn, err := sshClient.Dial("tcp", net.JoinHostPort(remoteHost, remotePort))
			if err != nil {
				log.Printf("Remote dial failed (%s:%s): %v", remoteHost, remotePort, err)
				return
			}
			defer remoteConn.Close()

			go func() {
				_, err := io.Copy(remoteConn, localConn)
				if err != nil && !errors.Is(err, io.EOF) {
					log.Printf("Local->Remote copy error (%s): %v", localPort, err)
				}
			}()

			_, err = io.Copy(localConn, remoteConn)
			if err != nil && !errors.Is(err, io.EOF) {
				log.Printf("Remote->Local copy error (%s): %v", localPort, err)
			}
		}(localConn)
	}
}

func main() {
	logFile, err := os.OpenFile("ssh_forward.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("Failed to open log file: %v", err)
	}
	defer logFile.Close()
	log.SetOutput(logFile)

	var config struct {
		Forward ForwardConfig `toml:"forward_config"`
	}

	if _, err := toml.DecodeFile("forward_config.toml", &config); err != nil {
		log.Fatalf("Error decoding TOML file: %v", err)
	}

	var wg sync.WaitGroup
	for _, rule := range config.Forward.Forwards {
		wg.Add(1)
		go func(r ForwardRule) {
			defer wg.Done()

			sshConfig, err := LoadSSHConfig(r.SshHost)
			if err != nil {
				log.Printf("Failed to load SSH config for %s: %v", r.SshHost, err)
				return
			}

			timeout := time.Duration(r.Timeout) * time.Second
			err = ForwardProxy(
				r.LocalPort, r.RemoteHost, r.RemotePort, sshConfig,
				timeout,
			)
			if err != nil {
				log.Printf("Forwarding failed for %s:%s: %v", r.RemoteHost, r.RemotePort, err)
			}
		}(rule)
	}

	wg.Wait()
}
