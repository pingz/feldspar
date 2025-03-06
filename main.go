package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"time"
	"sync"

	"github.com/BurntSushi/toml"
	"github.com/kevinburke/ssh_config"
	"golang.org/x/crypto/ssh"
)

// SSHConfig holds the configuration for the SSH connection
type SSHConfig struct {
	User       string
	Host       string
	Port       string
	PrivateKey string
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

// GetPort retrieves the port number for the given host from the configuration.
// It returns an error if the port is not a valid number between 22 and 65535.
func GetPort(cfg *ssh_config.Config, host string) (string, error) {
	// Try to get the port from the configuration.
	port, err := cfg.Get(host, "Port")
	if err != nil {
		return "", fmt.Errorf("failed to get port for host %s: %v", host, err)
	}

	// If no port is specified, use the default port 22.
	if port == "" {
		port = "22"
	}

	// Convert the port to an integer.
	portNum, err := strconv.Atoi(port)
	if err != nil {
		return "", fmt.Errorf("invalid port: %s", port)
	}

	// Validate the port number.
	if portNum < 22 || portNum > 65535 {
		return "", fmt.Errorf("port number out of range: %d", portNum)
	}

	return port, nil
}

// getSSHConfigValue 从 cfg 中获取指定键的值，并进行错误处理和空值校验
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

// validatePrivateKeyFile checks if the file exists and is readable.
// It returns an error if the file is invalid, otherwise it returns nil.
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
	// Check if the file is readable
	if info.Mode().Perm()&(1<<(uint(7))) == 0 {
		return fmt.Errorf("file is not readable: %s", path)
	}
	// If everything is fine, return nil
	return nil
}

// getKeyPath extracts and returns the path to the private key file.
func getKeyPath(cfg *ssh_config.Config, host string) (string, error) {
	// 假设私钥路径在配置中的键为 "KeyPath"
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

// LoadSSHConfig loads the SSH configuration from ~/.ssh/config for a given host
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
		Port: "22", // Default SSH port
	}
	// 使用辅助函数获取并设置 User
	var user string
	user, err = getSSHConfigValue(cfg, host, "User")
	if err != nil {
		return nil, err
	}
	log.Printf("Using user: %s", user)
	sshConfig.User = user

	// 使用辅助函数获取并设置 Hostname
	hostname, err := getSSHConfigValue(cfg, host, "Hostname")
	if err != nil {
		return nil, err
	}
	log.Printf("Using hostname: %s", hostname)

	sshConfig.Host = hostname
	// 使用辅助函数获取并设置 Port（允许为空，默认值为 "22"）
	port, err := GetPort(cfg, host)
	if err != nil {
		return nil, err
	}
	log.Printf("Using port: %s", port)
	sshConfig.Port = port

	// 使用辅助函数获取并设置 privateKey
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
	privateKeyBytes = nil
	return sshConfig, nil
}

// ForwardProxy starts a local proxy that forwards traffic to the remote server via SSH
func ForwardProxy(localPort, remoteHost, remotePort string, sshConfig *SSHConfig, timeout time.Duration) error {
	var signer ssh.Signer
	var err error
	passphrase := os.Getenv("SSH_PASSCODE")
	if passphrase != "" {
		// Parse the OpenSSH private key with passphrase
		parsedKey, err := ssh.ParseRawPrivateKeyWithPassphrase([]byte(sshConfig.PrivateKey), []byte(passphrase))
		if err != nil {
			return fmt.Errorf("unable to parse raw private key with passphrase: %v", err)
		}
		signer, err = ssh.NewSignerFromKey(parsedKey)
		if err != nil {
			return fmt.Errorf("unable to parse raw private key: %v", err)
		}
	} else {
		// Parse the OpenSSH private key without passphrase
		parsedKey, err := ssh.ParseRawPrivateKey([]byte(sshConfig.PrivateKey))
		if err != nil {
			return fmt.Errorf("unable to parse raw private key: %v", err)
		}
		signer, err = ssh.NewSignerFromKey(parsedKey)
		if err != nil {
			return fmt.Errorf("unable to parse raw private key: %v", err)
		}
	}

	// SSH client configuration
	config := &ssh.ClientConfig{
		User: sshConfig.User,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // Insecure: Use for testing only
		Timeout:         timeout,                     // Timeout for the SSH handshake
	}

	// Create a custom dialer with the tcp timeout
	dialer := &net.Dialer{
		Timeout: timeout,
	}
	// Establish a TCP connection with the custom dialer
	tcpConn, err := dialer.Dial("tcp", net.JoinHostPort(sshConfig.Host, sshConfig.Port))
	if err != nil {
		log.Fatalf("unable to connect to TCP server: %v", err)
	}
	defer tcpConn.Close()
	// Create an SSH client connection using the established TCP connection
	sshConn, chans, reqs, err := ssh.NewClientConn(tcpConn, net.JoinHostPort(sshConfig.Host, sshConfig.Port), config)
	if err != nil {
		log.Fatalf("unable to create SSH client connection: %v", err)
	}
	// Connect to the SSH server
	sshClient := ssh.NewClient(sshConn, chans, reqs)
	defer sshClient.Close()

	// Start listening on the local port
	listener, err := net.Listen("tcp", ":"+localPort)
	if err != nil {
		return fmt.Errorf("failed to listen on local port: %v", err)
	}

	defer func() {
		if err := listener.Close(); err != nil {
			log.Printf("Error closing listener: %v", err)
		}
	}()

	log.Printf("Forwarding proxy started on localhost:%s -> %s:%s via %s\n", localPort, remoteHost, remotePort, sshConfig.Host)

	for {
		// Accept incoming local connections
		localConn, err := listener.Accept()
		if err != nil {
			log.Printf("failed to accept local connection: %v", err)
			continue
		}

		// Handle the connection in a goroutine
		go func(localConn net.Conn) {
			defer localConn.Close()

			// Establish a connection to the remote server via SSH
			remoteConn, err := sshClient.Dial("tcp", net.JoinHostPort(remoteHost, remotePort))
			if err != nil {
				log.Printf("failed to dial remote server: %v", err)
				return
			}
			defer remoteConn.Close()

			// Copy data between the local and remote connections
			go func() {
				_, err := io.Copy(remoteConn, localConn)
				if err != nil {
					log.Printf("error copying data to remote: %v", err)
				}
			}()

			_, err = io.Copy(localConn, remoteConn)
			if err != nil {
				log.Printf("error copying data to local: %v", err)
			}
		}(localConn)
	}
}

func main() {
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
