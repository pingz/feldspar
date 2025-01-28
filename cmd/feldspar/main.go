package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"

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

	sshConfig := &SSHConfig{
		Host: host,
		Port: "22", // Default SSH port
	}

	// Get the User, Hostname, Port, and IdentityFile from the SSH config
	sshConfig.User = cfg.Get(host, "User")
	sshConfig.Host = cfg.Get(host, "Hostname")
	port := cfg.Get(host, "Port")
	if port != "" {
		sshConfig.Port = port
	}

	identityFile := cfg.Get(host, "IdentityFile")
	if identityFile == "" {
		return nil, fmt.Errorf("no IdentityFile specified for host %s in SSH config", host)
	}

	// Read the private key file
	privateKeyPath := filepath.Join(homeDir, ".ssh", identityFile)
	privateKeyBytes, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file: %v", err)
	}
	sshConfig.PrivateKey = string(privateKeyBytes)

	return sshConfig, nil
}

// ForwardProxy starts a local proxy that forwards traffic to the remote server via SSH
func ForwardProxy(localPort, remoteHost, remotePort string, sshConfig *SSHConfig) error {
	// Parse the private key
	signer, err := ssh.ParsePrivateKey([]byte(sshConfig.PrivateKey))
	if err != nil {
		return fmt.Errorf("unable to parse private key: %v", err)
	}

	// SSH client configuration
	config := &ssh.ClientConfig{
		User: sshConfig.User,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // Insecure: Use for testing only
	}

	// Connect to the SSH server
	sshClient, err := ssh.Dial("tcp", net.JoinHostPort(sshConfig.Host, sshConfig.Port), config)
	if err != nil {
		return fmt.Errorf("failed to dial SSH server: %v", err)
	}
	defer sshClient.Close()

	// Start listening on the local port
	listener, err := net.Listen("tcp", ":"+localPort)
	if err != nil {
		return fmt.Errorf("failed to listen on local port: %v", err)
	}
	defer listener.Close()

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
	// Host name from the SSH config file
	sshHost := "my-ssh-host" // Replace with the host name defined in ~/.ssh/config

	// Load SSH configuration from ~/.ssh/config
	sshConfig, err := LoadSSHConfig(sshHost)
	if err != nil {
		log.Fatalf("Failed to load SSH config: %v", err)
	}

	// Start the forwarding proxy
	err = ForwardProxy("8080", "remote-server.com", "80", sshConfig)
	if err != nil {
		log.Fatalf("Failed to start forwarding proxy: %v", err)
	}
}
