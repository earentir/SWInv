// Package ssh provides functions for SSH operations.
package ssh

import (
	"fmt"
	"net"
	"os"
	"os/user"

	"swinv/config"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// Login logs into the specified host using SSH.
func Login(host, username, password string) error {
	client, session, err := connectSSH(host, username, password)
	if err != nil {
		return err
	}
	defer client.Close()
	defer session.Close()

	fmt.Printf("Successfully logged in to %s\n", host)
	return nil
}

func connectSSH(host, username, password string) (*ssh.Client, *ssh.Session, error) {
	if username == "" {
		currentUser, err := user.Current()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to get current user: %v", err)
		}
		username = currentUser.Username
	}

	sshAgent, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK"))
	if err == nil {
		agentClient := agent.NewClient(sshAgent)
		signers, err := agentClient.Signers()
		if err != nil {
			logrus.Errorf("Failed to get signers from SSH agent: %v", err)
		} else {
			config := &ssh.ClientConfig{
				User: username,
				Auth: []ssh.AuthMethod{
					ssh.PublicKeys(signers...),
				},
				HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			}

			client, err := ssh.Dial("tcp", host+":22", config)
			if err == nil {
				session, err := client.NewSession()
				if err != nil {
					logrus.Errorf("Failed to create session: %v", err)
					return nil, nil, err
				}
				return client, session, nil
			}
		}
	}

	config := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	client, err := ssh.Dial("tcp", host+":22", config)
	if err != nil {
		return nil, nil, err
	}

	session, err := client.NewSession()
	if err != nil {
		return nil, nil, err
	}

	return client, session, nil
}

// ConnectSSHClientOnly connects to the SSH client only.
func ConnectSSHClientOnly(host string) (*ssh.Client, error) {
	username := GetUsernameForHost(host)
	password := "your-password" // Modify this part to retrieve the actual password if needed
	client, _, err := connectSSH(host, username, password)
	return client, err
}

// GetUsernameForHost retrieves the username for the given host.
func GetUsernameForHost(host string) string {
	if info, exists := config.Conf.Hosts[host]; exists && info.Username != "" {
		return info.Username
	}
	currentUser, err := user.Current()
	if err != nil {
		logrus.Errorf("Failed to get current user: %v", err)
		return ""
	}
	return currentUser.Username
}

// RunCommand runs the specified command on the SSH client.
func RunCommand(client *ssh.Client, cmd string) ([]byte, error) {
	session, err := client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %v", err)
	}
	defer session.Close()

	output, err := session.Output(cmd)
	if err != nil {
		return nil, fmt.Errorf("failed to run command %s: %v", cmd, err)
	}
	return output, nil
}
