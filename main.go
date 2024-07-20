package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/user"
	"strings"
	"time"

	cli "github.com/jawher/mow.cli"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type hostInfo struct {
	OS            string    `json:"os"`
	OSVersion     string    `json:"os_version"`
	IP            string    `json:"ip"`
	Hostname      string    `json:"hostname"`
	LastConnected time.Time `json:"last_connected"`
	LastPkgUpdate time.Time `json:"last_pkg_update,omitempty"`
	Username      string    `json:"username"`
}

type packageInfo struct {
	Name       string `json:"name"`
	Version    string `json:"version"`
	Repository string `json:"repository"`
}

type config struct {
	Hosts        map[string]hostInfo `json:"hosts"`
	ExcludedPkgs []string            `json:"excluded_pkgs"`
}

var configFile = "hosts.json"
var conf config

func main() {
	setupLogging()

	app := cli.App("inventory", "A tool to manage remote hosts and their software inventory")

	app.Command("login", "Login to a remote host", func(cmd *cli.Cmd) {
		host := cmd.StringArg("HOST", "", "Hostname or IP")
		user := cmd.StringOpt("user u", "", "Username")
		password := cmd.StringOpt("password p", "", "Password")

		cmd.Action = func() {
			if err := sshLogin(*host, *user, *password); err != nil {
				logrus.Fatal(err)
			}
		}
	})

	app.Command("update", "Update host information", func(cmd *cli.Cmd) {
		host := cmd.StringArg("HOST", "", "Hostname, IP or 'all'")
		cmd.Action = func() {
			if *host == "all" {
				if err := updateAllHosts(); err != nil {
					logrus.Fatal(err)
				}
			} else {
				if err := updateHostInfo(*host); err != nil {
					logrus.Fatal(err)
				}
			}
		}
	})

	app.Command("listpkgs", "List installed packages on the remote host", func(cmd *cli.Cmd) {
		host := cmd.StringArg("HOST", "", "Hostname, IP or 'all'")
		update := cmd.BoolOpt("update u", false, "Update host information before listing packages")
		cmd.Action = func() {
			if *host == "all" {
				if err := listPackagesAllHosts(*update); err != nil {
					logrus.Fatal(err)
				}
			} else {
				if *update {
					if err := updateHostInfo(*host); err != nil {
						logrus.Fatal(err)
					}
				}
				if err := listInstalledPackages(*host); err != nil {
					logrus.Fatal(err)
				}
			}
		}
	})

	app.Command("search", "Search for a package name and list all hosts that have it", func(cmd *cli.Cmd) {
		packageName := cmd.StringArg("PACKAGE", "", "Package name to search for")

		cmd.Action = func() {
			searchPackages(conf, *packageName)
		}
	})

	app.Run(os.Args)
}

func setupLogging() {
	logFile, err := os.OpenFile("softwareinventory.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		logrus.Fatalf("Failed to open log file: %v", err)
	}

	logrus.SetOutput(logFile)
	logrus.SetLevel(logrus.DebugLevel)
	logrus.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
	})

	consoleHook := &consoleHook{
		writer: os.Stderr,
		filterLevels: []logrus.Level{
			logrus.PanicLevel,
			logrus.FatalLevel,
			logrus.ErrorLevel,
		},
	}

	logrus.AddHook(consoleHook)
	readConfig()
}

type consoleHook struct {
	writer       *os.File
	filterLevels []logrus.Level
}

func (hook *consoleHook) Levels() []logrus.Level {
	return logrus.AllLevels
}

func (hook *consoleHook) Fire(entry *logrus.Entry) error {
	for _, level := range hook.filterLevels {
		if entry.Level == level {
			line, err := entry.String()
			if err != nil {
				return err
			}
			fmt.Fprintf(hook.writer, line)
		}
	}
	return nil
}

func readConfig() {
	file, err := os.ReadFile(configFile)
	if err != nil {
		logrus.Fatalf("Failed to read config file: %v", err)
	}
	err = json.Unmarshal(file, &conf)
	if err != nil {
		logrus.Fatalf("Failed to unmarshal config file: %v", err)
	}
}

func sshLogin(host, username, password string) error {
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

func updateHostInfo(host string) error {
	fmt.Printf("Inventorying host %s...", host)
	client, err := connectSSHClientOnly(host)
	if err != nil {
		fmt.Printf("Failed\n")
		logrus.Errorf("Failed to connect to host %s: %v", host, err)
		return err
	}
	defer client.Close()

	osInfo, err := runCommand(client, "grep '^ID=' /etc/os-release | cut -d= -f2")
	if err != nil {
		fmt.Printf("Failed\n")
		logrus.Errorf("Failed to get OS info on host %s: %v", host, err)
		return err
	}
	osVersion, err := runCommand(client, "grep 'VERSION_ID=' /etc/os-release | cut -d= -f2")
	if err != nil {
		fmt.Printf("Failed\n")
		logrus.Errorf("Failed to get OS version on host %s: %v", host, err)
		return err
	}
	hostname, err := runCommand(client, "hostname")
	if err != nil {
		fmt.Printf("Failed\n")
		logrus.Errorf("Failed to get hostname on host %s: %v", host, err)
		return err
	}

	username := getUsernameForHost(host)

	hostInfo := hostInfo{
		OS:            strings.TrimSpace(string(osInfo)),
		OSVersion:     strings.TrimSpace(string(osVersion)),
		IP:            host,
		Hostname:      strings.TrimSpace(string(hostname)),
		LastConnected: time.Now(),
		Username:      username,
	}

	conf.Hosts[host] = hostInfo
	writeConfig()

	fmt.Printf("Done ✓\n")
	return nil
}

func updateAllHosts() error {
	fmt.Println("Updating all hosts")
	for host := range conf.Hosts {
		if err := updateHostInfo(host); err != nil {
			logrus.Errorf("Failed to update host %s: %v", host, err)
		}
	}
	return nil
}

func listInstalledPackages(host string) error {
	fmt.Printf("Listing installed packages for host %s...", host)
	client, err := connectSSHClientOnly(host)
	if err != nil {
		fmt.Printf("Failed\n")
		logrus.Errorf("Failed to connect to host %s: %v", host, err)
		return err
	}
	defer client.Close()

	osType, err := runCommand(client, "uname -s")
	if err != nil {
		fmt.Printf("Failed\n")
		logrus.Errorf("Failed to run uname -s on host %s: %v", host, err)
		return err
	}

	var pkgList []byte
	if strings.TrimSpace(string(osType)) == "Linux" {
		distro, err := runCommand(client, "grep '^ID=' /etc/os-release | cut -d= -f2")
		if err != nil {
			fmt.Printf("Failed\n")
			logrus.Errorf("Failed to detect Linux distribution on host %s: %v", host, err)
			return err
		}
		distroStr := strings.TrimSpace(string(distro))
		if distroStr == "ubuntu" || distroStr == "debian" {
			pkgList, err = runCommand(client, `dpkg-query -W -f='${binary:Package}\t${Version}\t${source:Package}\n'`)
		} else if distroStr == "centos" || distroStr == "fedora" || distroStr == "rhel" {
			pkgList, err = runCommand(client, `rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\t%{VENDOR}\n'`)
		} else {
			err = fmt.Errorf("unsupported Linux distribution: %s", distroStr)
		}
	} else {
		err = fmt.Errorf("unsupported OS type: %s", osType)
	}

	if err != nil {
		fmt.Printf("Failed\n")
		logrus.Errorf("Failed to list packages on host %s: %v", host, err)
		return err
	}

	hostname, err := runCommand(client, "hostname")
	if err != nil {
		fmt.Printf("Failed\n")
		logrus.Errorf("Failed to get hostname on host %s: %v", host, err)
		return err
	}

	pkgs := parsePackages(strings.TrimSpace(string(pkgList)))
	pkgs = filterPackages(pkgs, conf.ExcludedPkgs)
	savePackages(host, strings.TrimSpace(string(hostname)), pkgs)

	hostInfo := conf.Hosts[host]
	hostInfo.LastPkgUpdate = time.Now()
	conf.Hosts[host] = hostInfo
	writeConfig()

	fmt.Printf("Done ✓\n")
	return nil
}

func filterPackages(pkgs []packageInfo, excludedPkgs []string) []packageInfo {
	var filteredPkgs []packageInfo
	excluded := make(map[string]bool)
	for _, pkg := range excludedPkgs {
		excluded[pkg] = true
	}
	for _, pkg := range pkgs {
		if !excluded[pkg.Name] {
			filteredPkgs = append(filteredPkgs, pkg)
		}
	}
	return filteredPkgs
}

func parsePackages(pkgList string) []packageInfo {
	lines := strings.Split(pkgList, "\n")
	var packages []packageInfo
	for _, line := range lines {
		parts := strings.Split(line, "\t")
		if len(parts) >= 3 {
			packages = append(packages, packageInfo{
				Name:       parts[0],
				Version:    parts[1],
				Repository: parts[2],
			})
		}
	}
	return packages
}

func listPackagesAllHosts(update bool) error {
	fmt.Println("Listing installed packages for all hosts")
	for host := range conf.Hosts {
		if update {
			if err := updateHostInfo(host); err != nil {
				logrus.Errorf("Failed to update host %s: %v", host, err)
			}
		}
		if err := listInstalledPackages(host); err != nil {
			logrus.Errorf("Failed to list packages for host %s: %v", host, err)
		}
	}
	return nil
}

func savePackages(host, hostname string, packages []packageInfo) {
	fileName := fmt.Sprintf("%s__%s.json", hostname, host)
	fileData, _ := json.MarshalIndent(packages, "", "  ")
	os.WriteFile(fileName, fileData, 0644)
}

func connectSSHClientOnly(host string) (*ssh.Client, error) {
	username := getUsernameForHost(host)
	password := "your-password" // Modify this part to retrieve the actual password if needed
	client, _, err := connectSSH(host, username, password)
	return client, err
}

func getUsernameForHost(host string) string {
	if info, exists := conf.Hosts[host]; exists && info.Username != "" {
		return info.Username
	}
	currentUser, err := user.Current()
	if err != nil {
		logrus.Errorf("Failed to get current user: %v", err)
		return ""
	}
	return currentUser.Username
}

func runCommand(client *ssh.Client, cmd string) ([]byte, error) {
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

func writeConfig() {
	file, err := json.MarshalIndent(conf, "", "  ")
	if err != nil {
		logrus.Errorf("Failed to marshal config: %v", err)
		return
	}
	if err := os.WriteFile(configFile, file, 0644); err != nil {
		logrus.Errorf("Failed to write config file: %v", err)
	}
}

func searchPackages(conf config, packageName string) {
	packageCounts := make(map[string]int)
	hostMatches := make(map[string][]packageInfo)

	for _, host := range conf.Hosts {
		filename := fmt.Sprintf("%s__%s.json", host.Hostname, host.IP)
		if _, err := os.Stat(filename); os.IsNotExist(err) {
			continue
		}
		packages, err := loadPackageList(filename)
		if err != nil {
			log.Printf("Error loading package list from %s: %v\n", filename, err)
			continue
		}
		for _, pkg := range packages {
			if pkg.Name == packageName {
				hostMatches[host.Hostname] = append(hostMatches[host.Hostname], pkg)
				packageCounts[pkg.Version]++
			}
		}
	}

	totalCount := 0
	for host, pkgs := range hostMatches {
		fmt.Printf("Host: %s\n", host)
		for _, pkg := range pkgs {
			fmt.Printf("  Version: %s, Repository: %s\n", pkg.Version, pkg.Repository)
			totalCount++
		}
	}

	fmt.Printf("\nSummary:\n")
	fmt.Printf("Total occurrences: %d\n", totalCount)
	for version, count := range packageCounts {
		fmt.Printf("Version: %s, Count: %d\n", version, count)
	}
}

func loadPackageList(filename string) ([]packageInfo, error) {
	var pkgs []packageInfo
	data, err := os.ReadFile(filename)
	if err != nil {
		return pkgs, err
	}
	err = json.Unmarshal(data, &pkgs)
	return pkgs, err
}
