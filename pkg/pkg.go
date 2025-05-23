package pkg

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"swinv/config"
	"swinv/ssh"

	"github.com/sirupsen/logrus"
)

// UpdateHostInfo updates the information of a single host.
func UpdateHostInfo(host string) error {
	fmt.Printf("Inventorying host %s...\n", host)

	// Resolve IP address of the host
	ips, err := net.LookupIP(host)
	if err != nil {
		fmt.Printf("Failed to resolve IP for host %s: %v\n", host, err)
		return err
	}
	ip := ips[0].String()
	fmt.Printf("Resolved IP for host %s: %s\n", host, ip)

	client, err := ssh.ConnectSSHClientOnly(host)
	if err != nil {
		fmt.Printf("Failed\n")
		logrus.Errorf("Failed to connect to host %s: %v", host, err)
		return err
	}
	defer client.Close()

	internalIP, err := ssh.RunCommand(client, "hostname -I | awk '{print $1}'")
	if err != nil {
		fmt.Printf("Failed to get internal IP on host %s: %v\n", host, err)
		logrus.Errorf("Failed to get internal IP on host %s: %v", host, err)
		return err
	}

	if strings.TrimSpace(ip) != strings.TrimSpace(string(internalIP)) {
		fmt.Printf("Warning: Resolved IP %s does not match internal IP %s on host %s\n", ip, strings.TrimSpace(string(internalIP)), host)
	}

	osInfo, err := ssh.RunCommand(client, "grep '^ID=' /etc/os-release | cut -d= -f2")
	if err != nil {
		fmt.Printf("Failed to get OS info on host %s: %v\n", host, err)
		logrus.Errorf("Failed to get OS info on host %s: %v", host, err)
		return err
	}
	osVersion, err := ssh.RunCommand(client, "grep 'VERSION_ID=' /etc/os-release | cut -d= -f2")
	if err != nil {
		fmt.Printf("Failed to get OS version on host %s: %v\n", host, err)
		logrus.Errorf("Failed to get OS version on host %s: %v", host, err)
		return err
	}
	hostname, err := ssh.RunCommand(client, "hostname")
	if err != nil {
		fmt.Printf("Failed to get hostname on host %s: %v\n", host, err)
		logrus.Errorf("Failed to get hostname on host %s: %v", host, err)
		return err
	}

	username := ssh.GetUsernameForHost(host)

	hostInfo := config.HostInfo{
		OS:            strings.Trim(strings.TrimSpace(string(osInfo)), "\""),
		OSVersion:     strings.Trim(strings.TrimSpace(string(osVersion)), "\""),
		IP:            strings.TrimSpace(string(internalIP)),
		Hostname:      strings.TrimSpace(string(hostname)),
		LastConnected: time.Now(),
		Username:      username,
	}

	// Update the existing host entry
	for k := range config.Conf.Hosts {
		if k == host {
			config.Conf.Hosts[k] = hostInfo
			break
		}
	}
	config.WriteConfig()

	fmt.Printf("Done ✓\n")
	return nil
}

// UpdateAllHosts updates the information of all hosts.
func UpdateAllHosts() error {
	fmt.Println("Updating all hosts")
	for host := range config.Conf.Hosts {
		if err := UpdateHostInfo(host); err != nil {
			logrus.Errorf("Failed to update host %s: %v", host, err)
		}
	}
	return nil
}

// ListInstalledPackages lists the installed packages on a single host.
func ListInstalledPackages(host string) error {
	fmt.Printf("Listing installed packages for host %s... ", host)
	client, err := ssh.ConnectSSHClientOnly(host)
	if err != nil {
		fmt.Printf("Failed\n")
		logrus.Errorf("Failed to connect to host %s: %v", host, err)
		return err
	}
	defer client.Close()

	osType, err := ssh.RunCommand(client, "uname -s")
	if err != nil {
		fmt.Printf("Failed\n")
		logrus.Errorf("Failed to run uname -s on host %s: %v", host, err)
		return err
	}

	var pkgList []byte
	if strings.TrimSpace(string(osType)) == "Linux" {
		distro, err := ssh.RunCommand(client, "grep '^ID=' /etc/os-release | cut -d= -f2")
		if err != nil {
			fmt.Printf("Failed\n")
			logrus.Errorf("Failed to detect Linux distribution on host %s: %v", host, err)
			return err
		}
		distroStr := strings.Trim(strings.TrimSpace(string(distro)), "\"")
		if distroStr == "ubuntu" || distroStr == "debian" {
			pkgList, err = ssh.RunCommand(client, `dpkg-query -W -f='${binary:Package}\t${Version}\t${source:Package}\n'`)
			if err != nil {
				fmt.Printf("Failed\n")
				logrus.Errorf("Failed to list packages on host %s: %v", host, err)
				return err
			}
		} else if distroStr == "centos" || distroStr == "fedora" || distroStr == "rhel" || distroStr == "ol" {
			pkgList, err = ssh.RunCommand(client, `rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\t%{VENDOR}\n'`)
			if err != nil {
				fmt.Printf("Failed\n")
				logrus.Errorf("Failed to list packages on host %s: %v", host, err)
				return err
			}
		} else {
			err := fmt.Errorf("unsupported Linux distribution: %s", distroStr)
			fmt.Printf("Failed\n")
			logrus.Errorf("Unsupported Linux distribution on host %s: %v", host, err)
			return err
		}
	} else {
		err := fmt.Errorf("unsupported OS type: %s", osType)
		fmt.Printf("Failed\n")
		logrus.Errorf("Unsupported OS type on host %s: %v", host, err)
		return err
	}

	hostname, err := ssh.RunCommand(client, "hostname")
	if err != nil {
		fmt.Printf("Failed\n")
		logrus.Errorf("Failed to get hostname on host %s: %v", host, err)
		return err
	}

	internalIP := config.Conf.Hosts[host].IP
	pkgs := parsePackages(strings.TrimSpace(string(pkgList)))
	pkgs = filterPackages(pkgs, config.Conf.ExcludedPkgs)
	savePackages(strings.TrimSpace(string(hostname)), internalIP, pkgs)

	hostInfo := config.Conf.Hosts[host]
	hostInfo.LastPkgUpdate = time.Now()
	config.Conf.Hosts[host] = hostInfo
	config.WriteConfig()

	fmt.Printf("Done ✓\n")
	return nil
}

// ListPackagesAllHosts lists the installed packages on all hosts.
func ListPackagesAllHosts(update bool) error {
	fmt.Println("Listing installed packages for all hosts")
	for host := range config.Conf.Hosts {
		if update {
			if err := UpdateHostInfo(host); err != nil {
				logrus.Errorf("Failed to update host %s: %v", host, err)
			}
		}
		if err := ListInstalledPackages(host); err != nil {
			logrus.Errorf("Failed to list packages for host %s: %v", host, err)
		}
	}
	return nil
}

func filterPackages(pkgs []config.PackageInfo, excludedPkgs []string) []config.PackageInfo {
	var filteredPkgs []config.PackageInfo
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

func parsePackages(pkgList string) []config.PackageInfo {
	lines := strings.Split(pkgList, "\n")
	var packages []config.PackageInfo
	for _, line := range lines {
		parts := strings.Split(line, "\t")
		if len(parts) >= 3 {
			packages = append(packages, config.PackageInfo{
				Name:       parts[0],
				Version:    parts[1],
				Repository: parts[2],
			})
		}
	}
	return packages
}

func savePackages(hostname, ip string, packages []config.PackageInfo) {
	fileName := fmt.Sprintf("%s__%s.json", hostname, ip)
	fileData, _ := json.MarshalIndent(packages, "", "  ")
	err := os.WriteFile(fileName, fileData, 0644)
	if err != nil {
		logrus.Errorf("Failed to save package list for host %s: %v", hostname, err)
	}
}

// SearchPackages searches for a package by name and lists all hosts that have it.
func SearchPackages(packageName string) {
	packageCounts := make(map[string]int)
	hostMatches := make(map[string][]config.PackageInfo)

	for _, host := range config.Conf.Hosts {
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
			if strings.Contains(pkg.Name, packageName) {
				hostMatches[host.Hostname] = append(hostMatches[host.Hostname], pkg)
				packageCounts[pkg.Version]++
			}
		}
	}

	totalCount := 0
	for host, pkgs := range hostMatches {
		fmt.Printf("Host: %s\n", host)
		for _, pkg := range pkgs {
			fmt.Printf("  Name: %s, Version: %s, Repository: %s\n", pkg.Name, pkg.Version, pkg.Repository)
			totalCount++
		}
	}

	fmt.Printf("\nSummary:\n")
	fmt.Printf("Total occurrences: %d\n", totalCount)
	for version, count := range packageCounts {
		fmt.Printf("Version: %s, Count: %d\n", version, count)
	}
}

func loadPackageList(filename string) ([]config.PackageInfo, error) {
	var pkgs []config.PackageInfo
	data, err := os.ReadFile(filename)
	if err != nil {
		return pkgs, err
	}
	err = json.Unmarshal(data, &pkgs)
	return pkgs, err
}
