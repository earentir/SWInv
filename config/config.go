// Package config provides functions for reading and writing configuration.
package config

import (
	"encoding/json"
	"os"
	"time"

	"github.com/sirupsen/logrus"
)

// HostInfo represents the information about a host.
type HostInfo struct {
	OS            string    `json:"os"`
	OSVersion     string    `json:"os_version"`
	IP            string    `json:"ip"`
	Hostname      string    `json:"hostname"`
	LastConnected time.Time `json:"last_connected"`
	LastPkgUpdate time.Time `json:"last_pkg_update,omitempty"`
	Username      string    `json:"username"`
}

// PackageInfo represents information about a package.
type PackageInfo struct {
	Name       string `json:"name"`
	Version    string `json:"version"`
	Repository string `json:"repository"`
}

// Config represents the configuration containing hosts and excluded packages.
type Config struct {
	Hosts        map[string]HostInfo `json:"hosts"`
	ExcludedPkgs []string            `json:"excluded_pkgs"`
}

// ConfigFile is the name of the configuration file.
var ConfigFile = "hosts.json"

// Conf is the global configuration.
var Conf Config

// ReadConfig reads the configuration from the file.
func ReadConfig() {
	file, err := os.ReadFile(ConfigFile)
	if err != nil {
		logrus.Fatalf("Failed to read config file: %v", err)
	}
	err = json.Unmarshal(file, &Conf)
	if err != nil {
		logrus.Fatalf("Failed to unmarshal config file: %v", err)
	}
}

// WriteConfig writes the configuration to the file.
func WriteConfig() {
	file, err := json.MarshalIndent(Conf, "", "  ")
	if err != nil {
		logrus.Errorf("Failed to marshal config: %v", err)
		return
	}
	if err := os.WriteFile(ConfigFile, file, 0644); err != nil {
		logrus.Errorf("Failed to write config file: %v", err)
	}
}
