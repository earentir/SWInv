package main

import (
	"bufio"
	"fmt"
	"os"

	"swinv/config"
	"swinv/pkg"
	"swinv/ssh"

	cli "github.com/jawher/mow.cli"
	"github.com/sirupsen/logrus"
)

var appVersion = "0.0.5"

func main() {
	setupLogging()

	app := cli.App("inventory", "A tool to manage remote hosts and their software inventory")
	app.Version("v version", fmt.Sprintf("Software Inventory %s", appVersion))

	app.Command("login", "Login to a remote host", func(cmd *cli.Cmd) {
		host := cmd.StringArg("HOST", "", "Hostname or IP")
		user := cmd.StringOpt("user u", "", "Username")
		password := cmd.StringOpt("password p", "", "Password")

		cmd.Action = func() {
			if err := ssh.Login(*host, *user, *password); err != nil {
				logrus.Fatal(err)
			}
		}
	})

	app.Command("update", "Update host information", func(cmd *cli.Cmd) {
		host := cmd.StringArg("HOST", "", "Hostname, IP or 'all'")
		cmd.Action = func() {
			if *host == "all" {
				if err := pkg.UpdateAllHosts(); err != nil {
					logrus.Fatal(err)
				}
			} else {
				if err := pkg.UpdateHostInfo(*host); err != nil {
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
				if err := pkg.ListPackagesAllHosts(*update); err != nil {
					logrus.Fatal(err)
				}
			} else {
				if *update {
					if err := pkg.UpdateHostInfo(*host); err != nil {
						logrus.Fatal(err)
					}
				}
				if err := pkg.ListInstalledPackages(*host); err != nil {
					logrus.Fatal(err)
				}
			}
		}
	})

	app.Command("search", "Search for a package name and list all hosts that have it", func(cmd *cli.Cmd) {
		packageName := cmd.StringArg("PACKAGE", "", "Package name to search for")

		cmd.Action = func() {
			pkg.SearchPackages(*packageName)
		}
	})

	app.Command("import", "Import hosts from a file", func(cmd *cli.Cmd) {
		file := cmd.StringArg("FILE", "", "File containing hostnames or IPs")
		update := cmd.BoolOpt("update u", false, "Update host information after importing")

		cmd.Action = func() {
			if err := importHosts(*file, *update); err != nil {
				logrus.Fatal(err)
			}
		}
	})

	err := app.Run(os.Args)
	if err != nil {
		logrus.Fatal(err)
	}
}

func setupLogging() {
	logFile, err := os.OpenFile("swinv.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		logrus.Fatalf("Failed to open log file: %v", err)
	}

	logrus.SetOutput(logFile)
	logrus.SetLevel(logrus.DebugLevel)
	logrus.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
	})

	consoleHook := &ConsoleHook{
		writer: os.Stderr,
		filterLevels: []logrus.Level{
			logrus.PanicLevel,
			logrus.FatalLevel,
			logrus.ErrorLevel,
		},
	}

	logrus.AddHook(consoleHook)
	config.ReadConfig()
}

type ConsoleHook struct {
	writer       *os.File
	filterLevels []logrus.Level
}

func (hook *ConsoleHook) Levels() []logrus.Level {
	return logrus.AllLevels
}

func (hook *ConsoleHook) Fire(entry *logrus.Entry) error {
	for _, level := range hook.filterLevels {
		if entry.Level == level {
			line, err := entry.String()
			if err != nil {
				return err
			}
			fmt.Fprint(hook.writer, line)
		}
	}
	return nil
}

func importHosts(file string, update bool) error {
	f, err := os.Open(file)
	if err != nil {
		return fmt.Errorf("failed to open file: %v", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		host := scanner.Text()
		if _, exists := config.Conf.Hosts[host]; !exists {
			config.Conf.Hosts[host] = config.HostInfo{
				IP: host,
			}
			if update {
				if err := pkg.UpdateHostInfo(host); err != nil {
					logrus.Errorf("Failed to update host %s: %v", host, err)
				}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("failed to read file: %v", err)
	}

	config.WriteConfig()
	return nil
}
