package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/docker/machine/libmachine/drivers"
	"github.com/docker/machine/libmachine/log"
	"github.com/docker/machine/libmachine/mcnflag"
	"github.com/docker/machine/libmachine/ssh"
	"github.com/docker/machine/libmachine/state"
)

const (
	privateNetworkName = "docker-machines"

	defaultSSHUser = "core"
)

type Driver struct {
	*drivers.BaseDriver
	EnginePort int
	FirstQuery bool

	Memory           int
	CPU              int
	Program          string
	Display          bool
	DisplayType      string
	Network          string
	PrivateNetwork   string
	NetworkInterface string
	NetworkAddress   string
	NetworkBridge    string
	CaCertPath       string
	PrivateKeyPath   string
	DiskPath         string
	TmpDir           string
	CacheMode        string
	IOMode           string
	connectionString string
	//	conn             *libvirt.Connect
	//	VM               *libvirt.Domain
	vmLoaded        bool
	LocalPorts      string
	LocalIP         string
}

func (d *Driver) GetCreateFlags() []mcnflag.Flag {
	return []mcnflag.Flag{
		mcnflag.IntFlag{
			Name:  "qemu-memory",
			Usage: "Size of memory for host in MB",
			Value: 1024,
		},
		mcnflag.IntFlag{
			Name:  "qemu-cpu-count",
			Usage: "Number of CPUs",
			Value: 1,
		},
		mcnflag.StringFlag{
			Name:  "qemu-program",
			Usage: "Name of program to run",
			Value: "qemu-system-x86_64",
		},
		mcnflag.BoolFlag{
			Name:  "qemu-display",
			Usage: "Display video output",
		},
		mcnflag.StringFlag{
			EnvVar: "QEMU_DISPLAY_TYPE",
			Name:   "qemu-display-type",
			Usage:  "Select type of display",
		},
		mcnflag.StringFlag{
			Name:  "qemu-network",
			Usage: "Name of network to connect to (user, tap, bridge)",
			Value: "user",
		},
		mcnflag.StringFlag{
			Name:  "qemu-network-interface",
			Usage: "Name of the network interface to be used for networking (for tap)",
			Value: "tap0",
		},
		mcnflag.StringFlag{
			Name:  "qemu-network-address",
			Usage: "IP of the network adress to be used for networking (for tap)",
		},
		mcnflag.StringFlag{
			Name:  "qemu-network-bridge",
			Usage: "Name of the network bridge to be used for networking (for bridge)",
			Value: "br0",
		},
		mcnflag.StringFlag{
			EnvVar: "QEMU_DISK_PATH",
			Name:   "qemu-disk-path",
			Usage:  "The path of the coreos image.",
		},
		mcnflag.StringFlag{
			Name:   "qemu-tmp-dir",
			Usage:  "The directory for all temporary data.",
		},
		mcnflag.StringFlag{
			Name:  "qemu-cache-mode",
			Usage: "Disk cache mode: default, none, writethrough, writeback, directsync, or unsafe",
			Value: "default",
		},
		mcnflag.StringFlag{
			Name:  "qemu-io-mode",
			Usage: "Disk IO mode: threads, native",
			Value: "threads",
		},
		mcnflag.StringFlag{
			EnvVar: "QEMU_LOCALPORTS",
			Name:   "qemu-localports",
			Usage:  "Port range to bind local SSH and engine ports",
		},
		mcnflag.StringFlag{
			Name:   "qemu-localip",
			Usage:  "IP to bind local SSH and engine ports",
			Value:  "127.0.0.1",
		},
		/* Not yet implemented
		mcnflag.Flag{
			Name:  "qemu-no-share",
			Usage: "Disable the mount of your home directory",
		},
		*/
	}
}

func (d *Driver) GetMachineName() string {
	return d.MachineName
}

func (d *Driver) GetSSHHostname() (string, error) {
	return d.GetIP()
}

func (d *Driver) GetSSHKeyPath() string {
	return d.ResolveStorePath("id_rsa")
}

func (d *Driver) GetSSHPort() (int, error) {
	if d.SSHPort == 0 {
		d.SSHPort = 22
	}

	return d.SSHPort, nil
}

func (d *Driver) GetSSHUsername() string {
	return defaultSSHUser
}

func (d *Driver) DriverName() string {
	return "qemu"
}

func (d *Driver) SetConfigFromFlags(flags drivers.DriverOptions) error {
	log.Debugf("SetConfigFromFlags called")
	d.Memory = flags.Int("qemu-memory")
	d.CPU = flags.Int("qemu-cpu-count")
	d.Program = flags.String("qemu-program")
	d.Display = flags.Bool("qemu-display")
	d.DisplayType = flags.String("qemu-display-type")
	d.Network = flags.String("qemu-network")
	d.NetworkInterface = flags.String("qemu-network-interface")
	d.NetworkAddress = flags.String("qemu-network-address")
	d.NetworkBridge = flags.String("qemu-network-bridge")
	d.DiskPath = flags.String("qemu-disk-path")
	d.TmpDir = flags.String("qemu-tmp-dir")
	d.CacheMode = flags.String("qemu-cache-mode")
	d.IOMode = flags.String("qemu-io-mode")

	d.SwarmMaster = flags.Bool("swarm-master")
	d.SwarmHost = flags.String("swarm-host")
	d.SwarmDiscovery = flags.String("swarm-discovery")
	d.EnginePort = 2376
	d.LocalPorts = flags.String("qemu-localports")
	d.LocalIP = flags.String("qemu-localip")
	d.FirstQuery = true
	d.SSHPort = 22

	if d.DiskPath == "" {
		return errors.New("missing the disk path (--qemu-disk-path)")
	}
	if d.TmpDir == "" {
		d.TmpDir = filepath.Join(d.StorePath, "machines", d.GetMachineName())
	}
	return nil
}

func (d *Driver) GetURL() (string, error) {
	log.Debugf("GetURL called")
	if _, err := os.Stat(d.pidfilePath()); err != nil {
		return "", nil
	}
	ip, err := d.GetIP()
	if err != nil {
		log.Warnf("Failed to get IP: %s", err)
		return "", err
	}
	if ip == "" {
		return "", nil
	}
	port := d.GetPort()
	return fmt.Sprintf("tcp://%s:%d", ip, port), nil
}

func NewDriver(hostName, storePath string) drivers.Driver {
	return &Driver{
		PrivateNetwork: privateNetworkName,
		BaseDriver: &drivers.BaseDriver{
			SSHUser:     defaultSSHUser,
			MachineName: hostName,
			StorePath:   storePath,
		},
	}
}

func (d *Driver) GetIP() (string, error) {
	if d.Network == "user" {
		return d.LocalIP, nil
	}
	return d.NetworkAddress, nil
}

func (d *Driver) GetPort() int {
	var port = d.EnginePort
	if d.FirstQuery {
		d.FirstQuery = false
		port = 2376
	}
	return port
}

func checkPid(pid int) error {
	process, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	return process.Signal(syscall.Signal(0))
}

func (d *Driver) GetState() (state.State, error) {

	if _, err := os.Stat(d.pidfilePath()); err != nil {
		return state.Stopped, nil
	}
	p, err := ioutil.ReadFile(d.pidfilePath())
	if err != nil {
		return state.Error, err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(p)))
	if err != nil {
		return state.Error, err
	}
	if err := checkPid(pid); err != nil {
		// No pid, remove pidfile
		os.Remove(d.pidfilePath())
		return state.Stopped, nil
	}
	ret, err := d.RunQMPCommand("query-status")
	if err != nil {
		return state.Error, err
	}
	// RunState is one of:
	// 'debug', 'inmigrate', 'internal-error', 'io-error', 'paused',
	// 'postmigrate', 'prelaunch', 'finish-migrate', 'restore-vm',
	// 'running', 'save-vm', 'shutdown', 'suspended', 'watchdog',
	// 'guest-panicked'
	switch ret["status"] {
	case "running":
		return state.Running, nil
	case "paused":
		return state.Paused, nil
	case "shutdown":
		return state.Stopped, nil
	}
	return state.None, nil
}

func (d *Driver) PreCreateCheck() error {
	return nil
}

func (d *Driver) Create() error {
	var err error
	if d.Network == "user" {
		d.SSHPort, err = d.getAvailableTCPPort()
		if err != nil {
			return err
		}

		for {
			d.EnginePort, err = d.getAvailableTCPPort()
			if err != nil {
				return err
			}
			if d.EnginePort == d.SSHPort {
				// can't have both on same port
				continue
			}
			break
		}
	}

	log.Infof("Creating SSH key...")
	if err := ssh.GenerateSSHKey(d.sshKeyPath()); err != nil {
		return err
	}

	log.Infof("Creating Ignition config...")
	if err := d.generateIgnitionConfig(); err != nil {
		return err
	}

	log.Infof("Starting QEMU VM...")
	return d.Start()
}

func parsePortRange(rawPortRange string) (int, int, error) {
	if rawPortRange == "" {
		return 0, 65535, nil
	}

	portRange := strings.Split(rawPortRange, "-")

	minPort, err := strconv.Atoi(portRange[0])
	if err != nil {
		return 0, 0, fmt.Errorf("Invalid port range")
	}
	maxPort, err := strconv.Atoi(portRange[1])
	if err != nil {
		return 0, 0, fmt.Errorf("Invalid port range")
	}

	if maxPort < minPort {
		return 0, 0, fmt.Errorf("Invalid port range")
	}

	if maxPort-minPort < 2 {
		return 0, 0, fmt.Errorf("Port range must be minimum 2 ports")
	}

	return minPort, maxPort, nil
}

func getRandomPortNumberInRange(min int, max int) int {
	return rand.Intn(max-min) + min
}

func (d *Driver) getAvailableTCPPort() (int, error) {
	minPort, maxPort, err := parsePortRange(d.LocalPorts)
	if err != nil {
		return 0, err
	}
	log.Debugf("port range: %d -> %d", minPort, maxPort)

	port := 0
	for i := 0; i <= 10; i++ {
		var ln net.Listener
		var err error
		if minPort == 0 && maxPort == 65535 {
			ln, err = net.Listen("tcp4", fmt.Sprintf("%s:0", d.LocalIP))
			if err != nil {
				return 0, err
			}
		} else {
			port = getRandomPortNumberInRange(minPort, maxPort)
			log.Debugf("testing port: %d", port)
			ln, err = net.Listen("tcp4", fmt.Sprintf("%s:%d", d.LocalIP, port))
			if err != nil {
				log.Debugf("port already in use: %s:%d", d.LocalIP, port)
				continue
			}
		}
		defer ln.Close()
		addr := ln.Addr().String()
		addrParts := strings.SplitN(addr, ":", 2)
		p, err := strconv.Atoi(addrParts[1])
		if err != nil {
			return 0, err
		}
		if p != 0 {
			port = p
			return port, nil
		}
		time.Sleep(1)
	}
	return 0, fmt.Errorf("unable to allocate tcp port")
}

func (d *Driver) Start() error {
	var startCmd []string

	if d.Display {
		if d.DisplayType != "" {
			startCmd = append(startCmd,
				"-display", d.DisplayType,
			)
		} else {
			// Use the default graphic output
		}
	} else {
		startCmd = append(startCmd,
			"-display", "none",
		)
	}

	startCmd = append(startCmd,
		"-machine", "accel=kvm,kernel_irqchip=on",
		"-cpu", "host",
		"-m", fmt.Sprintf("%d", d.Memory),
		"-smp", fmt.Sprintf("%d", d.CPU),
		"-qmp", fmt.Sprintf("unix:%s,server,nowait", d.monitorPath()),
		"-pidfile", d.pidfilePath(),
		"-fw_cfg", fmt.Sprintf("name=opt/com.coreos/config,file=%s", d.ignitionConfigPath()),
		"-object", "rng-random,filename=/dev/urandom,id=rng0",
		"-device", "virtio-rng-pci,rng=rng0",
	)

	if d.Network == "user" {
		startCmd = append(startCmd,
			"-net", "nic,model=virtio",
			"-net", fmt.Sprintf("user,hostfwd=tcp:%s:%d-:22,hostfwd=tcp:%s:%d-:2376,hostname=%s", d.LocalIP, d.SSHPort, d.LocalIP, d.EnginePort, d.GetMachineName()),
		)
	} else if d.Network == "tap" {
		startCmd = append(startCmd,
			"-net", "nic,model=virtio",
			"-net", fmt.Sprintf("tap,ifname=%s,script=no,downscript=no", d.NetworkInterface),
		)
	} else if d.Network == "bridge" {
		startCmd = append(startCmd,
			"-net", "nic,model=virtio",
			"-net", fmt.Sprintf("bridge,br=%s", d.NetworkBridge),
		)
	} else {
		log.Errorf("Unknown network: %s", d.Network)
	}

	startCmd = append(startCmd, "-daemonize")

	startCmd = append(startCmd,
		"-drive", fmt.Sprintf("file=%s,index=0,snapshot=on,if=virtio", d.DiskPath))

	if stdout, stderr, err := cmdOutErr(d.Program, d.TmpDir, startCmd...); err != nil {
		fmt.Printf("OUTPUT: %s\n", stdout)
		fmt.Printf("ERROR: %s\n", stderr)
		return err
		//if err := cmdStart(d.Program, startCmd...); err != nil {
		//	return err
	}
	log.Infof("Waiting for VM to start (ssh -p %d docker@%s)...", d.SSHPort, d.LocalIP)

	//return ssh.WaitForTCP(fmt.Sprintf("localhost:%d", d.SSHPort))
	return WaitForTCPWithDelay(fmt.Sprintf("%s:%d", d.LocalIP, d.SSHPort), time.Second)
}

func cmdOutErr(cmdStr, tempdir string, args ...string) (string, string, error) {
	cmd := exec.Command(cmdStr, args...)
	cmd.Env = append(os.Environ(), fmt.Sprintf("TMPDIR=%s", tempdir))
	log.Debugf("executing: %v %v", cmdStr, strings.Join(args, " "))
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	stderrStr := stderr.String()
	log.Debugf("STDOUT: %v", stdout.String())
	log.Debugf("STDERR: %v", stderrStr)
	if err != nil {
		if ee, ok := err.(*exec.Error); ok && ee == exec.ErrNotFound {
			err = fmt.Errorf("mystery error: %s", ee)
		}
	} else {
		// also catch error messages in stderr, even if the return code
		// looks OK
		if strings.Contains(stderrStr, "error:") {
			err = fmt.Errorf("%v %v failed: %v", cmdStr, strings.Join(args, " "), stderrStr)
		}
	}
	return stdout.String(), stderrStr, err
}

func cmdStart(cmdStr string, args ...string) error {
	cmd := exec.Command(cmdStr, args...)
	log.Debugf("executing: %v %v", cmdStr, strings.Join(args, " "))
	return cmd.Start()
}

func (d *Driver) Stop() error {
	// _, err := d.RunQMPCommand("stop")
	_, err := d.RunQMPCommand("system_powerdown")
	if err != nil {
		return err
	}
	return nil
}

func (d *Driver) Remove() error {
	s, err := d.GetState()
	if err != nil {
		return err
	}
	if s == state.Running {
		if err := d.Kill(); err != nil {
			return err
		}
	}
	if s != state.Stopped {
		_, err = d.RunQMPCommand("quit")
		if err != nil {
			return err
		}
	}
	return nil
}

func (d *Driver) Restart() error {
	s, err := d.GetState()
	if err != nil {
		return err
	}

	if s == state.Running {
		if err := d.Stop(); err != nil {
			return err
		}
	}
	return d.Start()
}

func (d *Driver) Kill() error {
	// _, err := d.RunQMPCommand("quit")
	_, err := d.RunQMPCommand("system_powerdown")
	if err != nil {
		return err
	}
	return nil
}

func (d *Driver) StartDocker() error {
	return fmt.Errorf("hosts without a driver cannot start docker")
}

func (d *Driver) StopDocker() error {
	return fmt.Errorf("hosts without a driver cannot stop docker")
}

func (d *Driver) GetDockerConfigDir() string {
	return ""
}

func (d *Driver) Upgrade() error {
	return fmt.Errorf("hosts without a driver cannot be upgraded")
}

//func (d *Driver) GetSSHCommand(args ...string) (*exec.Cmd, error) {
//	return ssh.GetSSHCommand("localhost", d.SSHPort, "docker", d.sshKeyPath(), args...), nil
//}

func (d *Driver) sshKeyPath() string {
	machineDir := filepath.Join(d.StorePath, "machines", d.GetMachineName())
	return filepath.Join(machineDir, "id_rsa")
}

func (d *Driver) publicSSHKeyPath() string {
	return d.sshKeyPath() + ".pub"
}

func (d *Driver) ignitionConfigPath() string {
	machineDir := filepath.Join(d.StorePath, "machines", d.GetMachineName())
	return filepath.Join(machineDir, "ignition.json")
}

func (d *Driver) monitorPath() string {
	machineDir := filepath.Join(d.StorePath, "machines", d.GetMachineName())
	return filepath.Join(machineDir, "monitor")
}

func (d *Driver) pidfilePath() string {
	machineDir := filepath.Join(d.StorePath, "machines", d.GetMachineName())
	return filepath.Join(machineDir, "qemu.pid")
}

func (d *Driver) generateIgnitionConfig() error {
	pubKey, err := ioutil.ReadFile(d.publicSSHKeyPath())
	if err != nil {
		return err
	}

	type ignitionConfigIgnition struct {
		Version string `json:"version"`
	}

	type ignitionConfigPasswdUser struct {
		Name string `json:"name"`
		SshAuthorizedKeys []string `json:"sshAuthorizedKeys"`
	}

	type ignitionConfigPasswd struct {
		Users []ignitionConfigPasswdUser `json:"users"`
	}

	type ignitionConfigSystemdUnit struct {
		Name string `json:"name"`
		Mask bool `json:"mask"`
	}

	type ignitionConfigSystemd struct {
		Units []ignitionConfigSystemdUnit `json:"units"`
	}

	type ignitionConfig struct {
		Ignition ignitionConfigIgnition `json:"ignition"`
		Passwd ignitionConfigPasswd `json:"passwd"`
		Systemd ignitionConfigSystemd `json:"systemd"`
	}

	config := ignitionConfig {
		Ignition: ignitionConfigIgnition { Version: "2.1.0" },
		Passwd: ignitionConfigPasswd {
			Users: []ignitionConfigPasswdUser {
				ignitionConfigPasswdUser {
					Name: defaultSSHUser,
					SshAuthorizedKeys: []string { string(pubKey) },
				},
			},
		},
		Systemd: ignitionConfigSystemd {
			Units: []ignitionConfigSystemdUnit {
				ignitionConfigSystemdUnit {
					Name: "locksmithd.service",
					Mask: true,
				},
				ignitionConfigSystemdUnit {
					Name: "update-engine.service",
					Mask: true,
				},
			},
		},
	}

	c, err := json.Marshal(config)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(d.ignitionConfigPath(), c, 0644)

	return err
}

func (d *Driver) RunQMPCommand(command string) (map[string]interface{}, error) {

	// connect to monitor
	conn, err := net.Dial("unix", d.monitorPath())
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// initial QMP response
	var buf [1024]byte
	nr, err := conn.Read(buf[:])
	if err != nil {
		return nil, err
	}
	type qmpInitialResponse struct {
		QMP struct {
			Version struct {
				QEMU struct {
					Micro int `json:"micro"`
					Minor int `json:"minor"`
					Major int `json:"major"`
				} `json:"qemu"`
				Package string `json:"package"`
			} `json:"version"`
			Capabilities []string `json:"capabilities"`
		} `jason:"QMP"`
	}

	var initialResponse qmpInitialResponse
	json.Unmarshal(buf[:nr], &initialResponse)

	// run 'qmp_capabilities' to switch to command mode
	// { "execute": "qmp_capabilities" }
	type qmpCommand struct {
		Command string `json:"execute"`
	}
	jsonCommand, err := json.Marshal(qmpCommand{Command: "qmp_capabilities"})
	if err != nil {
		return nil, err
	}
	_, err = conn.Write(jsonCommand)
	if err != nil {
		return nil, err
	}
	nr, err = conn.Read(buf[:])
	if err != nil {
		return nil, err
	}
	type qmpResponse struct {
		Return map[string]interface{} `json:"return"`
	}
	var response qmpResponse
	err = json.Unmarshal(buf[:nr], &response)
	if err != nil {
		return nil, err
	}
	// expecting empty response
	if len(response.Return) != 0 {
		return nil, fmt.Errorf("qmp_capabilities failed: %v", response.Return)
	}

	// { "execute": command }
	jsonCommand, err = json.Marshal(qmpCommand{Command: command})
	if err != nil {
		return nil, err
	}
	_, err = conn.Write(jsonCommand)
	if err != nil {
		return nil, err
	}
	nr, err = conn.Read(buf[:])
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(buf[:nr], &response)
	if err != nil {
		return nil, err
	}
	if strings.HasPrefix(command, "query-") {
		return response.Return, nil
	}
	// non-query commands should return an empty response
	if len(response.Return) != 0 {
		return nil, fmt.Errorf("%s failed: %v", command, response.Return)
	}
	return response.Return, nil
}

func WaitForTCPWithDelay(addr string, duration time.Duration) error {
	for {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			continue
		}
		defer conn.Close()
		if _, err = conn.Read(make([]byte, 1)); err != nil {
			time.Sleep(duration)
			continue
		}
		break
	}
	return nil
}
