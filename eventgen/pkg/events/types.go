package events

type SecurityEvent struct {
	ID          string
	Name        string
	Description string
	Category    string
	MITRE       []string
	Severity    string
	Privileged  bool
	Executor    func() error
}

type Category string

const (
	ContainerEscape    Category = "Container Escape"
	PrivilegeEscalation Category = "Privilege Escalation"
	CredentialAccess   Category = "Credential Access"
	CryptoMining       Category = "Crypto Mining"
	NetworkScanning    Category = "Network Scanning"
	C2Communication    Category = "C2 Communication"
	DefenseEvasion     Category = "Defense Evasion"
	Persistence        Category = "Persistence"
	Execution          Category = "Execution"
	Discovery          Category = "Discovery"
	LateralMovement    Category = "Lateral Movement"
	Collection         Category = "Collection"
	Impact             Category = "Impact"
)
