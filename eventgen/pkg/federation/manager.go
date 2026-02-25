package federation

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"sync"
	"time"
)

type ClusterRole string

const (
	ClusterRoleHub        ClusterRole = "hub"
	ClusterRoleSpoke      ClusterRole = "spoke"
	ClusterRoleStandalone ClusterRole = "standalone"
)

type ClusterState string

const (
	ClusterStateHealthy     ClusterState = "healthy"
	ClusterStateDegraded    ClusterState = "degraded"
	ClusterStateUnreachable ClusterState = "unreachable"
	ClusterStatePending     ClusterState = "pending"
)

type Cluster struct {
	ID            string            `json:"id"`
	Name          string            `json:"name"`
	Role          ClusterRole       `json:"role"`
	State         ClusterState      `json:"state"`
	Endpoint      string            `json:"endpoint"`
	Region        string            `json:"region"`
	Provider      string            `json:"provider"`
	Version       string            `json:"version"`
	Labels        map[string]string `json:"labels"`
	Capabilities  []string          `json:"capabilities"`
	NodeCount     int               `json:"nodeCount"`
	PodCount      int               `json:"podCount"`
	PolicyCount   int               `json:"policyCount"`
	LastHeartbeat time.Time         `json:"lastHeartbeat"`
	LastSyncAt    time.Time         `json:"lastSyncAt"`
	Token         string            `json:"-"`
	CACert        []byte            `json:"-"`
}

type FederatedPolicy struct {
	ID              string                  `json:"id"`
	Name            string                  `json:"name"`
	Description     string                  `json:"description"`
	Version         int                     `json:"version"`
	PolicyType      string                  `json:"policyType"`
	Spec            map[string]interface{}  `json:"spec"`
	TargetClusters  []string                `json:"targetClusters,omitempty"`
	TargetLabels    map[string]string       `json:"targetLabels,omitempty"`
	ExcludeClusters []string                `json:"excludeClusters,omitempty"`
	CreatedAt       time.Time               `json:"createdAt"`
	UpdatedAt       time.Time               `json:"updatedAt"`
	SyncStatus      map[string]SyncStatus   `json:"syncStatus"`
}

type SyncStatus struct {
	ClusterID  string    `json:"clusterId"`
	State      SyncState `json:"state"`
	Version    int       `json:"version"`
	LastSyncAt time.Time `json:"lastSyncAt"`
	Error      string    `json:"error,omitempty"`
	Hash       string    `json:"hash"`
}

type SyncState string

const (
	SyncStatePending  SyncState = "pending"
	SyncStateSynced   SyncState = "synced"
	SyncStateFailed   SyncState = "failed"
	SyncStateConflict SyncState = "conflict"
)

type FederatedEvent struct {
	ID             string                 `json:"id"`
	ClusterID      string                 `json:"clusterId"`
	ClusterName    string                 `json:"clusterName"`
	Timestamp      time.Time              `json:"timestamp"`
	EventType      string                 `json:"eventType"`
	Severity       string                 `json:"severity"`
	Category       string                 `json:"category"`
	Namespace      string                 `json:"namespace"`
	PodName        string                 `json:"podName"`
	ContainerName  string                 `json:"containerName"`
	ProcessName    string                 `json:"processName"`
	Description    string                 `json:"description"`
	MitreTactic    string                 `json:"mitreTactic,omitempty"`
	MitreTechnique string                 `json:"mitreTechnique,omitempty"`
	RawEvent       map[string]interface{} `json:"rawEvent,omitempty"`
	Correlated     bool                   `json:"correlated"`
	CorrelationID  string                 `json:"correlationId,omitempty"`
}

type CrossClusterCorrelation struct {
	ID              string            `json:"id"`
	Timestamp       time.Time         `json:"timestamp"`
	Type            string            `json:"type"`
	Severity        string            `json:"severity"`
	Confidence      float64           `json:"confidence"`
	Clusters        []string          `json:"clusters"`
	Events          []*FederatedEvent `json:"events"`
	Description     string            `json:"description"`
	Recommendations []string          `json:"recommendations"`
}

type FederationManager struct {
	mu              sync.RWMutex
	localCluster    *Cluster
	role            ClusterRole
	spokes          map[string]*Cluster
	policies        map[string]*FederatedPolicy
	hubEndpoint     string
	hubToken        string
	events          []*FederatedEvent
	maxEvents       int
	correlations    []*CrossClusterCorrelation
	httpClient      *http.Client
	onPolicySync    func(policy *FederatedPolicy, cluster *Cluster, err error)
	onEvent         func(event *FederatedEvent)
	onCorrelation   func(correlation *CrossClusterCorrelation)
	totalSyncs      int64
	successfulSyncs int64
	failedSyncs     int64
}

func NewFederationManager(localCluster *Cluster) *FederationManager {
	return &FederationManager{
		localCluster: localCluster,
		role:         localCluster.Role,
		spokes:       make(map[string]*Cluster),
		policies:     make(map[string]*FederatedPolicy),
		events:       make([]*FederatedEvent, 0),
		maxEvents:    100000,
		correlations: make([]*CrossClusterCorrelation, 0),
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (m *FederationManager) SetCallbacks(
	onPolicySync func(*FederatedPolicy, *Cluster, error),
	onEvent func(*FederatedEvent),
	onCorrelation func(*CrossClusterCorrelation),
) {
	m.onPolicySync = onPolicySync
	m.onEvent = onEvent
	m.onCorrelation = onCorrelation
}

func (m *FederationManager) RegisterSpoke(spoke *Cluster) error {
	if m.role != ClusterRoleHub {
		return fmt.Errorf("only hub can register spokes")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	spoke.State = ClusterStatePending
	spoke.LastHeartbeat = time.Now()
	m.spokes[spoke.ID] = spoke

	fmt.Printf("[Federation] Registered spoke cluster: %s (%s)\n", spoke.Name, spoke.ID)
	return nil
}

func (m *FederationManager) UnregisterSpoke(clusterID string) error {
	if m.role != ClusterRoleHub {
		return fmt.Errorf("only hub can unregister spokes")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.spokes[clusterID]; !exists {
		return fmt.Errorf("cluster %s not found", clusterID)
	}

	delete(m.spokes, clusterID)
	fmt.Printf("[Federation] Unregistered spoke cluster: %s\n", clusterID)
	return nil
}
func (m *FederationManager) CreatePolicy(policy *FederatedPolicy) error {
	if m.role != ClusterRoleHub {
		return fmt.Errorf("only hub can create federated policies")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	policy.ID = fmt.Sprintf("fp-%d", time.Now().UnixNano())
	policy.Version = 1
	policy.CreatedAt = time.Now()
	policy.UpdatedAt = time.Now()
	policy.SyncStatus = make(map[string]SyncStatus)

	m.policies[policy.ID] = policy

	fmt.Printf("[Federation] Created federated policy: %s\n", policy.Name)
	return nil
}
func (m *FederationManager) UpdatePolicy(policyID string, spec map[string]interface{}) error {
	if m.role != ClusterRoleHub {
		return fmt.Errorf("only hub can update federated policies")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	policy, exists := m.policies[policyID]
	if !exists {
		return fmt.Errorf("policy %s not found", policyID)
	}

	policy.Spec = spec
	policy.Version++
	policy.UpdatedAt = time.Now()

	// Reset sync status for all clusters
	for clusterID := range policy.SyncStatus {
		policy.SyncStatus[clusterID] = SyncStatus{
			ClusterID: clusterID,
			State:     SyncStatePending,
		}
	}

	fmt.Printf("[Federation] Updated federated policy: %s (v%d)\n", policy.Name, policy.Version)
	return nil
}
func (m *FederationManager) SyncPolicies(ctx context.Context) error {
	if m.role != ClusterRoleHub {
		return fmt.Errorf("only hub can sync policies")
	}

	m.mu.RLock()
	policies := make([]*FederatedPolicy, 0, len(m.policies))
	for _, p := range m.policies {
		policies = append(policies, p)
	}
	spokes := make([]*Cluster, 0, len(m.spokes))
	for _, s := range m.spokes {
		spokes = append(spokes, s)
	}
	m.mu.RUnlock()

	for _, policy := range policies {
		targetSpokes := m.getTargetClusters(policy, spokes)
		for _, spoke := range targetSpokes {
			go m.syncPolicyToCluster(ctx, policy, spoke)
		}
	}

	return nil
}

func (m *FederationManager) getTargetClusters(policy *FederatedPolicy, spokes []*Cluster) []*Cluster {
	result := make([]*Cluster, 0)

	for _, spoke := range spokes {
		// Check exclusions
		excluded := false
		for _, excludeID := range policy.ExcludeClusters {
			if spoke.ID == excludeID {
				excluded = true
				break
			}
		}
		if excluded {
			continue
		}

		// Check target list
		if len(policy.TargetClusters) > 0 {
			targeted := false
			for _, targetID := range policy.TargetClusters {
				if spoke.ID == targetID {
					targeted = true
					break
				}
			}
			if !targeted {
				continue
			}
		}

		// Check label selector
		if len(policy.TargetLabels) > 0 {
			matches := true
			for key, value := range policy.TargetLabels {
				if spoke.Labels[key] != value {
					matches = false
					break
				}
			}
			if !matches {
				continue
			}
		}

		result = append(result, spoke)
	}

	return result
}

func (m *FederationManager) syncPolicyToCluster(ctx context.Context, policy *FederatedPolicy, cluster *Cluster) {
	m.mu.Lock()
	m.totalSyncs++
	m.mu.Unlock()

	// Prepare sync request
	syncReq := struct {
		PolicyID   string                 `json:"policyId"`
		PolicyName string                 `json:"policyName"`
		PolicyType string                 `json:"policyType"`
		Version    int                    `json:"version"`
		Spec       map[string]interface{} `json:"spec"`
		Hash       string                 `json:"hash"`
	}{
		PolicyID:   policy.ID,
		PolicyName: policy.Name,
		PolicyType: policy.PolicyType,
		Version:    policy.Version,
		Spec:       policy.Spec,
		Hash:       calculatePolicyHash(policy),
	}

	data, err := json.Marshal(syncReq)
	if err != nil {
		m.recordSyncFailure(policy, cluster, err)
		return
	}

	// Send to spoke cluster
	url := fmt.Sprintf("%s/api/v1/federation/policies/sync", cluster.Endpoint)
	req, err := http.NewRequestWithContext(ctx, "POST", url, nil)
	if err != nil {
		m.recordSyncFailure(policy, cluster, err)
		return
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", cluster.Token))
	req.Header.Set("X-Federation-Hub", m.localCluster.ID)
	req.Header.Set("Content-Length", fmt.Sprintf("%d", len(data)))

	resp, err := m.httpClient.Do(req)
	if err != nil {
		m.recordSyncFailure(policy, cluster, err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		m.recordSyncFailure(policy, cluster, fmt.Errorf("sync failed: %s - %s", resp.Status, string(body)))
		return
	}

	// Record success
	m.mu.Lock()
	m.successfulSyncs++
	policy.SyncStatus[cluster.ID] = SyncStatus{
		ClusterID:  cluster.ID,
		State:      SyncStateSynced,
		Version:    policy.Version,
		LastSyncAt: time.Now(),
		Hash:       syncReq.Hash,
	}
	m.mu.Unlock()

	if m.onPolicySync != nil {
		m.onPolicySync(policy, cluster, nil)
	}

	fmt.Printf("[Federation] Synced policy %s to cluster %s\n", policy.Name, cluster.Name)
}

func (m *FederationManager) recordSyncFailure(policy *FederatedPolicy, cluster *Cluster, err error) {
	m.mu.Lock()
	m.failedSyncs++
	policy.SyncStatus[cluster.ID] = SyncStatus{
		ClusterID:  cluster.ID,
		State:      SyncStateFailed,
		LastSyncAt: time.Now(),
		Error:      err.Error(),
	}
	m.mu.Unlock()

	if m.onPolicySync != nil {
		m.onPolicySync(policy, cluster, err)
	}

	fmt.Printf("[Federation] Failed to sync policy %s to cluster %s: %v\n", policy.Name, cluster.Name, err)
}

func (m *FederationManager) ConnectToHub(hubEndpoint, token string) error {
	if m.role != ClusterRoleSpoke {
		return fmt.Errorf("only spoke can connect to hub")
	}

	m.mu.Lock()
	m.hubEndpoint = hubEndpoint
	m.hubToken = token
	m.mu.Unlock()

	// Register with hub
	regReq := struct {
		Cluster *Cluster `json:"cluster"`
	}{
		Cluster: m.localCluster,
	}

	data, err := json.Marshal(regReq)
	if err != nil {
		return fmt.Errorf("failed to marshal registration: %w", err)
	}

	url := fmt.Sprintf("%s/api/v1/federation/clusters/register", hubEndpoint)
	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Content-Length", fmt.Sprintf("%d", len(data)))

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to register with hub: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("registration failed: %s - %s", resp.Status, string(body))
	}

	fmt.Printf("[Federation] Connected to hub: %s\n", hubEndpoint)
	return nil
}
func (m *FederationManager) SendHeartbeat(ctx context.Context) error {
	if m.role != ClusterRoleSpoke || m.hubEndpoint == "" {
		return nil
	}

	heartbeat := struct {
		ClusterID string       `json:"clusterId"`
		State     ClusterState `json:"state"`
		NodeCount int          `json:"nodeCount"`
		PodCount  int          `json:"podCount"`
		Timestamp time.Time    `json:"timestamp"`
	}{
		ClusterID: m.localCluster.ID,
		State:     m.localCluster.State,
		NodeCount: m.localCluster.NodeCount,
		PodCount:  m.localCluster.PodCount,
		Timestamp: time.Now(),
	}

	data, err := json.Marshal(heartbeat)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/api/v1/federation/clusters/%s/heartbeat", m.hubEndpoint, m.localCluster.ID)
	req, err := http.NewRequestWithContext(ctx, "POST", url, nil)
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", m.hubToken))
	req.Header.Set("Content-Length", fmt.Sprintf("%d", len(data)))

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}

func (m *FederationManager) ReceiveEvent(event *FederatedEvent) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.events = append(m.events, event)
	if len(m.events) > m.maxEvents {
		m.events = m.events[1:]
	}

	// Fire callback
	if m.onEvent != nil {
		go m.onEvent(event)
	}

	if m.role == ClusterRoleHub {
		go m.checkCrossClusterCorrelation(event)
	}
}
func (m *FederationManager) ForwardEventToHub(ctx context.Context, event *FederatedEvent) error {
	if m.role != ClusterRoleSpoke || m.hubEndpoint == "" {
		return nil
	}

	event.ClusterID = m.localCluster.ID
	event.ClusterName = m.localCluster.Name

	data, err := json.Marshal(event)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/api/v1/federation/events", m.hubEndpoint)
	req, err := http.NewRequestWithContext(ctx, "POST", url, nil)
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", m.hubToken))
	req.Header.Set("Content-Length", fmt.Sprintf("%d", len(data)))

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}

// checkCrossClusterCorrelation checks if recent events form a cross-cluster attack pattern.
func (m *FederationManager) checkCrossClusterCorrelation(newEvent *FederatedEvent) {
	m.mu.RLock()
	// Get events from the last hour
	cutoff := time.Now().Add(-1 * time.Hour)
	recentEvents := make([]*FederatedEvent, 0)
	for _, e := range m.events {
		if e.Timestamp.After(cutoff) {
			recentEvents = append(recentEvents, e)
		}
	}
	m.mu.RUnlock()

	// Check for multi-cluster attack patterns

	// Pattern 1: Same attack across multiple clusters (coordinated attack)
	clusters := make(map[string]bool)
	sameTypeEvents := make([]*FederatedEvent, 0)
	for _, e := range recentEvents {
		if e.EventType == newEvent.EventType && e.MitreTechnique == newEvent.MitreTechnique {
			clusters[e.ClusterID] = true
			sameTypeEvents = append(sameTypeEvents, e)
		}
	}

	if len(clusters) >= 2 {
		clusterList := make([]string, 0, len(clusters))
		for c := range clusters {
			clusterList = append(clusterList, c)
		}

		correlation := &CrossClusterCorrelation{
			ID:          fmt.Sprintf("cc-%d", time.Now().UnixNano()),
			Timestamp:   time.Now(),
			Type:        "coordinated-attack",
			Severity:    "critical",
			Confidence:  0.8,
			Clusters:    clusterList,
			Events:      sameTypeEvents,
			Description: fmt.Sprintf("Same attack pattern (%s) detected across %d clusters", newEvent.EventType, len(clusters)),
			Recommendations: []string{
				"Investigate if clusters share common attack surface",
				"Check for shared compromised credentials",
				"Review network segmentation between clusters",
				"Enable enhanced logging on all affected clusters",
			},
		}

		m.mu.Lock()
		m.correlations = append(m.correlations, correlation)
		m.mu.Unlock()

		if m.onCorrelation != nil {
			go m.onCorrelation(correlation)
		}
	}

	// Pattern 2: Attack chain across clusters (lateral movement)
	if newEvent.MitreTactic == "lateral-movement" || newEvent.MitreTactic == "TA0008" {
		// Look for preceding reconnaissance in another cluster
		for _, e := range recentEvents {
			if e.ClusterID != newEvent.ClusterID &&
				(e.MitreTactic == "discovery" || e.MitreTactic == "TA0007") &&
				e.Timestamp.Before(newEvent.Timestamp) {

				correlation := &CrossClusterCorrelation{
					ID:          fmt.Sprintf("cc-%d", time.Now().UnixNano()),
					Timestamp:   time.Now(),
					Type:        "cross-cluster-lateral-movement",
					Severity:    "critical",
					Confidence:  0.75,
					Clusters:    []string{e.ClusterID, newEvent.ClusterID},
					Events:      []*FederatedEvent{e, newEvent},
					Description: fmt.Sprintf("Potential lateral movement from %s to %s", e.ClusterName, newEvent.ClusterName),
					Recommendations: []string{
						"Isolate affected workloads in both clusters",
						"Review inter-cluster network policies",
						"Audit service mesh configurations",
						"Check for shared secrets or service accounts",
					},
				}

				m.mu.Lock()
				m.correlations = append(m.correlations, correlation)
				m.mu.Unlock()

				if m.onCorrelation != nil {
					go m.onCorrelation(correlation)
				}
				break
			}
		}
	}

	// Pattern 3: Crypto mining spread
	if newEvent.Category == "cryptominer" || newEvent.EventType == "crypto-miner-execution" {
		minerEvents := make([]*FederatedEvent, 0)
		minerClusters := make(map[string]bool)
		for _, e := range recentEvents {
			if e.Category == "cryptominer" || e.EventType == "crypto-miner-execution" {
				minerEvents = append(minerEvents, e)
				minerClusters[e.ClusterID] = true
			}
		}

		if len(minerClusters) >= 2 {
			clusterList := make([]string, 0, len(minerClusters))
			for c := range minerClusters {
				clusterList = append(clusterList, c)
			}

			correlation := &CrossClusterCorrelation{
				ID:          fmt.Sprintf("cc-%d", time.Now().UnixNano()),
				Timestamp:   time.Now(),
				Type:        "multi-cluster-cryptominer",
				Severity:    "high",
				Confidence:  0.9,
				Clusters:    clusterList,
				Events:      minerEvents,
				Description: fmt.Sprintf("Cryptominer detected across %d clusters - possible supply chain or image compromise", len(minerClusters)),
				Recommendations: []string{
					"Audit container images used across clusters",
					"Check for shared registries or base images",
					"Review admission policies for image signing",
					"Scan all running containers for similar miners",
				},
			}

			m.mu.Lock()
			m.correlations = append(m.correlations, correlation)
			m.mu.Unlock()

			if m.onCorrelation != nil {
				go m.onCorrelation(correlation)
			}
		}
	}
}

func (m *FederationManager) HandlePolicySync(w http.ResponseWriter, r *http.Request) {
	if m.role != ClusterRoleSpoke {
		http.Error(w, "not a spoke cluster", http.StatusBadRequest)
		return
	}

	var syncReq struct {
		PolicyID   string                 `json:"policyId"`
		PolicyName string                 `json:"policyName"`
		PolicyType string                 `json:"policyType"`
		Version    int                    `json:"version"`
		Spec       map[string]interface{} `json:"spec"`
		Hash       string                 `json:"hash"`
	}

	if err := json.NewDecoder(r.Body).Decode(&syncReq); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	// Store/update policy locally
	m.mu.Lock()
	m.policies[syncReq.PolicyID] = &FederatedPolicy{
		ID:         syncReq.PolicyID,
		Name:       syncReq.PolicyName,
		PolicyType: syncReq.PolicyType,
		Version:    syncReq.Version,
		Spec:       syncReq.Spec,
		UpdatedAt:  time.Now(),
	}
	m.mu.Unlock()

	fmt.Printf("[Federation] Received policy sync: %s (v%d)\n", syncReq.PolicyName, syncReq.Version)

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "synced"})
}
func (m *FederationManager) HandleRegister(w http.ResponseWriter, r *http.Request) {
	if m.role != ClusterRoleHub {
		http.Error(w, "not a hub cluster", http.StatusBadRequest)
		return
	}

	var regReq struct {
		Cluster *Cluster `json:"cluster"`
	}

	if err := json.NewDecoder(r.Body).Decode(&regReq); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	if err := m.RegisterSpoke(regReq.Cluster); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "registered"})
}
func (m *FederationManager) HandleHeartbeat(w http.ResponseWriter, r *http.Request) {
	if m.role != ClusterRoleHub {
		http.Error(w, "not a hub cluster", http.StatusBadRequest)
		return
	}

	clusterID := r.URL.Query().Get("clusterId")
	if clusterID == "" {
		http.Error(w, "missing clusterId", http.StatusBadRequest)
		return
	}

	var heartbeat struct {
		State     ClusterState `json:"state"`
		NodeCount int          `json:"nodeCount"`
		PodCount  int          `json:"podCount"`
	}

	if err := json.NewDecoder(r.Body).Decode(&heartbeat); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	m.mu.Lock()
	if spoke, exists := m.spokes[clusterID]; exists {
		spoke.State = heartbeat.State
		spoke.NodeCount = heartbeat.NodeCount
		spoke.PodCount = heartbeat.PodCount
		spoke.LastHeartbeat = time.Now()
	}
	m.mu.Unlock()

	w.WriteHeader(http.StatusOK)
}
func (m *FederationManager) HandleEventReceive(w http.ResponseWriter, r *http.Request) {
	if m.role != ClusterRoleHub {
		http.Error(w, "not a hub cluster", http.StatusBadRequest)
		return
	}

	var event FederatedEvent
	if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	m.ReceiveEvent(&event)

	w.WriteHeader(http.StatusOK)
}

func (m *FederationManager) GetClusters() []*Cluster {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]*Cluster, 0, len(m.spokes)+1)
	result = append(result, m.localCluster)
	for _, s := range m.spokes {
		result = append(result, s)
	}
	return result
}
func (m *FederationManager) GetPolicies() []*FederatedPolicy {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]*FederatedPolicy, 0, len(m.policies))
	for _, p := range m.policies {
		result = append(result, p)
	}
	return result
}
func (m *FederationManager) GetRecentEvents(limit int) []*FederatedEvent {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if limit <= 0 || limit > len(m.events) {
		limit = len(m.events)
	}

	result := make([]*FederatedEvent, limit)
	copy(result, m.events[len(m.events)-limit:])
	return result
}
func (m *FederationManager) GetCorrelations() []*CrossClusterCorrelation {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]*CrossClusterCorrelation, len(m.correlations))
	copy(result, m.correlations)
	return result
}
func (m *FederationManager) GetEventsByCluster(clusterID string, limit int) []*FederatedEvent {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]*FederatedEvent, 0)
	for i := len(m.events) - 1; i >= 0 && len(result) < limit; i-- {
		if m.events[i].ClusterID == clusterID {
			result = append(result, m.events[i])
		}
	}
	return result
}
func (m *FederationManager) GetEventTimeline(start, end time.Time) []*FederatedEvent {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]*FederatedEvent, 0)
	for _, e := range m.events {
		if e.Timestamp.After(start) && e.Timestamp.Before(end) {
			result = append(result, e)
		}
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].Timestamp.Before(result[j].Timestamp)
	})

	return result
}
func (m *FederationManager) Stats() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	healthyClusters := 0
	for _, s := range m.spokes {
		if s.State == ClusterStateHealthy {
			healthyClusters++
		}
	}

	return map[string]interface{}{
		"role":              m.role,
		"local_cluster":     m.localCluster.Name,
		"spoke_count":       len(m.spokes),
		"healthy_clusters":  healthyClusters,
		"policy_count":      len(m.policies),
		"event_count":       len(m.events),
		"correlation_count": len(m.correlations),
		"total_syncs":       m.totalSyncs,
		"successful_syncs":  m.successfulSyncs,
		"failed_syncs":      m.failedSyncs,
	}
}

// calculatePolicyHash calculates a hash of the policy spec for change detection.
func calculatePolicyHash(policy *FederatedPolicy) string {
	data, _ := json.Marshal(policy.Spec)
	hash := sha256.Sum256(data)
	return fmt.Sprintf("%x", hash[:8])
}
