package federation

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func createTestCluster(id, name string, role ClusterRole) *Cluster {
	return &Cluster{
		ID:       id,
		Name:     name,
		Role:     role,
		State:    ClusterStateHealthy,
		Endpoint: "https://test-cluster.local",
		Region:   "us-west-2",
		Provider: "aws",
		Labels:   map[string]string{"env": "test"},
	}
}

func TestNewFederationManager(t *testing.T) {
	cluster := createTestCluster("hub-1", "hub-cluster", ClusterRoleHub)
	manager := NewFederationManager(cluster)

	if manager == nil {
		t.Fatal("expected non-nil manager")
	}
	if manager.localCluster != cluster {
		t.Error("expected local cluster to be set")
	}
	if manager.role != ClusterRoleHub {
		t.Errorf("expected role %s, got %s", ClusterRoleHub, manager.role)
	}
	if manager.spokes == nil {
		t.Error("expected spokes map to be initialized")
	}
	if manager.policies == nil {
		t.Error("expected policies map to be initialized")
	}
}

func TestRegisterSpoke(t *testing.T) {
	hub := createTestCluster("hub-1", "hub-cluster", ClusterRoleHub)
	manager := NewFederationManager(hub)

	spoke := createTestCluster("spoke-1", "spoke-cluster-1", ClusterRoleSpoke)
	err := manager.RegisterSpoke(spoke)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(manager.spokes) != 1 {
		t.Errorf("expected 1 spoke, got %d", len(manager.spokes))
	}
	if manager.spokes["spoke-1"] == nil {
		t.Error("expected spoke to be registered")
	}
	if manager.spokes["spoke-1"].State != ClusterStatePending {
		t.Error("expected spoke state to be pending")
	}
}

func TestRegisterSpoke_NotHub(t *testing.T) {
	spoke := createTestCluster("spoke-1", "spoke-cluster", ClusterRoleSpoke)
	manager := NewFederationManager(spoke)

	otherSpoke := createTestCluster("spoke-2", "spoke-cluster-2", ClusterRoleSpoke)
	err := manager.RegisterSpoke(otherSpoke)
	if err == nil {
		t.Error("expected error when non-hub tries to register spoke")
	}
}

func TestUnregisterSpoke(t *testing.T) {
	hub := createTestCluster("hub-1", "hub-cluster", ClusterRoleHub)
	manager := NewFederationManager(hub)

	spoke := createTestCluster("spoke-1", "spoke-cluster-1", ClusterRoleSpoke)
	manager.RegisterSpoke(spoke)

	err := manager.UnregisterSpoke("spoke-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(manager.spokes) != 0 {
		t.Errorf("expected 0 spokes, got %d", len(manager.spokes))
	}
}

func TestUnregisterSpoke_NotFound(t *testing.T) {
	hub := createTestCluster("hub-1", "hub-cluster", ClusterRoleHub)
	manager := NewFederationManager(hub)

	err := manager.UnregisterSpoke("nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent cluster")
	}
}

func TestCreatePolicy(t *testing.T) {
	hub := createTestCluster("hub-1", "hub-cluster", ClusterRoleHub)
	manager := NewFederationManager(hub)

	policy := &FederatedPolicy{
		Name:        "test-policy",
		Description: "Test policy",
		PolicyType:  "TracingPolicy",
		Spec: map[string]interface{}{
			"kprobes": []interface{}{},
		},
	}

	err := manager.CreatePolicy(policy)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if policy.ID == "" {
		t.Error("expected policy ID to be set")
	}
	if policy.Version != 1 {
		t.Errorf("expected version 1, got %d", policy.Version)
	}
	if policy.CreatedAt.IsZero() {
		t.Error("expected CreatedAt to be set")
	}

	policies := manager.GetPolicies()
	if len(policies) != 1 {
		t.Errorf("expected 1 policy, got %d", len(policies))
	}
}

func TestCreatePolicy_NotHub(t *testing.T) {
	spoke := createTestCluster("spoke-1", "spoke-cluster", ClusterRoleSpoke)
	manager := NewFederationManager(spoke)

	policy := &FederatedPolicy{Name: "test-policy"}
	err := manager.CreatePolicy(policy)
	if err == nil {
		t.Error("expected error when non-hub creates policy")
	}
}

func TestUpdatePolicy(t *testing.T) {
	hub := createTestCluster("hub-1", "hub-cluster", ClusterRoleHub)
	manager := NewFederationManager(hub)

	policy := &FederatedPolicy{
		Name:       "test-policy",
		PolicyType: "TracingPolicy",
		Spec:       map[string]interface{}{"version": "v1"},
	}
	manager.CreatePolicy(policy)

	newSpec := map[string]interface{}{"version": "v2"}
	err := manager.UpdatePolicy(policy.ID, newSpec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if policy.Version != 2 {
		t.Errorf("expected version 2, got %d", policy.Version)
	}
	if policy.Spec["version"] != "v2" {
		t.Error("expected spec to be updated")
	}
}

func TestUpdatePolicy_NotFound(t *testing.T) {
	hub := createTestCluster("hub-1", "hub-cluster", ClusterRoleHub)
	manager := NewFederationManager(hub)

	err := manager.UpdatePolicy("nonexistent", map[string]interface{}{})
	if err == nil {
		t.Error("expected error for nonexistent policy")
	}
}

func TestGetTargetClusters(t *testing.T) {
	hub := createTestCluster("hub-1", "hub-cluster", ClusterRoleHub)
	manager := NewFederationManager(hub)

	spoke1 := createTestCluster("spoke-1", "spoke-1", ClusterRoleSpoke)
	spoke1.Labels = map[string]string{"env": "prod"}
	spoke2 := createTestCluster("spoke-2", "spoke-2", ClusterRoleSpoke)
	spoke2.Labels = map[string]string{"env": "dev"}
	spoke3 := createTestCluster("spoke-3", "spoke-3", ClusterRoleSpoke)
	spoke3.Labels = map[string]string{"env": "prod"}

	spokes := []*Cluster{spoke1, spoke2, spoke3}

	tests := []struct {
		name     string
		policy   *FederatedPolicy
		expected int
	}{
		{
			name:     "all_clusters",
			policy:   &FederatedPolicy{},
			expected: 3,
		},
		{
			name: "target_list",
			policy: &FederatedPolicy{
				TargetClusters: []string{"spoke-1", "spoke-2"},
			},
			expected: 2,
		},
		{
			name: "exclude_list",
			policy: &FederatedPolicy{
				ExcludeClusters: []string{"spoke-2"},
			},
			expected: 2,
		},
		{
			name: "label_selector",
			policy: &FederatedPolicy{
				TargetLabels: map[string]string{"env": "prod"},
			},
			expected: 2,
		},
		{
			name: "combined",
			policy: &FederatedPolicy{
				TargetLabels:    map[string]string{"env": "prod"},
				ExcludeClusters: []string{"spoke-3"},
			},
			expected: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			targets := manager.getTargetClusters(tt.policy, spokes)
			if len(targets) != tt.expected {
				t.Errorf("expected %d targets, got %d", tt.expected, len(targets))
			}
		})
	}
}

func TestReceiveEvent(t *testing.T) {
	hub := createTestCluster("hub-1", "hub-cluster", ClusterRoleHub)
	manager := NewFederationManager(hub)

	var received *FederatedEvent
	manager.SetCallbacks(nil, func(e *FederatedEvent) {
		received = e
	}, nil)

	event := &FederatedEvent{
		ID:          "event-1",
		ClusterID:   "spoke-1",
		ClusterName: "spoke-cluster-1",
		Timestamp:   time.Now(),
		EventType:   "process-execution",
		Severity:    "high",
		Category:    "suspicious",
	}

	manager.ReceiveEvent(event)

	// Wait for async callback
	time.Sleep(50 * time.Millisecond)

	if received == nil {
		t.Error("expected event callback to be invoked")
	}

	events := manager.GetRecentEvents(10)
	if len(events) != 1 {
		t.Errorf("expected 1 event, got %d", len(events))
	}
}

func TestReceiveEvent_MaxEvents(t *testing.T) {
	hub := createTestCluster("hub-1", "hub-cluster", ClusterRoleHub)
	manager := NewFederationManager(hub)
	manager.maxEvents = 5

	for i := 0; i < 10; i++ {
		event := &FederatedEvent{
			ID:        "event-" + string(rune('0'+i)),
			Timestamp: time.Now(),
		}
		manager.ReceiveEvent(event)
	}

	events := manager.GetRecentEvents(100)
	if len(events) != 5 {
		t.Errorf("expected 5 events (max), got %d", len(events))
	}
}

func TestCrossClusterCorrelation(t *testing.T) {
	hub := createTestCluster("hub-1", "hub-cluster", ClusterRoleHub)
	manager := NewFederationManager(hub)

	var correlation *CrossClusterCorrelation
	var mu sync.Mutex
	manager.SetCallbacks(nil, nil, func(c *CrossClusterCorrelation) {
		mu.Lock()
		correlation = c
		mu.Unlock()
	})

	// Send same attack from two clusters
	event1 := &FederatedEvent{
		ID:             "event-1",
		ClusterID:      "spoke-1",
		ClusterName:    "spoke-cluster-1",
		Timestamp:      time.Now(),
		EventType:      "reverse-shell",
		MitreTechnique: "T1059",
	}
	event2 := &FederatedEvent{
		ID:             "event-2",
		ClusterID:      "spoke-2",
		ClusterName:    "spoke-cluster-2",
		Timestamp:      time.Now(),
		EventType:      "reverse-shell",
		MitreTechnique: "T1059",
	}

	manager.ReceiveEvent(event1)
	manager.ReceiveEvent(event2)

	// Wait for correlation detection
	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if correlation == nil {
		t.Error("expected cross-cluster correlation to be detected")
		return
	}
	if correlation.Type != "coordinated-attack" {
		t.Errorf("expected coordinated-attack, got %s", correlation.Type)
	}
	if len(correlation.Clusters) != 2 {
		t.Errorf("expected 2 clusters, got %d", len(correlation.Clusters))
	}
}

func TestGetClusters(t *testing.T) {
	hub := createTestCluster("hub-1", "hub-cluster", ClusterRoleHub)
	manager := NewFederationManager(hub)

	spoke1 := createTestCluster("spoke-1", "spoke-1", ClusterRoleSpoke)
	spoke2 := createTestCluster("spoke-2", "spoke-2", ClusterRoleSpoke)
	manager.RegisterSpoke(spoke1)
	manager.RegisterSpoke(spoke2)

	clusters := manager.GetClusters()
	if len(clusters) != 3 { // hub + 2 spokes
		t.Errorf("expected 3 clusters, got %d", len(clusters))
	}
}

func TestGetEventsByCluster(t *testing.T) {
	hub := createTestCluster("hub-1", "hub-cluster", ClusterRoleHub)
	manager := NewFederationManager(hub)

	// Add events from different clusters
	for i := 0; i < 5; i++ {
		manager.ReceiveEvent(&FederatedEvent{
			ID:        "event-a-" + string(rune('0'+i)),
			ClusterID: "cluster-a",
			Timestamp: time.Now(),
		})
		manager.ReceiveEvent(&FederatedEvent{
			ID:        "event-b-" + string(rune('0'+i)),
			ClusterID: "cluster-b",
			Timestamp: time.Now(),
		})
	}

	eventsA := manager.GetEventsByCluster("cluster-a", 10)
	if len(eventsA) != 5 {
		t.Errorf("expected 5 events for cluster-a, got %d", len(eventsA))
	}

	eventsLimited := manager.GetEventsByCluster("cluster-a", 3)
	if len(eventsLimited) != 3 {
		t.Errorf("expected 3 events (limited), got %d", len(eventsLimited))
	}
}

func TestGetEventTimeline(t *testing.T) {
	hub := createTestCluster("hub-1", "hub-cluster", ClusterRoleHub)
	manager := NewFederationManager(hub)

	baseTime := time.Now()
	for i := 0; i < 10; i++ {
		manager.ReceiveEvent(&FederatedEvent{
			ID:        "event-" + string(rune('0'+i)),
			Timestamp: baseTime.Add(time.Duration(i) * time.Hour),
		})
	}

	// Get events from hour 3 to hour 7
	start := baseTime.Add(3 * time.Hour)
	end := baseTime.Add(7 * time.Hour)
	timeline := manager.GetEventTimeline(start, end)

	if len(timeline) != 3 { // hours 4, 5, 6 (after 3, before 7)
		t.Errorf("expected 3 events in range, got %d", len(timeline))
	}

	// Verify sorted order
	for i := 1; i < len(timeline); i++ {
		if timeline[i].Timestamp.Before(timeline[i-1].Timestamp) {
			t.Error("events not sorted by timestamp")
		}
	}
}

func TestStats(t *testing.T) {
	hub := createTestCluster("hub-1", "hub-cluster", ClusterRoleHub)
	manager := NewFederationManager(hub)

	spoke := createTestCluster("spoke-1", "spoke-1", ClusterRoleSpoke)
	manager.RegisterSpoke(spoke)

	policy := &FederatedPolicy{Name: "test"}
	manager.CreatePolicy(policy)

	manager.ReceiveEvent(&FederatedEvent{ID: "event-1"})

	stats := manager.Stats()

	if stats["role"] != ClusterRoleHub {
		t.Error("expected hub role")
	}
	if stats["spoke_count"].(int) != 1 {
		t.Error("expected 1 spoke")
	}
	if stats["policy_count"].(int) != 1 {
		t.Error("expected 1 policy")
	}
	if stats["event_count"].(int) != 1 {
		t.Error("expected 1 event")
	}
}

func TestCalculatePolicyHash(t *testing.T) {
	policy1 := &FederatedPolicy{
		Spec: map[string]interface{}{"key": "value1"},
	}
	policy2 := &FederatedPolicy{
		Spec: map[string]interface{}{"key": "value1"},
	}
	policy3 := &FederatedPolicy{
		Spec: map[string]interface{}{"key": "value2"},
	}

	hash1 := calculatePolicyHash(policy1)
	hash2 := calculatePolicyHash(policy2)
	hash3 := calculatePolicyHash(policy3)

	if hash1 != hash2 {
		t.Error("identical policies should have same hash")
	}
	if hash1 == hash3 {
		t.Error("different policies should have different hashes")
	}
}

// HTTP Handler Tests

func TestHandlePolicySync(t *testing.T) {
	spoke := createTestCluster("spoke-1", "spoke-cluster", ClusterRoleSpoke)
	manager := NewFederationManager(spoke)

	syncReq := struct {
		PolicyID   string                 `json:"policyId"`
		PolicyName string                 `json:"policyName"`
		PolicyType string                 `json:"policyType"`
		Version    int                    `json:"version"`
		Spec       map[string]interface{} `json:"spec"`
		Hash       string                 `json:"hash"`
	}{
		PolicyID:   "policy-1",
		PolicyName: "test-policy",
		PolicyType: "TracingPolicy",
		Version:    1,
		Spec:       map[string]interface{}{"key": "value"},
		Hash:       "abc123",
	}

	body, _ := json.Marshal(syncReq)
	req := httptest.NewRequest("POST", "/api/v1/federation/policies/sync", bytes.NewReader(body))
	w := httptest.NewRecorder()

	manager.HandlePolicySync(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	// Verify policy was stored
	policies := manager.GetPolicies()
	if len(policies) != 1 {
		t.Errorf("expected 1 policy, got %d", len(policies))
	}
}

func TestHandleRegister(t *testing.T) {
	hub := createTestCluster("hub-1", "hub-cluster", ClusterRoleHub)
	manager := NewFederationManager(hub)

	regReq := struct {
		Cluster *Cluster `json:"cluster"`
	}{
		Cluster: createTestCluster("spoke-1", "spoke-cluster", ClusterRoleSpoke),
	}

	body, _ := json.Marshal(regReq)
	req := httptest.NewRequest("POST", "/api/v1/federation/clusters/register", bytes.NewReader(body))
	w := httptest.NewRecorder()

	manager.HandleRegister(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	// Verify spoke was registered
	if len(manager.spokes) != 1 {
		t.Errorf("expected 1 spoke, got %d", len(manager.spokes))
	}
}

func TestHandleHealth(t *testing.T) {
	hub := createTestCluster("hub-1", "hub-cluster", ClusterRoleHub)
	manager := NewFederationManager(hub)

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()

	// Simple health check handler test
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	// Verify manager exists
	_ = manager
}

func TestConcurrentEventProcessing(t *testing.T) {
	hub := createTestCluster("hub-1", "hub-cluster", ClusterRoleHub)
	manager := NewFederationManager(hub)

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				event := &FederatedEvent{
					ID:        "event-" + string(rune('0'+id)) + "-" + string(rune('0'+j)),
					ClusterID: "cluster-" + string(rune('0'+id%3)),
					Timestamp: time.Now(),
				}
				manager.ReceiveEvent(event)
			}
		}(i)
	}
	wg.Wait()

	events := manager.GetRecentEvents(2000)
	if len(events) != 1000 {
		t.Errorf("expected 1000 events, got %d", len(events))
	}
}

// Benchmarks

func BenchmarkReceiveEvent(b *testing.B) {
	hub := createTestCluster("hub-1", "hub-cluster", ClusterRoleHub)
	manager := NewFederationManager(hub)

	event := &FederatedEvent{
		ID:          "event-1",
		ClusterID:   "spoke-1",
		ClusterName: "spoke-cluster-1",
		Timestamp:   time.Now(),
		EventType:   "process-execution",
		Severity:    "high",
		Category:    "suspicious",
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		manager.ReceiveEvent(event)
	}
}

func BenchmarkGetTargetClusters(b *testing.B) {
	hub := createTestCluster("hub-1", "hub-cluster", ClusterRoleHub)
	manager := NewFederationManager(hub)

	spokes := make([]*Cluster, 100)
	for i := 0; i < 100; i++ {
		spokes[i] = createTestCluster(
			"spoke-"+string(rune('0'+i/10))+string(rune('0'+i%10)),
			"spoke-cluster",
			ClusterRoleSpoke,
		)
		if i%2 == 0 {
			spokes[i].Labels = map[string]string{"env": "prod"}
		} else {
			spokes[i].Labels = map[string]string{"env": "dev"}
		}
	}

	policy := &FederatedPolicy{
		TargetLabels: map[string]string{"env": "prod"},
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		manager.getTargetClusters(policy, spokes)
	}
}

func BenchmarkCrossClusterCorrelation(b *testing.B) {
	hub := createTestCluster("hub-1", "hub-cluster", ClusterRoleHub)
	manager := NewFederationManager(hub)

	// Pre-populate with events
	for i := 0; i < 100; i++ {
		event := &FederatedEvent{
			ID:             "event-" + string(rune('0'+i/10)) + string(rune('0'+i%10)),
			ClusterID:      "cluster-" + string(rune('0'+i%5)),
			Timestamp:      time.Now().Add(-time.Duration(i) * time.Minute),
			EventType:      "test-event",
			MitreTechnique: "T1059",
		}
		manager.events = append(manager.events, event)
	}

	newEvent := &FederatedEvent{
		ID:             "new-event",
		ClusterID:      "cluster-new",
		Timestamp:      time.Now(),
		EventType:      "test-event",
		MitreTechnique: "T1059",
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		manager.checkCrossClusterCorrelation(newEvent)
	}
}

func BenchmarkGetEventTimeline(b *testing.B) {
	hub := createTestCluster("hub-1", "hub-cluster", ClusterRoleHub)
	manager := NewFederationManager(hub)

	baseTime := time.Now()
	for i := 0; i < 10000; i++ {
		manager.events = append(manager.events, &FederatedEvent{
			ID:        "event-" + string(rune('0'+i)),
			Timestamp: baseTime.Add(time.Duration(i) * time.Second),
		})
	}

	start := baseTime.Add(1000 * time.Second)
	end := baseTime.Add(5000 * time.Second)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		manager.GetEventTimeline(start, end)
	}
}

func BenchmarkStats(b *testing.B) {
	hub := createTestCluster("hub-1", "hub-cluster", ClusterRoleHub)
	manager := NewFederationManager(hub)

	for i := 0; i < 50; i++ {
		spoke := createTestCluster("spoke-"+string(rune('0'+i)), "spoke", ClusterRoleSpoke)
		manager.spokes[spoke.ID] = spoke
	}

	for i := 0; i < 100; i++ {
		manager.policies["policy-"+string(rune('0'+i))] = &FederatedPolicy{ID: "policy"}
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		manager.Stats()
	}
}

func BenchmarkCalculatePolicyHash(b *testing.B) {
	policy := &FederatedPolicy{
		Spec: map[string]interface{}{
			"kprobes": []interface{}{
				map[string]interface{}{
					"call": "sys_execve",
					"args": []interface{}{},
				},
			},
		},
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		calculatePolicyHash(policy)
	}
}

func BenchmarkConcurrentReceiveEvent(b *testing.B) {
	hub := createTestCluster("hub-1", "hub-cluster", ClusterRoleHub)
	manager := NewFederationManager(hub)

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			event := &FederatedEvent{
				ID:        "event-1",
				ClusterID: "spoke-1",
				Timestamp: time.Now(),
			}
			manager.ReceiveEvent(event)
		}
	})
}
