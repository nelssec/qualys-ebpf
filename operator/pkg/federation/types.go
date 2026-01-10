package federation

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// FederatedCluster represents a cluster in the federation.
// This CRD is used on the hub cluster to manage spoke clusters.
type FederatedCluster struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   FederatedClusterSpec   `json:"spec,omitempty"`
	Status FederatedClusterStatus `json:"status,omitempty"`
}

// FederatedClusterSpec defines the desired state of FederatedCluster.
type FederatedClusterSpec struct {
	// Endpoint is the API server endpoint of the cluster.
	Endpoint string `json:"endpoint"`

	// Region is the geographic region of the cluster.
	// +optional
	Region string `json:"region,omitempty"`

	// Provider is the cloud provider (aws, gcp, azure, on-prem).
	// +optional
	Provider string `json:"provider,omitempty"`

	// SecretRef references a secret containing connection credentials.
	SecretRef SecretReference `json:"secretRef"`

	// PolicySelectors determines which policies are distributed to this cluster.
	// +optional
	PolicySelectors []PolicySelector `json:"policySelectors,omitempty"`

	// Paused indicates if policy sync is paused for this cluster.
	// +optional
	Paused bool `json:"paused,omitempty"`
}

// SecretReference references a Kubernetes secret.
type SecretReference struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	// Key containing the service account token
	TokenKey string `json:"tokenKey,omitempty"`
	// Key containing the CA certificate
	CAKey string `json:"caKey,omitempty"`
}

// PolicySelector selects policies for distribution.
type PolicySelector struct {
	// MatchLabels matches policies by label.
	// +optional
	MatchLabels map[string]string `json:"matchLabels,omitempty"`

	// MatchExpressions matches policies by label expressions.
	// +optional
	MatchExpressions []metav1.LabelSelectorRequirement `json:"matchExpressions,omitempty"`
}

// FederatedClusterStatus defines the observed state of FederatedCluster.
type FederatedClusterStatus struct {
	// State is the current state of the cluster.
	State ClusterState `json:"state,omitempty"`

	// LastHeartbeat is the timestamp of the last heartbeat.
	LastHeartbeat metav1.Time `json:"lastHeartbeat,omitempty"`

	// LastSyncTime is the timestamp of the last successful sync.
	LastSyncTime metav1.Time `json:"lastSyncTime,omitempty"`

	// KubernetesVersion is the version of the cluster.
	KubernetesVersion string `json:"kubernetesVersion,omitempty"`

	// NodeCount is the number of nodes in the cluster.
	NodeCount int `json:"nodeCount,omitempty"`

	// PodCount is the number of pods in the cluster.
	PodCount int `json:"podCount,omitempty"`

	// SyncedPolicies is the number of successfully synced policies.
	SyncedPolicies int `json:"syncedPolicies,omitempty"`

	// Conditions represent the latest available observations.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// FederatedClusterList contains a list of FederatedCluster.
type FederatedClusterList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []FederatedCluster `json:"items"`
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// FederatedTracingPolicy represents a TracingPolicy that is distributed across clusters.
type FederatedTracingPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   FederatedTracingPolicySpec   `json:"spec,omitempty"`
	Status FederatedTracingPolicyStatus `json:"status,omitempty"`
}

// FederatedTracingPolicySpec defines the desired state of FederatedTracingPolicy.
type FederatedTracingPolicySpec struct {
	// Template contains the TracingPolicy spec to distribute.
	Template TracingPolicyTemplate `json:"template"`

	// Placement determines which clusters receive this policy.
	Placement PlacementSpec `json:"placement,omitempty"`

	// Overrides allows cluster-specific customizations.
	// +optional
	Overrides []ClusterOverride `json:"overrides,omitempty"`
}

// TracingPolicyTemplate contains the TracingPolicy spec.
type TracingPolicyTemplate struct {
	// Metadata for the generated TracingPolicy.
	// +optional
	Metadata metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec is the TracingPolicy spec.
	Spec map[string]interface{} `json:"spec"`
}

// PlacementSpec determines policy placement.
type PlacementSpec struct {
	// ClusterSelector selects clusters by labels.
	// +optional
	ClusterSelector *metav1.LabelSelector `json:"clusterSelector,omitempty"`

	// Clusters explicitly lists target cluster names.
	// +optional
	Clusters []string `json:"clusters,omitempty"`

	// ExcludedClusters lists clusters to exclude.
	// +optional
	ExcludedClusters []string `json:"excludedClusters,omitempty"`
}

// ClusterOverride allows per-cluster policy customization.
type ClusterOverride struct {
	// ClusterName is the name of the target cluster.
	ClusterName string `json:"clusterName"`

	// Patches are JSON patches to apply to the policy.
	// +optional
	Patches []JSONPatch `json:"patches,omitempty"`

	// Disabled indicates the policy should not be deployed to this cluster.
	// +optional
	Disabled bool `json:"disabled,omitempty"`
}

// JSONPatch represents a JSON patch operation.
type JSONPatch struct {
	Op    string      `json:"op"`
	Path  string      `json:"path"`
	Value interface{} `json:"value,omitempty"`
}

// FederatedTracingPolicyStatus defines the observed state.
type FederatedTracingPolicyStatus struct {
	// ObservedGeneration is the generation observed by the controller.
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// ClusterStatuses contains per-cluster sync status.
	ClusterStatuses []ClusterPolicyStatus `json:"clusterStatuses,omitempty"`

	// Conditions represent the latest available observations.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// ClusterPolicyStatus represents the status of a policy on a cluster.
type ClusterPolicyStatus struct {
	ClusterName   string      `json:"clusterName"`
	State         SyncState   `json:"state"`
	Version       string      `json:"version,omitempty"`
	LastSyncTime  metav1.Time `json:"lastSyncTime,omitempty"`
	Message       string      `json:"message,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// FederatedTracingPolicyList contains a list of FederatedTracingPolicy.
type FederatedTracingPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []FederatedTracingPolicy `json:"items"`
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// FederatedNetworkPolicy represents a CiliumNetworkPolicy distributed across clusters.
type FederatedNetworkPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   FederatedNetworkPolicySpec   `json:"spec,omitempty"`
	Status FederatedNetworkPolicyStatus `json:"status,omitempty"`
}

// FederatedNetworkPolicySpec defines the desired state.
type FederatedNetworkPolicySpec struct {
	// Template contains the CiliumNetworkPolicy spec.
	Template NetworkPolicyTemplate `json:"template"`

	// Placement determines which clusters receive this policy.
	Placement PlacementSpec `json:"placement,omitempty"`

	// Overrides allows cluster-specific customizations.
	// +optional
	Overrides []ClusterOverride `json:"overrides,omitempty"`
}

// NetworkPolicyTemplate contains the network policy spec.
type NetworkPolicyTemplate struct {
	// Metadata for the generated policy.
	// +optional
	Metadata metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec is the CiliumNetworkPolicy spec.
	Spec map[string]interface{} `json:"spec"`
}

// FederatedNetworkPolicyStatus defines the observed state.
type FederatedNetworkPolicyStatus struct {
	// ObservedGeneration is the generation observed by the controller.
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// ClusterStatuses contains per-cluster sync status.
	ClusterStatuses []ClusterPolicyStatus `json:"clusterStatuses,omitempty"`

	// Conditions represent the latest available observations.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// FederatedNetworkPolicyList contains a list of FederatedNetworkPolicy.
type FederatedNetworkPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []FederatedNetworkPolicy `json:"items"`
}

// Condition types for federation resources
const (
	// ConditionTypeReady indicates the resource is ready.
	ConditionTypeReady = "Ready"

	// ConditionTypeSynced indicates the resource is synced to all clusters.
	ConditionTypeSynced = "Synced"

	// ConditionTypeDegraded indicates the resource is partially working.
	ConditionTypeDegraded = "Degraded"
)

// Condition reasons
const (
	ReasonSyncSuccess    = "SyncSuccess"
	ReasonSyncFailed     = "SyncFailed"
	ReasonClusterUnreachable = "ClusterUnreachable"
	ReasonPolicyConflict = "PolicyConflict"
	ReasonValidationFailed = "ValidationFailed"
)
