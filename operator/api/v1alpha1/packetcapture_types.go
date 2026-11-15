/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// CaptureMode selects where packets are captured.
// +kubebuilder:validation:Enum=Pod;Node
type CaptureMode string

const (
	// CaptureModePod captures inside each target pod's network namespace (the pod's own view:
	// pod IPs, no overlay encapsulation, includes same-node pod-to-pod traffic).
	CaptureModePod CaptureMode = "Pod"
	// CaptureModeNode captures on a node interface in the host network namespace (node-to-node
	// traffic; pod traffic may be encapsulated / SNATed depending on the CNI).
	CaptureModeNode CaptureMode = "Node"
)

// PodTarget selects pods in the PacketCapture's own namespace.
type PodTarget struct {
	// selector matches pods in the same namespace as the PacketCapture.
	// +required
	Selector metav1.LabelSelector `json:"selector"`

	// maxPods caps how many matching pods are captured (running pods, sorted by name).
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=20
	// +kubebuilder:default=5
	// +optional
	MaxPods int32 `json:"maxPods,omitempty"`

	// interface inside the pod network namespace. Empty = the interface that holds the pod IP.
	// +optional
	Interface string `json:"interface,omitempty"`
}

// NodeTarget selects nodes. Exactly one of nodeNames / selector should be set.
type NodeTarget struct {
	// nodeNames lists nodes explicitly.
	// +optional
	NodeNames []string `json:"nodeNames,omitempty"`

	// selector matches nodes by label.
	// +optional
	Selector *metav1.LabelSelector `json:"selector,omitempty"`

	// maxNodes caps how many matching nodes are captured (sorted by name).
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=20
	// +kubebuilder:default=3
	// +optional
	MaxNodes int32 `json:"maxNodes,omitempty"`

	// interface on the node. Empty = the interface of the default route. "any" captures every
	// interface (beware: pod traffic is then seen several times — veth, bridge, uplink).
	// +optional
	Interface string `json:"interface,omitempty"`
}

// AnalysisSpec says where the captured pcaps are sent in pcap-analyzer.
type AnalysisSpec struct {
	// analysisId is the pcap-analyzer analysis the runs are submitted to.
	// +kubebuilder:validation:Minimum=1
	// +required
	AnalysisID int64 `json:"analysisId"`

	// question for the LLM (the analysis's main question for this capture).
	// +kubebuilder:validation:MinLength=1
	// +required
	Question string `json:"question"`

	// description of the capture, passed to the LLM as context.
	// +optional
	Description string `json:"description,omitempty"`

	// provider is the LLM used by pcap-analyzer.
	// +kubebuilder:validation:Enum=claude;local
	// +kubebuilder:default=claude
	// +optional
	Provider string `json:"provider,omitempty"`

	// dryRun skips the LLM; only zeek/tshark parsing is done.
	// +optional
	DryRun bool `json:"dryRun,omitempty"`

	// comparePrevious gives earlier runs of the same analysis to the LLM as context.
	// +kubebuilder:default=true
	// +optional
	ComparePrevious *bool `json:"comparePrevious,omitempty"`
}

// PacketCaptureSpec defines the desired state of PacketCapture.
// +kubebuilder:validation:XValidation:rule="self.mode != 'Pod' || has(self.pod)",message="spec.pod is required when mode is Pod"
// +kubebuilder:validation:XValidation:rule="self.mode != 'Node' || has(self.node)",message="spec.node is required when mode is Node"
// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="spec is immutable; create a new PacketCapture"
type PacketCaptureSpec struct {
	// mode: Pod (inside the pod network namespace) or Node (on a node interface).
	// +kubebuilder:default=Pod
	// +optional
	Mode CaptureMode `json:"mode,omitempty"`

	// pod target; required when mode is Pod.
	// +optional
	Pod *PodTarget `json:"pod,omitempty"`

	// node target; required when mode is Node.
	// +optional
	Node *NodeTarget `json:"node,omitempty"`

	// filter is a tcpdump/BPF filter expression, e.g. "port 53".
	// +kubebuilder:validation:MaxLength=1024
	// +optional
	Filter string `json:"filter,omitempty"`

	// duration of the capture.
	// +kubebuilder:default="60s"
	// +optional
	Duration metav1.Duration `json:"duration,omitempty"`

	// maxSizeMB stops the capture early when the pcap reaches this size.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=500
	// +kubebuilder:default=100
	// +optional
	MaxSizeMB int32 `json:"maxSizeMB,omitempty"`

	// snapLen is the bytes captured per packet (0 = full packet).
	// +kubebuilder:validation:Minimum=0
	// +optional
	SnapLen int32 `json:"snapLen,omitempty"`

	// analysis is the pcap-analyzer destination.
	// +required
	Analysis AnalysisSpec `json:"analysis"`
}

// CapturePhase is the overall state of a PacketCapture.
// +kubebuilder:validation:Enum=Pending;Capturing;Analyzing;Completed;PartiallyFailed;Failed
type CapturePhase string

const (
	PhasePending         CapturePhase = "Pending"
	PhaseCapturing       CapturePhase = "Capturing"
	PhaseAnalyzing       CapturePhase = "Analyzing"
	PhaseCompleted       CapturePhase = "Completed"
	PhasePartiallyFailed CapturePhase = "PartiallyFailed"
	PhaseFailed          CapturePhase = "Failed"
)

// TargetPhase is the state of a single target (pod or node).
type TargetPhase string

const (
	// TargetPending: selected, capture job not created yet.
	TargetPending   TargetPhase = "Pending"
	TargetCapturing TargetPhase = "Capturing"
	TargetAnalyzing TargetPhase = "Analyzing"
	TargetCompleted TargetPhase = "Completed"
	TargetFailed    TargetPhase = "Failed"
)

// TargetStatus is the state of one captured pod or node.
type TargetStatus struct {
	// name of the pod (Pod mode) or node (Node mode).
	Name string `json:"name"`
	// nodeName the capture job runs on.
	NodeName string `json:"nodeName,omitempty"`
	// ip of the pod (Pod mode).
	IP string `json:"ip,omitempty"`
	// jobName of the capture job (in the operator namespace).
	JobName string `json:"jobName,omitempty"`
	// phase of this target.
	Phase TargetPhase `json:"phase,omitempty"`
	// runId in pcap-analyzer, set once the pcap was uploaded.
	RunID int64 `json:"runId,omitempty"`
	// runStatus / runStage / runProgress mirror pcap-analyzer's run state.
	RunStatus   string `json:"runStatus,omitempty"`
	RunStage    string `json:"runStage,omitempty"`
	RunProgress int32  `json:"runProgress,omitempty"`
	// pendingApprovals: commands Claude proposed that wait for approval in pcap-analyzer.
	PendingApprovals int32 `json:"pendingApprovals,omitempty"`
	// resultURL points to the run in pcap-analyzer.
	ResultURL string `json:"resultURL,omitempty"`
	// message explains failures.
	Message string `json:"message,omitempty"`
}

// PacketCaptureStatus defines the observed state of PacketCapture.
type PacketCaptureStatus struct {
	// phase is the overall state.
	// +optional
	Phase CapturePhase `json:"phase,omitempty"`

	// targets lists every captured pod / node, fixed when the capture starts.
	// +optional
	// +listType=map
	// +listMapKey=name
	Targets []TargetStatus `json:"targets,omitempty"`

	// startTime / completionTime of the whole capture.
	// +optional
	StartTime *metav1.Time `json:"startTime,omitempty"`
	// +optional
	CompletionTime *metav1.Time `json:"completionTime,omitempty"`

	// message for the overall state.
	// +optional
	Message string `json:"message,omitempty"`

	// conditions: "Ready" is True once every target is finished.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=pcap
// +kubebuilder:printcolumn:name="Mode",type=string,JSONPath=`.spec.mode`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Analysis",type=integer,JSONPath=`.spec.analysis.analysisId`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// PacketCapture captures traffic of pods or nodes and sends the pcaps to pcap-analyzer.
type PacketCapture struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state of PacketCapture
	// +required
	Spec PacketCaptureSpec `json:"spec"`

	// status defines the observed state of PacketCapture
	// +optional
	Status PacketCaptureStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// PacketCaptureList contains a list of PacketCapture
type PacketCaptureList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []PacketCapture `json:"items"`
}

func init() {
	SchemeBuilder.Register(func(scheme *runtime.Scheme) error {
		scheme.AddKnownTypes(SchemeGroupVersion, &PacketCapture{}, &PacketCaptureList{})
		return nil
	})
}
