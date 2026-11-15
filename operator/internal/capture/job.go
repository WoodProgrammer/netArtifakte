package capture

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	capturev1alpha1 "github.com/emirozbir/netsGo/operator/api/v1alpha1"
)

// Labels put on capture jobs. Jobs live in the operator namespace, so they can't have an owner
// reference to the (namespaced) PacketCapture; these labels link them back instead.
const (
	LabelManagedBy      = "app.kubernetes.io/managed-by"
	ManagedByValue      = "pcap-operator"
	LabelOwnerName      = "capture.netsgo.io/owner-name"
	LabelOwnerNamespace = "capture.netsgo.io/owner-namespace"
	LabelOwnerUID       = "capture.netsgo.io/owner-uid"
	AnnotationTarget    = "capture.netsgo.io/target"
	AnnotationOwner     = "capture.netsgo.io/owner" // "<namespace>/<name>" of the PacketCapture

	ContainerName = "capture"
)

// Config is the operator-level configuration for capture jobs.
type Config struct {
	Namespace       string // where capture jobs run (the operator namespace)
	Image           string // capture image (tcpdump, nsenter, curl, jq)
	AnalyzerURL     string // pcap-analyzer URL reachable from the jobs
	AnalyzerSecret  string // secret in Namespace with keys username / password
	JobTTLSeconds   int32  // ttlSecondsAfterFinished for capture jobs
	UploadGraceSecs int64  // extra time on top of the capture duration for setup + upload
}

// JobName is deterministic per (PacketCapture UID, target) so creating it twice is a no-op.
func JobName(pc *capturev1alpha1.PacketCapture, target string) string {
	h := sha256.Sum256([]byte(string(pc.UID) + "/" + target))
	prefix := pc.Name
	if len(prefix) > 40 {
		prefix = prefix[:40]
	}
	return strings.TrimRight(fmt.Sprintf("pcap-%s", prefix), "-.") + "-" + hex.EncodeToString(h[:])[:8]
}

// OwnerLabels identify the PacketCapture a job belongs to.
func OwnerLabels(pc *capturev1alpha1.PacketCapture) map[string]string {
	return map[string]string{
		LabelManagedBy:      ManagedByValue,
		LabelOwnerName:      truncLabel(pc.Name),
		LabelOwnerNamespace: pc.Namespace,
		LabelOwnerUID:       string(pc.UID),
	}
}

func truncLabel(s string) string {
	if len(s) > 63 {
		return strings.TrimRight(s[:63], "-._")
	}
	return s
}

// BuildJob returns the capture job for one target.
func BuildJob(cfg Config, pc *capturev1alpha1.PacketCapture, t Target, meta Meta) (*batchv1.Job, error) {
	metaJSON, err := json.Marshal(meta)
	if err != nil {
		return nil, err
	}
	s := pc.Spec
	duration := int64(s.Duration.Seconds())
	if duration <= 0 {
		duration = 60
	}
	maxSize := s.MaxSizeMB
	if maxSize <= 0 {
		maxSize = 100
	}
	provider := s.Analysis.Provider
	if provider == "" {
		provider = "claude"
	}
	compare := s.Analysis.ComparePrevious == nil || *s.Analysis.ComparePrevious

	podMode := s.Mode != capturev1alpha1.CaptureModeNode
	mode := capturev1alpha1.CaptureModePod
	if !podMode {
		mode = capturev1alpha1.CaptureModeNode
	}
	iface := ""
	pcapName := ""
	if podMode {
		if s.Pod != nil {
			iface = s.Pod.Interface
		}
		pcapName = fmt.Sprintf("%s_%s.pcap", t.Namespace, t.Name)
	} else {
		if s.Node != nil {
			iface = s.Node.Interface
		}
		pcapName = fmt.Sprintf("node_%s.pcap", t.Name)
	}

	secretEnv := func(name, key string) corev1.EnvVar {
		return corev1.EnvVar{Name: name, ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{
			LocalObjectReference: corev1.LocalObjectReference{Name: cfg.AnalyzerSecret}, Key: key}}}
	}
	env := []corev1.EnvVar{
		{Name: "MODE", Value: string(mode)},
		{Name: "POD_IP", Value: t.IP},
		{Name: "IFACE", Value: iface},
		{Name: "FILTER", Value: s.Filter},
		{Name: "DURATION", Value: strconv.FormatInt(duration, 10)},
		{Name: "MAX_SIZE_MB", Value: strconv.Itoa(int(maxSize))},
		{Name: "SNAPLEN", Value: strconv.Itoa(int(s.SnapLen))},
		{Name: "PCAP_NAME", Value: pcapName},
		{Name: "METADATA", Value: string(metaJSON)},
		{Name: "ANALYZER_URL", Value: strings.TrimRight(cfg.AnalyzerURL, "/")},
		{Name: "ANALYSIS_ID", Value: strconv.FormatInt(s.Analysis.AnalysisID, 10)},
		{Name: "PROVIDER", Value: provider},
		{Name: "DRY_RUN", Value: strconv.FormatBool(s.Analysis.DryRun)},
		{Name: "COMPARE_PREVIOUS", Value: strconv.FormatBool(compare)},
		secretEnv("ANALYZER_USERNAME", "username"),
		secretEnv("ANALYZER_PASSWORD", "password"),
	}

	workLimit := resource.MustParse(fmt.Sprintf("%dMi", maxSize+64))
	podSpec := corev1.PodSpec{
		RestartPolicy:                 corev1.RestartPolicyNever,
		NodeName:                      t.NodeName, // bypass the scheduler: must run on the target's node
		HostPID:                       podMode,    // to find the target pod's network namespace via /proc
		HostNetwork:                   !podMode,   // Node mode captures in the host network namespace
		AutomountServiceAccountToken:  ptr.To(false),
		TerminationGracePeriodSeconds: ptr.To[int64](10),
		Tolerations:                   []corev1.Toleration{{Operator: corev1.TolerationOpExists}},
		Containers: []corev1.Container{{
			Name:            ContainerName,
			Image:           cfg.Image,
			ImagePullPolicy: corev1.PullIfNotPresent,
			Command:         []string{"/usr/local/bin/capture.sh"},
			Env:             env,
			// nsenter into another netns needs CAP_SYS_ADMIN (+ SYS_PTRACE for /proc/<pid>/ns);
			// privileged keeps it simple across runtimes / AppArmor profiles.
			SecurityContext: &corev1.SecurityContext{Privileged: ptr.To(true)},
			Resources: corev1.ResourceRequirements{
				Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("50m"), corev1.ResourceMemory: resource.MustParse("64Mi")},
				Limits:   corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("256Mi")},
			},
			VolumeMounts:             []corev1.VolumeMount{{Name: "work", MountPath: "/work"}},
			TerminationMessagePolicy: corev1.TerminationMessageReadFile,
		}},
		Volumes: []corev1.Volume{{Name: "work", VolumeSource: corev1.VolumeSource{
			EmptyDir: &corev1.EmptyDirVolumeSource{SizeLimit: &workLimit}}}},
	}
	if !podMode {
		podSpec.DNSPolicy = corev1.DNSClusterFirstWithHostNet // resolve the analyzer Service from the host netns
	}

	labels := OwnerLabels(pc)
	ann := map[string]string{AnnotationTarget: t.Name, AnnotationOwner: pc.Namespace + "/" + pc.Name}
	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:        JobName(pc, t.Name),
			Namespace:   cfg.Namespace,
			Labels:      labels,
			Annotations: ann,
		},
		Spec: batchv1.JobSpec{
			BackoffLimit:            ptr.To[int32](0), // a retry would upload a second run
			ActiveDeadlineSeconds:   ptr.To(duration + cfg.UploadGraceSecs),
			TTLSecondsAfterFinished: ptr.To(cfg.JobTTLSeconds),
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: labels, Annotations: ann},
				Spec:       podSpec,
			},
		},
	}, nil
}

// Result is what capture.sh writes to the termination message.
type Result struct {
	RunID      int64  `json:"runId"`
	StopReason string `json:"stopReason"`
	Bytes      int64  `json:"bytes"`
	Error      string `json:"error"`
}

// ParseResult parses a capture container's termination message.
func ParseResult(msg string) (Result, error) {
	var r Result
	msg = strings.TrimSpace(msg)
	if msg == "" {
		return r, fmt.Errorf("empty termination message")
	}
	if err := json.Unmarshal([]byte(msg), &r); err != nil {
		return r, fmt.Errorf("invalid termination message %q: %w", msg, err)
	}
	return r, nil
}
