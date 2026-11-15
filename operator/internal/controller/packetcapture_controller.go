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

package controller

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	capturev1alpha1 "github.com/emirozbir/netsGo/operator/api/v1alpha1"
	"github.com/emirozbir/netsGo/operator/internal/analyzer"
	"github.com/emirozbir/netsGo/operator/internal/capture"
)

const (
	finalizerName = "capture.netsgo.io/cleanup"
	// jobAppearGrace: a just-created job may not be in the cache yet.
	jobAppearGrace = time.Minute
	conditionReady = "Ready"
)

// PacketCaptureReconciler reconciles a PacketCapture object
type PacketCaptureReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	Capture           capture.Config
	Analyzer          *analyzer.Client
	AnalyzerPublicURL string // base URL for links in status (defaults to Capture.AnalyzerURL)
	ServiceCIDR       string // optional, labels ClusterIPs in the metadata
	// NodeCaptureNamespaces: namespaces whose PacketCaptures may use Node mode (captures all
	// traffic of a node, so it is restricted). Pod mode only targets pods in the CR's own namespace.
	NodeCaptureNamespaces map[string]bool
	PollInterval          time.Duration // pcap-analyzer polling while runs are being analyzed
	TargetWaitTimeout     time.Duration // how long to wait for matching pods / nodes
}

// +kubebuilder:rbac:groups=capture.netsgo.io,resources=packetcaptures,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=capture.netsgo.io,resources=packetcaptures/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=capture.netsgo.io,resources=packetcaptures/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=pods;nodes;services,verbs=get;list;watch
// +kubebuilder:rbac:groups=batch,namespace=pcap-operator-system,resources=jobs,verbs=get;list;watch;create;delete;deletecollection
// +kubebuilder:rbac:groups="",namespace=pcap-operator-system,resources=secrets,verbs=get;list;watch

// Reconcile drives a PacketCapture: select targets → one capture job per target (the job captures
// and uploads the pcap to pcap-analyzer) → poll pcap-analyzer until every run is finished.
func (r *PacketCaptureReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	pc := &capturev1alpha1.PacketCapture{}
	if err := r.Get(ctx, req.NamespacedName, pc); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if !pc.DeletionTimestamp.IsZero() {
		if !controllerutil.ContainsFinalizer(pc, finalizerName) {
			return ctrl.Result{}, nil
		}
		if err := r.deleteJobs(ctx, pc); err != nil {
			return ctrl.Result{}, err
		}
		controllerutil.RemoveFinalizer(pc, finalizerName)
		return ctrl.Result{}, r.Update(ctx, pc)
	}
	if !controllerutil.ContainsFinalizer(pc, finalizerName) {
		controllerutil.AddFinalizer(pc, finalizerName)
		if err := r.Update(ctx, pc); err != nil {
			return ctrl.Result{}, err
		}
	}
	if isTerminal(pc.Status.Phase) {
		return ctrl.Result{}, nil
	}

	orig := pc.DeepCopy()
	var requeue time.Duration
	var err error
	if len(pc.Status.Targets) == 0 {
		requeue, err = r.selectTargets(ctx, pc)
	} else {
		requeue, err = r.advanceTargets(ctx, pc)
	}
	if err != nil {
		return ctrl.Result{}, err
	}
	aggregate(pc)

	if !equality.Semantic.DeepEqual(orig.Status, pc.Status) {
		if err := r.Status().Update(ctx, pc); err != nil {
			return ctrl.Result{}, err
		}
		log.V(1).Info("status updated", "phase", pc.Status.Phase)
	}
	return ctrl.Result{RequeueAfter: requeue}, nil
}

func isTerminal(p capturev1alpha1.CapturePhase) bool {
	return p == capturev1alpha1.PhaseCompleted || p == capturev1alpha1.PhaseFailed ||
		p == capturev1alpha1.PhasePartiallyFailed
}

// ---------------------------------------------------------------- target selection

// selectTargets fixes the list of pods / nodes once; later changes to the cluster don't alter it.
func (r *PacketCaptureReconciler) selectTargets(ctx context.Context, pc *capturev1alpha1.PacketCapture) (time.Duration, error) {
	var targets []capturev1alpha1.TargetStatus
	var err error
	switch pc.Spec.Mode {
	case capturev1alpha1.CaptureModeNode:
		if !r.NodeCaptureNamespaces[pc.Namespace] {
			fail(pc, fmt.Sprintf("Node mode is not allowed in namespace %q (operator flag --node-capture-namespaces)", pc.Namespace))
			return 0, nil
		}
		targets, err = r.selectNodes(ctx, pc)
	default:
		targets, err = r.selectPods(ctx, pc)
	}
	if err != nil {
		var invalid invalidSpecError
		if errors.As(err, &invalid) {
			fail(pc, invalid.Error())
			return 0, nil
		}
		return 0, err
	}

	if len(targets) == 0 {
		if time.Since(pc.CreationTimestamp.Time) > r.TargetWaitTimeout {
			fail(pc, "no matching running pods / ready nodes found")
			return 0, nil
		}
		pc.Status.Phase = capturev1alpha1.PhasePending
		pc.Status.Message = "waiting for matching running pods / ready nodes"
		return 10 * time.Second, nil
	}
	now := metav1.Now()
	pc.Status.Targets = targets
	pc.Status.StartTime = &now
	pc.Status.Message = ""
	return time.Second, nil // continue with job creation right away
}

func (r *PacketCaptureReconciler) selectPods(ctx context.Context, pc *capturev1alpha1.PacketCapture) ([]capturev1alpha1.TargetStatus, error) {
	if pc.Spec.Pod == nil {
		return nil, invalidSpecError("spec.pod is required in Pod mode")
	}
	sel, err := metav1.LabelSelectorAsSelector(&pc.Spec.Pod.Selector)
	if err != nil {
		return nil, invalidSpecError("invalid spec.pod.selector: " + err.Error())
	}
	if sel.Empty() {
		return nil, invalidSpecError("spec.pod.selector must not be empty")
	}
	var pods corev1.PodList
	if err := r.List(ctx, &pods, client.InNamespace(pc.Namespace), client.MatchingLabelsSelector{Selector: sel}); err != nil {
		return nil, err
	}
	var out []capturev1alpha1.TargetStatus
	for _, p := range pods.Items {
		if p.Status.Phase != corev1.PodRunning || p.Status.PodIP == "" || p.Spec.NodeName == "" || p.DeletionTimestamp != nil {
			continue
		}
		out = append(out, capturev1alpha1.TargetStatus{
			Name: p.Name, NodeName: p.Spec.NodeName, IP: p.Status.PodIP, Phase: capturev1alpha1.TargetPending,
		})
	}
	return capTargets(out, pc.Spec.Pod.MaxPods, 5), nil
}

func (r *PacketCaptureReconciler) selectNodes(ctx context.Context, pc *capturev1alpha1.PacketCapture) ([]capturev1alpha1.TargetStatus, error) {
	spec := pc.Spec.Node
	if spec == nil {
		return nil, invalidSpecError("spec.node is required in Node mode")
	}
	if (len(spec.NodeNames) == 0) == (spec.Selector == nil) {
		return nil, invalidSpecError("set exactly one of spec.node.nodeNames / spec.node.selector")
	}
	sel := labels.Everything()
	if spec.Selector != nil {
		s, err := metav1.LabelSelectorAsSelector(spec.Selector)
		if err != nil {
			return nil, invalidSpecError("invalid spec.node.selector: " + err.Error())
		}
		sel = s
	}
	var nodes corev1.NodeList
	if err := r.List(ctx, &nodes, client.MatchingLabelsSelector{Selector: sel}); err != nil {
		return nil, err
	}
	wanted := map[string]bool{}
	for _, n := range spec.NodeNames {
		wanted[n] = true
	}
	var out []capturev1alpha1.TargetStatus
	for _, n := range nodes.Items {
		if len(wanted) > 0 && !wanted[n.Name] {
			continue
		}
		if !nodeReady(&n) {
			continue
		}
		out = append(out, capturev1alpha1.TargetStatus{Name: n.Name, NodeName: n.Name, Phase: capturev1alpha1.TargetPending})
	}
	return capTargets(out, spec.MaxNodes, 3), nil
}

func capTargets(t []capturev1alpha1.TargetStatus, max, def int32) []capturev1alpha1.TargetStatus {
	if max <= 0 {
		max = def
	}
	slices.SortFunc(t, func(a, b capturev1alpha1.TargetStatus) int { return strings.Compare(a.Name, b.Name) })
	if len(t) > int(max) {
		t = t[:max]
	}
	return t
}

func nodeReady(n *corev1.Node) bool {
	for _, c := range n.Status.Conditions {
		if c.Type == corev1.NodeReady {
			return c.Status == corev1.ConditionTrue
		}
	}
	return false
}

// ---------------------------------------------------------------- per-target progress

// advanceTargets moves each target along Pending → Capturing → Analyzing → Completed/Failed.
func (r *PacketCaptureReconciler) advanceTargets(ctx context.Context, pc *capturev1alpha1.PacketCapture) (time.Duration, error) {
	var view *capture.ClusterView // loaded lazily, only when jobs are created
	var creds *analyzer.Credentials
	var credsErr error
	requeue := time.Duration(0)
	soon := func(d time.Duration) {
		if requeue == 0 || d < requeue {
			requeue = d
		}
	}

	for i := range pc.Status.Targets {
		t := &pc.Status.Targets[i]
		switch t.Phase {
		case capturev1alpha1.TargetPending:
			if view == nil {
				v, err := r.clusterView(ctx)
				if err != nil {
					return 0, err
				}
				view = v
			}
			if err := r.startCapture(ctx, pc, t, view); err != nil {
				return 0, err
			}
			soon(15 * time.Second)

		case capturev1alpha1.TargetCapturing:
			if err := r.checkJob(ctx, pc, t); err != nil {
				return 0, err
			}
			switch t.Phase {
			case capturev1alpha1.TargetCapturing:
				soon(15 * time.Second) // job events also trigger a reconcile; this is a safety net
			case capturev1alpha1.TargetAnalyzing:
				soon(time.Second)
			}

		case capturev1alpha1.TargetAnalyzing:
			if creds == nil && credsErr == nil {
				creds, credsErr = r.credentials(ctx)
			}
			if credsErr != nil {
				t.Message = "cannot read analyzer credentials: " + credsErr.Error()
			} else {
				r.pollRun(ctx, t, *creds)
			}
			if t.Phase == capturev1alpha1.TargetAnalyzing {
				soon(r.PollInterval)
			}
		}
	}
	return requeue, nil
}

func (r *PacketCaptureReconciler) startCapture(ctx context.Context, pc *capturev1alpha1.PacketCapture, t *capturev1alpha1.TargetStatus, view *capture.ClusterView) error {
	target := capture.Target{Name: t.Name, NodeName: t.NodeName, IP: t.IP}
	podMode := pc.Spec.Mode != capturev1alpha1.CaptureModeNode
	if podMode {
		target.Namespace = pc.Namespace
		var pod corev1.Pod
		err := r.Get(ctx, types.NamespacedName{Namespace: pc.Namespace, Name: t.Name}, &pod)
		if apierrors.IsNotFound(err) || (err == nil && (pod.Status.PodIP != t.IP || pod.Spec.NodeName != t.NodeName || pod.DeletionTimestamp != nil)) {
			t.Phase, t.Message = capturev1alpha1.TargetFailed, "pod was deleted or rescheduled before the capture started"
			return nil
		} else if err != nil {
			return err
		}
	}

	captureMeta := capture.BuildMeta(pc, target, scopedView(view, pc, target, podMode))
	job, err := capture.BuildJob(r.Capture, pc, target, captureMeta)
	if err != nil {
		return err
	}
	if err := r.Create(ctx, job); err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("create capture job for %s: %w", t.Name, err)
	}
	t.JobName = job.Name
	t.Phase = capturev1alpha1.TargetCapturing
	t.Message = ""
	return nil
}

// checkJob reads the result of a finished capture job (the run id is in the termination message).
func (r *PacketCaptureReconciler) checkJob(ctx context.Context, pc *capturev1alpha1.PacketCapture, t *capturev1alpha1.TargetStatus) error {
	var job batchv1.Job
	err := r.Get(ctx, types.NamespacedName{Namespace: r.Capture.Namespace, Name: t.JobName}, &job)
	if apierrors.IsNotFound(err) {
		if pc.Status.StartTime != nil && time.Since(pc.Status.StartTime.Time) < jobAppearGrace {
			return nil // probably not in the cache yet
		}
		t.Phase, t.Message = capturev1alpha1.TargetFailed, "capture job disappeared"
		return nil
	} else if err != nil {
		return err
	}

	complete, failed, failMsg := jobFinished(&job)
	if !complete && !failed {
		return nil
	}
	msg, err := r.terminationMessage(ctx, &job)
	if err != nil {
		return err
	}
	res, perr := capture.ParseResult(msg)
	switch {
	case complete && perr == nil && res.RunID > 0:
		t.Phase = capturev1alpha1.TargetAnalyzing
		t.RunID = res.RunID
		t.ResultURL = analyzer.RunURL(r.publicURL(), res.RunID)
		t.Message = fmt.Sprintf("captured %d bytes (stopped by %s)", res.Bytes, res.StopReason)
	case perr == nil && res.Error != "":
		t.Phase, t.Message = capturev1alpha1.TargetFailed, res.Error
	case failMsg != "":
		t.Phase, t.Message = capturev1alpha1.TargetFailed, "capture job failed: "+failMsg
	case perr != nil:
		t.Phase, t.Message = capturev1alpha1.TargetFailed, "capture job finished without a result: "+perr.Error()
	default:
		t.Phase, t.Message = capturev1alpha1.TargetFailed, "capture job finished without a run id"
	}
	return nil
}

func jobFinished(job *batchv1.Job) (complete, failed bool, msg string) {
	for _, c := range job.Status.Conditions {
		if c.Status != corev1.ConditionTrue {
			continue
		}
		switch c.Type {
		case batchv1.JobComplete:
			complete = true
		case batchv1.JobFailed:
			failed = true
			msg = strings.TrimSpace(c.Reason + ": " + c.Message)
		}
	}
	return complete, failed, msg
}

func (r *PacketCaptureReconciler) terminationMessage(ctx context.Context, job *batchv1.Job) (string, error) {
	var pods corev1.PodList
	if err := r.List(ctx, &pods, client.InNamespace(job.Namespace),
		client.MatchingLabels{batchv1.JobNameLabel: job.Name}); err != nil {
		return "", err
	}
	for _, p := range pods.Items {
		for _, cs := range p.Status.ContainerStatuses {
			if cs.Name == capture.ContainerName && cs.State.Terminated != nil && cs.State.Terminated.Message != "" {
				return cs.State.Terminated.Message, nil
			}
		}
	}
	return "", nil
}

func (r *PacketCaptureReconciler) pollRun(ctx context.Context, t *capturev1alpha1.TargetStatus, creds analyzer.Credentials) {
	run, err := r.Analyzer.GetRun(ctx, creds, t.RunID)
	if err != nil {
		t.Message = "analyzer: " + err.Error()
		return
	}
	t.RunStatus, t.RunStage, t.RunProgress, t.PendingApprovals = run.Status, run.Stage, run.Progress, run.PendingApprovals
	t.Message = ""
	switch run.Status {
	case analyzer.StatusDone:
		t.Phase = capturev1alpha1.TargetCompleted
	case analyzer.StatusFailed, analyzer.StatusCancelled:
		t.Phase = capturev1alpha1.TargetFailed
		t.Message = "analysis " + run.Status
		if run.Error != "" {
			t.Message += ": " + run.Error
		}
	case "awaiting_approval":
		t.Message = "waiting for command approval in pcap-analyzer"
	}
}

// ---------------------------------------------------------------- helpers

func (r *PacketCaptureReconciler) publicURL() string {
	if r.AnalyzerPublicURL != "" {
		return r.AnalyzerPublicURL
	}
	return r.Capture.AnalyzerURL
}

func (r *PacketCaptureReconciler) credentials(ctx context.Context) (*analyzer.Credentials, error) {
	var s corev1.Secret
	if err := r.Get(ctx, types.NamespacedName{Namespace: r.Capture.Namespace, Name: r.Capture.AnalyzerSecret}, &s); err != nil {
		return nil, err
	}
	u, p := string(s.Data["username"]), string(s.Data["password"])
	if u == "" || p == "" {
		return nil, fmt.Errorf("secret %s/%s needs the keys username and password", s.Namespace, s.Name)
	}
	return &analyzer.Credentials{Username: u, Password: p}, nil
}

func (r *PacketCaptureReconciler) clusterView(ctx context.Context) (*capture.ClusterView, error) {
	v := &capture.ClusterView{ServiceCIDR: r.ServiceCIDR}
	var nodes corev1.NodeList
	if err := r.List(ctx, &nodes); err != nil {
		return nil, err
	}
	var pods corev1.PodList
	if err := r.List(ctx, &pods); err != nil {
		return nil, err
	}
	var svcs corev1.ServiceList
	if err := r.List(ctx, &svcs); err != nil {
		return nil, err
	}
	v.Nodes, v.Pods, v.Services = nodes.Items, pods.Items, svcs.Items
	return v, nil
}

// scopedView keeps the metadata relevant (and small): Pod mode → the target namespace + kube-system;
// Node mode → pods on that node, their namespaces' services and kube-system.
func scopedView(v *capture.ClusterView, pc *capturev1alpha1.PacketCapture, t capture.Target, podMode bool) capture.ClusterView {
	out := capture.ClusterView{Nodes: v.Nodes, ServiceCIDR: v.ServiceCIDR}
	namespaces := map[string]bool{"kube-system": true}
	if podMode {
		namespaces[pc.Namespace] = true
	}
	for _, p := range v.Pods {
		if p.Status.Phase != corev1.PodRunning {
			continue
		}
		if namespaces[p.Namespace] || (!podMode && p.Spec.NodeName == t.Name) {
			out.Pods = append(out.Pods, p)
		}
	}
	if !podMode {
		for _, p := range out.Pods {
			namespaces[p.Namespace] = true
		}
	}
	for _, s := range v.Services {
		if namespaces[s.Namespace] {
			out.Services = append(out.Services, s)
		}
	}
	return out
}

func (r *PacketCaptureReconciler) deleteJobs(ctx context.Context, pc *capturev1alpha1.PacketCapture) error {
	return client.IgnoreNotFound(r.DeleteAllOf(ctx, &batchv1.Job{},
		client.InNamespace(r.Capture.Namespace),
		client.MatchingLabels{capture.LabelOwnerUID: string(pc.UID)},
		client.PropagationPolicy(metav1.DeletePropagationBackground)))
}

func fail(pc *capturev1alpha1.PacketCapture, msg string) {
	pc.Status.Phase = capturev1alpha1.PhaseFailed
	pc.Status.Message = msg
}

// aggregate derives the overall phase, message and Ready condition from the targets.
func aggregate(pc *capturev1alpha1.PacketCapture) {
	st := &pc.Status
	if len(st.Targets) == 0 {
		if st.Phase == capturev1alpha1.PhaseFailed {
			setReady(pc, metav1.ConditionFalse, "Failed", st.Message)
			setCompletion(pc)
		} else {
			setReady(pc, metav1.ConditionFalse, "Pending", st.Message)
		}
		return
	}
	counts := map[capturev1alpha1.TargetPhase]int{}
	approvals := 0
	for _, t := range st.Targets {
		counts[t.Phase]++
		approvals += int(t.PendingApprovals)
	}
	n := len(st.Targets)
	switch {
	case counts[capturev1alpha1.TargetPending]+counts[capturev1alpha1.TargetCapturing] > 0:
		st.Phase = capturev1alpha1.PhaseCapturing
	case counts[capturev1alpha1.TargetAnalyzing] > 0:
		st.Phase = capturev1alpha1.PhaseAnalyzing
	case counts[capturev1alpha1.TargetFailed] == 0:
		st.Phase = capturev1alpha1.PhaseCompleted
	case counts[capturev1alpha1.TargetFailed] == n:
		st.Phase = capturev1alpha1.PhaseFailed
	default:
		st.Phase = capturev1alpha1.PhasePartiallyFailed
	}
	st.Message = fmt.Sprintf("%d target(s): %d capturing, %d analyzing, %d completed, %d failed",
		n, counts[capturev1alpha1.TargetPending]+counts[capturev1alpha1.TargetCapturing],
		counts[capturev1alpha1.TargetAnalyzing], counts[capturev1alpha1.TargetCompleted], counts[capturev1alpha1.TargetFailed])
	if approvals > 0 {
		st.Message += fmt.Sprintf("; %d command(s) waiting for approval in pcap-analyzer", approvals)
	}
	if isTerminal(st.Phase) {
		status := metav1.ConditionTrue
		if st.Phase != capturev1alpha1.PhaseCompleted {
			status = metav1.ConditionFalse
		}
		setReady(pc, status, string(st.Phase), st.Message)
		setCompletion(pc)
	} else {
		setReady(pc, metav1.ConditionFalse, string(st.Phase), st.Message)
	}
}

func setReady(pc *capturev1alpha1.PacketCapture, status metav1.ConditionStatus, reason, msg string) {
	meta.SetStatusCondition(&pc.Status.Conditions, metav1.Condition{
		Type: conditionReady, Status: status, Reason: reason, Message: msg, ObservedGeneration: pc.Generation,
	})
}

func setCompletion(pc *capturev1alpha1.PacketCapture) {
	if pc.Status.CompletionTime == nil {
		now := metav1.Now()
		pc.Status.CompletionTime = &now
	}
}

type invalidSpecError string

func (e invalidSpecError) Error() string { return string(e) }

// SetupWithManager sets up the controller with the Manager.
func (r *PacketCaptureReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&capturev1alpha1.PacketCapture{}).
		// Capture jobs live in the operator namespace (no owner reference possible): map them back
		// to their PacketCapture through the owner annotation.
		Watches(&batchv1.Job{}, handler.EnqueueRequestsFromMapFunc(func(_ context.Context, o client.Object) []reconcile.Request {
			ns, name, ok := strings.Cut(o.GetAnnotations()[capture.AnnotationOwner], "/")
			if !ok || o.GetLabels()[capture.LabelManagedBy] != capture.ManagedByValue {
				return nil
			}
			return []reconcile.Request{{NamespacedName: types.NamespacedName{Namespace: ns, Name: name}}}
		})).
		Named("packetcapture").
		Complete(r)
}
