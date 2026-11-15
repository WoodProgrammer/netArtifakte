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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	capturev1alpha1 "github.com/emirozbir/netsGo/operator/api/v1alpha1"
	"github.com/emirozbir/netsGo/operator/internal/analyzer"
	"github.com/emirozbir/netsGo/operator/internal/capture"
)

const (
	captureNS   = "pcap-operator-system"
	testImage   = "pcap-capture:test"
	testNS      = "default"
	appLabel    = "app"
	targetPodIP = "10.244.1.7"
)

func ensureNamespace(ctx context.Context, name string) {
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}}
	if err := k8sClient.Create(ctx, ns); err != nil && !apierrors.IsAlreadyExists(err) {
		Expect(err).NotTo(HaveOccurred())
	}
}

func newReconciler(analyzerURL string) *PacketCaptureReconciler {
	return &PacketCaptureReconciler{
		Client: k8sClient,
		Scheme: k8sClient.Scheme(),
		Capture: capture.Config{
			Namespace: captureNS, Image: testImage, AnalyzerURL: analyzerURL,
			AnalyzerSecret: "pcap-analyzer-credentials", JobTTLSeconds: 600, UploadGraceSecs: 300,
		},
		Analyzer:              analyzer.New(analyzerURL),
		NodeCaptureNamespaces: map[string]bool{captureNS: true},
		PollInterval:          time.Second,
		TargetWaitTimeout:     time.Minute,
	}
}

var _ = Describe("PacketCapture Controller", func() {
	ctx := context.Background()

	BeforeEach(func() {
		ensureNamespace(ctx, captureNS)
	})

	reconcileOnce := func(r *PacketCaptureReconciler, key types.NamespacedName) reconcile.Result {
		res, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: key})
		Expect(err).NotTo(HaveOccurred())
		return res
	}
	get := func(key types.NamespacedName) *capturev1alpha1.PacketCapture {
		pc := &capturev1alpha1.PacketCapture{}
		Expect(k8sClient.Get(ctx, key, pc)).To(Succeed())
		return pc
	}

	It("waits (Pending) while no pod matches", func() {
		key := types.NamespacedName{Namespace: testNS, Name: "no-pods"}
		Expect(k8sClient.Create(ctx, &capturev1alpha1.PacketCapture{
			ObjectMeta: metav1.ObjectMeta{Name: key.Name, Namespace: key.Namespace},
			Spec: capturev1alpha1.PacketCaptureSpec{
				Mode:     capturev1alpha1.CaptureModePod,
				Pod:      &capturev1alpha1.PodTarget{Selector: metav1.LabelSelector{MatchLabels: map[string]string{appLabel: "nothing"}}},
				Analysis: capturev1alpha1.AnalysisSpec{AnalysisID: 1, Question: "why?"},
			},
		})).To(Succeed())

		res := reconcileOnce(newReconciler("http://unused"), key)
		pc := get(key)
		Expect(pc.Finalizers).To(ContainElement(finalizerName))
		Expect(pc.Status.Phase).To(Equal(capturev1alpha1.PhasePending))
		Expect(res.RequeueAfter).To(BeNumerically(">", 0))
		Expect(k8sClient.Delete(ctx, pc)).To(Succeed())
		reconcileOnce(newReconciler("http://unused"), key) // finalizer removal
	})

	It("rejects Node mode outside the allowed namespaces", func() {
		key := types.NamespacedName{Namespace: testNS, Name: "node-denied"}
		Expect(k8sClient.Create(ctx, &capturev1alpha1.PacketCapture{
			ObjectMeta: metav1.ObjectMeta{Name: key.Name, Namespace: key.Namespace},
			Spec: capturev1alpha1.PacketCaptureSpec{
				Mode:     capturev1alpha1.CaptureModeNode,
				Node:     &capturev1alpha1.NodeTarget{NodeNames: []string{"n1"}},
				Analysis: capturev1alpha1.AnalysisSpec{AnalysisID: 1, Question: "why?"},
			},
		})).To(Succeed())
		reconcileOnce(newReconciler("http://unused"), key)
		pc := get(key)
		Expect(pc.Status.Phase).To(Equal(capturev1alpha1.PhaseFailed))
		Expect(pc.Status.Message).To(ContainSubstring("not allowed"))
	})

	It("captures a pod, picks up the run id and follows the analysis to completion", func() {
		// Fake pcap-analyzer: run 42 is "llm" on the first poll, "done" afterwards.
		var polls atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			u, p, ok := req.BasicAuth()
			if !ok || u != "op" || p != "secret" || req.URL.Path != "/runs/42" {
				http.Error(w, "nope", http.StatusUnauthorized)
				return
			}
			status, stage, progress := "running", "llm", 60
			if polls.Add(1) > 1 {
				status, stage, progress = "done", "done", 100
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"id": 42, "status": status, "stage": stage, "progress": progress})
		}))
		defer srv.Close()
		r := newReconciler(srv.URL)

		Expect(k8sClient.Create(ctx, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "pcap-analyzer-credentials", Namespace: captureNS},
			StringData: map[string]string{"username": "op", "password": "secret"},
		})).To(Succeed())

		// Target pod (no kubelet in envtest: set the status by hand).
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "web-0", Namespace: testNS, Labels: map[string]string{appLabel: "web"}},
			Spec:       corev1.PodSpec{NodeName: "node-a", Containers: []corev1.Container{{Name: "c", Image: "nginx"}}},
		}
		Expect(k8sClient.Create(ctx, pod)).To(Succeed())
		pod.Status = corev1.PodStatus{Phase: corev1.PodRunning, PodIP: targetPodIP, PodIPs: []corev1.PodIP{{IP: targetPodIP}}}
		Expect(k8sClient.Status().Update(ctx, pod)).To(Succeed())

		key := types.NamespacedName{Namespace: testNS, Name: "web-dns"}
		Expect(k8sClient.Create(ctx, &capturev1alpha1.PacketCapture{
			ObjectMeta: metav1.ObjectMeta{Name: key.Name, Namespace: key.Namespace},
			Spec: capturev1alpha1.PacketCaptureSpec{
				Mode:     capturev1alpha1.CaptureModePod,
				Pod:      &capturev1alpha1.PodTarget{Selector: metav1.LabelSelector{MatchLabels: map[string]string{appLabel: "web"}}},
				Filter:   "port 53",
				Duration: metav1.Duration{Duration: 30 * time.Second},
				Analysis: capturev1alpha1.AnalysisSpec{AnalysisID: 7, Question: "DNS?"},
			},
		})).To(Succeed())

		By("selecting the target")
		reconcileOnce(r, key)
		pc := get(key)
		Expect(pc.Status.Targets).To(HaveLen(1))
		Expect(pc.Status.Targets[0].Name).To(Equal("web-0"))
		Expect(pc.Status.Targets[0].Phase).To(Equal(capturev1alpha1.TargetPending))

		By("creating the capture job on the pod's node")
		reconcileOnce(r, key)
		pc = get(key)
		Expect(pc.Status.Phase).To(Equal(capturev1alpha1.PhaseCapturing))
		jobName := pc.Status.Targets[0].JobName
		job := &batchv1.Job{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: captureNS, Name: jobName}, job)).To(Succeed())
		spec := job.Spec.Template.Spec
		Expect(spec.NodeName).To(Equal("node-a"))
		Expect(spec.HostPID).To(BeTrue())
		Expect(spec.HostNetwork).To(BeFalse())
		Expect(*job.Spec.BackoffLimit).To(BeZero())
		envs := map[string]string{}
		for _, e := range spec.Containers[0].Env {
			envs[e.Name] = e.Value
		}
		Expect(envs).To(HaveKeyWithValue("MODE", "Pod"))
		Expect(envs).To(HaveKeyWithValue("POD_IP", targetPodIP))
		Expect(envs).To(HaveKeyWithValue("FILTER", "port 53"))
		Expect(envs).To(HaveKeyWithValue("DURATION", "30"))
		Expect(envs).To(HaveKeyWithValue("ANALYSIS_ID", "7"))
		var meta capture.Meta
		Expect(json.Unmarshal([]byte(envs["METADATA"]), &meta)).To(Succeed())
		Expect(meta.Question).To(Equal("DNS?"))
		Expect(meta.KnownHosts).To(ContainElement(capture.KnownHost{IP: targetPodIP, Name: "pod/default/web-0 on node-a"}))

		By("finishing the job with a run id in the termination message")
		jobPod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: jobName + "-x", Namespace: captureNS,
				Labels: map[string]string{batchv1.JobNameLabel: jobName}},
			Spec: corev1.PodSpec{RestartPolicy: corev1.RestartPolicyNever,
				Containers: []corev1.Container{{Name: capture.ContainerName, Image: testImage}}},
		}
		Expect(k8sClient.Create(ctx, jobPod)).To(Succeed())
		jobPod.Status = corev1.PodStatus{Phase: corev1.PodSucceeded, ContainerStatuses: []corev1.ContainerStatus{{
			Name: capture.ContainerName, Image: testImage, ImageID: "x",
			State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{
				ExitCode: 0, Message: `{"runId":42,"stopReason":"duration","bytes":12345}`}},
		}}}
		Expect(k8sClient.Status().Update(ctx, jobPod)).To(Succeed())

		now := metav1.Now()
		job.Status = batchv1.JobStatus{
			StartTime: &now, CompletionTime: &now, Succeeded: 1,
			Conditions: []batchv1.JobCondition{
				{Type: batchv1.JobSuccessCriteriaMet, Status: corev1.ConditionTrue, LastTransitionTime: now},
				{Type: batchv1.JobComplete, Status: corev1.ConditionTrue, LastTransitionTime: now},
			},
		}
		Expect(k8sClient.Status().Update(ctx, job)).To(Succeed())

		reconcileOnce(r, key)
		pc = get(key)
		Expect(pc.Status.Targets[0].Phase).To(Equal(capturev1alpha1.TargetAnalyzing))
		Expect(pc.Status.Targets[0].RunID).To(Equal(int64(42)))
		Expect(pc.Status.Targets[0].ResultURL).To(Equal(srv.URL + "/#/r/42"))
		Expect(pc.Status.Phase).To(Equal(capturev1alpha1.PhaseAnalyzing))

		By("polling pcap-analyzer")
		reconcileOnce(r, key)
		pc = get(key)
		Expect(pc.Status.Targets[0].RunStage).To(Equal("llm"))
		Expect(pc.Status.Phase).To(Equal(capturev1alpha1.PhaseAnalyzing))

		reconcileOnce(r, key)
		pc = get(key)
		Expect(pc.Status.Targets[0].Phase).To(Equal(capturev1alpha1.TargetCompleted))
		Expect(pc.Status.Phase).To(Equal(capturev1alpha1.PhaseCompleted))
		Expect(pc.Status.CompletionTime).NotTo(BeNil())

		By("deleting the PacketCapture removes its jobs")
		Expect(k8sClient.Delete(ctx, pc)).To(Succeed())
		reconcileOnce(r, key)
		Eventually(func() bool {
			err := k8sClient.Get(ctx, types.NamespacedName{Namespace: captureNS, Name: jobName}, &batchv1.Job{})
			return apierrors.IsNotFound(err)
		}, 10*time.Second).Should(BeTrue())
	})
})
