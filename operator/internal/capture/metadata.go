// Package capture builds the capture jobs and the metadata sent to pcap-analyzer with each pcap.
package capture

import (
	"fmt"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"

	capturev1alpha1 "github.com/emirozbir/netsGo/operator/api/v1alpha1"
)

// MaxKnownHosts caps the known_hosts list so the metadata (and the LLM prompt) stays small.
const MaxKnownHosts = 400

// Network / KnownHost / Meta mirror pcap-analyzer's CaptureMeta (app/models.py).
type Network struct {
	CIDR string `json:"cidr"`
	Role string `json:"role"`
}

type KnownHost struct {
	IP   string `json:"ip"`
	Name string `json:"name"`
}

type Meta struct {
	Description  string      `json:"description"`
	CapturePoint string      `json:"capture_point"`
	Networks     []Network   `json:"networks"`
	KnownHosts   []KnownHost `json:"known_hosts"`
	Question     string      `json:"question"`
}

// ClusterView is the cluster state used to label IPs. The caller decides which pods/services are
// relevant (e.g. target namespace + kube-system, or the pods on a node).
type ClusterView struct {
	Nodes       []corev1.Node
	Pods        []corev1.Pod
	Services    []corev1.Service
	ServiceCIDR string // optional, from operator config
}

// Target is what a single capture job captures.
type Target struct {
	Name      string // pod or node name
	Namespace string // pod namespace (Pod mode)
	NodeName  string
	IP        string // pod IP (Pod mode)
}

// BuildMeta builds the pcap-analyzer metadata for one target.
//
// Labels are ordered nodes → services → pods because pcap-analyzer uses the first match.
func BuildMeta(pc *capturev1alpha1.PacketCapture, t Target, view ClusterView) Meta {
	m := Meta{Question: pc.Spec.Analysis.Question}

	seenCIDR := map[string]bool{}
	nodes := append([]corev1.Node(nil), view.Nodes...)
	slices.SortFunc(nodes, func(a, b corev1.Node) int { return strings.Compare(a.Name, b.Name) })
	for _, n := range nodes {
		cidrs := n.Spec.PodCIDRs
		if len(cidrs) == 0 && n.Spec.PodCIDR != "" {
			cidrs = []string{n.Spec.PodCIDR}
		}
		for _, c := range cidrs {
			if !seenCIDR[c] {
				seenCIDR[c] = true
				m.Networks = append(m.Networks, Network{CIDR: c, Role: "pod_network on node " + n.Name})
			}
		}
	}
	if view.ServiceCIDR != "" {
		for c := range strings.SplitSeq(view.ServiceCIDR, ",") {
			if c = strings.TrimSpace(c); c != "" {
				m.Networks = append(m.Networks, Network{CIDR: c, Role: "service_network (ClusterIP)"})
			}
		}
	}

	seenIP := map[string]bool{}
	add := func(ip, name string) {
		if ip == "" || ip == corev1.ClusterIPNone || seenIP[ip] || len(m.KnownHosts) >= MaxKnownHosts {
			return
		}
		seenIP[ip] = true
		m.KnownHosts = append(m.KnownHosts, KnownHost{IP: ip, Name: name})
	}
	for _, n := range nodes {
		for _, a := range n.Status.Addresses {
			if a.Type == corev1.NodeInternalIP || a.Type == corev1.NodeExternalIP {
				add(a.Address, "node/"+n.Name)
			}
		}
	}
	svcs := append([]corev1.Service(nil), view.Services...)
	slices.SortFunc(svcs, func(a, b corev1.Service) int { return strings.Compare(svcKey(a), svcKey(b)) })
	for _, s := range svcs {
		for _, ip := range s.Spec.ClusterIPs {
			add(ip, "svc/"+s.Namespace+"/"+s.Name)
		}
	}
	// The target pod first, so it is never cut off by MaxKnownHosts.
	pods := append([]corev1.Pod(nil), view.Pods...)
	isTarget := func(p corev1.Pod) bool { return p.Name == t.Name && p.Namespace == t.Namespace }
	slices.SortFunc(pods, func(a, b corev1.Pod) int {
		if ta, tb := isTarget(a), isTarget(b); ta != tb {
			if ta {
				return -1
			}
			return 1
		}
		return strings.Compare(a.Namespace+"/"+a.Name, b.Namespace+"/"+b.Name)
	})
	for _, p := range pods {
		if p.Spec.HostNetwork { // pod IP == node IP, already labeled as the node
			continue
		}
		name := "pod/" + p.Namespace + "/" + p.Name
		if p.Spec.NodeName != "" {
			name += " on " + p.Spec.NodeName
		}
		for _, ip := range p.Status.PodIPs {
			add(ip.IP, name)
		}
		if len(p.Status.PodIPs) == 0 {
			add(p.Status.PodIP, name)
		}
	}

	m.CapturePoint, m.Description = describe(pc, t)
	return m
}

func svcKey(s corev1.Service) string { return s.Namespace + "/" + s.Name }

func describe(pc *capturev1alpha1.PacketCapture, t Target) (point, desc string) {
	s := pc.Spec
	var b strings.Builder
	if s.Analysis.Description != "" {
		b.WriteString(strings.TrimSpace(s.Analysis.Description))
		b.WriteString("\n\n")
	}
	filter := s.Filter
	if filter == "" {
		filter = "(none)"
	}
	switch s.Mode {
	case capturev1alpha1.CaptureModeNode:
		iface := "default-route interface"
		if s.Node != nil && s.Node.Interface != "" {
			iface = s.Node.Interface
		}
		point = "node " + t.Name
		fmt.Fprintf(&b, "Captured by pcap-operator (Kubernetes) in Node mode on node %s, interface %s, "+
			"in the host network namespace. BPF filter: %s. Duration: %s.\n"+
			"Note: traffic between pods on different nodes may be encapsulated by the CNI (VXLAN udp/4789 or 8472, "+
			"Geneve udp/6081, IP-in-IP) or encrypted (WireGuard/IPsec); traffic between pods on the same node does "+
			"not pass this interface; egress traffic may be SNATed to the node IP.",
			t.Name, iface, filter, s.Duration.Duration)
		if iface == "any" {
			b.WriteString(" The 'any' interface sees pod packets several times (veth, bridge, uplink), so " +
				"duplicates are expected and are not retransmissions.")
		}
	default:
		point = fmt.Sprintf("pod %s/%s (%s) on node %s", t.Namespace, t.Name, t.IP, t.NodeName)
		fmt.Fprintf(&b, "Captured by pcap-operator (Kubernetes) in Pod mode inside the network namespace of pod "+
			"%s/%s (IP %s) on node %s: this is the pod's own view of its traffic, without overlay encapsulation. "+
			"BPF filter: %s. Duration: %s.",
			t.Namespace, t.Name, t.IP, t.NodeName, filter, s.Duration.Duration)
	}
	return point, b.String()
}
