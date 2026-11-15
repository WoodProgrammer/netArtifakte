# pcap-operator

Kubernetes operator that captures traffic with `tcpdump` (declared by a `PacketCapture` CR) and submits
the pcaps to [pcap-analyzer](../README.md) for zeek/tshark parsing and LLM analysis.

```
PacketCapture ──► operator ──► capture Job per target (operator namespace, on the target's node)
                                 tcpdump → curl POST /analyses/{id}/runs → runId in termination message
               ◄── operator polls GET /runs/{id} ──► status.targets[].runStatus / resultURL
```

## Capture modes
| | `Pod` | `Node` |
|---|---|---|
| Where | inside the target pod's network namespace (`hostPID` + `nsenter`, the netns is found by pod IP) | host network namespace, a node interface (default: default-route interface) |
| Sees | exactly the pod's traffic, real pod IPs, no overlay headers, same-node pod↔pod traffic | node↔node traffic; pod traffic may be VXLAN/Geneve/IPIP encapsulated, WireGuard/IPsec encrypted or SNATed; same-node pod traffic does **not** pass the uplink |
| Target pod touched? | no (no ephemeral container, no restart) | no |
| Allowed in | the CR's own namespace (selector matches only pods there) | only namespaces in `--node-capture-namespaces` (default: operator namespace) |

Each target becomes one run in the analysis. The metadata sent with each pcap is generated from the
cluster: pod CIDRs per node, node IPs, ClusterIPs, pod IPs → names, so the LLM sees
`10.244.1.7 (pod/default/web-0 on node-a)` instead of bare IPs.

## Setup
```bash
# capture image (tcpdump, nsenter, curl, jq) and operator image
docker build -t <registry>/pcap-capture:dev capture/
make docker-build docker-push IMG=<registry>/pcap-operator:dev

# set --analyzer-url / --capture-image in config/manager/manager.yaml, then
make deploy IMG=<registry>/pcap-operator:dev
kubectl apply -f config/samples/analyzer-credentials-secret.yaml   # a pcap-analyzer user (team member)
kubectl apply -f config/samples/capture_v1alpha1_packetcapture.yaml
kubectl get pcap -A -w
```

Operator flags: `--analyzer-url` (required), `--analyzer-public-url`, `--analyzer-secret`
(keys `username`/`password`, in the operator namespace), `--capture-image`, `--capture-namespace`,
`--node-capture-namespaces`, `--service-cidr`, `--job-ttl-seconds`, `--poll-interval`, `--target-wait-timeout`.

## Known limitations (v1alpha1)
- `analysisId` must exist in pcap-analyzer (no lookup by name / auto-create yet).
- No idempotency key on upload: a curl retry after a server-side timeout can create a second run.
- Several pods in one analysis: "compare with previous captures" compares across those pods.
- Capture jobs are privileged with `hostPID` / `hostNetwork`; the operator namespace is labeled PSA `privileged`.

## Development
```bash
make test   # envtest: target selection → job → termination message → analyzer polling
make lint
go run ./cmd/main.go --analyzer-url=http://localhost:8000 --capture-namespace=pcap-operator-system   # against the current kubeconfig
```
