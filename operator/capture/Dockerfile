# Capture job image for pcap-operator: tcpdump + nsenter + iproute2 + curl + jq.
# Build: docker build -t pcap-capture:latest operator/capture
FROM alpine:3.20

RUN apk add --no-cache tcpdump iproute2 util-linux-misc curl jq coreutils

COPY capture.sh /usr/local/bin/capture.sh
RUN chmod 0755 /usr/local/bin/capture.sh

# Runs as root on purpose: the job is privileged (nsenter into pod netns / raw capture).
ENTRYPOINT ["/usr/local/bin/capture.sh"]
