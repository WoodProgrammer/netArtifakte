"""Step 1: metadata the user submits along with the pcap."""
import ipaddress

from pydantic import BaseModel


class Network(BaseModel):
    cidr: str
    role: str


class KnownHost(BaseModel):
    ip: str
    name: str


class CaptureMeta(BaseModel):
    description: str = ""
    capture_point: str = ""
    networks: list[Network] = []
    known_hosts: list[KnownHost] = []
    question: str

    def label(self, ip: str) -> str:
        """Label an IP using known_hosts / networks: '172.16.0.10 (node-a)'."""
        for h in self.known_hosts:
            if h.ip == ip:
                return f"{ip} ({h.name})"
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return ip
        for n in self.networks:
            if addr in ipaddress.ip_network(n.cidr, strict=False):
                return f"{ip} [{n.role}]"
        return ip


class AnalysisCreate(BaseModel):
    """New analysis (project). If default_metadata is set, runs can be submitted without metadata."""
    name: str
    description: str = ""
    default_metadata: CaptureMeta | None = None


class AnalysisUpdate(BaseModel):
    """Partial update: only the fields sent are changed. default_metadata: null → clears it."""
    name: str | None = None
    description: str | None = None
    default_metadata: CaptureMeta | None = None


class ToolDecision(BaseModel):
    """User decision on a command proposal. command: edited command line (optional)."""
    command: str | None = None
    note: str | None = None
