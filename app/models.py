"""Step 1: metadata the user submits along with the pcap."""
import ipaddress

from pydantic import BaseModel, Field


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
    """New analysis (project). If default_metadata is set, runs can be submitted without metadata.

    team_id may be omitted when the user belongs to exactly one team.
    """
    name: str
    description: str = ""
    default_metadata: CaptureMeta | None = None
    team_id: int | None = None
    auto_approve: bool = False


class AnalysisUpdate(BaseModel):
    """Partial update: only the fields sent are changed. default_metadata: null → clears it."""
    name: str | None = None
    description: str | None = None
    default_metadata: CaptureMeta | None = None
    team_id: int | None = None
    auto_approve: bool | None = None


class ToolDecision(BaseModel):
    """User decision on a command proposal. command: edited command line (optional)."""
    command: str | None = None
    note: str | None = None


class FollowupCreate(BaseModel):
    question: str = Field(min_length=1, max_length=4000)


# ---------------------------------------------------------------- auth / admin
class LoginRequest(BaseModel):
    username: str
    password: str


class PasswordChange(BaseModel):
    current_password: str
    new_password: str


class UserCreate(BaseModel):
    username: str
    password: str
    is_admin: bool = False
    team_ids: list[int] = []


class UserUpdate(BaseModel):
    """Partial update by an admin. password: sets a new password (and logs the user out everywhere)."""
    password: str | None = None
    is_admin: bool | None = None
    active: bool | None = None
    team_ids: list[int] | None = None


class TeamCreate(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    member_ids: list[int] = []


class TeamUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=64)
    member_ids: list[int] | None = None
