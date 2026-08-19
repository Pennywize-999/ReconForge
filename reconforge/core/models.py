import json
import uuid
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from enum import Enum

class Confidence(Enum):
    CONFIRMED = "CONFIRMED"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    UNKNOWN = "UNKNOWN"

class FindingType(Enum):
    INFORMATION = "INFORMATION"
    INTERESTING = "INTERESTING"
    POTENTIAL_ISSUE = "POTENTIAL_ISSUE"
    VULNERABILITY = "VULNERABILITY"
    ERROR = "ERROR"

@dataclass
class Evidence:
    source_file: str
    source_type: str
    content: str

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Evidence":
        return cls(**data)

@dataclass
class Vulnerability:
    cve_id: Optional[str]
    title: str
    description: str
    severity: str
    cvss: Optional[float]
    affected_product: str
    detected_version: Optional[str] = None
    affected_versions: Optional[str] = None
    fixed_version: Optional[str] = None
    cpe: Optional[str] = None
    confidence: Confidence = Confidence.UNKNOWN
    source: str = ""
    evidence: List[Evidence] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    id: str = field(default_factory=lambda: str(uuid.uuid4()))

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Vulnerability":
        d = dict(data)
        if "confidence" in d and isinstance(d["confidence"], str):
            try:
                d["confidence"] = Confidence(d["confidence"])
            except ValueError:
                d["confidence"] = Confidence.UNKNOWN
        if "evidence" in d:
            d["evidence"] = [Evidence.from_dict(e) for e in d["evidence"]]
        # compatibility with older model
        if "affected_version" in d:
            d["detected_version"] = d.pop("affected_version")
        return cls(**d)

@dataclass
class Finding:
    title: str
    finding_type: FindingType
    severity: str
    confidence: Confidence
    description: str
    evidence: List[Evidence] = field(default_factory=list)
    source_file: str = ""
    source_type: str = ""
    references: List[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Finding":
        d = dict(data)
        if "finding_type" in d and isinstance(d["finding_type"], str):
            try:
                d["finding_type"] = FindingType(d["finding_type"])
            except ValueError:
                d["finding_type"] = FindingType.INFORMATION
        if "confidence" in d and isinstance(d["confidence"], str):
            try:
                d["confidence"] = Confidence(d["confidence"])
            except ValueError:
                d["confidence"] = Confidence.UNKNOWN
        if "evidence" in d:
            d["evidence"] = [Evidence.from_dict(e) for e in d["evidence"]]
        return cls(**d)

@dataclass
class Technology:
    name: str
    version: Optional[str] = None
    sources: List[str] = field(default_factory=list)
    detected_values: List[str] = field(default_factory=list)
    confidence: Confidence = Confidence.INFO

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Technology":
        d = dict(data)
        if "confidence" in d and isinstance(d["confidence"], str):
            try:
                d["confidence"] = Confidence(d["confidence"])
            except ValueError:
                d["confidence"] = Confidence.INFO
        return cls(**d)

@dataclass
class WebEndpoint:
    url: str
    path: str
    status_code: Optional[int]
    method: str = "GET"
    content_length: Optional[int] = None
    redirect_location: Optional[str] = None
    source: str = ""
    category: str = "Accessible"
    technologies: List[Technology] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "WebEndpoint":
        d = dict(data)
        if "technologies" in d:
            d["technologies"] = [Technology.from_dict(t) for t in d["technologies"]]
        return cls(**d)

@dataclass
class LowImpactProfile:
    request_policy: str = "Conservative"
    avoid_duplicate_requests: bool = True
    respect_retry_after: bool = True
    stop_after_blocking: bool = True
    aggressive_enumeration_disabled: bool = True
    evasion_techniques_disabled: bool = True

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "LowImpactProfile":
        return cls(**data)

@dataclass
class WAFAnalysis:
    detected: bool = False
    confidence: Confidence = Confidence.UNKNOWN
    provider: Optional[str] = None
    provider_confidence: Confidence = Confidence.UNKNOWN
    rate_limiting: bool = False
    status_counts: Dict[str, int] = field(default_factory=dict)
    indicators: List[str] = field(default_factory=list)
    evidence: List[Evidence] = field(default_factory=list)
    low_impact_profile: Optional[LowImpactProfile] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "WAFAnalysis":
        d = dict(data)
        if "confidence" in d and isinstance(d["confidence"], str):
            try:
                d["confidence"] = Confidence(d["confidence"])
            except ValueError:
                d["confidence"] = Confidence.UNKNOWN
        if "provider_confidence" in d and isinstance(d["provider_confidence"], str):
            try:
                d["provider_confidence"] = Confidence(d["provider_confidence"])
            except ValueError:
                d["provider_confidence"] = Confidence.UNKNOWN
        if "evidence" in d:
            d["evidence"] = [Evidence.from_dict(e) for e in d["evidence"]]
        if "low_impact_profile" in d and d["low_impact_profile"]:
            d["low_impact_profile"] = LowImpactProfile.from_dict(d["low_impact_profile"])
        return cls(**d)

@dataclass
class Service:
    name: str
    product: str = ""
    version: str = ""
    cpe: str = ""
    technologies: List[Technology] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Service":
        d = dict(data)
        if "technologies" in d:
            d["technologies"] = [Technology.from_dict(t) for t in d["technologies"]]
        return cls(**d)

@dataclass
class Port:
    number: int
    protocol: str
    state: str
    service: Optional[Service] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Port":
        d = dict(data)
        if "service" in d and d["service"] is not None:
            d["service"] = Service.from_dict(d["service"])
        return cls(**d)

@dataclass
class Host:
    ip: str
    status: str
    ipv6: str = ""
    mac: str = ""
    hostnames: List[str] = field(default_factory=list)
    os_guesses: List[str] = field(default_factory=list)
    os_cpes: List[str] = field(default_factory=list)
    ports: List[Port] = field(default_factory=list)
    web_endpoints: List[WebEndpoint] = field(default_factory=list)
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    waf_analysis: Optional[WAFAnalysis] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Host":
        d = dict(data)
        if "ports" in d:
            d["ports"] = [Port.from_dict(p) for p in d["ports"]]
        if "web_endpoints" in d:
            d["web_endpoints"] = [WebEndpoint.from_dict(w) for w in d["web_endpoints"]]
        if "vulnerabilities" in d:
            d["vulnerabilities"] = [Vulnerability.from_dict(v) for v in d["vulnerabilities"]]
        if "findings" in d:
            d["findings"] = [Finding.from_dict(f) for f in d["findings"]]
        if "waf_analysis" in d and d["waf_analysis"]:
            d["waf_analysis"] = WAFAnalysis.from_dict(d["waf_analysis"])
        return cls(**d)

@dataclass
class Target:
    hosts: Dict[str, Host] = field(default_factory=dict)
    evidence: List[Evidence] = field(default_factory=list)
    execution: List[Dict[str, Any]] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Target":
        d = dict(data)
        if "hosts" in d:
            d["hosts"] = {k: Host.from_dict(v) for k, v in d["hosts"].items()}
        if "evidence" in d:
            d["evidence"] = [Evidence.from_dict(e) for e in d["evidence"]]
        if "execution" in d:
            d["execution"] = list(d["execution"])
        return cls(**d)

@dataclass
class ScanSession:
    id: str
    timestamp: str
    target: Target
    raw_files: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ScanSession":
        d = dict(data)
        if "target" in d:
            d["target"] = Target.from_dict(d["target"])
        return cls(**d)

class ModelEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, Enum):
            return obj.value
        if hasattr(obj, '__dict__'):
            return obj.__dict__
        return super().default(obj)

@dataclass
class ReconTarget:
    input: str
    target_type: str  # 'ip' or 'url'
    ip: Optional[str] = None
    hostname: Optional[str] = None
    scheme: Optional[str] = None
    port: Optional[int] = None
    url: Optional[str] = None
    mode: str = "Standard Recon"
    source: str = "interactive"

@dataclass
class ReconPlan:
    mode: str
    target: ReconTarget
    modules: List[str] = field(default_factory=list)
    output_directory: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
