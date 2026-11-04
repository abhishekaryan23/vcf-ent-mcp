# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Enterprise VCF MCP Control Plane Configuration Manager.
Loads settings from YAML configuration and environment variables with type-safe defaults.
"""

from __future__ import annotations
import os
from typing import List, Dict, Any, Optional
try:
    import yaml
except ImportError:
    yaml = None

try:
    from pydantic import BaseModel, Field
except ImportError:
    class _FieldInfo:
        def __init__(self, default=None, default_factory=None, alias=None, **kwargs):
            self.default = default
            self.default_factory = default_factory
            self.alias = alias

    def Field(default=None, default_factory=None, alias=None, **kwargs):
        return _FieldInfo(default=default, default_factory=default_factory, alias=alias, **kwargs)

    class BaseModel:
        def __init__(self, **kwargs):
            for attr in dir(self.__class__):
                if attr.startswith("_"):
                    continue
                val = getattr(self.__class__, attr)
                if isinstance(val, _FieldInfo):
                    if val.default_factory is not None:
                        setattr(self, attr, val.default_factory())
                    else:
                        setattr(self, attr, val.default)
                elif not callable(val):
                    setattr(self, attr, val)
            for k, v in kwargs.items():
                setattr(self, k, v)


class ServerConfig(BaseModel):
    host: str = "0.0.0.0"
    port: int = 8443
    mcp_endpoint: str = "/mcp"
    enable_tls: bool = False
    cert_path: str = ""
    key_path: str = ""
    mode: str = "in_network"  # "in_network" or "remote_gateway"
    log_level: str = "INFO"
    environment: str = "production"  # "production", "development", "testing"
    storage_mode: str = "APPLIANCE"  # "APPLIANCE" (SQLite WAL) or "ENTERPRISE_HA" (PostgreSQL)
    postgres_dsn: str = ""
    # Strict production mode from the config file (same effect as VCF_MCP_ENV=production): refuses lab tokens,
    # loopback targets, test keys and the lab key material.
    production_mode: bool = False
    # Optional role skill applied to tools/list when the client does not request one, so small local models
    # see a short, pre-pruned tool list (see `vcf-mcp skills list`).
    default_skill: Optional[str] = None
    # Who approves and how callers are identified (see auth/personal.py and docs/authorization_model.md).
    #   personal: one person on their own machine (stdio only). No token needed: the caller is the local OS user, and
    #             that person confirms each change themselves (chat prompt, local page or their own terminal).
    #   team:     IdP or lab tokens for every call, an approver token, approver != initiator, two approvers for
    #             DESTRUCTIVE / SECURITY_SENSITIVE. REQUIRED for http / remote_gateway, production_mode,
    #             VCF_MCP_ENV=production and storage_mode ENTERPRISE_HA.
    # Absent = team (existing configs keep their behaviour); only the starter config written by
    # `vcf-mcp client-config` sets personal.
    access_mode: Optional[str] = None
    personal_user: Optional[str] = None  # default: <os user>@<short hostname>
    personal_roles: List[str] = Field(default_factory=lambda: ["VCF_PLATFORM_ADMIN"])


class IdPConfig(BaseModel):
    enabled: bool = True
    provider_name: str = "corporate-entra-id"
    issuer_url: str = "https://login.microsoftonline.com/common/v2.0"
    client_id: str = "vcf-mcp-control-plane-client"
    jwks_uri: str = "https://login.microsoftonline.com/common/discovery/v2.0/keys"
    user_claim: str = "preferred_username"
    groups_claim: str = "groups"
    roles_claim: str = "roles"
    tenant_claim: str = "tid"
    token_leeway_seconds: int = 60
    allowed_algorithms: List[str] = Field(default_factory=lambda: ["RS256", "ES256"])
    allow_anonymous: bool = False
    # Lab/local use only: trust the key made by `vcf-mcp token mint` (issuer urn:vcf-mcp:lab). Off by default,
    # ignored in production mode.
    allow_lab_tokens: bool = False
    trusted_providers: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    jwks_cache_ttl_seconds: int = 3600


class VCenterTarget(BaseModel):
    """An extra vCenter (for example a workload domain's) attached with `vcf-mcp vcenter add` or vcf_add_vcenter."""
    url: str                              # HTTPS base URL
    username: Optional[str] = None        # its own service account (an isolated SSO domain); None reuses the main vCenter account
    credential_ref: Optional[str] = None  # where that account's password lives in the secret store


class UpstreamVCFConfig(BaseModel):
    # No default appliance name: an example FQDN must never end up as a real endpoint.
    sddc_manager_fqdn: Optional[str] = None
    gateway_url: str = "http://127.0.0.1:8085"  # where the bundled Digital Twin listens
    dc1_vcenter_url: str = "http://127.0.0.1:9090"
    dc2_vcenter_url: str = "http://127.0.0.1:9091"
    active_version: str = "9.1.1"
    verify_ssl: bool = True
    ca_cert_path: Optional[str] = None
    sddc_service_user: str = "svc_vcf_mcp_control_plane"
    credential_ref: str = "local://prod/sddc-service"
    sddc_service_secret: Optional[str] = None
    # Real-VCF component endpoints (HTTPS base URLs). Required when the platform runs in REAL_VCF mode.
    sddc_manager_url: Optional[str] = None
    vcenter_url: Optional[str] = None
    nsx_url: Optional[str] = None
    operations_url: Optional[str] = None
    # Optional VCF Automation (VM Apps organization) endpoint and organization name; its API token is
    # the credential for component "vcf_automation".
    automation_url: Optional[str] = None
    automation_org: Optional[str] = None
    # Non-secret client id of the VCF Automation service account (written by `vcf-mcp setup automation`);
    # sent with every refresh-token exchange. The refresh token itself lives in the secret store.
    automation_client_id: Optional[str] = None
    # Orchestrator (embedded in VCF Automation, /vco/api): what the MCP may author and run.
    orchestrator_url: Optional[str] = None             # defaults to automation_url
    # How the MCP logs in to Orchestrator: "automation_token" (default: the VCF Automation service-account
    # token), "basic" (HTTP Basic, standalone Orchestrator) or "vcfa_session" (VCF Automation session login
    # with user@org and a password). basic/vcfa_session use the credential for component "vcf_orchestrator"
    # when configured, else "vcf_automation".
    orchestrator_auth: str = "automation_token"
    orchestrator_managed_category: str = "MCP-Managed"  # workflows the MCP may create/edit live under this root
    orchestrator_module_prefix: str = "com.mcp"         # actions the MCP may create/edit use this module prefix
    orchestrator_run_allowlist: List[str] = []          # extra category paths whose workflows may be run, e.g. "Northwind/*"
    orchestrator_blocked_workflows: List[str] = []      # workflow names never run through the MCP (high impact)
    orchestrator_repository_allowlist: List[str] = []   # URL prefixes allowed for action environment repositories
    orchestrator_script_level: str = "es5"              # "es5" (proven on a real 9.1.1 server) | "rhino_1_7_15" (let/const/arrow/template allowed)
    # Per-component credential references keyed by provider type
    # (sddc_manager, vcenter, nsx, vcf_operations); missing entries fall back to credential_ref.
    component_credential_refs: Dict[str, str] = {}
    # Non-secret service-account usernames per component (written by guided setup).
    component_usernames: Dict[str, str] = {}
    operations_auth_source: Optional[str] = None
    # Upstream destination allowlist for the SSRF guard (DNS suffixes / CIDRs of the VCF appliances).
    allowed_dns_suffixes: List[str] = []
    allowed_cidrs: List[str] = []
    # Lab-only: let setup reach appliances on loopback (e.g. local mock appliances). Refused in production.
    allow_loopback_targets: bool = False
    # Extra vCenters keyed by host name, on top of vcenter_url and those SDDC Manager reports. Inventory reads all of
    # them; a VM change goes to the vCenter that holds the VM.
    vcenters: Dict[str, VCenterTarget] = {}
    # FQDN -> base URL for discovered appliances (load balancer/proxy, or a lab simulator).
    endpoint_overrides: Dict[str, str] = {}
    # Explicit HTTPS proxy for appliance connections (CONNECT tunnel), e.g. http://proxy.example.internal:3128.
    # Falls back to the standard HTTPS_PROXY / NO_PROXY environment variables. The SSRF guard still checks the target.
    https_proxy: Optional[str] = None
    no_proxy: Optional[str] = None


class PolicyConfig(BaseModel):
    operating_mode: str = "DISCOVERY_ONLY"  # "DISCOVERY_ONLY", "AUDITED_OPERATIONS", "FULL_ENFORCEMENT"
    enforce_two_stage_auth: bool = True
    require_approval_for_high_impact: bool = True
    require_approval_for_destructive: bool = True
    require_approval_for_change: bool = False
    allow_dry_run_bypass_approval: bool = True
    allow_anonymous: bool = False
    max_token_ttl_seconds: int = 3600
    cache_policy_decisions_seconds: int = 60


class AuditConfig(BaseModel):
    enabled: bool = True
    export_target: str = "memory"  # "memory", "stdout", "file", "syslog", "opentelemetry"
    file_path: str = "audit_events.jsonl"
    redact_secrets: bool = True
    export_to_vcf_operations_logs: bool = False


class EnterpriseSettings(BaseModel):
    server: ServerConfig = Field(default_factory=ServerConfig)
    idp: IdPConfig = Field(default_factory=IdPConfig)
    vcf: UpstreamVCFConfig = Field(default_factory=UpstreamVCFConfig)
    policy: PolicyConfig = Field(default_factory=PolicyConfig)
    audit: AuditConfig = Field(default_factory=AuditConfig)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if isinstance(self.server, dict):
            self.server = ServerConfig(**self.server)
        if isinstance(self.idp, dict):
            self.idp = IdPConfig(**self.idp)
        if isinstance(self.vcf, dict):
            self.vcf = UpstreamVCFConfig(**self.vcf)
        if isinstance(self.policy, dict):
            self.policy = PolicyConfig(**self.policy)
        if isinstance(self.audit, dict):
            self.audit = AuditConfig(**self.audit)

    def validate_production_readiness(self) -> None:
        """Validates configuration against enterprise production security gates."""
        from vcf_enterprise_mcp.core.errors import ConfigurationException

        env = os.environ.get("VCF_MCP_ENV", self.server.environment).lower()
        if self.server.production_mode:
            env = "production"
        if env == "production":
            if self.idp.allow_anonymous or getattr(self.policy, "allow_anonymous", False):
                raise ConfigurationException(
                    "Production security gate failure: allow_anonymous is forbidden in production environment."
                )
            if "common/v2.0" in self.idp.issuer_url or "example.com" in self.idp.issuer_url:
                raise ConfigurationException(
                    f"Production security gate failure: unconstrained or test issuer '{self.idp.issuer_url}' is forbidden in production."
                )
            if self.server.storage_mode == "ENTERPRISE_HA" and not self.server.postgres_dsn:
                raise ConfigurationException(
                    "Production security gate failure: ENTERPRISE_HA mode requires a valid postgres_dsn."
                )
            if self.vcf.sddc_service_secret:
                raise ConfigurationException(
                    "Production security gate failure: Plaintext 'sddc_service_secret' is forbidden in production. Use credential_ref."
                )
            if self.vcf.credential_ref and self.vcf.credential_ref.startswith("env://"):
                raise ConfigurationException(
                    f"Production security gate failure: Environment variable credential reference '{self.vcf.credential_ref}' is forbidden in production. Use local encrypted or enterprise vault."
                )

    @staticmethod
    def config_path(path: Optional[str] = None):
        """The config file in use: explicit argument, VCF_ENTERPRISE_MCP_CONFIG, else ~/.vcf-mcp/config.yaml."""
        from pathlib import Path
        from vcf_enterprise_mcp.core.paths import default_config_path
        explicit = path or os.environ.get("VCF_ENTERPRISE_MCP_CONFIG")
        return Path(explicit).expanduser() if explicit else default_config_path()

    @classmethod
    def load_from_yaml(cls, path: Optional[str] = None) -> "EnterpriseSettings":
        from vcf_enterprise_mcp.core.errors import ConfigurationException
        explicit = path or os.environ.get("VCF_ENTERPRISE_MCP_CONFIG")
        cfg_path = cls.config_path(path)
        data: Dict[str, Any] = {}
        if cfg_path.exists():
            try:
                with cfg_path.open("r", encoding="utf-8") as f:
                    if yaml is None:
                        raise ConfigurationException("PyYAML is required to load configuration.")
                    data = yaml.safe_load(f) or {}
                if not isinstance(data, dict):
                    raise ConfigurationException("Configuration must be a YAML mapping.")
            except Exception as e:
                raise ConfigurationException(f"Cannot load configuration from {cfg_path}.") from e
        elif explicit:
            raise ConfigurationException(f"Configuration file does not exist: {cfg_path}")

        # Environment variable overrides
        if "VCF_OPERATING_MODE" in os.environ:
            data.setdefault("policy", {})["operating_mode"] = os.environ["VCF_OPERATING_MODE"]
        if "VCF_SDDC_MANAGER_FQDN" in os.environ:
            data.setdefault("vcf", {})["sddc_manager_fqdn"] = os.environ["VCF_SDDC_MANAGER_FQDN"]
        if "VCF_GATEWAY_URL" in os.environ:
            data.setdefault("vcf", {})["gateway_url"] = os.environ["VCF_GATEWAY_URL"]
        if "VCF_VERIFY_SSL" in os.environ:
            value = os.environ["VCF_VERIFY_SSL"].strip().lower()
            if value not in ("true", "false"):
                raise ValueError("VCF_VERIFY_SSL must be 'true' or 'false'.")
            data.setdefault("vcf", {})["verify_ssl"] = value == "true"
        if "VCF_CA_CERT_PATH" in os.environ:
            data.setdefault("vcf", {})["ca_cert_path"] = os.environ["VCF_CA_CERT_PATH"] or None

        return cls(**data)


_settings_instance: Optional[EnterpriseSettings] = None
_production_env_set_by_config = False


def apply_production_flag(settings: "EnterpriseSettings") -> None:
    """Makes `server.production_mode: true` in the config file equivalent to VCF_MCP_ENV=production for the
    whole process (lab key trust, loopback targets, test keys), and undoes it if a reload turns it off."""
    global _production_env_set_by_config
    if settings.server.production_mode:
        os.environ["VCF_MCP_ENV"] = "production"
        _production_env_set_by_config = True
    elif _production_env_set_by_config:
        os.environ.pop("VCF_MCP_ENV", None)
        _production_env_set_by_config = False


def get_enterprise_settings() -> EnterpriseSettings:
    global _settings_instance
    if _settings_instance is None:
        _settings_instance = EnterpriseSettings.load_from_yaml()
    return _settings_instance


def set_enterprise_settings(settings: EnterpriseSettings) -> None:
    global _settings_instance
    _settings_instance = settings


def attached_vcenters(vcf: Any) -> Dict[str, VCenterTarget]:
    """vcf.vcenters as VCenterTarget objects. Without pydantic the config loader keeps nested entries as plain mappings."""
    return {host: t if isinstance(t, VCenterTarget) else VCenterTarget(**t)
            for host, t in (getattr(vcf, "vcenters", None) or {}).items()}


def config_file_stamp() -> Optional[tuple]:
    """(path, modification time) of the config file in use, or None when there is none: a change means it was edited."""
    path = EnterpriseSettings.config_path()
    try:
        return str(path), path.stat().st_mtime_ns
    except OSError:
        return None
