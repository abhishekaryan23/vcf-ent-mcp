# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Identity-Aware Multi-Stage Tool Router with Parameter-Level Capability Gating (ROUTE-02).
Pipeline:
1. Version Compatibility Filter
2. RBAC Capability Filter
3. Resource Scope Verification
4. Structural Intent Parser (domain, entity, action, parameters, mutation)
5. Parameter-Level Capability & Hard-Negative Filtering
6. Semantic & Lexical Scoring
7. Confidence Threshold & Margin Safety Policy (Read, Safe-Write, Change, High-Impact)
8. Deterministic Output: MATCHED, NO_TOOL, or ROUTE_UNCERTAIN.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from vcf_enterprise_mcp.auth.identity import Principal
from vcf_enterprise_mcp.policy.models import CapabilityRole, RiskClass
from vcf_enterprise_mcp.policy.engine import PolicyDecisionPoint
from vcf_enterprise_mcp.router.catalog import EnterpriseToolCard, get_all_tool_cards


@dataclass
class StructuredIntent:
    """Parsed structured intent extracted from user query."""
    domain: Optional[str] = None
    entity: Optional[str] = None
    action: Optional[str] = None
    parameters: List[str] = field(default_factory=list)
    mutation: bool = False
    raw_query: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "domain": self.domain,
            "entity": self.entity,
            "action": self.action,
            "parameters": self.parameters,
            "mutation": self.mutation,
        }


@dataclass
class RoutedToolResult:
    """Outcome of identity-aware routing evaluation."""
    status: str  # "MATCHED", "NO_TOOL", "ROUTE_UNCERTAIN"
    selected_tool: Optional[str]
    confidence: float
    extracted_parameters: Dict[str, Any]
    candidate_count_initial: int
    candidate_count_after_version: int
    candidate_count_after_rbac: int
    candidate_count_final: int
    reasoning: str
    intent: Optional[StructuredIntent] = None

    @property
    def matched(self) -> bool:
        return self.status == "MATCHED"

    @property
    def is_no_tool(self) -> bool:
        return self.status == "NO_TOOL"

    @property
    def tool_card(self) -> Optional[EnterpriseToolCard]:
        if not self.selected_tool:
            return None
        for c in get_all_tool_cards():
            if c.name == self.selected_tool:
                return c
        return None

    @property
    def abstain_reason(self) -> str:
        return self.status if self.status in ("ROUTE_UNCERTAIN", "NO_TOOL") else ""


class IdentityAwareRouter:
    """
    Identity-aware and parameter-capability aware router.
    Prevents dispatch of unsupported parameters (e.g. disk resize), unsupported sub-actions
    (e.g. guest OS shutdown vs hypervisor power off), and enforces deterministic safety gates.
    """

    # Calibrated confidence thresholds by risk class
    READ_THRESHOLD: float = 0.50
    SAFE_WRITE_THRESHOLD: float = 0.65
    CHANGE_THRESHOLD: float = 0.70
    HIGH_IMPACT_THRESHOLD: float = 0.80

    EXTENDED_SPECIALIZED_TOOLS: Set[str] = {
        "vcf_list_domains",
        "vcf_list_clusters",
        "vcf_list_datastores",
        "vcf_list_nsx_segments",
        "vcf_list_nsx_gateways",
        "vcf_list_snapshots",
        "vcf_delete_snapshot",
        "vcf_list_upgrade_bundles",
        "vcf_verify_audit_chain",
    }

    EXTENDED_TOOL_PATTERNS: Dict[str, re.Pattern[str]] = {
        "vcf_list_snapshots": re.compile(r"\b(list|show|get|view)\s+(?:all\s+|vm\s+)?snapshots?\b", re.IGNORECASE),
        "vcf_delete_snapshot": re.compile(r"\b(delete|remove)\s+(?:vm\s+)?snapshots?\b", re.IGNORECASE),
        "vcf_list_datastores": re.compile(r"\b(list|show|get)\s+(?:all\s+|vsan\s+)?datastores?\b", re.IGNORECASE),
        "vcf_list_nsx_segments": re.compile(r"\b(list|show|get)\s+(?:all\s+|nsx\s+|logical\s+|overlay\s+)?segments?\b", re.IGNORECASE),
        "vcf_list_nsx_gateways": re.compile(r"\b(list|show|get)\s+(?:all\s+|nsx\s+|tier-[01]\s+)?gateways?\b", re.IGNORECASE),
        "vcf_list_domains": re.compile(r"\b(list|show|get)\s+(?:all\s+|vcf\s+|sddc\s+)?(?:workload\s+)?domains?\b", re.IGNORECASE),
        "vcf_list_clusters": re.compile(r"\b(list|show|get)\s+(?:all\s+|compute\s+|vsphere\s+)?clusters?\b", re.IGNORECASE),
        "vcf_list_upgrade_bundles": re.compile(r"\b(list|show|get)\s+(?:all\s+|applicable\s+|available\s+|sddc\s+|lcm\s+)?(?:upgrade\s+)?bundles?\b", re.IGNORECASE),
        "vcf_verify_audit_chain": re.compile(r"\b(verify|check|inspect|validate)\s+(?:cryptographic\s+|tamper(?:-evident)?\s+)?audit\s+(?:chain|log|trail)\b", re.IGNORECASE),
    }

    def __init__(self, pdp: Optional[PolicyDecisionPoint] = None):
        self.pdp = pdp or PolicyDecisionPoint()
        self.all_tools = get_all_tool_cards()
        self._tool_example_tokens: Dict[str, List[Set[str]]] = {}
        self._tool_trigger_tokens: Dict[str, List[Set[str]]] = {}
        self._tool_desc_tokens: Dict[str, Set[str]] = {}
        for t in self.all_tools:
            self._tool_example_tokens[t.name] = [set(re.findall(r"\w+", ex.lower())) for ex in t.examples]
            self._tool_trigger_tokens[t.name] = [set(re.findall(r"\w+", tr.lower())) for tr in t.use_when]
            self._tool_desc_tokens[t.name] = set(re.findall(r"\w+", t.description.lower()))

    def parse_intent_structurally(self, query: str) -> StructuredIntent:
        """
        Parses user query into structured components: domain, entity, action, parameters, and mutation flag.
        """
        q = query.lower()

        # 1. Action parsing
        action: Optional[str] = None
        mutation = False

        if re.search(r"\b(gracefully?\s+shut\s*down|graceful\s+shutdown|guest\s+shutdown|guest\s+os\s+shutdown|os\s+shutdown|clean\s+(?:os\s+)?shutdown)\b", q):
            action = "guest_shutdown"
            mutation = True
        elif re.search(r"\b(gracefully?\s+reboot|graceful\s+reboot|guest\s+reboot|os\s+reboot|via\s+vmware\s+tools)\b", q):
            action = "guest_reboot"
            mutation = True
        elif re.search(r"\b(hard\s+power\s*off|force\s+power\s*off|power\s*off|stop|poweroff)\b", q):
            action = "power_off"
            mutation = True
        elif re.search(r"\b(dr\s+test|test\s+failover|failover\s+drill|site\s+failover\s+drill|recovery\s+drill|simulate\s+failover|test\s+srm|disaster\s+recovery\s+drill|srm\s+recovery\s+plan|disaster\s+recovery\s+testing|disaster\s+recovery\s+test|site\s+recovery\s+test)\b", q):
            action = "dr_test"
            mutation = True  # Operational execution of recovery test drill
        elif re.search(r"\b(power\s*on|start|poweron|boot)\b", q) and not re.search(r"\b(upgrade|drill|test|testing|dr|recovery|srm)\b", q):
            action = "power_on"
            mutation = True
        elif re.search(r"\b(reboot|restart|reset)\b", q):
            action = "restart"
            mutation = True
        elif re.search(r"\b(resize|scale|increase|decrease|expand|shrink|grow|add\s+(?:more\s+)?(?:\d+\s+)?(?:cpu|ram|memory|disk|cores)|allocate)\b", q):
            action = "resize"
            mutation = True
        elif re.search(r"\b(take\s+snapshot|create\s+snapshot|snapshot)\b", q) and not re.search(r"\b(list|show|view|get)\b", q):
            action = "create_snapshot"
            mutation = True
        elif re.search(r"\b(create\s+segment|provision\s+segment|create\s+nsx|provision\s+nsx|add\s+segment|provision\s+(?:an?\s+)?(?:nsx\s+)?segment)\b", q):
            action = "create_nsx_segment"
            mutation = True
        elif re.search(r"\b(add|create|provision)\b", q) and "portgroup" in q:
            action = "create_portgroup"
            mutation = True
        elif re.search(r"\b(fail\s+production\s+over|failover|unplanned\s+failover|fail\s+over)\b", q):
            action = "dr_failover"
            mutation = True
        elif re.search(r"\b(reprotect|replication\s+sync|clean\s*up\s+dr)\b", q):
            action = "dr_maintenance"
            mutation = True
        elif re.search(r"\b(back\s*up|backup|take\s+backup|create\s+backup|restore|veeam|commvault)\b", q):
            action = "backup"
            mutation = True
        elif re.search(r"\b(upgrade|upgrading|patch|patching|lifecycle\s+patching|lifecycle\s+upgrade)\b", q):
            action = "upgrade"
            mutation = True
        elif re.search(r"\b(list|show|get|inspect|fetch|display|view|check|status|alarms|health|query|promql)\b", q):
            action = "query"
            mutation = False

        # 2. Entity parsing
        entity: Optional[str] = None
        if re.search(r"\b(promql|telemetry|utilization|usage|consumption|stats|cpu\s+usage|memory\s+usage)\b", q):
            entity = "metric"
        elif re.search(r"\b(alarm|alarms|health|system\s+status)\b", q):
            entity = "system"
        elif re.search(r"\b(dr|srm|recovery\s+plan|site\s+recovery|site\s+failover|failover\s+drill|disaster\s+recovery)\b", q):
            entity = "recovery_plan"
        elif re.search(r"\b(domain|workload\s+domain|sddc)\b", q):
            entity = "domain"
        elif re.search(r"\b(esxi|host|hosts|hypervisor|hypervisors|bare-metal)\b", q):
            entity = "host"
        elif re.search(r"\b(segment|segments|nsx\s+segment|portgroup|subnet|network)\b", q):
            entity = "network_segment"
        elif re.search(r"\b(snapshot|snapshots)\b", q):
            entity = "snapshot"
        elif re.search(r"\b(vm|vms|virtual\s+machine|virtual\s+machines|guest)\b", q):
            entity = "virtual_machine"
        elif re.search(r"\b(metric|metrics)\b", q):
            entity = "metric"

        # 3. Parameters parsing
        parameters: List[str] = []
        if re.search(r"\b(disk|disks|storage|volume|volumes|vmdk|vmdks|datastore|c\s+drive|drive)\b", q):
            parameters.append("disk")
        if re.search(r"\b(cpu|vcpu|vcpus|core|cores|processor)\b", q):
            parameters.append("cpu")
        if re.search(r"\b(memory|ram|gb|mb)\b", q):
            parameters.append("memory")
        if re.search(r"\b(nic|network\s+adapter|interface)\b", q):
            parameters.append("nic")
        if re.search(r"\b(portgroup|vlan|vpc|subnet)\b", q):
            parameters.append("portgroup")

        # 4. Domain inference
        domain = "compute"
        if entity == "metric" or re.search(r"\b(promql|metric|metrics|telemetry|utilization|usage|consumption|stats)\b", q):
            domain = "observability"
        elif entity in ("host", "virtual_machine", "cluster"):
            domain = "compute"
        elif entity in ("network_segment",) or "nsx" in q or "segment" in q:
            domain = "network"
        elif entity in ("snapshot",) or "vsan" in q:
            domain = "storage"
        elif entity in ("domain",) or action == "upgrade":
            domain = "lifecycle"
        elif entity in ("recovery_plan",) or "dr" in q or "failover" in q:
            domain = "disaster_recovery"
        elif entity in ("system",):
            domain = "observability"

        return StructuredIntent(
            domain=domain,
            entity=entity,
            action=action,
            parameters=parameters,
            mutation=mutation,
            raw_query=query,
        )

    def route_query(
        self,
        query: str,
        principal: Principal,
        target_version: str = "9.1.1",
        target_cluster: Optional[str] = None,
        target_domain: Optional[str] = None,
    ) -> RoutedToolResult:
        """Executes the multi-stage identity-aware filter, capability matching, and reranking pipeline."""
        initial_count = len(self.all_tools)
        q_lower = query.lower()

        # Parse query intent structurally
        intent = self.parse_intent_structurally(query)

        # Stage 0a: Adversarial Injection Protection
        if re.search(r"(ignore\s+(?:previous|all)\s+instructions|system\s+override|drop\s+table|rm\s+-rf|eval\(|<script|bypass\s+security|jailbreak|disregard\s+(?:prior|previous)|root\s+access|delete\s+all\s+datastores)", q_lower):
            return RoutedToolResult(
                status="ROUTE_UNCERTAIN",
                selected_tool=None,
                confidence=0.0,
                extracted_parameters={},
                candidate_count_initial=initial_count,
                candidate_count_after_version=0,
                candidate_count_after_rbac=0,
                candidate_count_final=0,
                reasoning="Adversarial prompt injection pattern detected.",
                intent=intent,
            )

        # Stage 0b: Multi-Action Decomposition & Ambiguity Guard (F22)
        if (
            re.search(r"\b(choose\s+for\s+me|decide\s+for\s+me|pick\s+(?:one|for\s+me))\b", q_lower)
            or (re.search(r"\b(maybe|perhaps)\b", q_lower) and re.search(r"\b(or|either)\b", q_lower))
            or re.search(r"\b(?:restart|power\s*off|stop)\b.*\bor\b.*\b(?:fail\s*(?:it\s*)?over|dr|upgrade)\b", q_lower)
            or re.search(r"\b(power\s*off|poweroff|stop)\b.*\band\b.*\b(snapshot|resize|power\s*on|delete|upgrade)\b", q_lower)
            or re.search(r"\b(snapshot)\b.*\band\b.*\b(power\s*off|resize|delete|upgrade)\b", q_lower)
        ):
            return RoutedToolResult(
                status="ROUTE_UNCERTAIN",
                selected_tool=None,
                confidence=0.0,
                extracted_parameters={},
                candidate_count_initial=initial_count,
                candidate_count_after_version=0,
                candidate_count_after_rbac=0,
                candidate_count_final=0,
                reasoning="Ambiguous multi-action or delegated choice query detected; cannot route safely to single atomic capability.",
                intent=intent,
            )

        # Destructive mass action guard
        if re.search(r"\b(?:how\s+to\s+)?(?:delete|destroy|wipe|kill)\s+(?:all|every)\s+(?:virtual\s+machines?|vms?)\b", q_lower):
            return RoutedToolResult(
                status="NO_TOOL",
                selected_tool=None,
                confidence=0.0,
                extracted_parameters={},
                candidate_count_initial=initial_count,
                candidate_count_after_version=0,
                candidate_count_after_rbac=0,
                candidate_count_final=0,
                reasoning="Destructive mass deletion operation is not supported by any registered enterprise tool.",
                intent=intent,
            )

        # Stage 1: Version Compatibility Filter
        matched_extended_tools = {
            tname for tname, pat in self.EXTENDED_TOOL_PATTERNS.items()
            if pat.search(q_lower)
        }
        if "vcf_delete_snapshot" in matched_extended_tools:
            intent.action = "delete_snapshot"
            intent.mutation = True
            intent.entity = "snapshot"
            intent.domain = "storage"

        v_candidates = [
            t for t in self.all_tools
            if t.supported_versions.get(target_version, True)
            and (t.name not in self.EXTENDED_SPECIALIZED_TOOLS or t.name in matched_extended_tools)
        ]
        count_v = len(v_candidates)

        # Stage 2: RBAC Capability Filter
        effective_roles = self.pdp.get_effective_roles_for_principal(principal)
        rbac_candidates = []
        for t in v_candidates:
            if CapabilityRole.VCF_PLATFORM_ADMIN in effective_roles:
                rbac_candidates.append(t)
            elif any(r in effective_roles for r in t.required_roles):
                rbac_candidates.append(t)
        count_rbac = len(rbac_candidates)

        if not rbac_candidates:
            return RoutedToolResult(
                status="ROUTE_UNCERTAIN",
                selected_tool=None,
                confidence=0.0,
                extracted_parameters={},
                candidate_count_initial=initial_count,
                candidate_count_after_version=count_v,
                candidate_count_after_rbac=0,
                candidate_count_final=0,
                reasoning="Principal lacks authorization for all tools in target subsystem.",
                intent=intent,
            )

        # Stage 3: Resource Scope Verification
        if not principal.is_in_resource_scope(domain_id=target_domain, cluster_id=target_cluster):
            return RoutedToolResult(
                status="ROUTE_UNCERTAIN",
                selected_tool=None,
                confidence=0.0,
                extracted_parameters={},
                candidate_count_initial=initial_count,
                candidate_count_after_version=count_v,
                candidate_count_after_rbac=count_rbac,
                candidate_count_final=0,
                reasoning=f"Resource scope denial: Principal cannot operate on cluster '{target_cluster}' or domain '{target_domain}'.",
                intent=intent,
            )

        # Stage 4: Parameter-Level Capability & Hard-Negative Filtering (ROUTE-02)
        valid_candidates: List[EnterpriseToolCard] = []
        disqualified_reasons: Dict[str, str] = {}

        for tool in rbac_candidates:
            # 4a. Hard-Negative pattern check
            disqualified_by_hn = False
            for hn in tool.hard_negatives:
                # Use word-boundary regex if possible, or substring
                if len(hn) > 3 and hn.lower() in q_lower:
                    disqualified_by_hn = True
                    disqualified_reasons[tool.name] = f"Matched hard-negative '{hn}'"
                    break
            if disqualified_by_hn:
                continue

            # 4b. Mutating intent cannot be satisfied by a READ tool
            if intent.mutation and tool.risk_class == RiskClass.READ:
                disqualified_reasons[tool.name] = f"Tool '{tool.name}' is read-only but intent is mutating ('{intent.action}')"
                continue

            # 4c. Supported action check for mutating tools
            if intent.mutation and intent.action and tool.risk_class != RiskClass.READ:
                if tool.supported_actions and intent.action not in tool.supported_actions:
                    disqualified_reasons[tool.name] = f"Action '{intent.action}' is not in tool's supported_actions"
                    continue

            # 4c. Unsupported action check
            if intent.action and tool.unsupported_actions:
                if intent.action in tool.unsupported_actions:
                    disqualified_reasons[tool.name] = f"Action '{intent.action}' is explicitly unsupported"
                    continue

            # 4d. Unsupported parameter check
            disqualified_by_param = False
            for p in intent.parameters:
                if p in tool.unsupported_parameters:
                    disqualified_by_param = True
                    disqualified_reasons[tool.name] = f"Parameter '{p}' is unsupported by '{tool.name}'"
                    break
            if disqualified_by_param:
                continue

            # 4e. Required parameter check for resize
            if intent.action == "resize" and tool.name == "vcf_resize_vm":
                if intent.parameters:
                    # If all requested parameters are outside supported_parameters
                    supported_set = set(tool.supported_parameters)
                    if not any(p in supported_set for p in intent.parameters):
                        disqualified_reasons[tool.name] = f"Requested parameters {intent.parameters} not supported"
                        continue

            # 4f. Required entity check for domain upgrade
            if intent.action == "upgrade" and tool.name == "vcf_upgrade_domain":
                if "cluster" in q_lower or "standalone" in q_lower or "host" in q_lower or "esxi" in q_lower:
                    if not ("workload domain" in q_lower or "mgmt-domain" in q_lower or "vi-workload" in q_lower):
                        disqualified_reasons[tool.name] = "Cluster or host upgrade without domain context is unsupported"
                        continue
                if intent.entity and intent.entity != "domain":
                    disqualified_reasons[tool.name] = f"Tool only supports domain upgrades, not {intent.entity}"
                    continue

            valid_candidates.append(tool)

        # 4g. Mutation Intent Capability Check:
        # If the user requested an operational mutation (mutation=True), but no mutating tool survives filtering
        if intent.mutation:
            mutating_survivors = [t for t in valid_candidates if t.risk_class != RiskClass.READ]
            if not mutating_survivors:
                return RoutedToolResult(
                    status="NO_TOOL",
                    selected_tool=None,
                    confidence=0.0,
                    extracted_parameters={},
                    candidate_count_initial=initial_count,
                    candidate_count_after_version=count_v,
                    candidate_count_after_rbac=count_rbac,
                    candidate_count_final=0,
                    reasoning=f"Mutation intent '{intent.action}' cannot be satisfied by catalog (NO_TOOL).",
                    intent=intent,
                )

        # Check if query had a concrete operational intent, but capability was disqualified (e.g. disk resize)
        if not valid_candidates:
            # If the query clearly targeted an entity and action (e.g. VM resize disk, or guest shutdown, or DR failover)
            if intent.entity or intent.action:
                return RoutedToolResult(
                    status="NO_TOOL",
                    selected_tool=None,
                    confidence=0.0,
                    extracted_parameters={},
                    candidate_count_initial=initial_count,
                    candidate_count_after_version=count_v,
                    candidate_count_after_rbac=count_rbac,
                    candidate_count_final=0,
                    reasoning=f"Intent '{intent.action}' on '{intent.entity}' is not supported by current capability catalog (NO_TOOL).",
                    intent=intent,
                )
            return RoutedToolResult(
                status="ROUTE_UNCERTAIN",
                selected_tool=None,
                confidence=0.0,
                extracted_parameters={},
                candidate_count_initial=initial_count,
                candidate_count_after_version=count_v,
                candidate_count_after_rbac=count_rbac,
                candidate_count_final=0,
                reasoning="No compatible tools found for query.",
                intent=intent,
            )

        # Stage 5: Semantic & Lexical Scoring
        q_tokens = set(re.findall(r"\w+", q_lower))
        scored_candidates: List[Tuple[EnterpriseToolCard, float]] = []

        is_telemetry = (
            intent.entity == "metric"
            or bool(re.search(r"\b(promql|telemetry|utilization|usage|consumption|stats)\b", q_lower))
        ) and not bool(re.search(r"\b(health|alarm|alarms|system\s+status|healthy)\b", q_lower))

        is_health = (
            intent.entity == "system"
            or bool(re.search(r"\b(health|alarm|alarms|system\s+status|healthy)\b", q_lower))
        ) and not is_telemetry
        is_host = intent.entity == "host"
        is_vm = intent.entity == "virtual_machine"
        is_resize = intent.action == "resize"
        is_power = intent.action in ("power_on", "power_off", "restart")
        is_snapshot = intent.action == "create_snapshot"
        is_nsx = intent.entity == "network_segment" or "nsx" in q_lower or "segment" in q_lower
        is_upgrade = intent.action == "upgrade" or "upgrade" in q_lower
        is_dr = intent.action in ("dr_test", "dr_failover") or "dr" in q_lower or "recover" in q_lower or "srm" in q_lower

        for tool in valid_candidates:
            score = 0.0

            # Match use_when and examples
            for e_tokens in self._tool_example_tokens.get(tool.name, []):
                overlap = len(q_tokens.intersection(e_tokens))
                if overlap > 0:
                    score += (overlap / max(len(e_tokens), 1)) * 0.40

            for t_tokens in self._tool_trigger_tokens.get(tool.name, []):
                overlap = len(q_tokens.intersection(t_tokens))
                if overlap > 0:
                    score += (overlap / max(len(t_tokens), 1)) * 0.35

            # Domain & Entity match
            if tool.domain == intent.domain:
                score += 0.25
            if intent.entity and intent.entity in tool.entity:
                score += 0.35

            # Tool token overlap
            tool_tokens = self._tool_desc_tokens.get(tool.name, set())
            token_overlap = len(q_tokens.intersection(tool_tokens))
            score += token_overlap * 0.10

            if tool.name in matched_extended_tools:
                score += 1.60

            # Specific intent adjustments
            if is_telemetry:
                if tool.name == "vcf_query_telemetry":
                    score += 1.50
                elif tool.level != "L1_QUERY":
                    score -= 2.00
                else:
                    score -= 1.00
            elif is_health:
                if tool.name == "vcf_get_health":
                    score += 1.50
                elif tool.level != "L1_QUERY":
                    score -= 1.50

            if is_host and not is_vm and not is_telemetry:
                if "host" in tool.name:
                    if tool.name == "vcf_list_hosts" and re.search(r"\b(list|all|inventory|hypervisors|hosts)\b", q_lower) and not re.search(r"\b(esxi-\d+|host-\d+)\b", q_lower):
                        score += 1.20
                    elif tool.name == "vcf_get_host" and re.search(r"\b(esxi-\d+|host-\d+|status\s+of|details)\b", q_lower):
                        score += 1.20
                    else:
                        score += 0.80
                elif "vm" in tool.name:
                    score -= 1.50

            if is_vm and not is_host and not is_telemetry:
                if "host" in tool.name:
                    score -= 1.50
                if not intent.mutation:
                    if tool.name == "vcf_list_vms":
                        # If query explicitly asks to list / inventory / all / display vm list
                        if re.search(r"\b(list|inventory|all|show\s+all|display\s+vm\s+list|vm\s+list|vms)\b", q_lower) and not re.search(r"\b(vm-\d+|app\d+)\b", q_lower):
                            score += 1.20
                        else:
                            score += 0.40
                    elif tool.name == "vcf_get_vm":
                        # If query asks for specific VM details
                        if re.search(r"\b(vm-\d+|app\d+|details|status\s+of|hardware|specific)\b", q_lower):
                            score += 1.20
                        elif not re.search(r"\b(list|inventory|all|vm\s+list)\b", q_lower):
                            score += 0.50
                    elif tool.level != "L1_QUERY":
                        score -= 1.20

            if is_resize:
                if tool.name == "vcf_resize_vm":
                    score += 1.30
                else:
                    score -= 0.80
            elif tool.name == "vcf_resize_vm":
                score -= 1.20

            if is_power:
                if tool.name == "vcf_power_vm":
                    score += 1.20
                else:
                    score -= 0.60

            if is_snapshot:
                if tool.name == "vcf_create_snapshot":
                    score += 1.20
                else:
                    score -= 0.60

            if is_nsx:
                if "nsx" in tool.name or "segment" in tool.name:
                    score += 1.20
                else:
                    score -= 0.60

            if is_upgrade:
                if "upgrade" in tool.name:
                    score += 1.20
                else:
                    score -= 0.60

            if is_dr:
                if "recover_site" in tool.name:
                    score += 1.40
                else:
                    score -= 0.60

            scored_candidates.append((tool, max(score, 0.0)))

        scored_candidates.sort(key=lambda x: x[1], reverse=True)
        top_tool, top_score = scored_candidates[0]

        # Extract parameters heuristically
        params = self._extract_parameters(query)
        if target_cluster:
            params["cluster_id"] = target_cluster
        if target_domain:
            params["domain_id"] = target_domain

        # Safety Gate: Prevent Unsafe Mutating Tool Dispatch on Read Queries
        if top_tool.risk_class in [RiskClass.CHANGE, RiskClass.HIGH_IMPACT, RiskClass.DESTRUCTIVE, RiskClass.SAFE_WRITE]:
            if not intent.mutation:
                # Fall back to best read candidate or abstain
                read_candidates = [c for c in scored_candidates if c[0].risk_class == RiskClass.READ and c[1] >= 0.40]
                if read_candidates:
                    top_tool, top_score = read_candidates[0]
                else:
                    return RoutedToolResult(
                        status="ROUTE_UNCERTAIN",
                        selected_tool=None,
                        confidence=0.0,
                        extracted_parameters=params,
                        candidate_count_initial=initial_count,
                        candidate_count_after_version=count_v,
                        candidate_count_after_rbac=count_rbac,
                        candidate_count_final=len(scored_candidates),
                        reasoning="Blocked mutating tool dispatch for non-mutating intent.",
                        intent=intent,
                    )

        # Confidence normalization
        normalized_conf = min(round(top_score, 2), 1.0)

        # Calibrated Risk-Class Confidence Thresholds
        required_threshold = self.READ_THRESHOLD
        if top_tool.risk_class == RiskClass.SAFE_WRITE:
            required_threshold = self.SAFE_WRITE_THRESHOLD
        elif top_tool.risk_class == RiskClass.CHANGE:
            required_threshold = self.CHANGE_THRESHOLD
        elif top_tool.risk_class in (RiskClass.HIGH_IMPACT, RiskClass.DESTRUCTIVE):
            required_threshold = self.HIGH_IMPACT_THRESHOLD

        if normalized_conf < required_threshold:
            # Check if this query is an unsupported request (NO_TOOL) or ambiguous (ROUTE_UNCERTAIN)
            if intent.parameters and any(p in ("disk", "nic", "portgroup") for p in intent.parameters):
                return RoutedToolResult(
                    status="NO_TOOL",
                    selected_tool=None,
                    confidence=normalized_conf,
                    extracted_parameters=params,
                    candidate_count_initial=initial_count,
                    candidate_count_after_version=count_v,
                    candidate_count_after_rbac=count_rbac,
                    candidate_count_final=len(scored_candidates),
                    reasoning=f"Unsupported parameter requested: {intent.parameters} (NO_TOOL).",
                    intent=intent,
                )
            return RoutedToolResult(
                status="ROUTE_UNCERTAIN",
                selected_tool=None,
                confidence=normalized_conf,
                extracted_parameters=params,
                candidate_count_initial=initial_count,
                candidate_count_after_version=count_v,
                candidate_count_after_rbac=count_rbac,
                candidate_count_final=len(scored_candidates),
                reasoning=f"Confidence {normalized_conf} below required threshold {required_threshold} for {top_tool.risk_class.name}.",
                intent=intent,
            )

        # Margin check: if top 2 candidates have very close score on different actions, abstain
        if len(scored_candidates) > 1:
            second_tool, second_score = scored_candidates[1]
            if top_score - second_score < 0.08 and top_tool.risk_class != second_tool.risk_class:
                return RoutedToolResult(
                    status="ROUTE_UNCERTAIN",
                    selected_tool=None,
                    confidence=normalized_conf,
                    extracted_parameters=params,
                    candidate_count_initial=initial_count,
                    candidate_count_after_version=count_v,
                    candidate_count_after_rbac=count_rbac,
                    candidate_count_final=len(scored_candidates),
                    reasoning=f"Ambiguous intent margin ({top_score - second_score:.2f}) between {top_tool.name} and {second_tool.name}.",
                    intent=intent,
                )

        return RoutedToolResult(
            status="MATCHED",
            selected_tool=top_tool.name,
            confidence=normalized_conf,
            extracted_parameters=params,
            candidate_count_initial=initial_count,
            candidate_count_after_version=count_v,
            candidate_count_after_rbac=count_rbac,
            candidate_count_final=len(scored_candidates),
            reasoning=f"Matched tool '{top_tool.name}' ({top_tool.level}) with confidence {normalized_conf}.",
            intent=intent,
        )

    def _extract_parameters(self, query: str) -> Dict[str, Any]:
        params: Dict[str, Any] = {}
        # Datacenter
        if "dc1" in query.lower() or "datacenter 1" in query.lower():
            params["datacenter_id"] = "dc1"
        elif "dc2" in query.lower() or "datacenter 2" in query.lower():
            params["datacenter_id"] = "dc2"

        # VM ID extraction (e.g. vm-102, app01)
        vm_match = re.search(r"\b(vm-[a-zA-Z0-9_-]+|app[0-9]+)\b", query, re.IGNORECASE)
        if vm_match:
            params["vm_id"] = vm_match.group(1)

        # Domain extraction
        dom_match = re.search(r"\b(wld-[a-zA-Z0-9_-]+|mgmt-domain|vi-workload-[a-zA-Z0-9_-]+)\b", query, re.IGNORECASE)
        if dom_match:
            params["domain_id"] = dom_match.group(1)

        # Cluster extraction
        cl_match = re.search(r"\b(cluster-[a-zA-Z0-9_-]+|cl-[a-zA-Z0-9_-]+)\b", query, re.IGNORECASE)
        if cl_match:
            params["cluster_id"] = cl_match.group(1)

        # RAM / Memory size extraction
        mem_match = re.search(r"(\d+)\s*(?:gb|g)\b", query, re.IGNORECASE)
        if mem_match:
            params["memory_gb"] = int(mem_match.group(1))

        # CPU core count extraction
        cpu_match = re.search(r"(\d+)\s*(?:cores|cpu|vcpus)\b", query, re.IGNORECASE)
        if cpu_match:
            params["cpu_cores"] = int(cpu_match.group(1))

        # Metric extraction for telemetry
        if "cpu" in query.lower():
            params["metric"] = "cpu_usage_pct"
        elif "memory" in query.lower() or "ram" in query.lower():
            params["metric"] = "mem_usage_pct"

        # PromQL query expression extraction
        promql_match = re.search(r"(?:promql|metric|query):\s*(.+)$", query, re.IGNORECASE)
        if promql_match:
            params["query"] = promql_match.group(1).strip()

        return params
