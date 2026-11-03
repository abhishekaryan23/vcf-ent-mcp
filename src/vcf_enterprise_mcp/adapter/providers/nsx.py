# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
NSX Policy API Provider.
Provides network segment management, Tier-0/1 gateway queries, and security policy retrieval.
"""

from __future__ import annotations
import ipaddress
from typing import Dict, Any, List, Optional
from vcf_enterprise_mcp.adapter.providers.base import BaseVCFProvider
from vcf_enterprise_mcp.adapter.transport.errors import UpstreamPreconditionException, UpstreamResourceNotFoundException
from vcf_enterprise_mcp.adapter.models import (
    ResourceRevision,
    ReconciliationStatus,
    ReconciliationResult,
    ExecutionIntent,
)


class NSXProvider(BaseVCFProvider):
    """Integrates with VMware NSX Policy APIs (/policy/api/v1/*)."""

    def get_segments(self) -> List[Dict[str, Any]]:
        resp = self.request("GET", "/policy/api/v1/infra/segments")
        data = resp.json()
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            return data.get("results", [])
        return []

    def get_segment(self, segment_name: str) -> Optional[Dict[str, Any]]:
        """GET /policy/api/v1/infra/segments/{id}; returns None when the segment does not exist."""
        try:
            resp = self.request("GET", f"/policy/api/v1/infra/segments/{segment_name}")
        except UpstreamResourceNotFoundException:
            return None
        data = resp.json()
        if isinstance(data, dict) and data.get("id", segment_name) == segment_name:
            return data
        return None

    @staticmethod
    def validate_gateway_cidr(cidr: str) -> str:
        """SegmentSubnet.gateway_address is the gateway IP with prefix (e.g. 10.1.1.1/24),
        not the network address."""
        try:
            iface = ipaddress.ip_interface(cidr)
        except ValueError:
            raise UpstreamPreconditionException("create_segment", f"'{cidr}' is not a gateway address in CIDR form, e.g. 10.1.1.1/24.")
        net = iface.network
        if net.num_addresses > 2 and iface.ip in (net.network_address, net.broadcast_address):
            raise UpstreamPreconditionException("create_segment", f"'{cidr}' is the network or broadcast address; supply the gateway IP, e.g. {next(net.hosts())}/{net.prefixlen}.")
        return str(iface)

    def create_segment(
        self,
        segment_name: str,
        gateway_id: str,
        cidr: str,
        transport_zone_path: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Creates a new overlay segment attached to a Tier-1 gateway.

        PUT on /infra/segments/{id} is create-OR-REPLACE in the NSX Policy API, so an existing
        segment is refused rather than overwritten. Creation uses PATCH after the existence check.
        """
        gateway_address = self.validate_gateway_cidr(cidr)
        if self.get_segment(segment_name) is not None:
            raise UpstreamPreconditionException("create_segment", f"Segment '{segment_name}' already exists; refusing to replace it.")
        body: Dict[str, Any] = {
            "display_name": segment_name,
            "connectivity_path": f"/infra/tier-1s/{gateway_id}",
            "subnets": [{"gateway_address": gateway_address}],
        }
        if transport_zone_path:
            body["transport_zone_path"] = transport_zone_path
        resp = self.request("PATCH", f"/policy/api/v1/infra/segments/{segment_name}", json_body=body)
        return {
            "segment_id": segment_name,
            "segment_path": f"/infra/segments/{segment_name}",
            "segment_name": segment_name,
            "gateway": gateway_id,
            "cidr": gateway_address,
            "status": "SUCCESS" if resp.is_success else "FAILED",
        }

    def get_realized_state(self, intent_path: str) -> Dict[str, Any]:
        """GET /policy/api/v1/infra/realized-state/status: whether desired state reached the data plane."""
        resp = self.request("GET", "/policy/api/v1/infra/realized-state/status", params={"intent_path": intent_path})
        data = resp.json()
        return data if isinstance(data, dict) else {}

    def get_version(self) -> Optional[str]:
        """GET /api/v1/node/version (node_version)."""
        data = self.request("GET", "/api/v1/node/version").json()
        return data.get("node_version") if isinstance(data, dict) else None

    def get_gateways(self) -> List[Dict[str, Any]]:
        resp = self.request("GET", "/policy/api/v1/infra/tier-1s")
        data = resp.json()
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            return data.get("results", [])
        return []

    async def reconcile_operation(
        self,
        intent: ExecutionIntent | Dict[str, Any],
    ) -> ReconciliationResult:
        """Reconciles NSX operations against upstream policy state."""
        target_res = intent.target_resource if isinstance(intent, ExecutionIntent) else intent.get("target_resource", "")
        op_id = intent.operation_id if isinstance(intent, ExecutionIntent) else intent.get("operation_id", "")
        try:
            seg = self.get_segment(target_res)
            if seg:
                return ReconciliationResult(
                    status=ReconciliationStatus.APPLIED,
                    details={"segment_name": target_res},
                    observed_revision=ResourceRevision("nsx", f"rev-seg-{target_res}"),
                )
            return ReconciliationResult(
                status=ReconciliationStatus.NOT_APPLIED,
                details={"segment_name": target_res},
            )
        except Exception as ex:
            return ReconciliationResult(
                status=ReconciliationStatus.UNKNOWN,
                details={"error": str(ex)},
            )

