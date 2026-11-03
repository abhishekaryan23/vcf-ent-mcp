# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
VCF Operations (Aria Operations) Provider.
Provides telemetry, metrics aggregation, capacity analytics, and alert inspection.
"""

from __future__ import annotations
import uuid
from typing import Dict, Any, List, Optional
from vcf_enterprise_mcp.adapter.providers.base import BaseVCFProvider
from vcf_enterprise_mcp.adapter.transport.errors import UpstreamPreconditionException


class VCFOperationsProvider(BaseVCFProvider):
    """Integrates with VMware Aria / VCF Operations REST APIs (/suite-api/*)."""

    # Alert criticality ordering (alert.alertLevel enum in the 9.x specification).
    ALERT_LEVELS = ["UNKNOWN", "NONE", "INFORMATION", "WARNING", "IMMEDIATE", "CRITICAL"]

    @staticmethod
    def _is_uuid(value: str) -> bool:
        try:
            uuid.UUID(str(value))
            return True
        except ValueError:
            return False

    def resolve_resource_id(self, entity: str) -> Optional[str]:
        """VCF Operations addresses objects by its own resource UUID, not vCenter morefs or names.
        Non-UUID input is looked up with GET /suite-api/api/resources?name=..."""
        if self._is_uuid(entity):
            return entity
        data = self.request("GET", "/suite-api/api/resources", params={"name": entity}).json()
        matches = data.get("resourceList", []) if isinstance(data, dict) else []
        exact = [r for r in matches if (r.get("resourceKey") or {}).get("name") == entity]
        candidates = exact or matches
        if len(candidates) != 1:
            return None
        return candidates[0].get("identifier")

    def query_telemetry(
        self,
        entity_id: str,
        metrics: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """GET /suite-api/api/resources/{id}/stats, normalized to {stat_key: [{timestamp, value}]}."""
        resource_id = self.resolve_resource_id(entity_id)
        if resource_id is None:
            raise UpstreamPreconditionException("query_telemetry", f"'{entity_id}' did not resolve to exactly one VCF Operations resource.")
        params: Dict[str, Any] = {"latestMaxSamples": 12}
        if metrics:
            params["statKey"] = metrics
        data = self.request("GET", f"/suite-api/api/resources/{resource_id}/stats", params=params).json()
        series: Dict[str, List[Dict[str, Any]]] = {}
        values = data.get("values", []) if isinstance(data, dict) else []
        for entry in values:
            for stat in (entry.get("stat-list") or {}).get("stat", []):
                key = (stat.get("statKey") or {}).get("key")
                points = list(zip(stat.get("timestamps") or [], stat.get("data") or []))
                if key:
                    series[key] = [{"timestamp": ts, "value": v} for ts, v in points]
        return {"entity_id": entity_id, "resource_id": resource_id, "source": "vcf-operations", "metrics": series}

    def get_alerts(self, entity_id: Optional[str] = None, active_only: bool = True) -> List[Dict[str, Any]]:
        """GET /suite-api/api/alerts (the 9.x operation has no status filter; filter client-side)."""
        params = {"resourceId": entity_id} if entity_id else None
        data = self.request("GET", "/suite-api/api/alerts", params=params).json()
        alerts = data if isinstance(data, list) else (data.get("alerts", []) if isinstance(data, dict) else [])
        if active_only:
            alerts = [a for a in alerts if str(a.get("status", "ACTIVE")).upper() == "ACTIVE"]
        return alerts

    def get_version(self) -> Optional[str]:
        """GET /suite-api/api/versions/current."""
        data = self.request("GET", "/suite-api/api/versions/current").json()
        if not isinstance(data, dict):
            return None
        parts = [data.get(k) for k in ("major", "minor", "minorMinor", "patch")]
        return ".".join(str(p) for p in parts) if all(isinstance(p, int) for p in parts) else data.get("releaseName")
