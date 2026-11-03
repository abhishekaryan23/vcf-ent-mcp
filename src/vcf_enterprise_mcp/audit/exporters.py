# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Audit Exporters for SIEM, Syslog, and OpenTelemetry.
"""

from __future__ import annotations
import json
from typing import List, Dict, Any
from vcf_enterprise_mcp.audit.recorder import AuditRecord


class AuditExporter:
    """Formats and exports audit records to enterprise observability systems."""

    @staticmethod
    def to_jsonl(records: List[AuditRecord]) -> str:
        """Serializes audit records to standard JSONL format for Splunk/Elastic ingestion."""
        return "\n".join(json.dumps(r.to_dict()) for r in records)

    @staticmethod
    def to_syslog_rfc5424(record: AuditRecord) -> str:
        """Formats record into CEF / Syslog message suitable for enterprise SIEM."""
        rec_d = record.to_dict()
        header = f"CEF:0|Unofficial|VCF-MCP-ControlPlane|1.0|{record.action_type}|{record.tool}|{5 if record.result_status == 'SUCCESS' else 8}|"
        ext = f"src={record.actor.get('client_ip')} suser={record.actor.get('user_id')} act={record.result_status} cs1={record.request_id} cs1Label=RequestID"
        return header + ext
