# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Resource Lease Manager for Enterprise VCF MCP Control Plane.
Guarantees distributed mutually exclusive operations on shared infrastructure entities
using monotonically increasing fencing tokens to eliminate split-brain and network partition races.
"""

from __future__ import annotations
import contextlib
from typing import Optional, Generator
from vcf_enterprise_mcp.state.durable_store import DurableStore, ResourceLease
from vcf_enterprise_mcp.core.errors import ResourceLockException, StaleFencingTokenException


class ResourceLeaseManager:
    """
    Manages exclusive leases on infrastructure resources using durable store
    backed by monotonic fencing tokens.
    """

    def __init__(self, store: DurableStore, tenant_id: str = "tenant-default"):
        self.store = store
        self.tenant_id = tenant_id

    def acquire_exclusive(
        self,
        resource_id: str,
        lease_holder: str,
        ttl_seconds: float = 30.0,
    ) -> ResourceLease:
        """
        Acquires an exclusive lease and issues a new monotonic fencing token.
        Raises ResourceLockException if already held by another party.
        """
        success, msg, fencing_token = self.store.acquire_lease(
            tenant_id=self.tenant_id,
            resource_id=resource_id,
            lease_holder=lease_holder,
            lease_type="EXCLUSIVE",
            ttl_seconds=ttl_seconds,
        )
        if not success:
            raise ResourceLockException(resource_id, msg)
        return ResourceLease(
            resource_id=resource_id,
            owner=lease_holder,
            fencing_token=fencing_token,
            expires_at=0.0,
            tenant_id=self.tenant_id,
        )

    def release(self, resource_id: str, lease_holder: str) -> None:
        """Releases the lease if held by lease_holder."""
        self.store.release_lease(self.tenant_id, resource_id, lease_holder)

    def get_active_lease(self, resource_id: str) -> Optional[ResourceLease]:
        """Retrieves currently active lease if not expired."""
        return self.store.get_active_lease(self.tenant_id, resource_id)

    def validate_fencing_token(self, resource_id: str, presented_token: int) -> bool:
        """
        Validates that the presented fencing token is still the active token.
        If superseded by a subsequent lease acquisition, raises StaleFencingTokenException.
        """
        active = self.get_active_lease(resource_id)
        if not active:
            raise StaleFencingTokenException(
                resource_id=resource_id,
                current_token=0,
                presented_token=presented_token,
                details={"reason": "Lease expired or does not exist"}
            )
        if active.fencing_token != presented_token:
            raise StaleFencingTokenException(
                resource_id=resource_id,
                current_token=active.fencing_token,
                presented_token=presented_token,
                details={"reason": "Fencing token superseded by subsequent lease acquisition"}
            )
        return True

    @contextlib.contextmanager
    def lease(
        self,
        resource_id: str,
        lease_holder: str,
        ttl_seconds: float = 30.0,
    ) -> Generator[ResourceLease, None, None]:
        """Context manager yielding the acquired ResourceLease with its fencing token."""
        lease_obj = self.acquire_exclusive(resource_id, lease_holder, ttl_seconds)
        try:
            yield lease_obj
        finally:
            self.release(resource_id, lease_holder)
