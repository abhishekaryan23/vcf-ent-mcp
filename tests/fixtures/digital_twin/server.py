# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Direct-Route Single-Inventory VCF Digital Twin Mock Server.
Serves the complete suite of native Broadcom REST endpoints on Port 8085 (or configurable).
Grounded directly in Broadcom VCF 9.0/9.1, vSphere, NSX Policy, SRM, VR, and Aria specifications.
"""

from __future__ import annotations

import os
import re
import uuid
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from fastapi import FastAPI, Request, HTTPException, status, Query, Response, Depends
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from digital_twin.state import DigitalTwinState

RFC1123_REGEX = re.compile(r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$")


def make_vapi_error(
    error_type: str,
    message: str,
    message_id: Optional[str] = None,
    args: Optional[List[str]] = None,
    status_code: int = status.HTTP_400_BAD_REQUEST,
) -> HTTPException:
    msg_id = message_id or f"com.vmware.vapi.{error_type.split('.')[-1]}"
    headers = {"vapi-error": error_type}
    detail = {
        "type": error_type,
        "value": {
            "messages": [
                {
                    "id": msg_id,
                    "default_message": message,
                    "args": args or [],
                }
            ]
        },
    }
    return HTTPException(status_code=status_code, detail=detail, headers=headers)


def make_nsx_error(
    error_message: str,
    error_code: int = 500001,
    http_status: str = "BAD_REQUEST",
    status_code: int = status.HTTP_400_BAD_REQUEST,
    details: Optional[List[Dict[str, Any]]] = None,
) -> HTTPException:
    detail = {
        "httpStatus": http_status,
        "error_code": error_code,
        "module_name": "policy",
        "error_message": error_message,
        "details": details or [],
    }
    return HTTPException(status_code=status_code, detail=detail)


def create_digital_twin_app(config_path: str = "digital_twin/vcf_inventory.yaml") -> FastAPI:
    app = FastAPI(
        title="Broadcom VCF Single-Inventory Digital Twin Mock Server",
        description="Emulates enterprise multi-tenant production VCF infrastructure with direct REST endpoints and cascading invariants.",
        version="9.1.0",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Custom exception handler to unwrap dict details for exact Broadcom API compatibility
    @app.exception_handler(HTTPException)
    async def custom_http_exception_handler(request: Request, exc: HTTPException):
        if isinstance(exc.detail, dict):
            return JSONResponse(status_code=exc.status_code, content=exc.detail, headers=exc.headers)
        return JSONResponse(status_code=exc.status_code, content={"message": str(exc.detail)}, headers=exc.headers)

    state = DigitalTwinState(config_path=config_path)
    app.state.dt_state = state

    def get_state() -> DigitalTwinState:
        return app.state.dt_state

    # --------------------------------------------------------------------------
    # 1. SDDC Manager APIs (/v1/*)
    # --------------------------------------------------------------------------
    @app.post("/v1/tokens", status_code=status.HTTP_200_OK)
    async def create_sddc_token(payload: Optional[Dict[str, Any]] = None, dt_state: DigitalTwinState = Depends(get_state)):
        token_id = f"sddc-tok-{uuid.uuid4().hex[:12]}"
        dt_state.tokens[token_id] = {"user": "administrator@vsphere.local", "role": "VCF_SUPER_ADMIN"}
        return {"accessToken": token_id, "tokenType": "Bearer", "expiresIn": 86400}

    @app.get("/")
    async def root_status(dt_state: DigitalTwinState = Depends(get_state)):
        return {
            "name": "VMware Cloud Foundation (VCF) Single-Inventory Digital Twin",
            "version": dt_state.config.environment.vcf_version,
            "buildNumber": dt_state.config.environment.build_number,
            "organization": dt_state.config.environment.organization,
            "status": "ONLINE",
            "active_inventory": dt_state.config.environment.name,
            "direct_apis": ["/v1/*", "/api/vcenter/*", "/policy/api/v1/*", "/api/srm/v1/*", "/api/vr/v1/*", "/suite-api/api/*"],
        }

    @app.get("/v1/system/health")
    async def get_system_health(dt_state: DigitalTwinState = Depends(get_state)):
        return dt_state.get_health_status()

    @app.get("/v1/system/version")
    async def get_system_version(dt_state: DigitalTwinState = Depends(get_state)):
        return {
            "version": dt_state.config.environment.vcf_version,
            "buildNumber": dt_state.config.environment.build_number,
            "name": dt_state.config.environment.name,
        }

    @app.get("/v1/releases")
    async def get_releases(dt_state: DigitalTwinState = Depends(get_state)):
        return {
            "elements": [
                {
                    "product": "vcf",
                    "version": dt_state.config.environment.vcf_version,
                    "buildNumber": dt_state.config.environment.build_number,
                    "description": f"VMware Cloud Foundation {dt_state.config.environment.vcf_version} Production Release",
                    "releaseDate": "2026-08-10T00:00:00.000Z",
                    "bom": [
                        {"product": "vcenter", "version": "9.1.0.0", "buildNumber": "24891100"},
                        {"product": "esxi", "version": "9.1.0.0", "buildNumber": "24889900"},
                        {"product": "nsx", "version": "4.2.1.0", "buildNumber": "24150386"},
                        {"product": "vsan", "version": "9.1.0.0", "buildNumber": "24890000"},
                    ],
                }
            ]
        }

    @app.get("/v1/manifests")
    async def get_manifests(dt_state: DigitalTwinState = Depends(get_state)):
        return {
            "vcfVersion": dt_state.config.environment.vcf_version,
            "manifestVersion": "9.1.0.0-MANIFEST-202608",
            "bundles": ["bundle-vcenter-9.1.0.0", "bundle-esx-9.1.0.0", "bundle-nsx-4.2.1.0"],
        }

    @app.get("/v1/domains")
    async def list_domains(dt_state: DigitalTwinState = Depends(get_state)):
        elements = [dt_state.config.management_domain.model_dump()]
        for wld in dt_state.config.workload_domains:
            elements.append(wld.model_dump())
        return {"elements": elements, "totalElements": len(elements)}

    @app.post("/v1/domains/validations", status_code=status.HTTP_200_OK)
    async def validate_domain(payload: Dict[str, Any], dt_state: DigitalTwinState = Depends(get_state)):
        return {"id": f"val-dom-{uuid.uuid4().hex[:6]}", "status": "SUCCEEDED", "description": "Pre-validation for Workload Domain passed"}

    @app.delete("/v1/domains/{domain_id}")
    async def delete_domain(domain_id: str, dt_state: DigitalTwinState = Depends(get_state)):
        if domain_id == dt_state.config.management_domain.id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"errorCode": "CANNOT_DELETE_MANAGEMENT_DOMAIN", "message": "The Management Domain cannot be deleted."},
            )
        for i, wld in enumerate(dt_state.config.workload_domains):
            if wld.id == domain_id:
                del dt_state.config.workload_domains[i]
                return {"id": f"task-{uuid.uuid4().hex[:8]}", "status": "IN_PROGRESS", "name": f"Delete Domain {domain_id}"}
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail={"message": f"Domain {domain_id} not found"})

    @app.get("/v1/clusters")
    async def list_clusters(dt_state: DigitalTwinState = Depends(get_state)):
        clusters = []
        mgmt_clusters = dt_state.config.management_domain.clusters or ([dt_state.config.management_domain.cluster] if dt_state.config.management_domain.cluster else [])
        for cl in mgmt_clusters:
            if cl:
                clusters.append(cl.model_dump())
        for wld in dt_state.config.workload_domains:
            for cl in wld.clusters:
                clusters.append(cl.model_dump())
        return {"elements": clusters, "totalElements": len(clusters)}

    @app.post("/v1/clusters/validations", status_code=status.HTTP_200_OK)
    async def validate_cluster(payload: Dict[str, Any], dt_state: DigitalTwinState = Depends(get_state)):
        cl_name = payload.get("name", "New-Compute-Cluster")
        return {"id": f"val-cl-{uuid.uuid4().hex[:6]}", "status": "SUCCEEDED", "description": f"Pre-validation for Cluster {cl_name} passed"}

    @app.delete("/v1/clusters/{cluster_id}")
    async def delete_cluster(cluster_id: str, dt_state: DigitalTwinState = Depends(get_state)):
        mgmt_clusters = dt_state.config.management_domain.clusters or ([dt_state.config.management_domain.cluster] if dt_state.config.management_domain.cluster else [])
        for cl in mgmt_clusters:
            if cl and cl.id == cluster_id:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail={"errorCode": "CANNOT_DELETE_MANAGEMENT_CLUSTER", "message": "Primary management cluster cannot be deleted."},
                )
        for wld in dt_state.config.workload_domains:
            for i, cl in enumerate(wld.clusters):
                if cl.id == cluster_id:
                    del wld.clusters[i]
                    return {"id": f"task-{uuid.uuid4().hex[:8]}", "status": "IN_PROGRESS", "name": f"Delete Cluster {cluster_id}"}
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail={"message": f"Cluster {cluster_id} not found"})

    @app.get("/v1/hosts")
    async def list_hosts(dt_state: DigitalTwinState = Depends(get_state)):
        return {"elements": list(dt_state.hosts.values()), "totalElements": len(dt_state.hosts)}

    @app.post("/v1/hosts/validations", status_code=status.HTTP_200_OK)
    async def validate_hosts(payload: Dict[str, Any], dt_state: DigitalTwinState = Depends(get_state)):
        hosts_list = payload.get("hosts", [])
        results = [
            {"fqdn": h.get("fqdn", "esx.corp.local"), "result": "PASS", "details": "Validated NTP, DNS, Storage, and Network"}
            for h in hosts_list
        ]
        return {"id": f"val-host-{uuid.uuid4().hex[:6]}", "status": "SUCCEEDED", "results": results}

    @app.get("/v1/hosts/{host_id}")
    async def get_host(host_id: str, dt_state: DigitalTwinState = Depends(get_state)):
        if host_id in dt_state.hosts:
            return dt_state.hosts[host_id]
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail={"message": f"Host {host_id} not found"})

    @app.post("/v1/hosts/{host_id}/decommission")
    async def decommission_host(host_id: str, dt_state: DigitalTwinState = Depends(get_state)):
        if host_id not in dt_state.hosts:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail={"message": f"Host {host_id} not found"})
        host = dt_state.hosts[host_id]
        if host.get("status") == "ASSIGNED" or host.get("cluster_id"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"errorCode": "HOST_IN_USE", "message": f"Host {host_id} is assigned to an active cluster and cannot be decommissioned."},
            )
        host["status"] = "UNASSIGNED"
        return {"id": f"task-{uuid.uuid4().hex[:8]}", "status": "COMPLETED", "name": f"Decommission Host {host_id}"}

    @app.delete("/v1/hosts/{host_id}")
    async def delete_host(host_id: str, dt_state: DigitalTwinState = Depends(get_state)):
        if host_id not in dt_state.hosts:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail={"message": f"Host {host_id} not found"})
        host = dt_state.hosts[host_id]
        if host.get("status") == "ASSIGNED" or host.get("cluster_id"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"errorCode": "CANNOT_DELETE_ASSIGNED_HOST", "message": f"Host {host_id} is assigned to a cluster and cannot be deleted."},
            )
        del dt_state.hosts[host_id]
        return {"status": "SUCCESS", "message": f"Host {host_id} removed successfully."}

    @app.get("/v1/network-pools")
    async def list_network_pools(dt_state: DigitalTwinState = Depends(get_state)):
        return {"elements": list(dt_state.network_pools.values())}

    @app.delete("/v1/network-pools/{pool_id}")
    async def delete_network_pool(pool_id: str, dt_state: DigitalTwinState = Depends(get_state)):
        if pool_id not in dt_state.network_pools:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail={"message": f"Network pool {pool_id} not found"})
        if len(dt_state.hosts) > 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"errorCode": "NETWORK_POOL_IN_USE", "message": f"Network pool {pool_id} is in use by active hosts/domains."},
            )
        del dt_state.network_pools[pool_id]
        return {"status": "SUCCESS", "message": f"Network pool {pool_id} deleted."}

    @app.get("/v1/licensing/licenses")
    async def list_licenses(dt_state: DigitalTwinState = Depends(get_state)):
        return {"elements": [lic.model_dump() for lic in dt_state.config.licensing]}

    @app.get("/v1/federation/fleet")
    async def get_fleet_federation(dt_state: DigitalTwinState = Depends(get_state)):
        return {
            "fleetStatus": "HEALTHY",
            "fleetManager": dt_state.config.sddc_manager.fqdn,
            "totalDomains": 1 + len(dt_state.config.workload_domains),
            "tenantOrganizations": list(dt_state.tenant_orgs.values()),
        }

    # Certificate Management APIs
    @app.get("/v1/certificates")
    async def list_certificates(
        domainId: Optional[str] = None,
        resourceType: Optional[str] = None,
        status: Optional[str] = None,
        dt_state: DigitalTwinState = Depends(get_state),
    ):
        certs = dt_state.certificates
        if domainId:
            certs = [c for c in certs if c.get("domainId") == domainId]
        if resourceType:
            certs = [c for c in certs if c.get("resourceType") == resourceType]
        if status:
            certs = [c for c in certs if c.get("status") == status]
        return {"elements": certs, "totalElements": len(certs)}

    @app.get("/v1/certificates/{cert_id}")
    async def get_certificate(cert_id: str, dt_state: DigitalTwinState = Depends(get_state)):
        for c in dt_state.certificates:
            if c.get("id") == cert_id:
                return c
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail={"message": f"Certificate {cert_id} not found"})

    @app.post("/v1/certificates/csr", status_code=status.HTTP_202_ACCEPTED)
    async def generate_csr(payload: Dict[str, Any], dt_state: DigitalTwinState = Depends(get_state)):
        domain_id = payload.get("domainId", dt_state.config.management_domain.id)
        resource_type = payload.get("resourceType", "VCENTER")
        common_name = payload.get("commonName", "sddc.corp.local")
        return {
            "id": f"task-{uuid.uuid4().hex[:8]}",
            "status": "IN_PROGRESS",
            "name": f"Generate CSR for {common_name} ({resource_type})",
            "resourceId": domain_id,
        }

    @app.post("/v1/certificates", status_code=status.HTTP_202_ACCEPTED)
    @app.put("/v1/certificates/{cert_id}", status_code=status.HTTP_202_ACCEPTED)
    async def install_certificate(payload: Dict[str, Any], cert_id: Optional[str] = None, dt_state: DigitalTwinState = Depends(get_state)):
        target_id = cert_id or payload.get("id", f"cert-{uuid.uuid4().hex[:8]}")
        return {
            "id": f"task-{uuid.uuid4().hex[:8]}",
            "status": "IN_PROGRESS",
            "name": f"Install Certificate {target_id}",
            "resourceId": target_id,
        }

    # --------------------------------------------------------------------------
    # 2. vCenter Server APIs (/api/vcenter/* & /api/session)
    # --------------------------------------------------------------------------
    @app.post("/api/session", status_code=status.HTTP_201_CREATED)
    async def create_vcenter_session(response: Response, dt_state: DigitalTwinState = Depends(get_state)):
        sess_id = f"vc-sess-{uuid.uuid4().hex[:12]}"
        dt_state.vcenter_sessions[sess_id] = {"user": "administrator@vsphere.local"}
        response.headers["vmware-api-session-id"] = sess_id
        return sess_id

    @app.get("/api/vcenter/datacenter")
    async def list_datacenters(dt_state: DigitalTwinState = Depends(get_state)):
        return [{"datacenter": "datacenter-1", "name": dt_state.config.environment.name}]

    @app.get("/api/vcenter/cluster")
    async def list_vcenter_clusters(dt_state: DigitalTwinState = Depends(get_state)):
        res = []
        mgmt_clusters = dt_state.config.management_domain.clusters or ([dt_state.config.management_domain.cluster] if dt_state.config.management_domain.cluster else [])
        for cl in mgmt_clusters:
            if cl:
                res.append({"cluster": cl.id, "name": cl.name})
        for wld in dt_state.config.workload_domains:
            for cl in wld.clusters:
                res.append({"cluster": cl.id, "name": cl.name, "domain_id": wld.id})
        return res

    @app.get("/api/vcenter/host")
    async def list_vcenter_hosts(dt_state: DigitalTwinState = Depends(get_state)):
        return [{"host": h["id"], "name": h["fqdn"], "connection_state": "CONNECTED", "power_state": "POWERED_ON"} for h in dt_state.hosts.values()]

    @app.get("/api/vcenter/vm")
    async def list_vms(dt_state: DigitalTwinState = Depends(get_state)):
        return {"value": list(dt_state.vms.values())}

    @app.get("/api/vcenter/vm/{vm_id}")
    async def get_vm(vm_id: str, dt_state: DigitalTwinState = Depends(get_state)):
        if vm_id in dt_state.vms:
            return dt_state.vms[vm_id]
        raise make_vapi_error(
            "com.vmware.vapi.std.errors.not_found",
            f"VM {vm_id} not found",
            message_id="com.vmware.vcenter.vm.not_found",
            args=[vm_id],
            status_code=status.HTTP_404_NOT_FOUND,
        )

    @app.post("/api/vcenter/vm", status_code=status.HTTP_201_CREATED)
    async def create_vm(payload: Dict[str, Any], dt_state: DigitalTwinState = Depends(get_state)):
        spec = payload.get("spec", payload)
        cpu_spec = spec.get("cpu", {})
        cpu_count = cpu_spec.get("count", 2) if isinstance(cpu_spec, dict) else 2
        mem_spec = spec.get("memory", {})
        mem_size = mem_spec.get("size_MiB", 4096) if isinstance(mem_spec, dict) else 4096

        if cpu_count <= 0:
            raise make_vapi_error(
                "com.vmware.vapi.std.errors.invalid_argument",
                "CPU count must be a positive integer.",
                message_id="vapi.data.validate.invalid_argument",
                status_code=status.HTTP_400_BAD_REQUEST,
            )
        if mem_size < 512:
            raise make_vapi_error(
                "com.vmware.vapi.std.errors.invalid_argument",
                "Memory size must be at least 512 MiB.",
                message_id="vapi.data.validate.invalid_argument",
                status_code=status.HTTP_400_BAD_REQUEST,
            )

        vm_id = f"vm-{uuid.uuid4().hex[:6]}"
        record = {
            "vm": vm_id,
            "name": spec.get("name", f"vm-{vm_id}"),
            "power_state": "POWERED_OFF",
            "cpu_count": cpu_count,
            "memory_size_MiB": mem_size,
            "datastore": spec.get("datastore", list(dt_state.datastores.keys())[0] if dt_state.datastores else "vsan-wld01-ds01"),
            "tenant_org": spec.get("tenant_org", "Default-Org"),
        }
        dt_state.vms[vm_id] = record
        return vm_id

    @app.post("/api/vcenter/vm/{vm_id}/power", status_code=status.HTTP_204_NO_CONTENT)
    async def control_vm_power(vm_id: str, action: str = Query("start", pattern="^(start|stop|reset|suspend)$"), dt_state: DigitalTwinState = Depends(get_state)):
        if vm_id not in dt_state.vms:
            raise make_vapi_error(
                "com.vmware.vapi.std.errors.not_found",
                f"VM {vm_id} not found",
                message_id="com.vmware.vcenter.vm.not_found",
                args=[vm_id],
                status_code=status.HTTP_404_NOT_FOUND,
            )
        dt_state.vms[vm_id]["power_state"] = {"start": "POWERED_ON", "stop": "POWERED_OFF", "reset": "POWERED_ON", "suspend": "SUSPENDED"}[action]
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    @app.patch("/api/vcenter/vm/{vm_id}/hardware/cpu", status_code=204)
    async def update_vm_cpu(vm_id: str, payload: Dict[str, Any], dt_state: DigitalTwinState = Depends(get_state)):
        if vm_id not in dt_state.vms:
            raise HTTPException(404, "VM not found")
        count = payload.get("count")
        if type(count) is not int or not 1 <= count <= 1024 or set(payload) != {"count"}:
            raise HTTPException(400, "Expected count between 1 and 1024")
        dt_state.vms[vm_id]["cpu_count"] = count
        return Response(status_code=204)

    @app.patch("/api/vcenter/vm/{vm_id}/hardware/memory", status_code=204)
    async def update_vm_memory(vm_id: str, payload: Dict[str, Any], dt_state: DigitalTwinState = Depends(get_state)):
        if vm_id not in dt_state.vms:
            raise HTTPException(404, "VM not found")
        size = payload.get("size_MiB")
        if type(size) is not int or not 512 <= size <= 16777216 or set(payload) != {"size_MiB"}:
            raise HTTPException(400, "Expected size_MiB between 512 and 16777216")
        dt_state.vms[vm_id]["memory_size_MiB"] = size
        return Response(status_code=204)

    @app.delete("/api/vcenter/vm/{vm_id}", status_code=status.HTTP_204_NO_CONTENT)
    async def delete_vm(vm_id: str, dt_state: DigitalTwinState = Depends(get_state)):
        if vm_id not in dt_state.vms:
            raise make_vapi_error(
                "com.vmware.vapi.std.errors.not_found",
                f"VM {vm_id} not found",
                message_id="com.vmware.vcenter.vm.not_found",
                args=[vm_id],
                status_code=status.HTTP_404_NOT_FOUND,
            )
        vm = dt_state.vms[vm_id]
        if vm.get("power_state") == "POWERED_ON":
            raise make_vapi_error(
                "com.vmware.vapi.std.errors.not_allowed_in_current_state",
                f"VM {vm_id} is in POWERED_ON state and cannot be deleted.",
                message_id="com.vmware.vcenter.vm.power.state_invalid",
                args=[vm_id],
                status_code=status.HTTP_400_BAD_REQUEST,
            )
        del dt_state.vms[vm_id]
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    @app.get("/api/vcenter/vm/{vm_id}/hardware/disk")
    async def get_vm_disks(vm_id: str, dt_state: DigitalTwinState = Depends(get_state)):
        if vm_id not in dt_state.vms:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail={"message": f"VM {vm_id} not found"})
        vm = dt_state.vms[vm_id]
        disks = vm.get("disks", [
            {
                "id": "disk-2000",
                "label": "Hard disk 1",
                "capacity_bytes": 107374182400,
                "capacity_gb": 100,
                "datastore": vm.get("datastore", "vsan-wld01-ds01"),
                "backing_file": f"[{vm.get('datastore', 'vsan-wld01-ds01')}] {vm.get('name')}/{vm.get('name')}.vmdk",
                "thin_provisioned": True,
                "storage_policy": "policy-vsan-esa-default",
            }
        ])
        return {"value": disks}

    @app.get("/api/vcenter/vm/{vm_id}/hardware/ethernet")
    async def get_vm_ethernet(vm_id: str, dt_state: DigitalTwinState = Depends(get_state)):
        if vm_id not in dt_state.vms:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail={"message": f"VM {vm_id} not found"})
        vm = dt_state.vms[vm_id]
        nics = vm.get("nics", [
            {
                "nic_id": "nic-4000",
                "label": "Network adapter 1",
                "mac_address": vm.get("mac_address", "00:50:56:a1:b2:c3"),
                "network": "seg-wld01-apps",
                "ip_addresses": [vm.get("ip_address", "192.168.110.10")],
                "connected": True,
            }
        ])
        return {"value": nics}

    @app.get("/api/vcenter/vm/{vm_id}/guest/identity")
    async def get_vm_guest_identity(vm_id: str, dt_state: DigitalTwinState = Depends(get_state)):
        if vm_id not in dt_state.vms:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail={"message": f"VM {vm_id} not found"})
        vm = dt_state.vms[vm_id]
        return {
            "name": vm.get("guest_hostname", f"{vm.get('name')}.corp.local"),
            "full_name": vm.get("guest_os", "Red Hat Enterprise Linux 9 (64-bit)"),
            "family": "LINUX" if "RHEL" in vm.get("guest_os", "") or "Linux" in vm.get("guest_os", "") else "WINDOWS",
            "ip_address": vm.get("ip_address", "192.168.110.10"),
        }

    @app.get("/api/vcenter/vm/{vm_id}/guest/local-filesystem")
    async def get_vm_guest_filesystems(vm_id: str, dt_state: DigitalTwinState = Depends(get_state)):
        if vm_id not in dt_state.vms:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail={"message": f"VM {vm_id} not found"})
        vm = dt_state.vms[vm_id]
        filesystems = vm.get("filesystems", [
            {
                "mount_point": "/",
                "filesystem_type": "ext4",
                "capacity_bytes": 107374182400,
                "free_bytes": 64424509440,
                "used_bytes": 42949672960,
                "percent_free": 60.0,
            }
        ])
        return {"value": filesystems}

    @app.get("/api/vcenter/vm/{vm_id}/guest/networking")
    async def get_vm_guest_networking(vm_id: str, dt_state: DigitalTwinState = Depends(get_state)):
        if vm_id not in dt_state.vms:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail={"message": f"VM {vm_id} not found"})
        vm = dt_state.vms[vm_id]
        return {
            "dns_values": {"domain_name": "corp.local", "host_name": vm.get("name"), "servers": ["192.168.10.1"]},
            "interfaces": vm.get("nics", [
                {"mac_address": vm.get("mac_address", "00:50:56:a1:b2:c3"), "ip_addresses": [vm.get("ip_address", "192.168.110.10")]}
            ]),
        }


    @app.get("/api/vcenter/datastore")
    async def list_datastores(dt_state: DigitalTwinState = Depends(get_state)):
        return list(dt_state.datastores.values())

    @app.get("/api/vcenter/network")
    async def list_networks(dt_state: DigitalTwinState = Depends(get_state)):
        res = [
            {"network": "network-pg-mgmt", "name": "pg-mgmt-vlan10", "type": "DISTRIBUTED_PORTGROUP"},
            {"network": "network-pg-vmotion", "name": "pg-vmotion-vlan11", "type": "DISTRIBUTED_PORTGROUP"},
            {"network": "network-pg-vsan", "name": "pg-vsan-vlan100", "type": "DISTRIBUTED_PORTGROUP"},
        ]
        for seg_id, seg in dt_state.nsx_segments.items():
            res.append({"network": f"network-{seg_id}", "name": seg["display_name"], "type": "OPAQUE_NETWORK"})
        return res

    @app.get("/api/vcenter/storage/policies")
    async def list_storage_policies():
        return [
            {"policy": "policy-vsan-esa-default", "name": "vSAN ESA Default Policy - RAID-1 Mirroring", "compliance_status": "COMPLIANT"},
            {"policy": "policy-vsan-esa-raid6", "name": "vSAN ESA Enterprise RAID-6 Erasure Coding", "compliance_status": "COMPLIANT"},
            {"policy": "policy-supervisor-gold", "name": "vSphere Supervisor Gold Storage Policy", "compliance_status": "COMPLIANT"},
        ]

    # --------------------------------------------------------------------------
    # 3. vSphere Supervisor APIs
    # --------------------------------------------------------------------------
    @app.get("/api/vcenter/namespace-management/clusters")
    async def list_supervisor_clusters(dt_state: DigitalTwinState = Depends(get_state)):
        clusters = []
        for wld in dt_state.config.workload_domains:
            for cl in wld.clusters:
                if cl.vsphere_supervisor:
                    clusters.append({
                        "cluster": cl.id,
                        "domain_id": wld.id,
                        "config_status": cl.vsphere_supervisor.config_status,
                        "kubernetes_status": cl.vsphere_supervisor.kubernetes_status,
                        "api_endpoint": cl.vsphere_supervisor.api_endpoint,
                        "kubernetes_version": cl.vsphere_supervisor.kubernetes_version,
                    })
        if not clusters:
            clusters.append({
                "cluster": "domain-c8",
                "config_status": "RUNNING",
                "kubernetes_status": "READY",
                "api_endpoint": "https://192.168.20.250:6443",
                "kubernetes_version": "v1.30.2+vmware.1",
            })
        return clusters

    @app.get("/api/vcenter/namespace-management/namespaces")
    @app.get("/api/vcenter/namespaces/instances")
    async def list_namespaces(dt_state: DigitalTwinState = Depends(get_state)):
        return list(dt_state.supervisor_namespaces.values())

    @app.post("/api/vcenter/namespace-management/namespaces", status_code=status.HTTP_201_CREATED)
    @app.post("/api/vcenter/namespaces/instances", status_code=status.HTTP_201_CREATED)
    async def create_namespace(payload: Dict[str, Any], dt_state: DigitalTwinState = Depends(get_state)):
        ns_name = payload.get("namespace", payload.get("name", f"ns-{uuid.uuid4().hex[:6]}"))
        if not RFC1123_REGEX.match(ns_name) or len(ns_name) > 63:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"type": "com.vmware.vapi.std.errors.invalid_argument", "message": f"Namespace name '{ns_name}' must conform to RFC 1123 DNS label regex."},
            )
        if ns_name in dt_state.supervisor_namespaces:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={"type": "com.vmware.vapi.std.errors.already_exists", "message": f"Namespace '{ns_name}' already exists."},
            )

        record = {
            "namespace": ns_name,
            "description": payload.get("description", "Production Workload Namespace"),
            "storage_limit_gb": payload.get("storage_limit_gb", 1000),
            "cluster": payload.get("cluster", "wld01-cl01"),
            "tenant_org": payload.get("tenant_org", "Default-Org"),
            "config_status": "RUNNING",
            "kubernetes_status": "READY",
        }
        dt_state.supervisor_namespaces[ns_name] = record
        return record

    @app.delete("/api/vcenter/namespace-management/namespaces/{namespace_id}", status_code=status.HTTP_204_NO_CONTENT)
    @app.delete("/api/vcenter/namespaces/instances/{namespace_id}", status_code=status.HTTP_204_NO_CONTENT)
    async def delete_namespace(namespace_id: str, dt_state: DigitalTwinState = Depends(get_state)):
        if namespace_id in dt_state.supervisor_namespaces:
            del dt_state.supervisor_namespaces[namespace_id]
            return Response(status_code=status.HTTP_204_NO_CONTENT)
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail={"message": f"Namespace {namespace_id} not found"})

    @app.get("/api/vcenter/namespace-management/virtual-machine-classes")
    async def list_vm_classes(dt_state: DigitalTwinState = Depends(get_state)):
        return list(dt_state.supervisor_classes.values())

    @app.post("/api/vcenter/namespace-management/virtual-machine-classes", status_code=status.HTTP_201_CREATED)
    async def create_vm_class(payload: Dict[str, Any], dt_state: DigitalTwinState = Depends(get_state)):
        name = payload.get("name", payload.get("id", f"class-{uuid.uuid4().hex[:6]}"))
        cpu = payload.get("cpu", payload.get("cpu_count", 2))
        mem = payload.get("memory_mb", payload.get("memory_MB", 4096))
        if cpu <= 0 or mem <= 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"type": "com.vmware.vapi.std.errors.invalid_argument", "message": "CPU and Memory must be positive integers."},
            )
        record = {
            "name": name,
            "cpu": cpu,
            "memory_mb": mem,
            "vgpu_profile": payload.get("vgpu_profile"),
        }
        dt_state.supervisor_classes[name] = record
        return record

    # --------------------------------------------------------------------------
    # 4. NSX Policy APIs (/policy/api/v1/*)
    # --------------------------------------------------------------------------
    @app.get("/policy/api/v1/cluster/status")
    async def get_nsx_cluster_status():
        return {"control_cluster_status": {"status": "STABLE"}, "mgmt_cluster_status": {"status": "STABLE"}}

    @app.get("/policy/api/v1/infra/tier-0s")
    async def list_tier0s(dt_state: DigitalTwinState = Depends(get_state)):
        return {"results": list(dt_state.nsx_tier0s.values())}

    @app.delete("/policy/api/v1/infra/tier-0s/{tier0_id}")
    async def delete_tier0(tier0_id: str, dt_state: DigitalTwinState = Depends(get_state)):
        if tier0_id not in dt_state.nsx_tier0s:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail={"error_code": 404, "error_message": f"Tier-0 {tier0_id} not found"})
        connected_t1s = [t1["id"] for t1 in dt_state.nsx_tier1s.values() if t1.get("tier0_path", "").endswith(tier0_id)]
        if connected_t1s:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"error_code": 400, "error_message": f"Tier-0 {tier0_id} cannot be deleted because Tier-1 Gateways {connected_t1s} are connected to it."},
            )
        del dt_state.nsx_tier0s[tier0_id]
        return {"status": "SUCCESS", "message": f"Tier-0 {tier0_id} deleted."}

    @app.get("/policy/api/v1/infra/tier-1s")
    async def list_tier1s(dt_state: DigitalTwinState = Depends(get_state)):
        return {"results": list(dt_state.nsx_tier1s.values())}

    @app.delete("/policy/api/v1/infra/tier-1s/{tier1_id}")
    async def delete_tier1(tier1_id: str, dt_state: DigitalTwinState = Depends(get_state)):
        if tier1_id not in dt_state.nsx_tier1s:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail={"error_code": 404, "error_message": f"Tier-1 {tier1_id} not found"})
        connected_segs = [s["id"] for s in dt_state.nsx_segments.values() if s.get("connectivity_path", "").endswith(tier1_id)]
        if connected_segs:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"error_code": 400, "error_message": f"Tier-1 {tier1_id} cannot be deleted because Segments {connected_segs} are attached to it."},
            )
        del dt_state.nsx_tier1s[tier1_id]
        return {"status": "SUCCESS", "message": f"Tier-1 {tier1_id} deleted."}

    @app.get("/policy/api/v1/infra/segments")
    async def list_segments(dt_state: DigitalTwinState = Depends(get_state)):
        return {"results": list(dt_state.nsx_segments.values())}

    @app.post("/policy/api/v1/infra/segments/{segment_id}", status_code=status.HTTP_200_OK)
    async def create_segment(segment_id: str, payload: Dict[str, Any], dt_state: DigitalTwinState = Depends(get_state)):
        record = {
            "id": segment_id,
            "display_name": payload.get("display_name", segment_id),
            "connectivity_path": payload.get("connectivity_path", "/infra/tier-1s/t1-production"),
            "subnets": payload.get("subnets", [{"gateway_address": "192.168.150.1/24"}]),
            "tenant_org": payload.get("tenant_org", "Default-Org"),
        }
        dt_state.nsx_segments[segment_id] = record
        return record

    @app.delete("/policy/api/v1/infra/segments/{segment_id}")
    async def delete_segment(segment_id: str, dt_state: DigitalTwinState = Depends(get_state)):
        if segment_id not in dt_state.nsx_segments:
            raise make_nsx_error(f"Segment {segment_id} not found", error_code=404, http_status="NOT_FOUND", status_code=status.HTTP_404_NOT_FOUND)
        
        # Check if active VMs are connected to this segment
        attached_vms = []
        for vm_id, vm in dt_state.vms.items():
            if vm.get("network") == segment_id:
                attached_vms.append(vm.get("name", vm_id))
            for nic in vm.get("nics", []):
                nic_val = nic.get("value", nic) if isinstance(nic, dict) else {}
                if isinstance(nic_val, dict) and nic_val.get("network") == segment_id:
                    attached_vms.append(vm.get("name", vm_id))
                elif isinstance(nic, dict) and nic.get("network") == segment_id:
                    attached_vms.append(vm.get("name", vm_id))

        if attached_vms:
            raise make_nsx_error(
                f"Segment '{segment_id}' cannot be deleted because active virtual machine(s) ({', '.join(set(attached_vms))}) are connected to it.",
                error_code=500045,
                http_status="CONFLICT",
                status_code=status.HTTP_409_CONFLICT,
                details=[{"error_code": 500046, "error_message": f"Active port attachment on VM '{v}'"} for v in set(attached_vms)],
            )

        del dt_state.nsx_segments[segment_id]
        return {"status": "SUCCESS", "message": f"Segment {segment_id} deleted."}

    @app.get("/policy/api/v1/infra/domains/{domain_id}/groups")
    async def list_groups(domain_id: str, dt_state: DigitalTwinState = Depends(get_state)):
        return {"results": list(dt_state.nsx_groups.values())}

    @app.delete("/policy/api/v1/infra/domains/{domain_id}/groups/{group_id}")
    async def delete_group(domain_id: str, group_id: str, dt_state: DigitalTwinState = Depends(get_state)):
        if group_id not in dt_state.nsx_groups:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail={"error_code": 404, "error_message": f"Group {group_id} not found"})
        for pol in dt_state.nsx_security_policies.values():
            if any(group_id in s for s in pol.get("scope", [])):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail={"error_code": 400, "error_message": f"Group {group_id} is referenced in Security Policies and cannot be deleted."},
                )
        del dt_state.nsx_groups[group_id]
        return {"status": "SUCCESS", "message": f"Group {group_id} deleted."}

    # --------------------------------------------------------------------------
    # 5. Site Recovery Manager (SRM) & Replication APIs
    # --------------------------------------------------------------------------
    @app.post("/api/srm/v1/sessions", status_code=status.HTTP_201_CREATED)
    async def create_srm_session(response: Response, dt_state: DigitalTwinState = Depends(get_state)):
        sess_id = f"srm-sess-{uuid.uuid4().hex[:12]}"
        dt_state.srm_sessions[sess_id] = {"user": "administrator@vsphere.local"}
        response.headers["srm-session-id"] = sess_id
        return {"session_id": sess_id}

    @app.get("/api/srm/v1/pairings")
    async def list_pairings(dt_state: DigitalTwinState = Depends(get_state)):
        return list(dt_state.srm_pairings.values())

    @app.get("/api/srm/v1/protection-groups")
    async def list_protection_groups(dt_state: DigitalTwinState = Depends(get_state)):
        return list(dt_state.srm_protection_groups.values())

    @app.delete("/api/srm/v1/protection-groups/{pg_id}")
    async def delete_protection_group(pg_id: str, dt_state: DigitalTwinState = Depends(get_state)):
        if pg_id not in dt_state.srm_protection_groups:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail={"code": 404, "message": f"Protection group {pg_id} not found"})
        for rp in dt_state.srm_recovery_plans.values():
            if pg_id in rp.get("protection_groups", []):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail={"code": 400, "message": f"Protection group {pg_id} cannot be deleted because it is included in active Recovery Plans."},
                )
        del dt_state.srm_protection_groups[pg_id]
        return {"status": "SUCCESS", "message": f"Protection group {pg_id} deleted."}

    @app.get("/api/srm/v1/recovery-plans")
    async def list_recovery_plans(dt_state: DigitalTwinState = Depends(get_state)):
        return list(dt_state.srm_recovery_plans.values())

    @app.post("/api/srm/v1/recovery-plans/{plan_id}/test")
    async def test_recovery_plan(plan_id: str, dt_state: DigitalTwinState = Depends(get_state)):
        if plan_id not in dt_state.srm_recovery_plans:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail={"code": 404, "message": f"Recovery plan {plan_id} not found"})
        curr_status = dt_state.srm_recovery_plans[plan_id].get("status", "READY")
        if curr_status in ("TESTING", "RECOVERING", "IN_PROGRESS"):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "code": 409,
                    "errorCode": "SRM_EXECUTION_IN_PROGRESS",
                    "message": f"Recovery plan {plan_id} is currently in state '{curr_status}'. Concurrent executions are locked.",
                },
            )
        exec_id = f"exec-test-{uuid.uuid4().hex[:6]}"
        record = {
            "executionId": exec_id,
            "planId": plan_id,
            "state": "COMPLETED",
            "result": "SUCCESSFUL",
            "testNetwork": "seg-wld01-apps-bubble",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        dt_state.srm_executions.append(record)
        return record

    @app.post("/api/srm/v1/recovery-plans/{plan_id}/recovery")
    async def execute_recovery_plan(plan_id: str, dt_state: DigitalTwinState = Depends(get_state)):
        if plan_id not in dt_state.srm_recovery_plans:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail={"code": 404, "message": f"Recovery plan {plan_id} not found"})
        curr_status = dt_state.srm_recovery_plans[plan_id].get("status", "READY")
        if curr_status in ("TESTING", "RECOVERING", "IN_PROGRESS"):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "code": 409,
                    "errorCode": "SRM_EXECUTION_IN_PROGRESS",
                    "message": f"Recovery plan {plan_id} is currently in state '{curr_status}'. Concurrent executions are locked.",
                },
            )
        exec_id = f"exec-failover-{uuid.uuid4().hex[:6]}"
        record = {
            "executionId": exec_id,
            "planId": plan_id,
            "state": "COMPLETED",
            "result": "SUCCESSFUL",
            "mode": "PLANNED_MIGRATION",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        dt_state.srm_executions.append(record)
        return record

    @app.get("/api/vr/v1/replication-profiles")
    async def list_vr_profiles(dt_state: DigitalTwinState = Depends(get_state)):
        return list(dt_state.vr_profiles.values())

    @app.post("/api/vr/v1/replication-profiles", status_code=status.HTTP_201_CREATED)
    async def create_vr_profile(payload: Dict[str, Any], dt_state: DigitalTwinState = Depends(get_state)):
        rpo = payload.get("rpo_minutes", 5)
        if rpo < 5:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"message": f"Minimum supported RPO in vSphere Replication is 5 minutes. Provided: {rpo} minutes."},
            )
        prof_id = payload.get("id", f"vr-prof-{uuid.uuid4().hex[:6]}")
        record = {"id": prof_id, "name": payload.get("name", prof_id), "rpo_minutes": rpo}
        dt_state.vr_profiles[prof_id] = record
        return record

    @app.delete("/api/vr/v1/replication-profiles/{profile_id}", status_code=status.HTTP_204_NO_CONTENT)
    async def delete_vr_profile(profile_id: str, dt_state: DigitalTwinState = Depends(get_state)):
        if profile_id not in dt_state.vr_profiles:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail={"message": f"Profile {profile_id} not found"})
        for rep in dt_state.vr_replications.values():
            if rep.get("rpo_minutes") == dt_state.vr_profiles[profile_id].get("rpo_minutes"):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail={"message": f"Replication profile {profile_id} is in use by active replications."},
                )
        del dt_state.vr_profiles[profile_id]
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    # --------------------------------------------------------------------------
    # 6. VCF Automation & Operations APIs
    # --------------------------------------------------------------------------
    @app.post("/csp/gateway/am/api/auth/token", status_code=status.HTTP_200_OK)
    async def create_csp_token():
        return {"access_token": f"csp-tok-{uuid.uuid4().hex[:12]}", "token_type": "Bearer", "expires_in": 1800}

    @app.get("/iaas/api/machines")
    async def list_iaas_machines(dt_state: DigitalTwinState = Depends(get_state)):
        return {"content": [{"id": f"machine-{v['vm']}", "name": v["name"], "powerState": v["power_state"], "tenantOrg": v.get("tenant_org")} for v in dt_state.vms.values()]}

    @app.get("/iaas/api/projects")
    async def list_iaas_projects(dt_state: DigitalTwinState = Depends(get_state)):
        return {"content": list(dt_state.tenant_orgs.values())}

    @app.get("/suite-api/api/resources/stats")
    async def get_suite_stats(resourceId: Optional[str] = None, statKey: Optional[List[str]] = Query(None), dt_state: DigitalTwinState = Depends(get_state)):
        clusters = await list_vcenter_clusters(dt_state)
        known = set(dt_state.vms) | {c["cluster"] for c in clusters}
        if resourceId is not None and resourceId not in known:
            raise HTTPException(404, "Telemetry resource not found")
        resources = [resourceId] if resourceId else sorted(known)
        metrics = statKey or ["cpu|usage_average"]
        now = int(datetime.now(timezone.utc).timestamp() * 1000)
        return {"resourceStats": [{"resourceId": rid, "statKey": metric, "timestamps": [now], "values": [34.5], "synthetic": True}
                                  for rid in resources for metric in metrics]}

    @app.get("/suite-api/api/adapter-instances")
    async def list_dt_adapter_instances():
        return {
            "adapterInstancesInfoDto": [
                {"id": "adapter-vcf-sddc", "name": "VCF SDDC Manager Adapter", "adapterKindKey": "SDDCAdapter", "resourceStatus": "DATA_RECEIVING"},
                {"id": "adapter-vcenter-mgmt", "name": "vCenter Management Adapter", "adapterKindKey": "VMWARE", "resourceStatus": "DATA_RECEIVING"},
                {"id": "adapter-nsx-mgmt", "name": "NSX-T Manager Adapter", "adapterKindKey": "NSXTAdapter", "resourceStatus": "DATA_RECEIVING"},
                {"id": "adapter-vsan-esa", "name": "vSAN ESA Adapter", "adapterKindKey": "vSANAdapter", "resourceStatus": "DATA_RECEIVING"},
                {"id": "adapter-srm-vr", "name": "SRM Replication Adapter", "adapterKindKey": "SRMAdapter", "resourceStatus": "DATA_RECEIVING"},
            ]
        }

    @app.get("/suite-api/api/sddc/health")
    async def get_dt_sddc_health(dt_state: DigitalTwinState = Depends(get_state)):
        return {
            "status": "GREEN",
            "sddcHealthScore": 99,
            "managementDomain": {
                "id": dt_state.config.management_domain.id,
                "health": "GREEN",
                "vcenter": dt_state.config.management_domain.vcenter.fqdn,
                "nsx": dt_state.config.management_domain.nsx_manager.vip_fqdn,
            },
            "workloadDomains": [
                {"id": wld.id, "name": wld.name, "health": "GREEN", "clustersCount": len(wld.clusters)}
                for wld in dt_state.config.workload_domains
            ],
            "totalHosts": len(dt_state.hosts),
            "totalVMs": len(dt_state.vms),
        }

    @app.get("/suite-api/api/sddc/management-packs")
    async def list_dt_sddc_management_packs():
        return {
            "managementPacks": [
                {"id": "mp-vcf-sddc", "name": "VMware Cloud Foundation SDDC Management Pack", "version": "9.1.0", "status": "ACTIVE"},
                {"id": "mp-vsphere", "name": "VMware vSphere Management Pack", "version": "9.1.0", "status": "ACTIVE"},
                {"id": "mp-nsx", "name": "VMware NSX-T Management Pack", "version": "4.2.1", "status": "ACTIVE"},
                {"id": "mp-vsan", "name": "VMware vSAN ESA Management Pack", "version": "9.1.0", "status": "ACTIVE"},
                {"id": "mp-srm-vr", "name": "VMware Live Site Recovery & VR Management Pack", "version": "9.1.0", "status": "ACTIVE"},
                {"id": "mp-tkg-k8s", "name": "VMware Tanzu Kubernetes Grid Management Pack", "version": "1.30.2", "status": "ACTIVE"},
                {"id": "mp-private-ai", "name": "VMware Private AI & GPU Telemetry Management Pack", "version": "1.2.0", "status": "ACTIVE"},
            ]
        }

    @app.get("/suite-api/api/sddc/compliance")
    async def get_dt_sddc_compliance():
        return {
            "overallComplianceScore": 98.2,
            "frameworks": [
                {"framework": "CIS VMware ESXi 8/9 Benchmark", "rulesEvaluated": 84, "passed": 84, "compliancePct": 100.0},
                {"framework": "VCF Security Configuration Guide (SCG)", "rulesEvaluated": 120, "passed": 119, "compliancePct": 99.2},
                {"framework": "FIPS 140-3 Cryptographic Enforcement", "rulesEvaluated": 32, "passed": 32, "compliancePct": 100.0},
            ]
        }

    @app.get("/suite-api/api/sddc/benchmarks")
    async def get_dt_sddc_benchmarks(dt_state: DigitalTwinState = Depends(get_state)):
        return {
            "computeBenchmark": {"totalCores": sum(h.get("cores", 64) for h in dt_state.hosts.values()), "averageUtilizationPct": 38.5},
            "memoryBenchmark": {"totalMemoryGb": sum(h.get("memory_gb", 1024) for h in dt_state.hosts.values()), "averageUtilizationPct": 52.0},
            "storageBenchmark": {"totalStorageTb": sum(ds.get("capacity_tb", 100.0) for ds in dt_state.datastores.values()), "iopsCapacity": 300000},
        }

    @app.get("/api/ni/flows")
    async def get_network_flows():
        return {
            "flows": [
                {"flow_id": "flow-01", "source_ip": "192.168.110.10", "destination_ip": "192.168.110.20", "destination_port": 1521, "protocol": "TCP", "action": "ALLOWED", "firewall_rule": "ALLOW_DB_ACCESS"}
            ]
        }

    # --------------------------------------------------------------------------
    # 7. Admin & Hot Reload
    # --------------------------------------------------------------------------
    @app.post("/vcf/admin/config/reload")
    async def reload_config(payload: Optional[Dict[str, Any]] = None, dt_state: DigitalTwinState = Depends(get_state)):
        config_path = payload.get("configPath") if payload else None
        dt_state.reload(config_path)
        return {"status": "SUCCESS", "message": "Digital Twin state reloaded successfully", "totalHosts": len(dt_state.hosts), "totalVMs": len(dt_state.vms)}

    return app


def main():
    import uvicorn
    import argparse

    parser = argparse.ArgumentParser(description="VCF Digital Twin Mock Server")
    parser.add_argument("--port", "-p", type=int, default=8085, help="Port to listen on (default 8085)")
    parser.add_argument("--host", default="0.0.0.0", help="Host address (default 0.0.0.0)")
    parser.add_argument("--config", "-c", default="digital_twin/vcf_inventory.yaml", help="Path to vcf_inventory.yaml")
    args = parser.parse_args()

    print(f"[*] Starting VCF Digital Twin Mock Server on port {args.port}...")
    app = create_digital_twin_app(args.config)
    uvicorn.run(app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
