# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""Obtain real signed plans for positive mutation tests; never bypass execution gates."""
from vcf_enterprise_mcp.auth.identity import Principal
from vcf_enterprise_mcp.policy.models import RiskClass


async def execute_authorized(tool, principal, arguments, **kwargs):
    args = dict(arguments)
    if tool.risk_class != RiskClass.READ and not args.get('dry_run') and not args.get('plan_id'):
        if args.get('vm_id'):
            vm = tool.platform.get_vm(args['vm_id'])
            if isinstance(vm, dict):
                for coord in ('cluster', 'domain'):
                    value = vm.get(coord + '_id') or vm.get(coord)
                    if value:
                        args[coord + '_id'] = value
        target = args.get('vm_id') or args.get('cluster_id') or args.get('domain_id') or args.get('segment_name') or tool.name
        plan = tool.plan_manager.create_dry_run_plan(principal, tool.name, args, {}, [target], tool.risk_class)
        approver = Principal(user_id='independent-approver', tenant_id=principal.tenant_id,
                             environment_ids=principal.environment_ids, corporate_groups=['VCF-Platform-Admins', 'VCF-Security-Admins'])
        auth = tool.plan_manager.approve_plan(plan['plan_id'], approver)
        args.update(plan_id=plan['plan_id'], approval_id=auth.approval_id, nonce=auth.nonce)
    return await tool.execute(principal, args, **kwargs)
