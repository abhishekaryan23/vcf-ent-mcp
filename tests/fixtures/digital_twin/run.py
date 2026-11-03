# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Abhishek Rai. VCF Enterprise MCP: https://github.com/abhishekaryan23/vcf-ent-mcp
"""
Single-Inventory VCF Digital Twin Mock Server Runner (digital_twin/run.py).
Launches the standalone VCF Digital Twin mock server.
"""

import os
import argparse
import uvicorn
from digital_twin.server import create_digital_twin_app


def main():
    default_config = os.path.join(os.path.dirname(__file__), "vcf_inventory.yaml")
    parser = argparse.ArgumentParser(description="Launch Single-Inventory VCF Digital Twin Mock Server")
    parser.add_argument("--port", "-p", type=int, default=8085, help="Port to bind Digital Twin mock server (default: 8085)")
    parser.add_argument("--host", default="0.0.0.0", help="Host address (default: 0.0.0.0)")
    parser.add_argument("--config", "-c", default=default_config, help="Path to vcf_inventory.yaml")
    args = parser.parse_args()

    print("================================================================================")
    print("           VMware Cloud Foundation (VCF) Single-Inventory Digital Twin          ")
    print("================================================================================")
    print(f"[*] Configuration : {args.config}")
    print(f"[*] Binding Port  : http://{args.host}:{args.port}")
    print(f"[*] Direct APIs   : /v1/*, /api/vcenter/*, /policy/api/v1/*, /api/srm/v1/*")
    print(f"[*] Ready for     : Terraform, PowerCLI, Python SDK, Ansible & vcf_mcp_server")
    print("================================================================================")

    app = create_digital_twin_app(args.config)
    uvicorn.run(app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
