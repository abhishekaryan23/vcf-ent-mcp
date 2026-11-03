# Audience and presentation design

This is a task-based audience profile, not a survey. It combines the user's described audience with official VCF API documentation. The intent is to choose familiar anchors, not to assume every engineer has the same background.

| Role | Familiar starting point | First question the walkthrough should answer |
| --- | --- | --- |
| VCF operations engineer | SDDC Manager, vCenter, NSX, VCF Operations, tasks and alerts | Where did a request stop, and which system owns the next check? |
| Automation engineer | vRO / VCF Operations Orchestrator workflows, REST calls, credentials | What endpoint do I call, which identity is used, and how do I track a long-running change? |
| Consultant or architect | Workload domains, deployment topology, identity, network and lifecycle boundaries | What sits in the trust boundary, and what must be ready before production use? |

The product model follows the [VCF API reference](https://developer.broadcom.com/xapis/vmware-cloud-foundation-api/latest/), which describes VCF as an integrated stack and SDDC Manager as the workload-domain, lifecycle and operations control plane. The [VCF Operations API](https://developer.broadcom.com/xapis/vcf-operations-api/latest/) describes its inventory and monitoring REST surface. The [VCF Operations Orchestrator API](https://developer.broadcom.com/xapis/vcf-operations-orchestrator-api/latest/) provides the workflow and REST integration frame for vRO users. These sources support the role anchors; the specific internal flow in the generated report is derived from this repository's source code.

## How to brief this audience

- Start with a single left-to-right request path. Keep the code names below the operational meaning.
- Show one read, one controlled change, and one failure path. These are the everyday tasks that make the architecture useful.
- Put source links beside claims. Engineers can verify a step without reading a long design document.
- State uncertain or missing evidence. Filename inference is marked separately from source-backed statements.
- Put risks into short review cards: what was found, why it could matter, and where to inspect it. A pattern match is never called a confirmed vulnerability.
- Use the same HTML for screen sharing and a printed PDF. This keeps one maintained artifact.

## Scope of the issue cards

The rules look for a few source patterns such as dynamic code execution and debug settings. For this VCF repo, the app also checks two deployment-readiness concerns: all-interface HTTP listener defaults and whether the production readiness validator has a direct call in application source. These are prompts for human review, since deployment gateways and indirect invocation can change the conclusion.
