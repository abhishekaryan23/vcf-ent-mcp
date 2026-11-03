# Third-party notices

## vcf-orchestrator-mcp by imtrinity94 (MIT), https://github.com/imtrinity94/vcf-orchestrator-mcp

Parts of the Orchestrator support are ported from this community project, which was verified against a real VCF Automation 9.1.1
server. The ported logic is marked with a credit line at the top of each module:

- `src/vcf_enterprise_mcp/automation/wire.py`: typed-value wire format (from `values.ts`).
- `src/vcf_enterprise_mcp/automation/wf_compiler.py`: `schema-workflow` XML layout (from `workflow.ts`).
- `src/vcf_enterprise_mcp/automation/orch_changes.py`: change tracking (from `changes.ts`).
- `src/vcf_enterprise_mcp/automation/orchestrator.py`: run, action, folder, version-bump and package-export logic (from `index.ts`).

The project's Orchestrator OpenAPI file (`spec/vcfoo-9.0.0.json`) was used to check request and response shapes; it is not copied into this repository.

```
MIT License

Copyright (c) 2026 imtrinity94

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
