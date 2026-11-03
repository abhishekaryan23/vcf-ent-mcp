# Audits and reviews

Reviews of this project, newest first. This is an **unofficial project under testing**: none of these documents is a certification, and the older ones describe the code as it stood on their dates.

| Document | What it is |
| --- | --- |
| [independent_review_2026_11_02.md](independent_review_2026_11_02.md) | Current. Independent senior-architect review of guided setup, architecture and VCF 9.x fit (findings F1-F21 with file and line evidence). Most findings were fixed before the public release; the ones still open (F4 in part, F6, F12, F13, F21) are listed under "Known limitations" in the top-level README |
| [independent_production_audit_report_v2.md](independent_production_audit_report_v2.md) | Historical (September 2026). Second internal audit of an older commit; its readiness wording ("pilot ready") is superseded by the review above and by the project's "unofficial, under testing" status |
| [independent_audit_1.0.0.md](independent_audit_1.0.0.md) | Historical (September 2026). First internal audit of v1.0.0 and its P0 findings |
| [remediation_status.md](remediation_status.md) | Historical. Tracking table for the two September audits above |

## Notes carried over from the removed `audit/` evidence tree

An earlier `audit/` folder held September 2026 internal audit runs (probes, evidence dumps, verdicts such as "not live-test ready" about commits that no longer exist). It was removed before publication: the verdicts were stale, and some evidence files were machine-readable extracts of Broadcom's API specifications, which this repository does not redistribute. The guidance that still applies:

- **Audits are a record, not a certification.** Keep any new audit labelled with the commit it covers and say plainly that the project is unofficial and under testing.
- **Scrub before publishing evidence.** Replace absolute local paths and machine names with placeholders (`<repo>`, `<workspace>`, `<tmp>`, `~`, `<host>`), refresh any checksum manifest for files that change, and never edit a finding, verdict or measured result while scrubbing.
- **Do not commit Broadcom specification data.** The API-contract tests read the specifications from your own clone: set `VCF_API_SPECS_DIR` to a checkout of [github.com/vmware/vcf-api-specs](https://github.com/vmware/vcf-api-specs) (tag 9.1.1.0 is a good default). Without it those tests skip.
