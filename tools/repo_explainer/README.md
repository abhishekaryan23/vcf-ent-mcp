# Repo Lens

A portable, offline app that turns a source repository into a five-minute visual walkthrough. It uses only Python's standard library and has no dependency on this VCF project. Copy this directory anywhere and point it at a different repository. Keep `report_template.html` beside the Python file.

## Run

```bash
python3 repo_explainer.py serve
```

Open <http://127.0.0.1:8765>, enter an absolute repository path, and view the report. Use **Print / PDF** in the report to create a handout.

For a standalone HTML file:

```bash
python3 repo_explainer.py generate /path/to/any/repo -o /path/to/walkthrough.html
```

## What the report shows

1. A four-zone system map: caller, guardrails, work engine and external APIs.
2. A runnable local setup and validation path for this VCF repo, followed by real-VCF acceptance gates. Other repos receive a clearly marked setup worksheet until commands are verified.
3. A clickable request journey, with source evidence for every detected stage.
4. Read, change, and failure timelines for this VCF repository, or generic scenarios for other repositories.
5. External API connection modules and up to five source-backed review prompts.
6. A starting point for operators, automation engineers, and architects.

The VCF explanation activates only when its source layout is detected. Other repositories use filename-based inference and say so. The app does not execute repository code or make network requests. It skips common build directories, symlinks, and files over 512 KB; scans up to 3,000 source and manifest files. Its issue rules are intentionally narrow. A missing flag means only that those patterns were not found; it is not a security assessment.

The setup section lists commands and expected pass signals; it does not claim the target environment has passed them. The local Digital Twin path is runnable from this repository with its sibling Twin source. Real VCF acceptance includes an explicit provider endpoint/auth binding gate because current startup uses default loopback provider registration.

## Presentation approach

Use the HTML as both a short document and a live briefing. Start with the architecture map, walk through one real request, then show the relevant API connection and review flag. The print layout produces a static PDF for handoff. The audience rationale and research sources are in [AUDIENCE.md](AUDIENCE.md).
