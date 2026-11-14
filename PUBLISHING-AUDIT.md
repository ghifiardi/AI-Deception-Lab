# Pre-publication audit (14 November 2026)

Target public repository: https://github.com/ghifiardi/AI-Deception-Lab (separate from the private parent project).

Scope: the `deception-lab/` folder only. The parent `gatra_world_monitor` repository and its git history were not reachable from this audit; run the history checks below yourself.

## Status

Redactions applied on 14 November 2026; originals kept in `_private/originals/` (git-ignored). Handoff notes moved to `_private/`.

## Result

No API keys, private keys, cloud credentials, `.env` files or real HMAC control keys were found. Remaining items are personal details, machine paths and large files.

| Finding | Where | Risk | Recommendation |
| --- | --- | --- | --- |
| Personal e-mail address | `HANDOFF-DEFENSE-V2.md`, `docs/GCP-LIVE-DEMO.md`, `docs/evidence/2026-11-13-gcp-test.md`, `docs/GATRA Deception Lab — Audience Guide.md` | Privacy | Replace with `you@example.com` |
| Absolute local paths `/Users/<name>/...` | `docs/evidence/2026-11-14-swarm-gcp-{ollama,tantular-live,scripted}.txt` | Privacy (reveals username) | Replace with `<repo>/...` |
| External VM IP (ephemeral, now redacted) | `docs/evidence/2026-11-13-gcp-vm.json` | Low (ephemeral IP, VM deleted) | Replace with `<redacted-ephemeral-ip>` |
| GCP project ID and VM name (`tantular-dashboard`, `gatra-deception-demo`) | 11 files | Low (VM and network deleted) | Optional: keep for reproducibility, or use placeholders |
| Internal handoff notes | `HANDOFF-DEFENSE-V2.md`, `HANDOFF-SWARM-LAB.md` | Low; mentions account setup | Move out of the public tree or redact |
| Synthetic `LABKEY-…` values | `experiments/results/*.json`, `experiments/swarm/results/*` | None: per-run synthetic lab keys that open nothing | Keep; they are part of the evidence |
| `admin@lab.local`, `root@lab.local` | swarm result files | None: strings a model agent tried as tokens | Keep |
| Large media (about 113 MB) | `recordings/*.mp4`, `recordings/*.webm`, `docs/*.mp4` | Repository bloat | Excluded by the new `.gitignore`; attach to a GitHub release or Zenodo |
| Build output | `dist/` | Not source | Excluded by `.gitignore` |

## Added for publication

- `LICENSE`: MIT, for code. Consider CC BY 4.0 for documents and data if you want a separate licence.
- `CITATION.cff`: GitHub shows a "Cite this repository" button from it. Add the arXiv ID and DOI when assigned.
- `.gitignore`: keeps build output, large media and local secrets out of git.

## Check git history before making the repository public

Files that were committed and later deleted stay in history. From the repository root:

```bash
git log --all --oneline | wc -l
git log --all -p | grep -nE "sk-ant-|AKIA|BEGIN .*PRIVATE KEY|ANTHROPIC_API_KEY=|ghp_" | head
git log --all -p | grep -c "<personal-email>"
git rev-list --objects --all | git cat-file --batch-check='%(objecttype) %(objectname) %(objectsize) %(rest)' | sort -k3 -n | tail -10
```

If anything sensitive appears, clean history with `git filter-repo` (or publish a fresh repository from a clean copy) and rotate the exposed secret.

## Release steps

1. Apply the redactions above.
2. Push, then make the repository public (Settings, Danger zone, Change visibility).
3. Sign in to zenodo.org with GitHub, enable the repository, and publish a release `v1.0-preprint`; Zenodo then issues a DOI.
4. Put the GitHub URL and DOI into `paper/main.tex` (Section IX) and `CITATION.cff`.
