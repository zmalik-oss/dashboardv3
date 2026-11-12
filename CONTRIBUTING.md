# Contributing

## Workflow

1. Pull `main`, then branch: `git checkout -b <area>/<short-description>` (for example `rules/log-tampering`).
2. Make a small change, run `pytest`, commit with a clear message.
3. Push the branch and open a pull request. One teammate reviews and merges. Nobody pushes to `main` directly.
4. If you change `config/rules.yaml` or scoring logic, say in the PR what behavior changed and why.

## Ownership

Fill this in at the next group meeting so every piece has an owner and a reviewer.

| Area | Files | Owner | Reviewer |
|---|---|---|---|
| Rubric to rules, rule tuning | `config/rules.yaml`, `scoring.py`, `docs/rubric-to-rules.md` | TBD | TBD |
| Data, baseline, event grouping | `loader.py`, `features.py`, `baseline.py`, `grouping.py` | TBD | TBD |
| Benchmark and analysis | `benchmark.py`, `docs/benchmark-protocol.md` | TBD | TBD |
| Dashboard and demo | `dashboard/`, `export.py` | TBD | TBD |
| Cloud deployment | `docs/aws-deployment.md` | TBD | TBD |
| Report, slides, meeting records | `docs/course-checklist.md` | TBD | TBD |

## Rules that protect the benchmark

- Never read `sus` or `evil` in feature extraction, baseline fitting, or scoring. The label-independence test will fail if you do.
- Tune settings on the **validation** split (it has no attacks, so it measures false alarms). Report results on **test** once, after the settings are frozen.
- Record every change to `rules.yaml` thresholds in the PR description so the report can describe the tuning honestly.

## Never commit

- The BETH CSV files (large; use `scripts/download_beth.sh`)
- Credentials: `kaggle.json`, AWS keys, `.env` files, `.pem` files
- `artifacts/` output, except when a teammate deliberately adds a result for the report
