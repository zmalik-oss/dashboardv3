# BETH Risk Triage

Explainable, rule-based risk scoring for host-event logs, benchmarked on the
[BETH dataset](https://www.kaggle.com/datasets/katehighnam/beth-dataset). AIT 670 (Cloud Computing Security) group project.

The scoring model is the team's *Security Analysis and Risk Classification Framework*: four weighted
factors add up to a 0-100 score, and the score decides what a human analyst sees.

| Factor | Max | Source columns |
|---|---|---|
| Suspicious behavior | 40 | `eventName`, `returnValue` (attempted vs. successful) |
| Elevated privilege and misuse | 20 | `userId` (0 = root), privilege-changing syscalls |
| Access to sensitive resources | 20 | `eventName`, `args` (file paths and open flags) |
| Supporting evidence | 20 | related events from the same `processId`, repeated attempts |

| Score | Tier | Action |
|---|---|---|
| 0-39 | Low | Log automatically |
| 40-69 | Medium | Flag for investigation |
| 70-100 | High | High-priority alert |

## Design decisions

1. **Labels are the answer key, never an input.** `sus` and `evil` are not read by feature extraction,
   the baseline, or scoring (`tests/test_pipeline.py::test_scores_do_not_depend_on_labels` enforces it).
   They are used only to benchmark, and to build a *label disagreement* review queue. That queue is how
   we handle the rubric's sshd example: the score stays honest, and a human looks at cases where the
   dataset and the rubric disagree.
2. **Action groups, not single events.** Events from one host and process within 5 seconds are scored
   together, so several syscalls from one action count once and Supporting Evidence has context.
3. **"Normal" is learned, not guessed.** A baseline from the training split (unsupervised) tells the
   rules which process/event pairs and file accesses are routine, so `sshd` reading `/etc/shadow` is
   not treated like an unknown binary doing it.
4. **Everything tunable lives in `config/rules.yaml`** (syscall categories, sensitive paths,
   thresholds), so teammates can change behavior without touching code.

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pytest                                                # 17 tests

# 1) Try it on the synthetic sample (NOT real BETH data)
python scripts/make_sample_data.py
python -m triage benchmark --data-dir data/sample --sample
open dashboard/index.html                             # or double-click it

# 2) Real BETH
bash scripts/download_beth.sh                         # needs a Kaggle API token, see data/README.md
python -m triage describe --data data/beth/labelled_training_data.csv   # check eventName values vs rules.yaml
python -m triage benchmark --data-dir data/beth
```

Outputs land in `artifacts/` (`report.md`, `metrics.json`, `review_queue.csv`, `groups_test.csv`,
`baseline.json`) and `dashboard/results.js`. The dashboard is a static page: no server or build step.

## Layout

```
config/rules.yaml        rubric-to-rules settings (edit this to tune)
src/triage/              loader, features, baseline, grouping, scoring, benchmark, export, cli
dashboard/index.html     three-tier triage dashboard (reads dashboard/results.js)
data/                    BETH goes in data/beth (git-ignored); synthetic sample in data/sample
scripts/                 download_beth.sh, make_sample_data.py
tests/                   pytest suite
docs/                    rubric mapping, benchmark protocol, GitHub + AWS setup, course checklist
```

## Status

| Item | State |
|---|---|
| Rubric implemented as code | Done, needs validation on real BETH |
| Grouping, baseline, scoring, benchmark, dashboard | Done, run on the synthetic sample and once on real BETH |
| Rules adapted to real BETH | Partly. `routine_min_count` tuned on validation; known rule problems and proposed fixes are in `results/FINDINGS.md` |
| Results on real BETH | **Done once.** Rubric as written: group-level Medium+ F1 0.50; it does not beat the simple event-level baselines. See `results/FINDINGS.md` |
| Cloud component (AWS) | Planned, see `docs/aws-deployment.md` |
| Known gaps | Parent/child process lineage is not used; lone unprivileged port scans score Low |

Numbers from `data/sample` only show the pipeline runs; do not quote them. Real-BETH results are in `results/`, and the dashboard shows them.

See [docs/course-checklist.md](docs/course-checklist.md) for deliverables and [CONTRIBUTING.md](CONTRIBUTING.md) for the team workflow.
