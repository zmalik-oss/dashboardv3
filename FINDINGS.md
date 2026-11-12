# Results on real BETH

Run on 2026-10-26 with the Kaggle BETH archive (`labelled_training_data.csv`, `labelled_validation_data.csv`,
`labelled_testing_data.csv`; the per-host raw files and DNS files in the archive were not used).
The shipped rubric, as written, did **not** beat the simple baselines on this benchmark. The reasons are
specific and fixable, and they are listed below as proposed changes for the team to approve.

## What the data looks like (measured)

| Split | Events | Hosts | `sus` events | `evil` events |
|---|---|---|---|---|
| Train | 763,144 | 8 | 1,269 | 0 |
| Validation | 188,967 | 4 | 786 | 0 |
| Test | 188,967 | 1 | 171,459 | 158,432 (83.8%) |

The test split is mostly attack. One process, `tsm`, accounts for 149,155 of its 188,967 events (79%), almost
all `connect` calls, and 78% of test events have a negative return value. Event-level metrics on this split
are therefore dominated by that one process. Group-level metrics (one row per process action) are a fairer view.

## Run history

How the rules got to the headline run, in order. Nothing here was tuned on the test split, but the first
run's test results were seen before the threshold was chosen, so treat the headline as lightly exposed.

| Run | Rules | Notes |
|---|---|---|
| v1 | Rules as first shipped (`routine_min_count: 50`), plus `fchmod`, `fchown`, `lchown` added as event names | First real run. 6.1% of attack-free validation groups reached Medium+ |
| **v1b (headline)** | `routine_min_count: 10` | Chosen as the largest value keeping validation Medium+ alerts under 2% of groups. Sweep: 50 gives 6.09%, 20 gives 2.43%, **10 gives 1.91%**, 5 gives 1.74%, 1 gives 1.22% (`scripts/sweep_routine_threshold.py`). Test run once with this setting |
| v2 (sensitivity, post-hoc) | v1b plus the optional network-burst indicator at 100 failed calls | Designed after seeing why `tsm` was missed, so it is not a clean held-out result. See below |

## Headline: rubric as written (v1b), test split

| Measure | Medium+ (score >= 40) | High (score >= 70) |
|---|---|---|
| Group-level precision | 0.650 (52 of 80 alerts) | 0.222 (2 of 9) |
| Group-level recall | 0.406 (52 of 128 evil groups) | 0.016 |
| Group-level F1 | 0.500 | 0.029 |
| Event-level precision / recall / F1 | 0.728 / 0.284 / 0.408 | 0.873 / 0.259 / 0.400 |

| Event-level baseline | Precision | Recall | F1 |
|---|---|---|---|
| `sus` flag | 0.924 | 1.000 | 0.961 |
| Isolation Forest (alert budget matched to the rubric's validation false-alarm rate) | 0.991 | 0.936 | 0.963 |

Validation (attack-free) false alarms: 1.9% of groups and 0.27% of events reach Medium+; none reach High.
Workload on test: 178 of 258 groups (69%) auto-logged Low, 71 Medium, 9 High.
Label disagreements: 76 groups labeled malicious but scored Low, 7 labeled benign but scored High
(`results/real-beth-rubric-as-written/review_queue.csv`).

## Why it missed, and what to change

1. **Failed-connection floods score Low (the big one).** The 7 `tsm` groups that scored Low are thousands of
   `connect` calls returning -114/-115. Those are "already in progress" and "in progress" codes, which are normal for
   non-blocking sockets, and the pattern is consistent with a scanner or proxy tool. As written, the rubric tops out
   at 20 behavior points plus 10 supporting points (30) for repeated failed attempts by an unprivileged process.
   *Proposal:* add a burst indicator. In the attack-free train and validation data the largest burst of failed
   network calls in one action group is 16 (from `sshd`), so a threshold of 100 is well clear of normal.
   The code has this as an optional setting, off by default (`ioc.network_burst_min_failures`).
2. **`/etc/ld.so.preload` probes create false High alerts.** The 7 benign-labeled groups scored High are Ubuntu
   helper processes (names suggest apt and MOTD scripts: `apt-config`, `50-landscape-sy`, `hwe-support-sta`).
   Six of the seven (the `apt-config` and `50-landscape-sy` groups) call `access()` on `/etc/ld.so.preload`, which
   fails with -2 (file not found). The dynamic linker probes for that file at program start, so this is routine. *Proposal:* treat failed not-found (-2) lookups as non-suspicious,
   and keep `ld.so.preload` as critical only for modification.
3. **Treating -114/-115 as failures.** Same cause as item 1. *Proposal:* exclude in-progress codes from "failed".
4. **Attacker shell activity looks ordinary.** Many evil-labeled groups from `sh`, `sshd` and `bash` score about
   35 (just under Medium). Their individual events are routine. *Proposal:* use parent/child lineage, so a group whose
   parent is flagged inherits some suspicion (not implemented).
5. **High tier precision is low (2 of 9).** Mostly item 2. Revisit after that fix.

## Sensitivity run: optional burst rule on (v2, post-hoc)

| Measure | Rubric as written (v1b) | With burst rule (v2) |
|---|---|---|
| Group-level Medium+ precision / recall / F1 | 0.650 / 0.406 / 0.500 | 0.667 / 0.438 / 0.528 |
| Event-level Medium+ precision / recall / F1 | 0.728 / 0.284 / 0.408 | 0.901 / 0.967 / 0.933 |
| Validation false-alarm rate (groups / events) | 1.91% / 0.27% | 1.91% / 0.27% (unchanged) |

The event-level jump comes from one rule catching the `tsm` flood. It is still below the two event-level baselines
(0.96) and group-level recall barely moves, because most missed evil groups are small shell sessions (item 4).
Do not report v2 as a held-out result. If the team adopts the rule, say it was added after error analysis on test.

## Caveats for the report

- One test host, honeypot traffic, and an attack dominated by a single process.
- Baselines are event-level only; the rubric's natural unit is the action group, so compare like with like.
- `evil` is the dataset's label. The 83 disagreements deserve a manual read, and a few may be label noise.
- Rules were written by the team and tuned on one validation split, so some fit to this data is unavoidable.

## Machine-learning models (added after the rubric results; test split, action-group level)

Unsupervised models fit on attack-free training groups, each allowed the rubric's own validation false-alarm budget
(1.91% of groups). Process names are not features. Training-host features use a baseline fit on the other hosts.
Full tables: `results/ml-models-real-beth/report.md`. Run with `python -m triage benchmark --data-dir data/beth --ml`.

| Method | Precision | Recall | F1 | ROC AUC |
|---|---|---|---|---|
| Rubric score >= 40 | 0.650 | 0.406 | 0.500 | 0.732 |
| Isolation Forest, group features | 0.576 | 0.148 | 0.236 | 0.742 |
| Local Outlier Factor, group features | 0.500 | 0.023 | 0.045 | 0.444 |
| **Hybrid: Isolation Forest + rubric scores** | 0.739 | 0.531 | 0.618 | 0.763 |

What this does and does not show:
- The hybrid is the best of the four at the group level, but the gain over the rubric (F1 0.50 to 0.62, AUC 0.73 to 0.76) is
  modest and the test split has only 258 groups, so it should be called promising, not proven.
- Behavior features alone do not beat the rubric. Local Outlier Factor does worse than chance (AUC 0.44) on this data.
- Event-level scores (hybrid 0.94) are dominated by the single `tsm` process and are not a fair headline.
- Nothing here was tuned on test, but all of it was designed after seeing the rubric's test results.
