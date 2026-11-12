# Rubric to rules

How each level in the team's framework is implemented. Code: `src/triage/scoring.py`. Settings: `config/rules.yaml`.

Terms: an **action group** is a set of events from one host and process, each within 5 seconds of the last.
**Routine** means the (process, event) or (process, file) pair appeared at least 10 times in the training
split (`baseline.routine_min_count`, tuned on validation; see `results/FINDINGS.md`). **Non-routine** is the opposite. **Failed** means `returnValue < 0`.

## Wording in the tool's output

The framework's top bands are named "Confirmed malicious". The tool cannot confirm intent, only that a high-risk
signature occurred, so its reason text says "high-risk indicator" instead (for example "High-risk indicator: modified
or deleted log files"). The scores and tiers are unchanged. The tables below keep the framework's original band names.

## Suspicious behavior (max 40)

| Pts | Rubric level | Rule in code |
|---|---|---|
| 40 | Confirmed malicious | At least one indicator of compromise (below) succeeded |
| 30 | Extremely suspicious | A non-routine *high-severity* call succeeded (privilege change, process control, system modification, file modification) |
| 20 | Suspicious | A non-routine high-severity call failed, or 3+ non-routine medium-severity calls failed (execution, network) |
| 10 | Unusual | Non-routine execution/network call, or unexpected access to a sensitive file |
| 0 | Normal | None of the above |

Indicators of compromise (never read the labels): executing a file from `/tmp`, `/var/tmp` or `/dev/shm`
when that process does not normally; modifying or deleting `/var/log/` files; modifying credential or SSH
config files (`/etc/shadow`, `/etc/passwd`, `/etc/sudoers`, `authorized_keys`, `sshd_config`,
`ld.so.preload`); loading a kernel module; unexpected escalation to root.

## Elevated privilege and misuse (max 20)

| Pts | Rubric level | Rule |
|---|---|---|
| 20 | Confirmed malicious use | Unexpected escalation to root **and** at least one indicator of compromise |
| 15 | Suspicious use | Non-routine privilege-changing call (success or failure), or unexpected escalation (uid non-zero to 0 in one process) |
| 10 | Unusual use | Root, but the process is root in under 5% of baseline events |
| 5 | Elevated, unclear | Root, and the process has no baseline |
| 0 | Normal | Root use matches baseline, or not root |

## Access to sensitive resources (max 20)

| Pts | Rubric level | Rule |
|---|---|---|
| 20 | Critical resource compromised | Successful, unexpected write/unlink/rename/chmod on a critical path |
| 15 | Suspicious sensitive access | Unexpected access (or failed attempt) on a critical or sensitive path |
| 10 | Sensitive access, no anomaly | Critical or sensitive path accessed, consistent with baseline |
| 5 | Low-sensitivity access | `/tmp`, `/var/tmp`, `/dev/shm`, `/home` |
| 0 | Normal | No sensitive paths, or only routine ones (`ld.so.cache`, `/etc/ssl/`, ...) |

Path tiers and the write-flag markers are in `rules.yaml`.

## Supporting evidence (max 20)

Count distinct indicators in the group: failed attempt, unexpected success, unexpected sensitive access,
privilege anomaly, each indicator of compromise, escalation, and "rare process doing something risky".

| Pts | Rubric level | Rule |
|---|---|---|
| 20 | Confirmed malicious | 2+ independent indicators of compromise |
| 15 | Strong | 4+ distinct indicators |
| 10 | Moderate | 3 distinct indicators, or 3+ repeated failed attempts |
| 5 | Limited | 2 distinct indicators |
| 0 | None | 0 or 1 |

## Decisions the team should confirm

These were judgment calls made while turning the rubric into code. Check them with Iman before the
report calls them final.

1. **Labels as input.** The rubric says not to rely *solely* on `sus`/`evil`. We use them for no scoring at all, so the benchmark is not circular. If the team wants them as one weak input, the benchmark must change (hold them out of the evaluation).
2. **The sshd example.** The rubric says to flag it for human review. Our scorer gives it Low, and the dashboard's "label disagreements" tab puts it in front of a human. Decide whether that satisfies the intent.
3. **Defining "normal".** Routine = 10+ occurrences in training. This is the main tuning knob (`baseline.routine_min_count`); too low hides attacks, too high floods analysts. On real BETH, 50 gave 6.1% false alarms on attack-free validation groups and 10 gave 1.9%.
4. **BETH `eventName` coverage.** The syscall lists were written from general knowledge of Linux and eBPF tracing, not from the data. Run `describe` on real BETH and update `risky_syscalls` and `path_events`.
5. **Process-name trust.** An attacker who names a binary `sshd` inherits sshd's baseline. Worth a sentence in the report's limitations.
6. **Not implemented:** parent/child lineage (a child of a flagged process is not boosted) and time-of-day features.
7. **Optional network-burst indicator (off by default).** On real BETH the rubric as written rates a flood of failed connections as Low. `ioc.network_burst_min_failures` adds a burst indicator; it is not part of the written rubric, so turning it on needs the team's approval (and Iman's).
8. **Rule fixes found by error analysis on test** (not yet applied): treat not-found (-2) lookups, such as the dynamic linker probing `/etc/ld.so.preload`, as non-suspicious, and exclude in-progress (-114/-115) connect codes from "failed". Details in `results/FINDINGS.md`.
