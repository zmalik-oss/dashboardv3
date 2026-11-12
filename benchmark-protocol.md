# Benchmark protocol

## Why the splits are used this way

In the Kaggle files, the training and validation splits contain no attacks (`evil` is 0 throughout); `evil` events appear only in the
test split, where they are 84% of events. That shapes the protocol.

| Split | Role | What we measure |
|---|---|---|
| Train | Fit the baseline (what is routine). No labels used. | Nothing |
| Validation | Attack-free, so every Medium/High alert is a false alarm. Tune `rules.yaml` here. | False-alarm rate |
| Test | Frozen settings, run once. | Precision, recall, F1 against `evil`; analyst workload |

Do not tune anything on test. If a result on test prompts a rule change, say so in the report and
re-validate; do not present the post-change number as a clean held-out result.

## Metrics

- **Detection vs. `evil`:** precision, recall, F1 at Medium+ (score >= 40) and High (>= 70), at the action-group level (a group is positive if any event is `evil`) and at the event level (each event inherits its group's tier).
- **Workload:** share of groups auto-logged (Low) and share needing review. This is the framework's stated goal.
- **False alarms:** Medium+ and High alert rates on validation.
- **Label disagreements:** groups labeled malicious but scored Low, and groups scored High but labeled benign. These are written to `artifacts/review_queue.csv`. Read them by hand and pick a few to discuss in the report; the sshd case is the model.

## Baselines

1. **`sus` flag:** predict `evil` whenever `sus` is set. Shows what the dataset's own flag buys you.
2. **Isolation Forest:** unsupervised, single-event features, fit on train. Its alert threshold is set so its alert rate on validation equals the framework's, so both methods spend the same false-alarm budget.

If the framework does not beat these, report that honestly and use the review queue to explain why.

## Reporting rules

- Report test numbers from one frozen run, with the `rules.yaml` version (git commit hash) that produced them.
- Never report numbers from `data/sample`. Those prove the pipeline runs and nothing else.
- State the limits: one test host, honeypot traffic, and rules written by the team (so some tuning to this data is unavoidable).

## Run log (real BETH)

Numbers are in `results/FINDINGS.md`. The first run used `routine_min_count: 50` and gave 6.1% false alarms on validation.
The threshold was then set to 10 using validation only (largest value under a 2% false-alarm target) and the test split was
scored with that setting. The first run's test results had already been seen, so the headline is lightly exposed. Changes
motivated by test-set error analysis (the optional network-burst indicator and the proposed rule fixes) are labeled post-hoc
and are not part of the headline.
