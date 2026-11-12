# Benchmark report

Splits: train=`labelled_training_data.csv`, validation=`labelled_validation_data.csv`, test=`labelled_testing_data.csv`.

## Test split: detection vs. the `evil` label

| Method | Level | Precision | Recall | F1 | Alerts | TP | FP | FN |
|---|---|---|---|---|---|---|---|---|
| Rubric score >= 40 (Medium+) | action group | 0.667 | 0.438 | 0.528 | 84 | 56 | 28 | 72 |
| Rubric score >= 70 (High) | action group | 0.222 | 0.016 | 0.029 | 9 | 2 | 7 | 126 |
| Rubric score >= 40 (Medium+) | event | 0.901 | 0.967 | 0.933 | 169939 | 153183 | 16756 | 5249 |
| Rubric score >= 70 (High) | event | 0.873 | 0.259 | 0.400 | 47070 | 41100 | 5970 | 117332 |
| Baseline: `sus` flag | event | 0.924 | 1.000 | 0.961 | 171459 | 158432 | 13027 | 0 |
| Baseline: Isolation Forest (matched alert budget) | event | 0.991 | 0.936 | 0.963 | 149581 | 148274 | 1307 | 10158 |

## Analyst workload (test split)

- Action groups: 258 (188,967 events)
- Auto-logged (Low): 174 (67.4%)
- Flagged (Medium): 75   High-priority: 9
- Groups needing human review: 84 (32.6% of all groups)

## False-alarm check (validation split, no attacks)

- Groups: 575
- Medium+ alert rate: 1.913% of groups, 0.269% of events
- High alert rate: 0.000% of groups

## Disagreements with the dataset labels (test)

- Labeled malicious but scored Low: 72
- Labeled benign but scored High: 7

These go to `review_queue.csv` for manual analysis. Each is either a scoring miss or a label that deserves a second look; the report should discuss specific cases.

## Threshold sweep (test, informational only; thresholds stay at 40/70)

| Threshold | Alert rate | Precision | Recall | F1 |
|---|---|---|---|---|
| 0 | 100.000% | 0.496 | 1.000 | 0.663 |
| 5 | 82.171% | 0.557 | 0.922 | 0.694 |
| 10 | 80.233% | 0.570 | 0.922 | 0.705 |
| 15 | 63.566% | 0.713 | 0.914 | 0.801 |
| 20 | 63.566% | 0.713 | 0.914 | 0.801 |
| 25 | 63.566% | 0.713 | 0.914 | 0.801 |
| 30 | 62.791% | 0.722 | 0.914 | 0.807 |
| 35 | 38.760% | 0.720 | 0.562 | 0.632 |
| 40 | 32.558% | 0.667 | 0.438 | 0.528 |
| 45 | 16.667% | 0.581 | 0.195 | 0.292 |
| 50 | 10.853% | 0.393 | 0.086 | 0.141 |
| 55 | 6.589% | 0.176 | 0.023 | 0.041 |
| 60 | 5.814% | 0.200 | 0.023 | 0.042 |
| 65 | 3.876% | 0.200 | 0.016 | 0.029 |
| 70 | 3.488% | 0.222 | 0.016 | 0.029 |
| 75 | 3.101% | 0.125 | 0.008 | 0.015 |
| 80 | 0.388% | 0.000 | 0.000 | 0.000 |
| 85 | 0.000% | 0.000 | 0.000 | 0.000 |
| 90 | 0.000% | 0.000 | 0.000 | 0.000 |
| 95 | 0.000% | 0.000 | 0.000 | 0.000 |
| 100 | 0.000% | 0.000 | 0.000 | 0.000 |
