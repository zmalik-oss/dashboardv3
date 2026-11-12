"""Sweep baseline.routine_min_count using ONLY the attack-free validation split."""
import sys

from triage.baseline import fit_baseline
from triage.config import load_rules
from triage.features import add_event_features
from triage.loader import load_beth
from triage.scoring import score_events

d, rules_path = sys.argv[1], sys.argv[2]
rules = load_rules(rules_path)
train = add_event_features(load_beth(f"{d}/labelled_training_data.csv"), rules)
val = add_event_features(load_beth(f"{d}/labelled_validation_data.csv"), rules)
bl = fit_baseline(train)

print(f"{'routine_min':>11} {'groups':>7} {'Medium+':>8} {'High':>5} {'grp %':>7} {'evt %':>7}")
for n in (1, 2, 3, 5, 10, 20, 50):
    rules["baseline"]["routine_min_count"] = n
    g, e = score_events(val, bl, rules)
    mp = int((g["score"] >= 40).sum())
    hi = int((g["score"] >= 70).sum())
    print(f"{n:>11} {len(g):>7} {mp:>8} {hi:>5} {100*mp/len(g):>6.2f}% {100*(e['score']>=40).mean():>6.2f}%")
