import pandas as pd
import pytest

from triage.baseline import fit_baseline
from triage.config import load_rules
from triage.features import PathClassifier, add_event_features
from triage.grouping import assign_groups
from triage.loader import prepare_frame
from triage.sample_data import make_splits
from triage.scoring import score_events, tier_for


@pytest.fixture(scope="module")
def rules():
    return load_rules()


@pytest.fixture(scope="module")
def scored(rules):
    train, val, test = make_splits(seed=7)
    ft = add_event_features(prepare_frame(train), rules)
    fte = add_event_features(prepare_frame(test), rules)
    bl = fit_baseline(ft)
    groups, events = score_events(fte, bl, rules)
    return groups, events, bl, fte


def _by_proc(groups, name):
    return groups[groups["processName"] == name]


# ---- tiers -----------------------------------------------------------------
@pytest.mark.parametrize("score,tier", [(0, "low"), (39, "low"), (40, "medium"),
                                        (69, "medium"), (70, "high"), (100, "high")])
def test_tier_boundaries(score, tier):
    assert tier_for(score) == tier


# ---- grouping --------------------------------------------------------------
def test_grouping_gap_and_process_split():
    df = pd.DataFrame({
        "hostName": ["h"] * 5, "processId": [1, 1, 1, 2, 2],
        "timestamp": [0.0, 1.0, 20.0, 21.0, 22.0], "row_id": range(5)})
    g = assign_groups(df, gap_seconds=5.0)
    assert g["group_id"].tolist() == [0, 0, 1, 2, 2]


# ---- path handling ---------------------------------------------------------
def test_path_classification_and_write_flags(rules):
    pc = PathClassifier(rules)
    args = repr([{"name": "pathname", "type": "const char*", "value": "/etc/shadow"},
                 {"name": "flags", "type": "int", "value": "O_WRONLY|O_APPEND"}])
    path, tier, entry, is_write, in_ww = pc.info(args)
    assert (path, tier, entry, is_write, in_ww) == ("/etc/shadow", "critical", "/etc/shadow", True, False)
    assert pc.info(repr([{"name": "pathname", "type": "x", "value": "/etc/ld.so.cache"}]))[1] == "routine"
    assert pc.info(repr([{"name": "pathname", "type": "x", "value": "/tmp/a"}]))[4] is True
    assert pc.info("not python")[1] == "none"  # malformed args must not crash


# ---- rubric behaviour on the sample scenarios -------------------------------
def test_benign_sshd_cleanup_scores_low(scored):
    g = _by_proc(scored[0], "sshd")
    cleanup = g[(g["evil_any"] == 0) & (g["n_events"] == 5)]
    assert len(cleanup) > 0
    assert (cleanup["tier"] == "low").all()


def test_privilege_escalation_chain_is_high_with_full_marks(scored):
    g = _by_proc(scored[0], "exploit")
    assert len(g) == 6
    assert (g["tier"] == "high").all()
    assert (g["score"] == 100).all()
    assert {"log_tampering", "credential_file_modified", "exec_from_writable_dir"} <= set(g.iloc[0]["indicators"])


def test_failed_escalation_is_medium_not_high(scored):
    g = _by_proc(scored[0], "pwn")
    assert (g["tier"] == "medium").all()
    assert (g["behavior"] == 20).all()          # attempted, not successful (rubric: 20 not 30)


def test_rootkit_loader_reaches_high(scored):
    assert (_by_proc(scored[0], "rkload")["tier"] == "high").all()


def test_lone_port_scan_stays_low_known_gap(scored):
    # Documents a limitation: unprivileged failed connects alone do not reach Medium.
    assert (_by_proc(scored[0], "portscan")["tier"] == "low").all()


def test_routine_root_activity_is_not_flagged(scored):
    g = scored[0]
    for name in ("rsyslogd", "cron", "sudo", "nginx"):
        sub = _by_proc(g, name)
        assert len(sub) and (sub["tier"] == "low").all(), name


# ---- the invariant that keeps the benchmark honest --------------------------
def test_scores_do_not_depend_on_labels(rules, scored):
    groups, _, bl, fte = scored
    flipped = fte.copy()
    flipped["sus"] = 1 - flipped["sus"]
    flipped["evil"] = 1 - flipped["evil"]
    g2, _ = score_events(flipped, bl, rules)
    assert groups["score"].tolist() == g2["score"].tolist()
    assert groups["tier"].tolist() == g2["tier"].tolist()


def test_label_disagreements_are_surfaced(scored):
    groups = scored[0]
    low_but_evil = groups[groups["disagreement"] == "malicious_label_scored_low"]
    procs = set(low_but_evil["processName"])
    assert {"portscan", "sshd"} <= procs        # port scans + the rubric's sshd example
    assert (groups[groups["processId"] == 1407]["tier"] == "low").all()


# ---- optional network-burst indicator (off by default) -----------------------
def test_network_burst_is_off_by_default_and_opt_in(rules, scored):
    groups, _, bl, fte = scored
    assert rules["ioc"].get("network_burst_min_failures") is None
    assert (_by_proc(groups, "portscan")["tier"] == "low").all()

    import copy
    on = copy.deepcopy(rules)
    on["ioc"]["network_burst_min_failures"] = 10      # the sample scanner makes exactly 10 failed connects
    g2, _ = score_events(fte, bl, on)
    scan = _by_proc(g2, "portscan")
    assert (scan["tier"] == "medium").all()
    assert all("network_failure_burst" in i for i in scan["indicators"])
    # everything else is untouched by switching it on
    other = g2["processName"] != "portscan"
    assert g2.loc[other, "score"].tolist() == groups.loc[other, "score"].tolist()


def test_ml_features_exclude_labels_and_process_names():
    from triage.ml import FEATURES, FEATURES_HYBRID
    banned = {"sus", "evil", "evil_any", "sus_any", "processName", "hostName", "processId"}
    assert not banned & set(FEATURES_HYBRID)
