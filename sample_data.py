"""Synthetic, BETH-shaped sample data for tests and demos.

NOT real BETH data. Benign templates are repeated enough that the baseline learns them;
the test split adds a few labelled attack scenarios plus two deliberately "wrong" labels
(a benign sshd cleanup marked evil, and a port scan the rules should miss) so the
review-queue workflow has something to show.
"""
from __future__ import annotations

import random
import zlib

import pandas as pd

COLUMNS = ["timestamp", "processId", "threadId", "parentProcessId", "userId", "mountNamespace",
           "processName", "hostName", "eventId", "eventName", "stackAddresses", "argsNum",
           "returnValue", "args", "sus", "evil"]


def _arg(name, typ, value):
    return {"name": name, "type": typ, "value": value}


def _path(p):
    return _arg("pathname", "const char*", p)


class _Gen:
    def __init__(self, seed, host_prefix="ip-10-100-1-"):
        self.rng = random.Random(seed)
        self.rows = []
        self.t = 100.0
        self.pid = 2000
        self.hp = host_prefix

    def _emit(self, host, pid, ppid, uid, proc, events, sus=0, evil=0):
        """events: (name, returnValue, args[, uid_override]); one call = one action group."""
        t = self.t
        for ev in events:
            name, ret, args, *rest = ev
            u = rest[0] if rest else uid
            t += self.rng.uniform(0.001, 0.02)
            self.rows.append({
                "timestamp": round(t, 6), "processId": pid, "threadId": pid, "parentProcessId": ppid,
                "userId": u, "mountNamespace": 4026531840, "processName": proc, "hostName": host,
                "eventId": zlib.crc32(name.encode()) % 400, "eventName": name, "stackAddresses": "[1401]",
                "argsNum": len(args), "returnValue": ret, "args": repr(args), "sus": sus, "evil": evil})
        self.t = t + self.rng.uniform(8, 40)   # always larger than the grouping gap between groups

    def host(self):
        return f"{self.hp}{self.rng.randint(1, 4)}"

    def next_pid(self):
        self.pid += self.rng.randint(1, 9)
        return self.pid

    # ---- benign templates -------------------------------------------------
    def sshd_cleanup(self, pid=None, sus=0, evil=0):
        pid = pid or self.next_pid()
        sock = f"/tmp/ssh-XXXX/agent.{pid}"
        self._emit(self.host(), pid, 1326, 0, "sshd", [
            ("close", 0, [_arg("fd", "int", 10)]),
            ("security_inode_unlink", 0, [_path(sock)]),
            ("unlink", 0, [_path(sock)]),
            ("close", 0, [_arg("fd", "int", 4)]),
            ("sched_process_exit", 0, [])], sus, evil)

    def sshd_auth(self):
        pid = self.next_pid()
        self._emit(self.host(), pid, 1, 0, "sshd", [
            ("security_file_open", 0, [_path("/etc/ssh/sshd_config"), _arg("flags", "int", "O_RDONLY")]),
            ("security_file_open", 0, [_path("/etc/shadow"), _arg("flags", "int", "O_RDONLY")]),
            ("close", 0, [_arg("fd", "int", 5)])])

    def bash_ls(self):
        pid = self.next_pid()
        self._emit(self.host(), pid, 1400, 1000, "bash", [
            ("execve", 0, [_path("/bin/ls")]),
            ("openat", 3, [_path("/etc/ld.so.cache"), _arg("flags", "int", "O_RDONLY")]),
            ("getdents64", 0, [_arg("fd", "int", 3)]),
            ("close", 0, [_arg("fd", "int", 3)])])

    def sudo(self):
        pid = self.next_pid()
        self._emit(self.host(), pid, 1400, 1000, "sudo", [
            ("security_file_open", 0, [_path("/etc/sudoers"), _arg("flags", "int", "O_RDONLY")]),
            ("setuid", 0, [_arg("uid", "uid_t", 0)], 0),
            ("execve", 0, [_path("/usr/bin/apt")], 0)])

    def rsyslog(self):
        pid = self.next_pid()
        self._emit(self.host(), pid, 1, 0, "rsyslogd", [
            ("openat", 4, [_path("/var/log/syslog"), _arg("flags", "int", "O_WRONLY|O_APPEND")]),
            ("close", 0, [_arg("fd", "int", 4)])])

    def cron(self):
        pid = self.next_pid()
        self._emit(self.host(), pid, 1, 0, "cron", [
            ("openat", 5, [_path("/etc/crontab"), _arg("flags", "int", "O_RDONLY")]),
            ("execve", 0, [_path("/usr/sbin/cron")])])

    def webserver(self):
        pid = self.next_pid()
        self._emit(self.host(), pid, 1, 33, "nginx", [
            ("bind", 0, [_arg("fd", "int", 6)]), ("listen", 0, [_arg("fd", "int", 6)]),
            ("accept", 7, [_arg("fd", "int", 6)])])

    def vim_passwd(self):
        pid = self.next_pid()
        self._emit(self.host(), pid, 1400, 1000, "vim", [
            ("security_file_open", 0, [_path("/etc/passwd"), _arg("flags", "int", "O_RDONLY")])])

    def backup_root(self):
        pid = self.next_pid()
        self._emit(self.host(), pid, 1, 0, "backupd", [
            ("security_file_open", 0, [_path("/etc/shadow"), _arg("flags", "int", "O_RDONLY")])])

    # ---- attack scenarios (evil=1) ---------------------------------------
    def attack_priv_esc(self):
        pid = self.next_pid()
        self._emit(self.host(), pid, 1500, 1001, "exploit", [
            ("execve", 0, [_path("/tmp/.x/exploit")]),
            ("setuid", 0, [_arg("uid", "uid_t", 0)], 0),
            ("security_file_open", 0, [_path("/etc/shadow"), _arg("flags", "int", "O_RDONLY")], 0),
            ("openat", 3, [_path("/root/.ssh/authorized_keys"), _arg("flags", "int", "O_WRONLY|O_APPEND")], 0),
            ("unlink", 0, [_path("/var/log/auth.log")], 0)], 1, 1)

    def attack_failed_priv(self):
        pid = self.next_pid()
        self._emit(self.host(), pid, 1500, 1001, "pwn", [
            ("setuid", -1, [_arg("uid", "uid_t", 0)]), ("setuid", -1, [_arg("uid", "uid_t", 0)]),
            ("setuid", -1, [_arg("uid", "uid_t", 0)]),
            ("openat", -13, [_path("/etc/shadow"), _arg("flags", "int", "O_RDONLY")])], 1, 1)

    def attack_portscan(self):
        pid = self.next_pid()
        self._emit(self.host(), pid, 1500, 1000, "portscan",
                   [("connect", -111, [_arg("fd", "int", 3)]) for _ in range(10)], 1, 1)

    def attack_rootkit(self):
        pid = self.next_pid()
        self._emit(self.host(), pid, 1500, 0, "rkload", [
            ("execve", 0, [_path("/tmp/rk")]),
            ("init_module", 0, [_arg("module_image", "void*", "0x0")]),
            ("openat", 3, [_path("/tmp/rk.ko"), _arg("flags", "int", "O_RDONLY")])], 1, 1)


def _df(g):
    return pd.DataFrame(g.rows, columns=COLUMNS)


def make_splits(seed=7):
    """Return (train, validation, test) DataFrames shaped like labelled_*.csv."""
    benign = [("sshd_cleanup", 140), ("sshd_auth", 120), ("bash_ls", 160), ("sudo", 110),
              ("rsyslog", 130), ("cron", 90), ("webserver", 90)]

    def benign_block(g, scale):
        order = [name for name, n in benign for _ in range(int(n * scale))]
        g.rng.shuffle(order)
        for name in order:
            getattr(g, name)()

    # train
    g = _Gen(seed)
    benign_block(g, 1.0)
    for _ in range(12):
        g.vim_passwd()
    train = _df(g)

    # validation: benign only (like BETH validation, which has no attacks)
    g = _Gen(seed + 1)
    benign_block(g, 0.4)
    for _ in range(3):
        g.vim_passwd()
    g.backup_root()
    val = _df(g)

    # test: benign + labelled attacks + the two "interesting" labels
    g = _Gen(seed + 2)
    benign_block(g, 0.4)
    for _ in range(3):
        g.vim_passwd()
    g.backup_root()
    for _ in range(6):
        g.attack_priv_esc()
    for _ in range(6):
        g.attack_failed_priv()
    for _ in range(6):
        g.attack_portscan()
    for _ in range(4):
        g.attack_rootkit()
    g.sshd_cleanup(pid=1407, sus=1, evil=1)   # the rubric's worked example: benign cleanup labelled evil
    test = _df(g)
    return train, val, test


def write_sample(out_dir, seed=7):
    import pathlib
    out = pathlib.Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    train, val, test = make_splits(seed)
    train.to_csv(out / "labelled_train.csv", index=False)
    val.to_csv(out / "labelled_validation.csv", index=False)
    test.to_csv(out / "labelled_test.csv", index=False)
    return len(train), len(val), len(test)
