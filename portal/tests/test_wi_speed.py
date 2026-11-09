"""Check what makes an item of a live migration faster without leaving out a check (2026-10-29: Nova needed 25-80 s per
instance, the portal's checks about 3 minutes): one SSH connection per node for the whole item, and the time of each
phase in the item's log.

Run from the portal folder:
    .venv/bin/python -m unittest tests.test_wi_speed -v
"""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "modules", "wi"))

from wi_analysis import wi_ops  # noqa: E402

SSH = wi_ops.SSH + ["tripleo-admin@192.168.253.27", "sudo -n sh -c 'virsh list'"]


class FakePool(wi_ops.SshPool):
    """SshPool with its ssh control commands answered here: master (bool) says whether a connection answers."""

    def __init__(self, opens=True):
        super().__init__()
        self.calls, self.master, self.opens = [], False, opens

    def _quiet(self, argv, timeout):
        self.calls.append(argv)
        if "-O" in argv:
            if argv[argv.index("-O") + 1] == "exit":
                self.master = False
            return 0 if self.master else 255
        if "ControlMaster=yes" in argv:
            self.master = self.opens
            return 0 if self.opens else 255
        return 0


class SshPoolTest(unittest.TestCase):
    def test_one_connection_per_node(self):
        pool = FakePool()
        first = pool.wrap(SSH)
        path = pool.paths["tripleo-admin@192.168.253.27"]
        self.assertTrue(path.startswith(pool.folder + "/"))
        # the command itself: the same options, target and command, over the node's connection only (never opens one)
        self.assertEqual(first, ["ssh"] + wi_ops.SSH[1:] + ["-o", "ControlMaster=no", "-o", f"ControlPath={path}"] + SSH[-2:])
        opened = [c for c in pool.calls if "ControlMaster=yes" in c]
        self.assertEqual(len(opened), 1)
        self.assertEqual(opened[0][-2:], ["tripleo-admin@192.168.253.27", "true"])   # opened apart, with a command of its own
        self.assertIn(f"ControlPersist={wi_ops.SshPool.PERSIST}", opened[0])
        self.assertTrue(set(wi_ops.SSH[1:]) <= set(opened[0]))                       # BatchMode, timeouts... kept
        pool.calls.clear()
        self.assertEqual(pool.wrap(SSH), first)
        self.assertEqual(len(pool.calls), 1)                                          # only the check: reused
        self.assertEqual(pool.calls[0][:4], ["ssh", "-S", path, "-O"])
        # another node: its own connection
        other = pool.wrap(wi_ops.SSH + ["tripleo-admin@192.168.253.29", "true"])
        self.assertNotEqual(pool.paths["tripleo-admin@192.168.253.29"], path)
        self.assertIn("ControlMaster=no", other)
        for p in pool.paths.values():
            open(p, "w").close()                      # what the masters leave: their sockets
        pool.close()
        self.assertEqual(len([c for c in pool.calls if c[-2:-1] == ["exit"]]), 2)
        self.assertFalse(os.path.exists(pool.folder))

    def test_without_a_connection_the_command_runs_as_before(self):
        pool = FakePool(opens=False)
        self.assertEqual(pool.wrap(SSH), SSH)
        tries = len(pool.calls)
        self.assertEqual(pool.wrap(SSH), SSH)              # not tried again: the node may be down
        self.assertEqual(len(pool.calls), tries)
        pool.close()
        # not an ssh to a node, or an ssh that already handles its connection: untouched
        pool = FakePool()
        for argv in (["openstack", "server", "show", "x"], ["ssh", "-S", "/tmp/x", "-O", "check", "a@b"], ["ssh", "host"]):
            self.assertEqual(pool.wrap(argv), argv)
        self.assertEqual(pool.calls, [])
        pool.close()

    def test_the_real_runner_uses_the_pool_and_the_fakes_do_not(self):
        seen = []
        saved = wi_ops.SSH_POOL
        try:
            wi_ops.SSH_POOL = type("P", (), {"wrap": staticmethod(lambda argv: seen.append(argv) or ["true"])})()
            rc, _ = wi_ops.Director._subprocess(SSH, 10)
            self.assertEqual((rc, seen), (0, [SSH]))
        finally:
            wi_ops.SSH_POOL = saved


class ReadAheadTest(unittest.TestCase):
    def test_reads_made_ahead_run_at_once_and_are_used_once(self):
        import threading
        import time
        busy, most, lock = [0], [0], threading.Lock()

        def runner(argv, timeout):   # every command takes 0.3 s; counts how many run at the same time
            with lock:
                busy[0] += 1
                most[0] = max(most[0], busy[0])
            time.sleep(0.3)
            with lock:
                busy[0] -= 1
            if "console" in argv:
                return 0, "line 1\nline 2"
            if "port" in argv:
                return 0, "[]"
            if argv[0] == "ssh":
                raise RuntimeError("no route")
            return 0, "[]"
        d = wi_ops.Director(runner=runner, write=lambda line: None, parallel=True)
        sid = "5e5e5e5e-0000-4000-8000-000000000001"
        start = time.time()
        d.prefetch(("console_log", sid), ("port_states", sid), ("computes",), ("vendor", "192.168.253.27", "heat-admin"))
        self.assertEqual(d.console_log(sid), ["line 1", "line 2"])
        d.port_states(sid)
        d.computes()
        with self.assertRaises(RuntimeError):            # an error of a read made ahead comes where its result is used
            d.vendor("192.168.253.27", "heat-admin")
        self.assertLess(time.time() - start, 0.9)          # 4 reads of 0.3 s: at once, not 1.2 s
        self.assertGreaterEqual(most[0], 3)
        self.assertEqual(d._ahead, {})
        start = time.time()
        d.console_log(sid)                                 # the next call reads again
        self.assertGreaterEqual(time.time() - start, 0.3)

    def test_without_threads_the_reads_are_made_in_order_when_asked(self):
        seen = []
        d = wi_ops.Director(runner=lambda argv, t: seen.append(argv[0]) or (0, "[]"), write=lambda line: None)
        self.assertFalse(d.parallel)                       # a test's runner: one after the other
        d.prefetch(("computes",), ("port_states", "x"))
        self.assertEqual(len(seen), 2)
        d.computes()
        d.port_states("x")
        self.assertEqual(len(seen), 2)                     # used, not read again


class TimingTest(unittest.TestCase):
    def test_the_phases_of_an_item(self):
        now = [1000.0]
        log = []
        d = wi_ops.Director(runner=lambda argv, t: (0, ""), clock=lambda: now[0], write=log.append)
        self.assertEqual(d.timing(), "")              # no migration: no line
        now[0] += 95
        d.mark("migration")
        now[0] += 20
        d.mark("migration")                           # a second attempt: still the migration
        now[0] += 21
        d.mark("checks after")
        now[0] += 63
        self.assertEqual(d.timing(), "Time: checks before 1 min 35 s, migration 41 s, checks after 1 min 3 s (in all 3 min 19 s)")


if __name__ == "__main__":
    unittest.main()
