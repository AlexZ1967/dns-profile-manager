"""Terminal progress gauge is driven by worker output without running dialog."""
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import dns_menu


class FakePipe:
    def __init__(self):
        self.parts = []
        self.closed = False

    def write(self, value):
        self.parts.append(value)

    def flush(self):
        pass

    def close(self):
        self.closed = True

    def getvalue(self):
        return ''.join(self.parts)


class FakeGauge:
    def __init__(self, *_args, **_kwargs):
        self.stdin = FakePipe()
        self.returncode = 0
        self.waited = False

    def wait(self):
        self.waited = True
        return self.returncode


class InlineWorker:
    def __init__(self, target, daemon):
        self.target = target
        self.alive = False
        self.polls = 0
        self.joined = []
        self.daemon = daemon

    def start(self):
        self.target()
        self.alive = True

    def is_alive(self):
        self.polls += 1
        if self.polls > 1:
            self.alive = False
        return self.alive

    def join(self, timeout=None):
        self.joined.append(timeout)


class TerminalGaugeTests(unittest.TestCase):
    def test_task_shows_progress_and_preserves_report(self):
        gauge = FakeGauge()
        reports = []
        with patch.object(dns_menu.subprocess, 'Popen', return_value=gauge) as popen, \
             patch.object(dns_menu.threading, 'Thread', InlineWorker), \
             patch.object(dns_menu, 'report', side_effect=lambda title, body: reports.append((title, body))):
            dns_menu.task('Проверка', lambda emit: emit('Проверено MagicDNS'))

        args, kwargs = popen.call_args
        self.assertEqual(args[0][1:3], ['--title', 'Проверка'])
        self.assertIn('--gauge', args[0])
        self.assertIn('stdin', kwargs)
        self.assertTrue(gauge.waited)
        self.assertIn('XXX\n0\nПроверено MagicDNS\nXXX\n', gauge.stdin.getvalue())
        self.assertEqual(reports, [('Проверка', 'Проверено MagicDNS')])

    def test_worker_error_is_reported_and_gauge_still_closes(self):
        gauge = FakeGauge()
        reports = []

        def fail(_emit):
            raise RuntimeError('fixture failure')

        with patch.object(dns_menu.subprocess, 'Popen', return_value=gauge), \
             patch.object(dns_menu.threading, 'Thread', InlineWorker), \
             patch.object(dns_menu, 'report', side_effect=lambda title, body: reports.append((title, body))):
            dns_menu.task('Операция', fail)

        self.assertTrue(gauge.waited)
        self.assertEqual(reports, [('Операция', 'Ошибка: fixture failure')])


if __name__ == '__main__':
    unittest.main()
