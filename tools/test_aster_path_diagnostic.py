#!/usr/bin/env python3
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
import unittest
import sys
import argparse
from pathlib import Path
import tempfile
from unittest.mock import patch
import aster_path_diagnostic as diagnostic


class OracleTests(unittest.TestCase):
    def test_image_cannot_become_a_docker_option(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(diagnostic.ExecutionError):
                diagnostic.OwnedDocker('docker', Path(directory), lambda *_: b'', image='--privileged')

    def test_completed_delivery_after_deadline_is_failure(self):
        event = {'id': 'a', 'logicalKey': 'aw==', 'payload': 'eA=='}
        with patch.object(diagnostic.time, 'monotonic', return_value=11):
            with self.assertRaises(TimeoutError):
                diagnostic.verify_events({'a': event}, {'a': event}, deadline=10)

    def test_proc_disappearance_during_shutdown_is_success(self):
        with patch.object(Path, 'read_text', side_effect=ProcessLookupError(3, 'No such process')):
            diagnostic.wait_stopped(123)

    def test_paced_workload_counts_rejection_and_unknown_failure(self):
        class Client:
            def publish(self, operation, key, payload, topic, scope):
                if key.endswith(b'000001'):
                    raise diagnostic.RpcError('local application request PublishEvent failed with HTTP 429')
                return {'id': key.decode()}

            def call(self, method, request):
                return {'deliveries': []}

        workload = diagnostic.Workload(Client(), 'sub', 'probe', 3, 20, 32)
        workload.publisher.join(5)
        result = workload.snapshot()
        workload.close()
        self.assertTrue(result['done'])
        self.assertEqual(len(result['accepted']), 2)
        self.assertEqual(len(result['rejected']), 1)
        self.assertEqual(result['errors'], [])

        class Failed(Client):
            def publish(self, *args):
                raise diagnostic.RpcError('unknown outcome')

        workload = diagnostic.Workload(Failed(), 'sub', 'probe', 1, 20, 32)
        workload.publisher.join(5)
        result = workload.snapshot()
        workload.close()
        self.assertEqual(result['errors'], ['unknown outcome'])
        self.assertEqual(result['accepted'], {})

    def test_explicit_image_does_not_change_default_smoke(self):
        calls = []

        def run(argv, timeout):
            calls.append(argv)
            path = Path(argv[argv.index('--cidfile') + 1])
            path.write_text('a' * 64)
            path.chmod(0o600)
            return b''

        with tempfile.TemporaryDirectory() as directory:
            owner = diagnostic.OwnedDocker('docker', Path(directory), run,
                                            image='aster-path-delivery:diagnostic-local')
            owner.create('wan', ['--network', 'none'], ['sleep', '10'])
            self.assertIn('aster-path-delivery:diagnostic-local', calls[-1])
        with tempfile.TemporaryDirectory() as directory:
            owner = diagnostic.OwnedDocker('docker', Path(directory), run)
            owner.create('wan', ['--network', 'none'], ['sleep', '10'])
            self.assertIn('aster-path-delivery:local', calls[-1])

    def test_exact_nonempty_delivery_required(self):
        event = {'id': 'a', 'logicalKey': 'aw==', 'payload': 'eA=='}
        for exact in (False, True):
            self.assertEqual(diagnostic.verify_events({'a': event}, {'a': event}, exact=exact), 1)
            for accepted, actual in [({}, {}), ({'a': event}, {}),
                                     ({'a': event}, {'a': dict(event, payload='eQ==')}),
                                     ({'a': event}, {'a': dict(event, logicalKey='eg==')})]:
                with self.subTest(exact=exact, accepted=accepted, actual=actual):
                    with self.assertRaises(ValueError):
                        diagnostic.verify_events(accepted, actual, exact=exact)

    def test_setup_failure_always_cleans_owned_resources(self):
        cleaned = []

        class Owned:
            def __init__(self, *_, **kwargs):
                pass

            def create(self, *_):
                raise ValueError('injected setup failure')

            def cleanup(self):
                cleaned.append(True)
                return []

        with tempfile.TemporaryDirectory() as directory:
            with patch.object(diagnostic, 'OwnedDocker', Owned):
                result = diagnostic.run_profile(argparse.Namespace(output=Path(directory)), 'baseline', {})
            self.assertEqual(result['status'], 'fail')
            self.assertEqual(result['error'], 'injected setup failure')
            self.assertEqual(cleaned, [True])
            self.assertEqual(result['cleanup_errors'], [])
            self.assertFalse(Path(result['ownership_directory']).exists())

    def test_receipt_write_failure_cannot_skip_cleanup(self):
        cleaned = []

        class Owned:
            def __init__(self, *_, **kwargs):
                pass

            def cleanup(self):
                cleaned.append(True)
                return []

        with tempfile.TemporaryDirectory() as directory:
            owned_path = Path(directory) / 'owned'
            owned_path.mkdir()
            with patch.object(diagnostic, 'OwnedDocker', Owned), \
                    patch.object(diagnostic.tempfile, 'mkdtemp', return_value=str(owned_path)), \
                    patch.object(Path, 'write_text', side_effect=PermissionError):
                with self.assertRaises(PermissionError):
                    diagnostic.run_profile(argparse.Namespace(output=Path(directory)), 'baseline', {})
            self.assertEqual(cleaned, [True])

    def test_worker_timeout_is_failure_and_reaped(self):
        worker = diagnostic.Worker([sys.executable, '-c', 'import time; time.sleep(30)'])
        try:
            with self.assertRaises(TimeoutError):
                worker.call('status', timeout=0.05)
        finally:
            worker.close()
        self.assertIsNotNone(worker.process.poll())

    def test_worker_eof_is_failure_and_reaped(self):
        worker = diagnostic.Worker([sys.executable, '-c', 'pass'])
        try:
            with self.assertRaises((ValueError, BrokenPipeError)):
                worker.call('status', timeout=1)
        finally:
            worker.close()
        self.assertIsNotNone(worker.process.poll())

    def test_query_exceeds_old_nine_page_limit(self):
        class Client:
            def call(self, method, request):
                marker = int(request['afterAcceptanceMarker'])
                return {'events': [{'id': str(marker)}], 'scannedThrough': str(marker + 1),
                        'hasMore': marker < 12}
        self.assertEqual(len(diagnostic.query_all(Client(), 20)), 13)
        with self.assertRaises(ValueError):
            diagnostic.query_all(Client(), 4)

    def test_netem_profiles_are_separate_and_bounded(self):
        self.assertNotIn('reorder', diagnostic.netem_args('impaired', 40, 5, 1, 100, 10))
        self.assertIn('reorder', diagnostic.netem_args('reorder', 40, 5, 1, 100, 10))
        self.assertEqual(diagnostic.netem_args('outage', 40, 5, 1, 100, 10), ['loss', '100%'])
        with self.assertRaises(ValueError):
            diagnostic.netem_args('invalid', 40, 5, 1, 100, 10)


class FinalizationTests(unittest.TestCase):
    """Real workload threads, with only Docker/IPC and the RPC peer replaced."""

    def run_profile(self, *, fail_ack=False, extra_event=False, shutdown_timeout=False):
        import json
        import os
        import threading

        events = {role: {'id': role,
                        'logicalKey': diagnostic.base64.b64encode((role + '-000000').encode()).decode(),
                        'payload': diagnostic.base64.b64encode(b'n').decode()}
                  for role in ('node-a', 'node-b')}
        ack_entered = threading.Event()
        release_ack = threading.Event()
        workers = []
        actions = []
        cleaned = []
        testcase = self

        class Client:
            def __init__(self, role):
                self.role = role
                self.polled = False

            def publish(self, operation, key, payload, topic, scope):
                if key.endswith(b'000001'):
                    raise diagnostic.RpcError('local application request PublishEvent failed with HTTP 429')
                return {'id': self.role}

            def call(self, method, request):
                if method == 'PollEvents':
                    if self.polled:
                        return {'deliveries': []}
                    self.polled = True
                    return {'deliveries': [{'event': event} for event in events.values()]}
                if method == 'AcknowledgeEvent' and self.role == 'node-a' and request['eventId'] == 'node-b':
                    ack_entered.set()
                    if not release_ack.wait(5):
                        raise TimeoutError('test acknowledgement release deadline')
                    if fail_ack:
                        raise ValueError('injected final acknowledgement failure')
                return {}

        class Worker:
            def __init__(self, argv):
                self.role = argv[argv.index('-i') + 1]
                self.workload = None
                workers.append(self)

            def call(self, action, **kwargs):
                actions.append((self.role, action))
                if action == 'start-workload':
                    self.workload = diagnostic.Workload(Client(self.role), 'sub', self.role, 2, 20, 1)
                    self.workload.publisher.join(5)
                elif action == 'progress':
                    testcase.assertTrue(ack_entered.wait(5))
                    assert self.workload is not None
                    return self.workload.snapshot()
                elif action in ('end-workload', 'stop'):
                    if action == 'end-workload' and self.role == 'node-a' and shutdown_timeout:
                        # Keep the real consumer blocked, but skip the ten-second join wait.
                        assert self.workload is not None
                        with patch.object(self.workload.consumer, 'join'):
                            self.workload.close()
                    # The final ack completes only AFTER drain has observed its delivery.
                    release_ack.set()
                    if self.workload:
                        self.workload.close()
                        if action == 'end-workload':
                            return self.workload.snapshot()
                    return {'stopped_pid': 123}
                elif action == 'query':
                    actual = dict(events)
                    if extra_event:
                        actual['unexpected'] = dict(events['node-a'], id='unexpected')

                    class QueryClient:
                        def call(self, method, request):
                            return {'events': list(actual.values()), 'hasMore': False}

                    return diagnostic.query_all(QueryClient(), kwargs['maximum'])
                return {}

            def close(self):
                release_ack.set()
                if self.workload:
                    self.workload.close()

        class Owned:
            def __init__(self, *args, **kwargs):
                pass

            def create(self, role, *args):
                return role

            def cleanup(self):
                cleaned.append(True)
                return []

        def command(argv, timeout):
            if 'inspect' in argv:
                return b'123'
            if any("os.stat('/target')" in arg for arg in argv):
                inode = os.stat('/proc/self/ns/net').st_ino
                return json.dumps([inode + 1, inode + 2]).encode()
            if 'sha256sum' in argv:
                return b'test-hash'
            if 'tc' in argv:
                return b'[]' if '-j' in argv else b'loss 100%'
            return b''

        with tempfile.TemporaryDirectory() as directory:
            config = argparse.Namespace(output=Path(directory), duration_seconds=1,
                events_per_second=2, payload_bytes=1, delay_ms=40, jitter_ms=5,
                loss_percent=1, rate_mbit=100, reorder_percent=10,
                restore_deadline_seconds=5, sample_seconds=5)
            with patch.object(diagnostic, 'OwnedDocker', Owned), \
                    patch.object(diagnostic, 'Worker', Worker), \
                    patch.object(diagnostic, '_pinned_docker', return_value=command):
                result = diagnostic.run_profile(config, 'baseline', {})
            self.assertEqual(json.loads((Path(directory) / 'baseline.json').read_text()), result)
        self.assertEqual(cleaned, [True])
        self.assertEqual(result['cleanup_errors'], [])
        self.assertFalse(Path(result['ownership_directory']).exists())
        for worker in workers:
            self.assertFalse(worker.workload.publisher.is_alive())
            self.assertFalse(worker.workload.consumer.is_alive())
        return result, actions

    def test_final_ack_failure_after_drain_prevents_peerless_success(self):
        result, actions = self.run_profile(fail_ack=True)
        self.assertEqual(result['status'], 'fail')
        self.assertIn('injected final acknowledgement failure', result['error'])
        self.assertIn('drain', [row['phase'] for row in result['phases']])
        self.assertNotIn('peerless', [action for _, action in actions])

    def test_peerless_extra_id_with_rejected_publications_fails(self):
        result, actions = self.run_profile(extra_event=True)
        self.assertEqual(result['status'], 'fail')
        self.assertIn('Event ID set mismatch', result['error'])
        self.assertIn('query', [action for _, action in actions])
        self.assertEqual([len(rows) for rows in result['rejected'].values()], [1, 1])

    def test_pending_ack_shutdown_timeout_prevents_peerless_success(self):
        result, actions = self.run_profile(shutdown_timeout=True)
        self.assertEqual(result['status'], 'fail')
        self.assertIn('workload thread shutdown deadline', result['error'])
        self.assertNotIn('peerless', [action for _, action in actions])

    def test_successful_final_ack_and_exact_peerless_inventory_pass(self):
        result, actions = self.run_profile()
        self.assertEqual(result['status'], 'pass')
        self.assertEqual([row['exact_events'] for row in result['peerless'].values()], [2, 2])


class WorkflowTests(unittest.TestCase):
    """Dependency-free checks for the deliberately fixed manual launch."""

    @classmethod
    def setUpClass(cls):
        import re
        cls.workflow = (Path(__file__).resolve().parents[1] /
                        '.github/workflows/diagnostic-runtime-volume.yml').read_text()
        cls.scripts = re.findall(r'        run: \|\n((?:          .*\n|\n)+)', cls.workflow)
        cls.scripts = ['\n'.join(line[10:] for line in block.splitlines())
                       for block in cls.scripts]

    def test_manual_read_only_pinned_and_always_retained(self):
        import re
        text = self.workflow
        self.assertIn('on:\n  workflow_dispatch:\n\npermissions:\n  contents: read\n', text)
        self.assertIn('persist-credentials: false', text)
        self.assertIn('timeout-minutes: 90', text)
        self.assertIn('if: ${{ always() }}', text)
        self.assertIn('path: artifacts/path-diagnostic/', text)
        self.assertIn('retention-days: 14', text)
        self.assertEqual(len(re.findall(r'uses: [\w/-]+@[0-9a-f]{40} ', text)), 2)
        for forbidden in ('pull_request:', 'push:', 'inputs:', 'sudo ', '--privileged',
                          '--network=host', 'docker system prune', 'continue-on-error:'):
            self.assertNotIn(forbidden, text)

    def test_shell_syntax_and_canonical_build(self):
        import subprocess
        self.assertEqual(len(self.scripts), 3)
        for script in self.scripts:
            subprocess.run(['bash', '-n'], input=script, text=True, check=True)
            self.assertNotIn('${{', script)
        self.assertIn('--file docker/path-lab/Dockerfile.delivery', self.scripts[1])
        self.assertIn('--tag aster-path-delivery:local .', self.scripts[1])
        self.assertIn('timeout --signal=TERM --kill-after=300s 50m', self.scripts[2])
        self.assertIn('2>&1 | tee artifacts/path-diagnostic/controller.log', self.scripts[2])

    def test_preflight_failure_survives_log_pipeline(self):
        import subprocess
        with tempfile.TemporaryDirectory() as directory:
            # A failing first command must not be hidden by later checks or tee.
            result = subprocess.run(
                ['bash', '-e', '-o', 'pipefail', '-c',
                 'git() { return 23; };\n' + self.scripts[0]],
                cwd=directory, capture_output=True, text=True)
            self.assertEqual(result.returncode, 23)
            self.assertTrue((Path(directory) / 'artifacts/path-diagnostic/preflight.log').is_file())

    def test_launch_arguments_use_actual_cli_defaults(self):
        import shlex
        script = self.scripts[2].replace('\\\n', '')
        argv = shlex.split(script)
        start = argv.index('tools/aster_path_diagnostic.py')
        argv = argv[start:argv.index('2>&1')]
        self.assertEqual(argv[1:], ['--output', 'artifacts/path-diagnostic'])
        configurations = []

        def profile(config, name, row):
            configurations.append((name, config))
            row.update(status='pass')

        with tempfile.TemporaryDirectory() as directory:
            argv[-1] = directory
            with patch.object(sys, 'argv', argv), \
                    patch.object(diagnostic, 'run_profile', side_effect=profile), \
                    patch.object(diagnostic, '_run_command', return_value=b'test-source'), \
                    patch.object(diagnostic, '_pinned_docker', return_value=lambda *_: b'test-image'), \
                    patch.object(diagnostic.signal, 'signal'):
                self.assertEqual(diagnostic.main(), 0)
        self.assertEqual([name for name, _ in configurations],
                         ['baseline', 'impaired', 'reorder', 'outage'])
        config = configurations[0][1]
        self.assertEqual((config.duration_seconds, config.events_per_second, config.payload_bytes),
                         (60, 10, 1024))
        self.assertEqual((config.reorder_percent, config.outage_seconds, config.restore_deadline_seconds),
                         (10, 10, 120))
        self.assertEqual((config.image, config.build_kind),
                         ('aster-path-delivery:local', 'canonical-release'))


if __name__ == '__main__':
    unittest.main()
