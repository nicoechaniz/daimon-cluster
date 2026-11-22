"""Disposable process/pipe fixture: changes only its selected temporary file."""
import json
from pathlib import Path
import sys
import time

from clusterctl.onboarding_membership_maintenance import MembershipPause, serve_scope
from clusterctl.operation_journal import OperationJournal
from tests.test_onboarding_membership_maintenance import MatrixFixture


class Manager(MatrixFixture):
    def __init__(self, root, delay):
        super().__init__(root)
        self.marker = root / 'manager.json'
        self.delay = delay
        self.save()

    def save(self):
        self.marker.write_text(json.dumps(dict(state=self.state, stops=self.stops, starts=self.starts)))

    def bind(self, observation):
        assert observation == {'process': {'fixture': True}}

    def stop(self):
        super().stop()
        self.save()

    def start(self):
        time.sleep(self.delay)
        super().start()
        self.save()


def main():
    root = Path(sys.argv[1])
    deadline_ns, delay = int(sys.argv[2]), float(sys.argv[3])
    pause = MembershipPause(OperationJournal(root / 'journal'), 'original', 'b' * 64, Manager(root, delay))
    serve_scope(pause, sys.stdin.fileno(), sys.stdout.fileno(), deadline_ns=deadline_ns, cleanup_seconds=3)


if __name__ == '__main__':
    main()
