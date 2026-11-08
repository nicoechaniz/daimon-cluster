"""Native holder commands through an already qualified offline SDK generation.

This selects software only. FirstCustody still owns exact per-plan grants,
separate holders, private password FDs and resumable publication.
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

from . import onboarding_code_successor, onboarding_release, onboarding_sdk
from .onboarding import OnboardingError
from .onboarding_custody import _native_run

MODULES = frozenset({'daimon_matrix.operator_genesis',
    'daimon_matrix.operator_first_embodiment', 'clusterctl.onboarding_holder_backup',
    'clusterctl.onboarding_credential'})


def native_command(venv: Path, imports: Path, code: Path, module: str,
                   arguments: list[str]) -> list[str]:
    if module not in MODULES or imports != venv.parent / 'runtime-imports':
        raise OnboardingError('qualified_native_custody_required')
    launcher = '''import sys,runpy
sys.prefix = sys.exec_prefix = sys.argv.pop(1)
imports,code,module = sys.argv[1:4]
del sys.argv[1:4]
sys.path[:0] = [code,imports]
sys.dont_write_bytecode = True
sys.pycache_prefix = imports + '/.disabled-bytecode'
runpy.run_module(module,run_name='__main__',alter_sys=True)
'''
    return [str(venv / 'bin/python'), '-B', '-I', '-S', '-c', launcher,
            str(venv), str(imports), str(code), module, *arguments]


class QualifiedHolderRunner:
    def __init__(self, home: Path, code: Path, code_digest: str,
                 base: Path, base_digest: str):
        onboarding_code_successor.verify(code, code_digest, base, base_digest, uid=0)
        parameters = onboarding_code_successor.sdk_parameters(code)
        if not parameters:
            raise OnboardingError('qualified_native_custody_required')
        release = onboarding_release.verify(code, code_digest, uid=0)
        required = {'clusterctl/onboarding_custody_native.py',
                    'clusterctl/onboarding_custody.py', 'clusterctl/onboarding_holder_backup.py'}
        if not required <= {row['path'] for row in release['files']}:
            raise OnboardingError('qualified_native_custody_required')
        self.code, self.code_digest = code, code_digest
        self.venv = onboarding_sdk.observe(home, code, code_uid=0, **parameters)
        self.imports = onboarding_sdk.runtime_imports(self.venv, code, code_uid=0, **parameters)

    def __call__(self, arguments: list[str], password: Path | None) -> None:
        selected = ['--venv', str(self.venv), '--code', str(self.code),
                    '--code-digest', self.code_digest]
        if password is not None:
            selected += ['--password-file', str(password)]
        command = onboarding_sdk.runtime_command(self.venv, self.imports, self.code,
            'clusterctl.onboarding_custody_native', [*selected, '--', *arguments])
        try:
            result = subprocess.run(command, stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=180, check=False)
        except (OSError, subprocess.TimeoutExpired):
            raise OnboardingError('native_onboarding_custody_refused') from None
        if result.returncode:
            raise OnboardingError('native_onboarding_custody_refused')


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--venv', type=Path, required=True)
    parser.add_argument('--code', type=Path, required=True)
    parser.add_argument('--code-digest', required=True)
    parser.add_argument('--password-file', type=Path)
    parser.add_argument('arguments', nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    arguments = args.arguments[1:] if args.arguments[:1] == ['--'] else args.arguments
    if not arguments:
        raise OnboardingError('qualified_native_custody_required')
    parameters = onboarding_code_successor.sdk_parameters(args.code)
    if not parameters:
        raise OnboardingError('qualified_native_custody_required')
    # This proof belongs to this actual process, before opening a holder or FD.
    onboarding_sdk.qualified_startup(args.venv, args.code, code_digest=args.code_digest,
        code_uid=0, **parameters)
    imports = args.venv.parent / 'runtime-imports'
    _native_run(arguments, args.password_file, command_builder=lambda module, values:
        native_command(args.venv, imports, args.code, module, values))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
