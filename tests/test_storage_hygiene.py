"""Retention excludes live, recently changed and non-cache data."""
import importlib.util
import fcntl
from pathlib import Path
import subprocess
import shutil
import tempfile
import time
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("storage_hygiene", Path(__file__).parents[1] / "tools/storage_hygiene.py")
hygiene = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(hygiene)


class StorageHygieneTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.projects = Path(self.temp.name)
        self.repo = self.projects / "repo"
        self.repo.mkdir()
        subprocess.run(["git", "init", "-q", str(self.repo)], check=True)
        workspace = self.repo / "nested"
        workspace.mkdir()
        (workspace / "Cargo.toml").write_text("[workspace]\n")
        self.root = workspace / "target/dev-small/incremental"
        self.candidate = self.root / "crate-cache"
        self.candidate.mkdir(parents=True)
        (self.candidate / "cache.bin").write_bytes(b"cache")
        self.config = {"projects_root": str(self.projects), "cache_roots": [str(self.root)], "cache_min_age_days": 2}
        self.future = time.time() + 3 * 86400

    def test_nested_cache_removed_but_sources_and_executable_preserved(self):
        executable = self.root.parent / "app"
        executable.write_bytes(b"selected executable")
        report = hygiene.clean(self.config, apply=True, now=self.future, active_paths=set())
        self.assertEqual(report["cache_dirs_removed"], 1)
        self.assertFalse(self.candidate.exists())
        self.assertTrue(executable.exists())
        self.assertTrue((self.repo / "nested/Cargo.toml").exists())

    def reset(self, **kwargs):
        (self.root.parent/'.cargo-lock').touch(exist_ok=True)
        return hygiene.reset_incremental(self.config, activity_scan=lambda:set(), **kwargs)

    def test_explicit_idle_reset_reclaims_recent_cache_preserves_other_build_data(self):
        executable=self.root.parent/'app';executable.write_bytes(b'kept executable')
        deps=self.root.parent/'deps';deps.mkdir();(deps/'compiled.rlib').write_bytes(b'kept dependency')
        report=self.reset(apply=True,max_bytes=1024)
        self.assertEqual(report['cache_dirs_removed'],1)
        self.assertEqual(report['bytes_removed'],5)
        self.assertTrue(executable.exists());self.assertTrue((deps/'compiled.rlib').exists())

    def test_explicit_reset_keeps_busy_cargo_profile(self):
        lock=self.root.parent/'.cargo-lock';lock.touch()
        with lock.open('r+b') as handle:
            fcntl.flock(handle,fcntl.LOCK_EX|fcntl.LOCK_NB)
            report=self.reset(apply=True)
        self.assertEqual(report['skipped'],1);self.assertTrue(self.candidate.exists())

    def test_explicit_reset_does_not_treat_its_own_exclusive_lock_as_a_builder(self):
        lock=self.root.parent/'.cargo-lock';lock.touch()
        report=hygiene.reset_incremental(self.config,apply=True,
            activity_scan=lambda:{lock})
        self.assertEqual(report['cache_dirs_removed'],1)
        self.assertFalse(self.candidate.exists())

    def test_explicit_reset_dry_run_and_byte_ceiling_keep_candidate(self):
        report=self.reset(apply=False)
        self.assertTrue(self.candidate.exists());self.assertEqual(report['bytes_removed'],0)
        report=self.reset(apply=True,max_bytes=1)
        self.assertEqual(report['budget_exhausted'],'byte_limit')
        self.assertTrue(self.candidate.exists())

    def test_explicit_reset_keeps_mapped_source_and_refuses_linked_lock(self):
        (self.root.parent/'.cargo-lock').touch()
        report=hygiene.reset_incremental(self.config,apply=True,
            activity_scan=lambda:{self.repo/'active'})
        self.assertTrue(self.candidate.exists());self.assertEqual(report['skipped'],1)
        lock=self.root.parent/'.cargo-lock';lock.unlink();lock.symlink_to(self.repo/'other')
        report=hygiene.reset_incremental(self.config,apply=True,activity_scan=lambda:set())
        self.assertTrue(self.candidate.exists());self.assertEqual(report['errors'],1)

    def test_count_budget_limits_each_pass(self):
        second = self.root / "second-cache"
        second.mkdir()
        (second / "cache.bin").write_bytes(b"cache")
        report = hygiene.clean({**self.config, "max_cache_dirs_per_run": 1}, apply=True,
                               now=self.future, active_paths=set())
        self.assertEqual(report["cache_dirs_removed"], 1)
        self.assertEqual(sum(p.exists() for p in [self.candidate, second]), 1)

    def test_byte_budget_preserves_oversized_cache_without_partial_deletion(self):
        report=hygiene.clean({**self.config,'max_bytes_per_run':4},apply=True,
                             now=self.future,active_paths=set())
        self.assertEqual(report['budget_exhausted'],'byte_limit')
        self.assertEqual(report['bytes_removed'],0)
        self.assertTrue((self.candidate/'cache.bin').exists())

    def test_byte_budget_counts_actual_completed_removal(self):
        second=self.root/'second-cache';second.mkdir();(second/'cache.bin').write_bytes(b'cache')
        report=hygiene.clean({**self.config,'max_bytes_per_run':5},apply=True,
                             now=self.future,active_paths=set())
        self.assertEqual(report['bytes_removed'],5)
        self.assertEqual(report['cache_dirs_removed'],1)
        self.assertEqual(report['budget_exhausted'],'byte_limit')
        self.assertEqual(sum(p.exists() for p in [self.candidate,second]),1)

    def test_entry_and_time_limits_stop_before_removal(self):
        report=hygiene.clean({**self.config,'max_entries_per_run':1},apply=True,
                             now=self.future,active_paths=set())
        self.assertEqual(report['budget_exhausted'],'entry_limit')
        self.assertTrue(self.candidate.exists())
        with patch.object(hygiene.time,'monotonic',side_effect=[0,0,2]):
            report=hygiene.clean({**self.config,'max_seconds_per_run':1},apply=True,
                                 now=self.future,active_paths=set())
        self.assertEqual(report['budget_exhausted'],'time_limit')
        self.assertTrue(self.candidate.exists())

    def test_flat_non_cache_files_consume_entry_budget(self):
        shutil.rmtree(self.candidate)
        for n in range(10):(self.root/('flat-'+str(n))).write_bytes(b'kept')
        report=hygiene.clean({**self.config,'max_entries_per_run':1},apply=True,
                             now=self.future,active_paths=set())
        self.assertEqual(report['budget_exhausted'],'entry_limit')
        self.assertTrue(all((self.root/('flat-'+str(n))).exists() for n in range(10)))

    def test_privileged_projection_callback_is_repeated_before_deletion(self):
        provider=unittest.mock.Mock(side_effect=[set(),{self.repo/'active-task'}])
        report=hygiene.clean(self.config,apply=True,now=self.future,activity_scan=provider)
        self.assertEqual(report['cache_dirs_removed'],0)
        self.assertEqual(provider.call_count,2)
        self.assertTrue(self.candidate.exists())

    def worktree(self):
        def git(*args):
            subprocess.run(['git','-C',str(self.repo),'-c','user.name=fixture',
                            '-c','user.email=fixture@example.invalid','-c','commit.gpgsign=false',
                            *args],check=True,capture_output=True)
        git('add','nested/Cargo.toml');git('commit','-qm','fictional source')
        root=self.projects/'worktrees';root.mkdir();path=root/'finished'
        git('worktree','add','-qb','retired-fixture',str(path))
        config={'projects_root':str(self.projects),'cache_roots':[],
                'worktree_roots':[str(root)],'retired_worktrees':[]}
        hygiene.retire_worktree(config,self.repo,path,'HEAD')
        return path,config

    def test_explicit_integrated_worktree_uses_same_byte_budget(self):
        path,config=self.worktree()
        report=hygiene.clean({**config,'max_bytes_per_run':1},apply=True,
                             now=time.time()+20*86400,activity_scan=lambda:set())
        self.assertEqual(report['budget_exhausted'],'byte_limit')
        self.assertTrue(path.exists());self.assertEqual(len(config['retired_worktrees']),1)

    def test_explicit_clean_integrated_worktree_removal_preserves_base_repo(self):
        path,config=self.worktree()
        report=hygiene.clean(config,apply=True,now=time.time()+20*86400,activity_scan=lambda:set())
        self.assertEqual(report['worktrees_removed'],1)
        self.assertGreater(report['bytes_removed'],0)
        self.assertFalse(path.exists());self.assertTrue((self.repo/'nested/Cargo.toml').exists())

    def test_active_or_mapped_project_is_preserved(self):
        report = hygiene.clean(self.config, apply=True, now=self.future, active_paths={self.root.parent / "app"})
        self.assertEqual(report["cache_dirs_removed"], 0)
        self.assertTrue(self.candidate.exists())

    def test_recent_cache_and_dry_run_are_preserved(self):
        for apply, now in [(True, time.time()), (False, self.future)]:
            report = hygiene.clean(self.config, apply=apply, now=now, active_paths=set())
            self.assertEqual(report["cache_dirs_removed"], 0)
            self.assertTrue(self.candidate.exists())

    def test_symlink_and_release_paths_rejected(self):
        linked = self.root.parent / "linked"
        linked.symlink_to(self.candidate, target_is_directory=True)
        hygiene.clean(self.config, apply=True, now=self.future, active_paths=set())
        self.assertTrue(linked.is_symlink())
        for path in [self.repo / "nested/target/release/incremental", self.root.parent / "deps"]:
            with self.assertRaises(ValueError):
                hygiene.clean({**self.config, "cache_roots": [str(path)]}, active_paths=set())

    def test_failed_host_inspection_prevents_deletion(self):
        with patch.object(hygiene, "process_paths", side_effect=RuntimeError("unavailable")):
            with self.assertRaises(RuntimeError):
                hygiene.clean(self.config, apply=True, now=self.future)
        self.assertTrue(self.candidate.exists())

    def test_active_project_appearing_on_final_scan_is_preserved(self):
        with patch.object(hygiene, "process_paths", side_effect=[set(), {self.repo / "new-writer"}]):
            report = hygiene.clean(self.config, apply=True, now=self.future)
        self.assertEqual(report["cache_dirs_removed"], 0)
        self.assertTrue(self.candidate.exists())


if __name__ == "__main__":
    unittest.main()
