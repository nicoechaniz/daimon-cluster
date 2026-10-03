import pytest
import multiprocessing
import os
import stat

from clusterctl.embodiments import Registry, RegistryError


def test_new_body_gets_embodiment_and_each_start_gets_incarnation(tmp_path):
    registry = Registry(tmp_path)
    embodiment = registry.register(body_ref="cluster:legion:compaii")
    first = registry.start(embodiment["embodiment_id"])
    registry.stop(embodiment["embodiment_id"])
    second = registry.start(embodiment["embodiment_id"])
    assert first["incarnation_id"] != second["incarnation_id"]
    assert registry.status(embodiment["embodiment_id"])["status"] == "running"
    assert len(registry.status(embodiment["embodiment_id"])["incarnations"]) == 2


def test_multiple_bodies_are_not_exclusive(tmp_path):
    registry = Registry(tmp_path)
    first = registry.register(body_ref="cluster:legion:compaii")
    second = registry.register(body_ref="cluster:daimonmatrix:compaii")
    registry.start(first["embodiment_id"])
    registry.start(second["embodiment_id"])
    assert registry.status(first["embodiment_id"])["status"] == "running"
    assert registry.status(second["embodiment_id"])["status"] == "running"


def test_same_body_cannot_be_registered_twice(tmp_path):
    registry = Registry(tmp_path)
    registry.register(body_ref="cluster:legion:compaii")
    with pytest.raises(RegistryError, match="already registered"):
        registry.register(body_ref="cluster:legion:compaii")


def test_list_all_is_stable(tmp_path):
    registry = Registry(tmp_path)
    second = "embodiment:ffffffff-ffff-4fff-8fff-ffffffffffff"
    first = "embodiment:00000000-0000-4000-8000-000000000000"
    registry.register(body_ref="cluster:matrix:compaii", embodiment_id=second)
    registry.register(body_ref="cluster:legion:compaii", embodiment_id=first)
    assert [row["embodiment_id"] for row in registry.list_all()] == [first, second]


def test_running_embodiment_cannot_open_overlapping_incarnation(tmp_path):
    registry = Registry(tmp_path)
    embodiment = registry.register(body_ref="cluster:legion:compaii")
    registry.start(embodiment["embodiment_id"])
    with pytest.raises(RegistryError, match="already running"):
        registry.start(embodiment["embodiment_id"])


def _concurrent_register(root, body, loaded, release, attempted, results):
    registry = Registry(root)
    native_load = registry.load

    def pause_after_load():
        value = native_load()
        loaded.set()
        if release is not None and not release.wait(4):
            raise RuntimeError("test holder was not released")
        return value

    registry.load = pause_after_load
    attempted.set()
    try:
        registry.register(body_ref=body)
        results.put("ok")
    except Exception as error:
        results.put(type(error).__name__)


def test_disjoint_bodies_serialize_entire_read_modify_replace(tmp_path):
    ctx = multiprocessing.get_context("fork")
    first_loaded, second_loaded = ctx.Event(), ctx.Event()
    release, first_attempted, second_attempted = ctx.Event(), ctx.Event(), ctx.Event()
    results = ctx.Queue()
    first = ctx.Process(target=_concurrent_register, args=(
        tmp_path, "first", first_loaded, release, first_attempted, results,
    ))
    second = ctx.Process(target=_concurrent_register, args=(
        tmp_path, "second", second_loaded, None, second_attempted, results,
    ))
    first.start()
    try:
        assert first_loaded.wait(3)
        second.start()
        assert second_attempted.wait(3)
        assert not second_loaded.wait(0.2), "second mutation read stale state"
        release.set()
        first.join(3)
        second.join(3)
        assert first.exitcode == second.exitcode == 0
        assert [results.get(timeout=1) for _ in range(2)] == ["ok", "ok"]
        assert {row["body_ref"] for row in Registry(tmp_path).list_all()} == {
            "first", "second",
        }
    finally:
        release.set()
        for process in (first, second):
            if process.pid is not None:
                if process.is_alive():
                    process.terminate()
                process.join(3)
        results.close()
        results.join_thread()


def _hold_until_killed(root, ready):
    with Registry(root)._mutation_lock():
        ready.set()
        multiprocessing.Event().wait()


def test_process_exit_releases_lock_without_unlinking_inode(tmp_path):
    ctx = multiprocessing.get_context("fork")
    ready = ctx.Event()
    holder = ctx.Process(target=_hold_until_killed, args=(tmp_path, ready))
    holder.start()
    try:
        assert ready.wait(3)
        inode = (tmp_path / "embodiments.lock").stat().st_ino
        holder.terminate()
        holder.join(3)
        Registry(tmp_path).register(body_ref="after-crash")
        assert (tmp_path / "embodiments.lock").stat().st_ino == inode
    finally:
        if holder.is_alive():
            holder.terminate()
        holder.join(3)


def test_identifier_collision_does_not_replace_another_body(tmp_path):
    registry = Registry(tmp_path)
    original = registry.register(body_ref="existing", embodiment_id="embodiment:fixed")
    before = registry.path.read_bytes()
    with pytest.raises(RegistryError, match="already registered"):
        registry.register(body_ref="different", embodiment_id=original["embodiment_id"])
    assert registry.path.read_bytes() == before


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "public", "directory"])
def test_unsafe_lock_refuses_before_registry_write(tmp_path, kind):
    registry = Registry(tmp_path)
    registry.register(body_ref="existing")
    before = registry.path.read_bytes()
    lock = tmp_path / "embodiments.lock"
    lock.unlink()
    other = tmp_path / "other"
    other.write_bytes(b"preserve")
    other.chmod(0o600)
    if kind == "symlink":
        lock.symlink_to(other)
    elif kind == "hardlink":
        os.link(other, lock)
    elif kind == "directory":
        lock.mkdir()
    else:
        lock.write_bytes(b"")
        lock.chmod(0o644)
    with pytest.raises(RegistryError, match="lock"):
        registry.register(body_ref="new")
    assert registry.path.read_bytes() == before
    assert other.read_bytes() == b"preserve"


def test_read_only_registry_queries_do_not_create_lock(tmp_path):
    registry = Registry(tmp_path / "absent")
    assert registry.list_all() == []
    assert not registry.path.parent.exists()
    registry.register(body_ref="existing")
    lock = registry.path.parent / "embodiments.lock"
    assert stat.S_IMODE(lock.stat().st_mode) == 0o600
    lock.unlink()
    assert len(registry.list_all()) == 1
    assert not lock.exists()


@pytest.mark.parametrize("operation", ["register", "start", "stop"])
def test_busy_lock_does_not_break_live_holder(tmp_path, monkeypatch, operation):
    import clusterctl.embodiments as module
    registry = Registry(tmp_path)
    embodiment = registry.register(body_ref="existing")["embodiment_id"]
    if operation == "stop":
        registry.start(embodiment)
    before = registry.path.read_bytes()
    with registry._mutation_lock():
        inode = (tmp_path / "embodiments.lock").stat().st_ino
        monkeypatch.setattr(module, "MUTATION_LOCK_TIMEOUT_SECONDS", 0.02)
        with pytest.raises(RegistryError, match="busy"):
            writer = Registry(tmp_path)
            if operation == "register":
                writer.register(body_ref="new")
            else:
                getattr(writer, operation)(embodiment)
        assert (tmp_path / "embodiments.lock").stat().st_ino == inode
        assert registry.path.read_bytes() == before
