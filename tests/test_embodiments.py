import pytest

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
