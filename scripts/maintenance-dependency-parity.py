"""Report genuine installed Matrix/source parity; does not alter installation."""
import hashlib
import importlib.metadata as metadata
import json
from pathlib import Path
import subprocess
import sys


def main():
    source = Path(sys.argv[1]).resolve()
    revision = "8e7d8870609507e61eec1be769280dc33c487366"
    distribution = metadata.distribution("daimon-matrix")
    direct = json.loads(distribution.read_text("direct_url.json"))
    assert direct["vcs_info"]["commit_id"] == revision
    assert not direct.get("dir_info", {}).get("editable", False)
    names = subprocess.check_output(
        ["git", "-C", str(source), "ls-tree", "-r", "--name-only", revision, "src/daimon_matrix"], text=True,
    ).splitlines()
    rows = {}
    for name in names:
        expected = subprocess.check_output(["git", "-C", str(source), "show", f"{revision}:{name}"])
        installed = Path(distribution.locate_file(name.removeprefix("src/")))
        actual = installed.read_bytes()
        assert actual == expected, name
        rows[name] = hashlib.sha256(actual).hexdigest()
    assert rows
    tracked = {name.removeprefix("src/") for name in names}
    installed_python = {str(p) for p in distribution.files if str(p).startswith("daimon_matrix/") and str(p).endswith(".py")}
    assert not installed_python - tracked
    from clusterctl.matrix_host import _matrix_api
    _matrix_api()
    print(json.dumps({
        "python": sys.version, "executable": sys.executable,
        "direct_url": direct, "license_expression": distribution.metadata.get("License-Expression"),
        "matrix_requires_dist": distribution.requires,
        "source_sha256": rows,
        "resolved_distributions": dict(sorted((d.metadata["Name"], d.version) for d in metadata.distributions())),
        "scope": "Installed source bytes verified against exact Git object; not an independent wheel/release signature or transitive artifact audit",
    }, indent=2))


if __name__ == "__main__":
    # Run as a module from checkout root, so only this complete Cluster tree loads.
    main()
