"""Every bundled data file reaches every distribution.

The EoL table (subnetsleuth/data/eol.json) once shipped in no wheel, zip or binary because
pyproject's package-data globs and both PyInstaller specs each listed data files by hand
and none of the three was updated. These tests pin the three lists to what is on disk.
"""
import fnmatch
import importlib.util
import os
import tomllib

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PKG = os.path.join(ROOT, "subnetsleuth")
DATA_DIRS = ("data", "vendor")


def _files_on_disk() -> set[str]:
    out = set()
    for sub in DATA_DIRS:
        for dirpath, _dirs, files in os.walk(os.path.join(PKG, sub)):
            for f in files:
                if f.startswith(".") or f.endswith((".pyc", ".tmp")):
                    continue
                out.add(os.path.relpath(os.path.join(dirpath, f), PKG).replace(os.sep, "/"))
    return out


def _bundle():
    spec = importlib.util.spec_from_file_location("bundle", os.path.join(ROOT, "packaging", "bundle.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_data_files_exist():
    files = _files_on_disk()
    assert {"data/eol.json", "data/oui.tsv", "vendor/vis-network.min.js"} <= files, files


def test_pyproject_package_data_covers_every_data_file():
    with open(os.path.join(ROOT, "pyproject.toml"), "rb") as f:
        py = tomllib.load(f)
    globs = py["tool"]["setuptools"]["package-data"]["subnetsleuth"]
    missing = sorted(rel for rel in _files_on_disk() if not any(fnmatch.fnmatch(rel, g) for g in globs))
    assert not missing, f"not covered by [tool.setuptools.package-data]: {missing} (globs: {globs})"


def test_bundle_lists_exactly_the_files_on_disk():
    bundle = _bundle()
    listed = set(bundle.DATA_FILES)
    on_disk = _files_on_disk()
    assert listed == on_disk, f"packaging/bundle.py DATA_FILES vs disk: missing={sorted(on_disk - listed)} stale={sorted(listed - on_disk)}"


@pytest.mark.parametrize("with_sample", [True, False])
def test_bundle_datas_resolve_to_real_files(with_sample):
    bundle = _bundle()
    datas = bundle.data_files(ROOT, with_sample=with_sample)
    srcs = {os.path.relpath(src, PKG).replace(os.sep, "/") for src, _dest in datas}
    expected = set(bundle.DATA_FILES) - (set() if with_sample else {bundle.SAMPLE_PROJECT})
    assert srcs == expected
    for src, dest in datas:
        assert os.path.isfile(src)
        # destination folder mirrors the package layout, so util.resource_path() finds it when frozen
        assert dest == "subnetsleuth/" + os.path.dirname(os.path.relpath(src, PKG).replace(os.sep, "/"))
    assert "data/eol.json" in srcs


@pytest.mark.parametrize("spec", ["subnetsleuth.spec", os.path.join("packaging", "subnetsleuth-gui.spec")])
def test_specs_take_their_data_from_bundle(spec):
    """Both specs must build their datas from packaging/bundle.py, never a private list."""
    text = open(os.path.join(ROOT, spec), encoding="utf-8").read()
    assert 'spec_from_file_location("bundle"' in text and "bundle.collect(" in text, spec
    for rel in ("vendor/vis-network.min.js", "data/oui.tsv", "data/eol.json"):
        # no hand-maintained copies left behind
        assert rel not in text, f"{spec} lists {rel} directly; add it to packaging/bundle.py instead"


def test_eol_table_loads_from_the_installed_package():
    """What the packaging bug actually broke: eol.py silently returns an empty table."""
    from subnetsleuth import eol

    eol._RECORDS = None
    table = eol._load()
    assert len(table) > 20
    assert eol.eol_status("Cisco", "WS-C2960-24TT-L") is not None
