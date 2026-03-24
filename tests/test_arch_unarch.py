"""
Test Archive and Unarchive facts and operations in functional way.
Parameter validation, e.g. bad fmt is only covered by JSON tests and not here as there is no
target interaction.

See https://docs.pyinfra.com/en/3.x/api/index.html for API details.

As of 2026-03-22 example is incorrect about how to get host, i.e. state.hosts.inventory['@local']
does _not_ work.  See correct way at pyinfra_setup_local_rtn below.

"""

import logging
import shlex
import subprocess
from contextlib import contextmanager
from pathlib import Path

import pytest

from pyinfra.api import Config, Inventory, State
from pyinfra.api.connect import connect_all
from pyinfra.api.exceptions import OperationError, PyinfraError
from pyinfra.api.operation import add_op
from pyinfra.api.operations import run_ops
from pyinfra.facts.files import KNOWN_ARCHIVE_KINDS, ArchiveFiles, ArchiveFormatType
from pyinfra.operations import files

LOCAL = "@local"

COMPRESSORS = {
    "bz2": ["bzip2"],
    "gz": ["gzip"],
    "tar": ["cat"],
    "xz": ["xz"],
    "zip": [],
    "zstd": ["zstd"],
}
if set(COMPRESSORS) != KNOWN_ARCHIVE_KINDS:
    raise RuntimeError("ARCH_INFO keys do not match KNOWN_ARCHIVE_KINDS")


def debug_log_twice(caplog, s: str) -> bool:
    return (
        sum(
            1
            for _ in (
                r for r in caplog.records if (r.levelno == logging.DEBUG) and (s in r.message)
            )
        )
        == 2
    )


def no_warnings_or_errors(
    caplog,
) -> bool:
    return sum(1 for _ in (e for e in caplog.records if e.levelname in {"WARNING", "ERROR"})) == 0


@contextmanager
def pyinfra_setup_local_rtn():
    state = State(inventory=Inventory(([LOCAL], {})), config=Config())
    connect_all(state)

    yield state, state.inventory.get_host(LOCAL)


@pytest.fixture
def pyinfra_setup_local():
    return pyinfra_setup_local_rtn


def arch_suffix(kind: ArchiveFormatType) -> str:
    return f".{'' if kind in ['tar', 'zip'] else 'tar.'}{kind}"


def make_archive(dest: Path, paths: list[Path], kind: str) -> None:
    cx = COMPRESSORS[kind]
    file_names = [shlex.quote(p.name) for p in paths]
    dest_q = shlex.quote(dest.name)
    cmd = (
        ["zip", dest_q, *file_names]
        if kind == "zip"
        else ["tar", "cvf", "-", *file_names, "|", *cx, ">", dest_q]
    )
    result = subprocess.run(  # noqa: S602
        " ".join(cmd), shell=True, cwd=paths[0].parent, capture_output=True, check=True
    )
    if result.returncode != 0:
        pytest.fail("failed to create archive file - rc")
    if not dest.exists():
        pytest.fail("failed to create archive file - exists")


@pytest.mark.parametrize("filename", ["never_created.txt", "never created.txt"])
@pytest.mark.parametrize("kind", KNOWN_ARCHIVE_KINDS)
def test_archive_files_on_non_existent_file_gives_null(
    pyinfra_setup_local, tmp_path, kind, filename
):
    should_not_exist = tmp_path / filename
    if Path(should_not_exist).exists():
        pytest.fail(f"file that should not exist does: {should_not_exist}")
    with pyinfra_setup_local() as (_state, host):
        result = host.get_fact(ArchiveFiles, path=should_not_exist, fmt=kind)
        assert result is None


@pytest.mark.parametrize("stem", ["filename", "file name"])
@pytest.mark.parametrize("kind", KNOWN_ARCHIVE_KINDS)
def test_archive_files_on_non_archive_file_gives_empty_list(
    caplog, pyinfra_setup_local, tmp_path, kind, stem
):
    test_file = (tmp_path / stem).with_suffix(arch_suffix(kind))
    with test_file.open(mode="w") as f:
        f.write(f"not the start of a {kind} file")
    with pyinfra_setup_local() as (_state, host):
        result = host.get_fact(ArchiveFiles, path=test_file, fmt=kind)
        assert no_warnings_or_errors(caplog)
        assert result == []


@pytest.mark.parametrize("arch_stem", ["archive", "archive name"])
@pytest.mark.parametrize("file_stem", ["filename", "file name"])
@pytest.mark.parametrize("kind", KNOWN_ARCHIVE_KINDS)
@pytest.mark.parametrize("count", [1, 2, 5])
def test_archive_files_works_for_valid_archives(
    caplog, pyinfra_setup_local, tmp_path, kind, count, arch_stem, file_stem
):
    test_archive = (tmp_path / arch_stem).with_suffix(arch_suffix(kind))
    paths = [tmp_path / f"{file_stem}{file_num:03d}.txt" for file_num in range(1, count + 1, 1)]
    for i, path in enumerate(paths, 1):
        with path.open(mode="w") as f:
            f.write(i * "a")
    make_archive(test_archive, paths, kind)
    with pyinfra_setup_local() as (_state, host):
        result = host.get_fact(ArchiveFiles, path=test_archive, fmt=kind)
    assert result is not None
    assert no_warnings_or_errors(caplog)
    assert len(result) == count
    for i, entry in enumerate(result):
        assert entry.name == paths[i].name
        assert entry.size == i + 1
        # FIXME - check date, owner, group, mode


@pytest.mark.parametrize("bad_kind", ["xxx", "123", "ctr"])
@pytest.mark.parametrize("op", [files.archive, files.unarchive])
def test_files_un_and_archive_bad_format_raises_exception(
    pyinfra_setup_local, tmp_path, bad_kind, op
):
    path, dest = tmp_path / "source.txt", tmp_path / f"dest.{bad_kind}"
    if bad_kind in KNOWN_ARCHIVE_KINDS:
        pytest.fail(f"archive kind '{bad_kind}' actually is known")
    with pyinfra_setup_local() as (state, _host):  # noqa: SIM117
        with pytest.raises(OperationError, match=rf"Unsupported archive format: '{bad_kind}"):  # noqa: PT012
            add_op(state, op, path, dest, fmt=bad_kind)
            run_ops(state)


@pytest.mark.parametrize("dest_parent", ["parent", "parent dir"])
@pytest.mark.parametrize("stem", ["archive", "archive name"])
@pytest.mark.parametrize("kind", KNOWN_ARCHIVE_KINDS)
@pytest.mark.parametrize("op", [files.archive, files.unarchive])
def test_files_un_and_archive_parent_dir_missing_gives_error(
    pyinfra_setup_local, tmp_path, op, kind, stem, dest_parent
):
    path = tmp_path / "source.txt"
    dest = (tmp_path / dest_parent / stem).with_suffix(arch_suffix(kind))
    error = f"pyinfra: {'parent of' if op == files.archive else 'archive'} {dest} not found"
    with pyinfra_setup_local() as (state, host):  # noqa: SIM117
        first, second = (str(path), str(dest)) if op == files.archive else (str(dest), str(path))
        with pytest.raises(PyinfraError, match=r"No hosts remaining!"):  # noqa: PT012
            result = add_op(state, op, first, second, fmt=kind)
            run_ops(state)
    # TODO - look for errors in logs
    # TODO - can we check did_error ?
    assert result[host].stderr == error


@pytest.mark.parametrize("kind", KNOWN_ARCHIVE_KINDS)
@pytest.mark.parametrize("stem", ["archive", "archive name"])
@pytest.mark.parametrize("no_files", [[], None])
def test_files_archive_add_no_files_gives_nop(
    caplog, pyinfra_setup_local, tmp_path, no_files, kind, stem
):
    dest = (tmp_path / stem).with_suffix(arch_suffix(kind))
    with pyinfra_setup_local() as (state, host):
        result = add_op(state, files.archive, no_files, str(dest), fmt=kind)
        run_ops(state)
    assert result is not None
    assert not result[host].did_error()
    assert result[host].stderr == ""
    assert result[host].stdout == ""
    assert len(result[host]._commands) == 0  # noqa: SLF001
    # FIXME - it seems host.noop text is only logged so need to dig through captured log
    assert debug_log_twice(caplog, "noop: no source paths specified")


@pytest.mark.parametrize("kind", KNOWN_ARCHIVE_KINDS)
@pytest.mark.parametrize("count", [1, 2, 5])
def test_files_archive_create_works(caplog, pyinfra_setup_local, tmp_path, kind, count):
    dest = tmp_path / f"file.{'' if kind in ['tar', 'zip'] else 'tar.'}{kind}"
    paths = [tmp_path / f"file{file_num:03d}.txt" for file_num in range(1, count + 1, 1)]
    for i, path in enumerate(paths, 1):
        with path.open(mode="w") as f:
            f.write(i * "a")

    with pyinfra_setup_local() as (state, host):
        result = add_op(
            state,
            files.archive,
            [p.name for p in paths],
            str(dest),
            fmt=kind,
            _chdir=str(dest.parent),
        )
        run_ops(state)
    assert result is not None
    assert not result[host].did_error()
    if kind != "zip":  # writes to both stdout and stderr; tar only writes to stderr
        assert result[host].stdout == ""
    assert no_warnings_or_errors(caplog)
    info_list = host.get_fact(ArchiveFiles, path=str(dest), fmt=kind)
    assert len(info_list) == count
    for i, entry in enumerate(info_list):
        assert entry.name == paths[i].name
        assert entry.size == i + 1
        # FIXME - check date, owner, group, mode


# FIXME - restore zip once files.archive makes an error when zip complains in stdout
@pytest.mark.parametrize("kind", KNOWN_ARCHIVE_KINDS - {"zip"})
@pytest.mark.parametrize(("count", "missing"), [(1, 1), (3, 2)])
def test_files_archive_missing_file_gives_error(
    pyinfra_setup_local, tmp_path, kind, count, missing
):
    with pyinfra_setup_local() as (state, _host):
        dest = tmp_path / f"file.{'' if kind in ['tar', 'zip'] else 'tar.'}{kind}"
        paths = [tmp_path / f"file{file_num:03d}.txt" for file_num in range(1, count + 1, 1)]
        for i, path in enumerate(paths, 1):
            if i == missing:
                continue
            with path.open(mode="w") as f:
                f.write(i * "a")
        with pytest.raises(PyinfraError, match=r"No hosts remaining!"):  # noqa: PT012
            add_op(
                state,
                files.archive,
                [p.name for p in paths],
                str(dest),
                fmt=kind,
                _chdir=str(dest.parent),
            )
            run_ops(state)


@pytest.mark.parametrize("kind", KNOWN_ARCHIVE_KINDS)
@pytest.mark.parametrize("arch_stem", ["archive", "archive name"])
def test_files_unarchive_non_existent_archive_gives_error(
    pyinfra_setup_local, tmp_path, kind, arch_stem
):
    src = (tmp_path / arch_stem).with_suffix(arch_suffix(kind))
    dest = tmp_path / "dest-dir"
    with pyinfra_setup_local() as (state, host):  # noqa: SIM117
        with pytest.raises(PyinfraError, match=r"No hosts remaining!"):  # noqa: PT012
            result = add_op(state, files.unarchive, str(src), str(dest), fmt=kind)
            run_ops(state)
    assert result[host].stderr == f"pyinfra: archive {src} not found"


@pytest.mark.parametrize("kind", KNOWN_ARCHIVE_KINDS)
@pytest.mark.parametrize("count", [1, 2, 5])
@pytest.mark.parametrize("file_stem", ["filename", "file name"])
@pytest.mark.parametrize("arch_stem", ["archive", "archive name"])
@pytest.mark.parametrize("destdir", ["destdir", "dest dir"])
def test_files_unarchive_extract_works(
    caplog, pyinfra_setup_local, tmp_path, kind, count, arch_stem, file_stem, destdir
):
    src = (tmp_path / arch_stem).with_suffix(arch_suffix(kind))
    dest = tmp_path / destdir
    dest.mkdir()
    paths = [tmp_path / f"{file_stem}{file_num:03d}.txt" for file_num in range(1, count + 1, 1)]
    for i, path in enumerate(paths, 1):
        with path.open(mode="w") as f:
            f.write(i * "a")
    make_archive(src, paths, kind)

    with pyinfra_setup_local() as (state, host):
        result = add_op(state, files.unarchive, str(src), str(dest), fmt=kind)
        run_ops(state)

    assert result[host] is not None
    assert no_warnings_or_errors(caplog)
    assert not result[host].did_error()
    assert result[host].stderr == ""
    assert result[host].stdout == ""
    for i, path in enumerate(paths, 1):
        assert path.is_file()
        assert path.open("r").read() == i * "a"
        # TODO - check user, group, mode and date
