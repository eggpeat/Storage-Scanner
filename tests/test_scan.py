import os
import queue
import sys
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from storage_scanner import scanner
from storage_scanner.models import FileNode, Node, detached_file, row_flags
from storage_scanner.scanner import _rollup, find_inaccessible_paths, scan


def _run_scan(path):
    progress_q = queue.Queue()
    cancel_event = threading.Event()
    return scan(str(path), progress_q, cancel_event)


def _run_scan_with_messages(path):
    progress_q = queue.Queue()
    cancel_event = threading.Event()
    root = scan(str(path), progress_q, cancel_event)
    messages = []
    while True:
        try:
            messages.append(progress_q.get_nowait())
        except queue.Empty:
            break
    return root, messages


def _by_name(node):
    return {child.name: child for child in node.children}


def _file(parent, name, size=0, **kw):
    return FileNode(parent, parent.add_file(name, size, **kw))


def _use_mountinfo(monkeypatch, tmp_path_factory, content):
    # A real file of raw bytes, as the kernel writes it: only space, tab,
    # newline and backslash are octal-escaped, every other path byte (0xff
    # too) is raw. Opened with whatever mode and encoding scanner asks for.
    mountinfo = tmp_path_factory.mktemp("proc") / "mountinfo"
    mountinfo.write_bytes(content)
    real_open = open
    monkeypatch.setattr(
        scanner, "open", lambda _path, *args, **kw: real_open(mountinfo, *args, **kw), raising=False
    )


def test_mount_boundaries_are_empty_leaves_but_can_be_scanned_directly(tmp_path, monkeypatch):
    mounted = tmp_path / "mounted"
    mounted.mkdir()
    (mounted / "outside.bin").write_bytes(b"x" * 1000)
    local = tmp_path / "local"
    local.mkdir()
    (local / "inside.bin").write_bytes(b"y" * 7)
    root_device = tmp_path.stat().st_dev
    real_stat, real_scandir = os.stat, os.scandir
    visited = []

    def device_stat(path, **kwargs):
        info = real_stat(path, **kwargs)
        if os.path.commonpath([str(mounted), os.fspath(path)]) == str(mounted):
            values = {name: getattr(info, name) for name in dir(info) if name.startswith("st_")}
            values["st_dev"] = root_device + 1
            return SimpleNamespace(**values)
        return info

    class Entry:
        def __init__(self, entry):
            self.path, self.name = entry.path, entry.name
            self.is_dir = entry.is_dir

        def stat(self, **kwargs):
            return device_stat(self.path, **kwargs)

    class Listing:
        def __init__(self, path):
            visited.append(path)
            self.listing = real_scandir(path)

        def __enter__(self):
            return (Entry(entry) for entry in self.listing)

        def __exit__(self, *args):
            self.listing.close()

    monkeypatch.setattr(scanner.os, "stat", device_stat)
    monkeypatch.setattr(scanner.os, "scandir", Listing)
    monkeypatch.setattr(scanner, "_measure_alloc_size", lambda path, info: info.st_size)

    root, messages = _run_scan_with_messages(tmp_path)
    boundary = _by_name(root)["mounted"]
    assert boundary.is_dir and not boundary.children
    assert boundary.size == boundary.alloc_size == 0
    assert not root.error
    assert root.size == root.alloc_size == 7
    assert root.file_count == 1
    assert str(mounted) not in visited
    snapshot = [payload for kind, payload in messages if kind == "walk"][-1]
    assert snapshot.bytes == snapshot.alloc_bytes == 7
    assert snapshot.files == 1 and snapshot.pending == 0

    direct = _run_scan(mounted)
    assert direct.size == 1000
    assert direct.file_count == 1


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux mountinfo")
@pytest.mark.parametrize("filesystem", ["proc", "sysfs", "devtmpfs", "devpts", "cgroup2"])
def test_pseudo_filesystem_targets_are_not_scanned(
    tmp_path, tmp_path_factory, monkeypatch, filesystem
):
    target = tmp_path / "kernel-view"
    target.mkdir()
    kernel_file = target / "kcore"
    kernel_file.write_bytes(b"not stored file data")
    device = target.stat().st_dev
    _use_mountinfo(
        monkeypatch,
        tmp_path_factory,
        f"24 1 {os.major(device)}:{os.minor(device)} / /arbitrary\\040mount rw shared:1"
        f" - {filesystem} none rw\n".encode(),
    )

    visited = []
    real_scandir = os.scandir

    def tracked_scandir(path):
        visited.append(path)
        return real_scandir(path)

    monkeypatch.setattr(scanner.os, "scandir", tracked_scandir)
    root = _run_scan(target)
    assert root.is_dir and not root.children
    assert root.size == root.alloc_size == root.file_count == 0
    file_root = _run_scan(kernel_file)
    assert not file_root.is_dir
    assert file_root.size == file_root.alloc_size == 0
    assert not visited


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux mountinfo")
def test_mountinfo_filters_types_and_tolerates_unavailable_metadata(
    tmp_path, tmp_path_factory, monkeypatch
):
    _use_mountinfo(
        monkeypatch,
        tmp_path_factory,
        b"24 1 0:42 / /renamed\\040proc rw shared:1 - proc none rw\n"
        b"25 1 8:1 / / rw - ext4 /dev/root rw\n"
        b"26 1 0:43 / /ram rw - tmpfs tmpfs rw\n"
        b"invalid mountinfo\n"
        b"27 1 bad / /bad rw - proc none rw\n"
        b"28 1 0:44 / /bad rw - \n",
    )
    assert scanner._pseudo_filesystem_devices() == {os.makedev(0, 42)}

    def unavailable(*args, **kwargs):
        raise FileNotFoundError

    monkeypatch.setattr(scanner, "open", unavailable)
    (tmp_path / "regular.bin").write_bytes(b"123")
    assert _run_scan(tmp_path).size == 3


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux mountinfo")
def test_mountinfo_with_non_utf8_mount_paths_does_not_stop_scans(
    tmp_path, tmp_path_factory, monkeypatch
):
    _use_mountinfo(
        monkeypatch,
        tmp_path_factory,
        b"24 1 0:42 / /media/caf\xe9\\040disk rw shared:1 - proc none rw\n"
        b"25 1 8:1 / /mnt/\xff rw - ext4 /dev/disk/by-label/\xff rw\n"
        b"26 1 0:43 / /sys\\134\xfe rw - sysfs sysfs rw\n",
    )
    assert scanner._pseudo_filesystem_devices() == {os.makedev(0, 42), os.makedev(0, 43)}
    # Fields decode the way os.scandir decodes names, so they map back to
    # the exact path bytes, escapes included.
    decoded = scanner._mountinfo_field(b"/media/caf\xe9\\040disk\\134\\011\xff")
    assert os.fsencode(decoded) == b"/media/caf\xe9 disk\\\t\xff"

    (tmp_path / "regular.bin").write_bytes(b"123")
    assert _run_scan(tmp_path).size == 3


def test_hardlinks_are_not_double_counted(tmp_path):
    original = tmp_path / "original.bin"
    original.write_bytes(b"x" * 1000)
    linked = tmp_path / "linked.bin"
    os.link(original, linked)

    root = _run_scan(tmp_path)

    assert root.file_count == 2
    assert root.size == 1000

    children = _by_name(root)
    dup_flags = {children["original.bin"].hardlink_dup, children["linked.bin"].hardlink_dup}
    assert dup_flags == {False, True}


def test_hardlinks_are_not_double_counted_on_the_windows_stat_path(tmp_path, monkeypatch):
    """entry.stat() (from os.scandir) never populates real st_ino/st_dev/
    st_nlink on Windows -- always 0/0/1, regardless of actual link count,
    per CPython's own documented Windows limitation -- which silently
    disabled hard-link dedup on Windows entirely until _scan_one() was
    fixed to call os.stat() directly instead, on that platform. Forcing
    _IS_WINDOWS here exercises that exact branch on whatever host actually
    runs this test: a real hard link's st_ino/st_nlink are correct via
    os.stat() on any platform, so this doesn't need an actual Windows
    machine to catch a regression here."""
    monkeypatch.setattr(scanner, "_IS_WINDOWS", True)
    # Isolate this test to just the st_info/hard-link-identity branch under
    # test: _measure_alloc_size has its own, separate _IS_WINDOWS branch
    # that calls the real ctypes.windll (which doesn't exist at all on a
    # non-Windows host -- an AttributeError there would silently kill this
    # scan's worker thread, not what this test means to exercise).
    monkeypatch.setattr(scanner, "_measure_alloc_size", lambda path, st_info: st_info.st_size)

    original = tmp_path / "original.bin"
    original.write_bytes(b"x" * 1000)
    linked = tmp_path / "linked.bin"
    os.link(original, linked)

    root = _run_scan(tmp_path)

    assert root.file_count == 2
    assert root.size == 1000

    children = _by_name(root)
    dup_flags = {children["original.bin"].hardlink_dup, children["linked.bin"].hardlink_dup}
    assert dup_flags == {False, True}


def test_independent_files_are_each_counted(tmp_path):
    (tmp_path / "a.bin").write_bytes(b"x" * 100)
    (tmp_path / "b.bin").write_bytes(b"y" * 200)

    root = _run_scan(tmp_path)

    assert root.file_count == 2
    assert root.size == 300
    assert not any(child.hardlink_dup for child in root.children)


def test_rollup_propagates_a_grandchilds_error_all_the_way_to_the_root():
    """A permission-denied folder anywhere in the tree must leave every
    ancestor's size/file_count total visibly marked as incomplete (the ⚠
    icon in main_window._insert_node reads node.error directly) -- not
    just the one row that actually failed to list, which a user could
    easily never have expanded."""
    root = Node("C:\\Data", "Data")
    mid = Node("C:\\Data\\mid", "mid")
    locked = Node("C:\\Data\\mid\\locked", "locked")
    locked.error = True  # os.scandir() raised OSError on this one
    _file(root, "ok.bin", 100)

    mid.dirs.append(locked)
    root.dirs.append(mid)

    _rollup(root)

    assert locked.error is True
    assert mid.error is True  # propagated from its direct child
    assert root.error is True  # propagated transitively, in the same pass
    # The rest of the rollup still works normally alongside the propagation.
    assert root.size == 100


def test_rollup_leaves_error_false_when_nothing_failed():
    root = Node("C:\\Data", "Data")
    child = Node("C:\\Data\\ok", "ok")
    _file(child, "a.bin", 50)
    root.dirs.append(child)

    _rollup(root)

    assert child.error is False
    assert root.error is False


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="symlinks not supported")
def test_symlinked_directory_is_not_traversed(tmp_path):
    real_dir = tmp_path / "real"
    real_dir.mkdir()
    (real_dir / "inside.bin").write_bytes(b"z" * 5000)

    link_dir = tmp_path / "link_to_real"
    try:
        os.symlink(real_dir, link_dir, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("could not create a symlink in this environment")

    root = _run_scan(tmp_path)
    children = _by_name(root)

    assert children["real"].is_dir
    assert children["real"].size == 5000

    link_node = children["link_to_real"]
    assert not link_node.children
    assert root.size == children["real"].size + link_node.size


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="symlinks not supported")
def test_a_symlink_is_flagged_as_a_link(tmp_path):
    """A symbolic link is a link on every platform, not only on Windows
    (where it shows up as a reparse point). On POSIX it was recorded as an
    ordinary file, so it could be reported as a duplicate copy of the file
    it points at."""
    target = tmp_path / "target.log"
    target.write_bytes(b"y" * 50)
    link = tmp_path / "link.log"
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError):
        pytest.skip("could not create a symlink in this environment")

    root = _run_scan(tmp_path)
    children = _by_name(root)

    assert children["link.log"].is_link
    assert not children["target.log"].is_link


@pytest.mark.windows
def test_symlinked_file_is_billed_its_own_allocation_not_its_targets(tmp_path):
    # GetCompressedFileSizeW follows a symbolic link, so a link next to a
    # 50,000-byte file was billed that file's clusters a second time
    # (checklist runs 4-5: a glog .INFO link in Windows\Temp).
    target = tmp_path / "target.log"
    target.write_bytes(b"y" * 50000)
    link = tmp_path / "link.INFO"
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError):
        pytest.skip("could not create a symlink in this environment")

    root = _run_scan(tmp_path)
    children = _by_name(root)

    assert children["link.INFO"].is_link
    assert children["target.log"].alloc_size >= 50000
    assert children["link.INFO"].alloc_size < 50000
    assert root.alloc_size == children["target.log"].alloc_size + children["link.INFO"].alloc_size


def test_scanning_a_single_file_never_posts_a_live_tree(tmp_path):
    # A single-file target returns instantly -- there's no in-progress
    # tree worth watching, so scan() shouldn't claim there is one.
    target = tmp_path / "solo.bin"
    target.write_bytes(b"x" * 100)
    _root, messages = _run_scan_with_messages(target)

    assert not any(kind == "live_tree" for kind, _payload in messages)


# -- find_inaccessible_paths ------------------------------------------------ #


def test_find_inaccessible_paths_returns_empty_for_a_clean_tree():
    root = Node("/root", "root")
    _file(root, "ok.bin")

    assert find_inaccessible_paths(root) == []


def test_find_inaccessible_paths_finds_a_directory_that_could_not_be_listed():
    root = Node("/root", "root")
    locked = Node("/root/System Volume Information", "System Volume Information")
    locked.error = True  # scandir() failed -- no children were ever discovered
    root.dirs.append(locked)

    assert find_inaccessible_paths(root) == [locked]


def test_find_inaccessible_paths_finds_a_file_whose_metadata_could_not_be_read():
    root = Node("/root", "root")
    _file(root, "ok.bin")
    bad = _file(root, "locked.bin", flags=row_flags(error=True))

    assert find_inaccessible_paths(root) == [bad]


def test_find_inaccessible_paths_finds_errors_nested_several_levels_deep():
    root = Node("/root", "root")
    sub = Node("/root/sub", "sub")
    deep = Node("/root/sub/deep", "deep")
    root.dirs.append(sub)
    sub.dirs.append(deep)
    bad_file = _file(deep, "locked.bin", flags=row_flags(error=True))

    assert find_inaccessible_paths(root) == [bad_file]


def test_find_inaccessible_paths_collects_every_error_across_separate_branches():
    root = Node("/root", "root")
    bad_a = Node("/root/a", "a")
    bad_a.error = True
    ok = Node("/root/c", "c")
    root.dirs.extend([bad_a, ok])
    bad_b = _file(root, "b.bin", flags=row_flags(error=True))

    found = find_inaccessible_paths(root)

    assert set(found) == {bad_a, bad_b}


def test_find_inaccessible_paths_includes_the_root_itself_when_it_errored():
    # A single-file scan target whose own os.stat() failed (see scan()'s
    # early-return path) -- the whole "tree" is just this one errored node.
    root = detached_file("/solo.bin", flags=row_flags(error=True))

    assert find_inaccessible_paths(root) == [root]


@pytest.mark.windows
def test_a_name_ending_in_a_dot_is_scanned_as_itself_not_its_namesake(tmp_path):
    # Win32 reads `foo.` as `foo`. Found on a real drive by the Turbo Scan
    # checklist: foo.\a.txt (10 bytes) was listed as foo\a.txt's 6.
    literal = "\\\\?\\" + str(tmp_path)
    for folder, size in (("foo", 6), ("foo.", 10)):
        os.mkdir(os.path.join(literal, folder))
        with open(os.path.join(literal, folder, "a.txt"), "wb") as f:
            f.write(b"x" * size)
    with open(os.path.join(literal, "b. "), "wb") as f:
        f.write(b"x" * 3)

    root = _run_scan(tmp_path)
    folders = _by_name(root)

    assert _by_name(folders["foo."])["a.txt"].size == 10
    assert _by_name(folders["foo"])["a.txt"].size == 6
    assert folders["foo."].path == os.path.join(str(tmp_path), "foo.")
    assert _by_name(root)["b. "].size == 3
    assert root.size == 19
