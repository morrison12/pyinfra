"""
The files facts provide information about the filesystem and it's contents on the target host.

Facts need to be imported before use, eg

from pyinfra.facts.files import File
"""

from __future__ import annotations

import re
import shlex
import stat
from collections.abc import Iterable, Sequence
from datetime import datetime, timezone
from typing import TYPE_CHECKING, List, NamedTuple, Optional, Tuple, Union, get_args

import dateutil.parser
from typing_extensions import Literal, NotRequired, TypedDict, override

from pyinfra import logger
from pyinfra.api import StringCommand
from pyinfra.api.command import QuoteString, make_formatted_string_command
from pyinfra.api.facts import FactBase
from pyinfra.api.util import try_int
from pyinfra.facts.util.units import parse_size

LINUX_STAT_COMMAND = "stat -c 'user=%U group=%G mode=%A atime=%X mtime=%Y ctime=%Z size=%s %N'"
BSD_STAT_COMMAND = "stat -f 'user=%Su group=%Sg mode=%Sp atime=%a mtime=%m ctime=%c size=%z %N%SY'"
LS_COMMAND = "ls -ld"

STAT_REGEX = (
    r"user=(.*) group=(.*) mode=(.*) "
    r"atime=(-?[0-9]*) mtime=(-?[0-9]*) ctime=(-?[0-9]*) "
    r"size=([0-9]*) (.*)"
)

# ls -ld output: permissions links user group size month day year/time path
# Supports attribute markers: . (SELinux), @ (extended attrs), + (ACL)
# Handles both "MMM DD" and "DD MMM" date formats
LS_REGEX = (
    r"^([dlbcsp-][-rwxstST]{9}[.@+]?)\s+\d+\s+(\S+)\s+(\S+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.+)$"
)

FLAG_TO_TYPE = {
    "b": "block",
    "c": "character",
    "d": "directory",
    "l": "link",
    "s": "socket",
    "p": "fifo",
    "-": "file",
}

# Each item is a map of character to permission octal to be combined, taken from stdlib:
# https://github.com/python/cpython/blob/c1c3be0f9dc414bfae9a5718451ca217751ac687/Lib/stat.py#L128-L154
CHAR_TO_PERMISSION = (
    # User
    {"r": stat.S_IRUSR},
    {"w": stat.S_IWUSR},
    {"x": stat.S_IXUSR, "S": stat.S_ISUID, "s": stat.S_IXUSR | stat.S_ISUID},
    # Group
    {"r": stat.S_IRGRP},
    {"w": stat.S_IWGRP},
    {"x": stat.S_IXGRP, "S": stat.S_ISGID, "s": stat.S_IXGRP | stat.S_ISGID},
    # Other
    {"r": stat.S_IROTH},
    {"w": stat.S_IWOTH},
    {"x": stat.S_IXOTH, "T": stat.S_ISVTX, "t": stat.S_IXOTH | stat.S_ISVTX},
)


def _parse_mode(mode: str) -> int:
    """
    Converts ls mode output (rwxrwxrwx) -> octal permission integer (755).
    """

    out = 0

    for i, char in enumerate(mode):
        for c, m in CHAR_TO_PERMISSION[i].items():
            if char == c:
                out |= m
                break

    return int(oct(out)[2:])


def _parse_datetime(value: str) -> Optional[datetime]:
    value = try_int(value)
    if isinstance(value, int):
        return datetime.fromtimestamp(value, timezone.utc).replace(tzinfo=None)
    return None


def _parse_ls_timestamp(month: str, day: str, year_or_time: str) -> Optional[datetime]:
    """
    Parse ls timestamp format.
    Examples: "Jan  1  1970", "Apr  2  2025", "Dec 31 12:34"
    """
    try:
        # Month abbreviation to number mapping
        month_map = {
            "Jan": 1,
            "Feb": 2,
            "Mar": 3,
            "Apr": 4,
            "May": 5,
            "Jun": 6,
            "Jul": 7,
            "Aug": 8,
            "Sep": 9,
            "Oct": 10,
            "Nov": 11,
            "Dec": 12,
        }

        month_num = month_map.get(month)
        if month_num is None:
            return None

        day_num = int(day)

        # Check if year_or_time is a year (4 digits) or time (HH:MM)
        if ":" in year_or_time:
            # It's a time, assume current year
            import time

            current_year = time.gmtime().tm_year
            hour, minute = map(int, year_or_time.split(":"))
            return datetime(current_year, month_num, day_num, hour, minute)
        else:
            # It's a year
            year_num = int(year_or_time)
            return datetime(year_num, month_num, day_num)

    except (ValueError, TypeError):
        return None


def _parse_ls_output(output: str) -> Optional[tuple[FileDict, str]]:
    """
    Parse ls -ld output and extract file information.
    Example: drwxr-xr-x    1 root     root           416 Jan  1  1970 /
    """
    match = re.match(LS_REGEX, output.strip())
    if not match:
        return None

    permissions = match.group(1)
    user = match.group(2)
    group = match.group(3)
    size = match.group(4)
    date_part1 = match.group(5)
    date_part2 = match.group(6)
    year_or_time = match.group(7)
    path = match.group(8)

    # Determine if it's "MMM DD" or "DD MMM" format
    if date_part1.isdigit():
        # "DD MMM" format (e.g., "22 Jun")
        day = date_part1
        month = date_part2
    else:
        # "MMM DD" format (e.g., "Jun 22")
        month = date_part1
        day = date_part2

    # Extract file type from first character of permissions
    path_type = FLAG_TO_TYPE[permissions[0]]

    # Parse mode (skip first character which is file type, and any trailing attribute markers)
    # Remove trailing attribute markers (.@+) if present
    mode_str = permissions[1:10]  # Take exactly 9 characters after file type
    mode = _parse_mode(mode_str)

    # Parse timestamp - ls shows modification time
    mtime = _parse_ls_timestamp(month, day, year_or_time)

    data: FileDict = {
        "user": user,
        "group": group,
        "mode": mode,
        "atime": None,  # ls doesn't provide atime
        "mtime": mtime,
        "ctime": None,  # ls doesn't provide ctime
        "size": try_int(size),
    }

    # Handle symbolic links
    if path_type == "link" and " -> " in path:
        filename, target = path.split(" -> ", 1)
        data["link_target"] = target.strip("'").lstrip("`")

    return data, path_type


class FileDict(TypedDict):
    mode: int
    size: Union[int, str]
    atime: Optional[datetime]
    mtime: Optional[datetime]
    ctime: Optional[datetime]
    user: str
    group: str
    link_target: NotRequired[str]


class File(FactBase[Union[FileDict, Literal[False], None]]):
    """
    Returns information about a file on the remote system:

    .. code:: python

        {
            "user": "pyinfra",
            "group": "pyinfra",
            "mode": 644,
            "size": 3928,
        }

    If the path does not exist:
        returns ``None``

    If the path exists but is not a file:
        returns ``False``
    """

    type = "file"

    @override
    def command(self, path):
        if path.startswith("~/"):
            # Do not quote leading tilde to ensure that it gets properly expanded by the shell
            path = f"~/{shlex.quote(path[2:])}"
        else:
            path = QuoteString(path)

        return make_formatted_string_command(
            (
                # only stat if the path exists (file or symlink)
                "! (test -e {0} || test -L {0} ) || "
                "( {linux_stat_command} {0} 2> /dev/null || "
                "{bsd_stat_command} {0} || {ls_command} {0} )"
            ),
            path,
            linux_stat_command=LINUX_STAT_COMMAND,
            bsd_stat_command=BSD_STAT_COMMAND,
            ls_command=LS_COMMAND,
        )

    @override
    def process(self, output) -> Union[FileDict, Literal[False], None]:
        # Try to parse as stat output first
        match = re.match(STAT_REGEX, output[0])
        if match:
            mode = match.group(3)
            path_type = FLAG_TO_TYPE[mode[0]]

            data: FileDict = {
                "user": match.group(1),
                "group": match.group(2),
                "mode": _parse_mode(mode[1:]),
                "atime": _parse_datetime(match.group(4)),
                "mtime": _parse_datetime(match.group(5)),
                "ctime": _parse_datetime(match.group(6)),
                "size": try_int(match.group(7)),
            }

            if path_type != self.type:
                return False

            if path_type == "link":
                filename = match.group(8)
                filename, target = filename.split(" -> ")
                data["link_target"] = target.strip("'").lstrip("`")

            return data

        # Try to parse as ls output
        ls_result = _parse_ls_output(output[0])
        if ls_result is not None:
            data, path_type = ls_result

            if path_type != self.type:
                return False

            return data

        return None


class Link(File):
    """
    Returns information about a link on the remote system:

    .. code:: python

        {
            "user": "pyinfra",
            "group": "pyinfra",
            "link_target": "/path/to/link/target"
        }

    If the path does not exist:
        returns ``None``

    If the path exists but is not a link:
        returns ``False``
    """

    type = "link"


class Directory(File):
    """
    Returns information about a directory on the remote system:

    .. code:: python

        {
            "user": "pyinfra",
            "group": "pyinfra",
            "mode": 644,
        }

    If the path does not exist:
        returns ``None``

    If the path exists but is not a directory:
        returns ``False``
    """

    type = "directory"


class Socket(File):
    """
    Returns information about a socket on the remote system:

    .. code:: python

        {
            "user": "pyinfra",
            "group": "pyinfra",
        }

    If the path does not exist:
        returns ``None``

    If the path exists but is not a socket:
        returns ``False``
    """

    type = "socket"


if TYPE_CHECKING:
    FactBaseOptionalStr = FactBase[Optional[str]]
else:
    FactBaseOptionalStr = FactBase


class HashFileFactBase(FactBaseOptionalStr):
    _raw_cmd: str
    _regexes: Tuple[str, str]

    @override
    def __init_subclass__(cls, digits: int, cmds: List[str], **kwargs) -> None:
        super().__init_subclass__(**kwargs)

        raw_hash_cmds = ["%s {0} 2> /dev/null" % cmd for cmd in cmds]
        raw_hash_cmd = " || ".join(raw_hash_cmds)
        cls._raw_cmd = "test -e {0} && ( %s ) || true" % raw_hash_cmd

        assert cls.__name__.endswith("File")
        hash_name = cls.__name__[:-4].upper()
        cls._regexes = (
            # GNU coreutils style:
            r"^([a-fA-F0-9]{%d})\s+%%s$" % digits,
            # BSD style:
            r"^%s\s+\(%%s\)\s+=\s+([a-fA-F0-9]{%d})$" % (hash_name, digits),
        )

    @override
    def command(self, path):
        self.path = path
        return make_formatted_string_command(self._raw_cmd, QuoteString(path))

    @override
    def process(self, output) -> Optional[str]:
        output = output[0]
        escaped_path = re.escape(self.path)
        for regex in self._regexes:
            matches = re.match(regex % escaped_path, output)
            if matches:
                return matches.group(1)
        return None


class Sha1File(HashFileFactBase, digits=40, cmds=["sha1sum", "shasum", "sha1"]):
    """
    Returns a SHA1 hash of a file. Works with both sha1sum and sha1. Returns
    ``None`` if the file doest not exist.
    """


class Sha256File(HashFileFactBase, digits=64, cmds=["sha256sum", "shasum -a 256", "sha256"]):
    """
    Returns a SHA256 hash of a file, or ``None`` if the file does not exist.
    """


class Sha384File(HashFileFactBase, digits=96, cmds=["sha384sum", "shasum -a 384", "sha384"]):
    """
    Returns a SHA384 hash of a file, or ``None`` if the file does not exist.
    """


class Md5File(HashFileFactBase, digits=32, cmds=["md5sum", "md5"]):
    """
    Returns an MD5 hash of a file, or ``None`` if the file does not exist.
    """


class FindInFile(FactBase):
    """
    Checks for the existence of text in a file using grep. Returns a list of matching
    lines if the file exists, and ``None`` if the file does not.
    """

    @override
    def command(self, path, pattern, interpolate_variables=False):
        self.exists_flag = "__pyinfra_exists_{0}".format(path)

        if interpolate_variables:
            pattern = '"{0}"'.format(pattern.replace('"', '\\"'))
        else:
            pattern = QuoteString(pattern)

        return make_formatted_string_command(
            (
                "grep -e {0} {1} 2> /dev/null || "
                "( find {1} -type f > /dev/null && echo {2} || true )"
            ),
            pattern,
            QuoteString(path),
            QuoteString(self.exists_flag),
        )

    @override
    def process(self, output):
        # If output is the special string: no matches, so return an empty list;
        # this allows us to differentiate between no matches in an existing file
        # or a file not existing.
        if output and output[0] == self.exists_flag:
            return []

        return output


class FindFilesBase(FactBase):
    abstract = True
    default = list
    type_flag: str

    @override
    def process(self, output):
        return output

    @override
    def command(
        self,
        path: str,
        size: Optional[str | int] = None,
        min_size: Optional[str | int] = None,
        max_size: Optional[str | int] = None,
        maxdepth: Optional[int] = None,
        fname: Optional[str] = None,
        iname: Optional[str] = None,
        regex: Optional[str] = None,
        args: Optional[List[str]] = None,
        quote_path=True,
    ):
        """
        @param path: the path to start the search from
        @param size: exact size in bytes or human-readable format.
                     GB means 1e9 bytes, GiB means 2^30 bytes
        @param min_size: minimum size in bytes or human-readable format
        @param max_size: maximum size in bytes or human-readable format
        @param maxdepth: maximum depth to descend to
        @param name: True if the last component of the pathname being examined matches pattern.
                      Special shell pattern matching characters (“[”, “]”, “*”, and “?”)
                      may be used as part of pattern.
                      These characters may be matched explicitly
                      by escaping them with a backslash (“\\”).

        @param iname: Like -name, but the match is case insensitive.
        @param regex: True if the whole path of the file matches pattern using regular expression.
        @param args: additional arguments to pass to find
        @param quote_path: if the path should be quoted
        @return:
        """
        if args is None:
            args = []

        def maybe_quote(value):
            return QuoteString(value) if quote_path else value

        command = [
            "find",
            maybe_quote(path),
            "-type",
            self.type_flag,
        ]

        """
        Why we need special handling for size:
        https://unix.stackexchange.com/questions/275925/why-does-find-size-1g-not-find-any-files
        In short, 'c' means bytes, without it, it means 512-byte blocks.
        If we use any units other than 'c', it has a weird rounding behavior,
        and is implementation-specific. So, we always use 'c'
        """
        if "-size" not in args:
            if min_size is not None:
                command.append("-size")
                command.append("+{0}c".format(parse_size(min_size)))

            if max_size is not None:
                command.append("-size")
                command.append("-{0}c".format(parse_size(max_size)))

            if size is not None:
                command.append("-size")
                command.append("{0}c".format(size))

        if maxdepth is not None and "-maxdepth" not in args:
            command.append("-maxdepth")
            command.append("{0}".format(maxdepth))

        if fname is not None and "-fname" not in args:
            command.append("-name")
            command.append(maybe_quote(fname))

        if iname is not None and "-iname" not in args:
            command.append("-iname")
            command.append(maybe_quote(iname))

        if regex is not None and "-regex" not in args:
            command.append("-regex")
            command.append(maybe_quote(regex))

        command.extend(args)

        command.append("||")
        command.append("true")

        return StringCommand(*command)


class FindFiles(FindFilesBase):
    """
    Returns a list of files from a start path, recursively using ``find``.
    """

    type_flag = "f"


class FindLinks(FindFilesBase):
    """
    Returns a list of links from a start path, recursively using ``find``.
    """

    type_flag = "l"


class FindDirectories(FindFilesBase):
    """
    Returns a list of directories from a start path, recursively using ``find``.
    """

    type_flag = "d"


class Flags(FactBase):
    """
    Returns a list of the file flags set for the specified file or directory.
    """

    @override
    def requires_command(self, path) -> str:
        return "chflags"  # don't try to retrieve them if we can't set them

    @override
    def command(self, path):
        return make_formatted_string_command(
            "! test -e {0} || stat -f %Sf {0}",
            QuoteString(path),
        )

    @override
    def process(self, output):
        return [flag for flag in output[0].split(",") if len(flag) > 0] if len(output) == 1 else []


MARKER_DEFAULT = "# {mark} PYINFRA BLOCK"
MARKER_BEGIN_DEFAULT = "BEGIN"
MARKER_END_DEFAULT = "END"
EXISTS = "__pyinfra_exists_"
MISSING = "__pyinfra_missing_"


class Block(FactBase):
    """
    Returns a (possibly empty) list of the lines found between the markers.

    .. code:: python

        [
            "xray: one",
            "alpha: two"
        ]

    If the ``path`` doesn't exist
        returns ``None``

    If the ``path`` exists but the markers are not found
        returns ``[]``
    """

    # if markers aren't found, awk will return 0 and produce no output but we need to
    # distinguish between "markers not found" and "markers found but nothing between them"
    # for the former we use the empty list (created the call to default) and for the latter
    # the list with a single empty string.
    default = list

    @override
    def command(self, path, marker=None, begin=None, end=None):
        self.path = path
        start = (marker or MARKER_DEFAULT).format(mark=begin or MARKER_BEGIN_DEFAULT)
        end = (marker or MARKER_DEFAULT).format(mark=end or MARKER_END_DEFAULT)
        if start == end:
            raise ValueError(f"delimiters for block must be different but found only '{start}'")

        backstop = make_formatted_string_command(
            "(find {0} -type f > /dev/null && echo {1} || echo {2} )",
            QuoteString(path),
            QuoteString(f"{EXISTS}{path}"),
            QuoteString(f"{MISSING}{path}"),
        )

        cmd = StringCommand(
            f"awk '/{end}/{{ f=0}} f; /{start}/{{ f=1}} ' ",
            QuoteString(path),
            " || ",
            backstop,
            _separator="",
        )
        return cmd

    @override
    def process(self, output):
        if output and (output[0] == f"{EXISTS}{self.path}"):
            return []
        if output and (output[0] == f"{MISSING}{self.path}"):
            return None
        return output


class FileContents(FactBase):
    """
    Returns the contents of a file as a list of lines, or ``None`` if the file does not exist.
    """

    @override
    def command(self, path):
        self.missing_flag = "{0}{1}".format(MISSING, path)
        return make_formatted_string_command(
            "( test -e {0} && cat {0} ) || echo {1}",
            QuoteString(path),
            QuoteString(self.missing_flag),
        )

    @override
    def process(self, output):
        # If output is the missing flag, the file doesn't exist
        if output and output[0] == self.missing_flag:
            return None
        return output


ERROR = "_pyinfra_error"

ArchiveFormatType = Literal["bz2", "gz", "tar", "xz", "zip", "zstd"]
KNOWN_ARCHIVE_KINDS = set(get_args(ArchiveFormatType))


class ArchInfo(NamedTuple):
    archive: list[str]
    compress: list[str]
    unarchive: list[str]
    uncompress: list[str]
    view_toc: list[str]


TAR_NO_PIPE = ["tar", "cf"]
TAR = [*TAR_NO_PIPE, "|"]
UNTAR = ["|", "tar", "xf"]
VIEW_TAR = ["|", "tar", "tvf", "-"]

ARCH_INFO = {
    "bz2": ArchInfo(TAR, ["|", "bzip2"], UNTAR, ["bzcat"], VIEW_TAR),
    "gz": ArchInfo(TAR, ["|", "gzip"], UNTAR, ["gzcat"], VIEW_TAR),
    "tar": ArchInfo(TAR_NO_PIPE, [], UNTAR, ["cat"], VIEW_TAR),
    "xz": ArchInfo(TAR, ["|", "xz"], UNTAR, ["xzcat"], VIEW_TAR),
    "zip": ArchInfo([], ["zip", "-r"], [], ["unzip", "-q"], ["unzip", "-Zl"]),
    "zstd": ArchInfo(TAR, ["|", "zstd"], UNTAR, ["zstdcat"], VIEW_TAR),
}
if set(ARCH_INFO) != KNOWN_ARCHIVE_KINDS:
    raise RuntimeError("ARCH_INFO keys do not match KNOWN_ARCHIVE_KINDS")


class TocEntry(NamedTuple):
    name: str
    size: int
    timestamp: datetime


# example: -rw-r--r--  3.0 unx    20578 tx     7960 defN 26-Mar-15 17:33 CHANGELOG.md
ZIP_REGEX = re.compile(
    r"""
                        ^
                        \s*
                        (?P<perms>[^\s]+)\s+
                        ([^\s]+\s+){2}
                        (?P<size>\d+)\s+
                        ([^\s]+\s+){3}
                        (?P<datetime>[^\s]+\s[^\s]+)\s+
                        (?P<name>.*)
                        $
                        """,
    re.VERBOSE,
)

# example: rw-r--r--  0 james  staff   20578 Mar 15 17:33 CHANGELOG.md
TAR_REGEX = re.compile(
    r"""
                        ^
                        \s*
                        (?P<perms>[^\s]+)\s+
                        ([^\s]+\s+){3}
                        (?P<size>\d+)\s+
                        (?P<datetime>[^\s]+\s[^\s]+\s[^\s]+)\s+
                        (?P<name>.*)
                        $
                        """,
    re.VERBOSE,
)


class ArchiveFiles(FactBase[list[TocEntry] | None]):
    """
    Returns the list of files contained in the archive.

    + path: path to the archive
    + kind: format of archive: : ``bz2``, ``gz``, ``xz``, ``zip``, ``zstd`` or ``tar``

    Returns None if ``path`` doesn't exist and [] if the archive can't be read.
    """

    # NOTE: to maximize portability only tar is used, not gtar

    @staticmethod
    def default() -> list[TocEntry] | None:
        return []

    @override
    def requires_command(self, path: str, fmt: ArchiveFormatType) -> str | None:  # noqa: ARG002
        """
        Make sure we have the command we need for this kind of archive.
        Only 'tar' is required, not 'gtar' to maximize portability at the cost of some
        complexity in the
        """
        # FIXME - need decompressor as well as tar but not clear how to require multiple commands
        # bad format caught in command which, at least today, is called before requires_command
        return ARCH_INFO[fmt].view_toc[0]

    @override
    def command(self, path: str, fmt: ArchiveFormatType) -> StringCommand | str:
        if fmt not in KNOWN_ARCHIVE_KINDS:
            raise ValueError(f"Unsupported archive format: '{fmt}'")

        self.fmt = fmt
        path_q = QuoteString(path)  # FIXME - need QuotePath that doesn't quote ~ at start of path
        if fmt == "zip":
            cmd = [*ARCH_INFO[fmt].view_toc, path_q]
        else:
            cmd = [
                *ARCH_INFO[fmt].uncompress,
                path_q,
                *ARCH_INFO[fmt].view_toc,
                # failure of decompressor doesn't propagate across pipe (no pipefail in sh) so check
                *["&&", "[[", "${PIPESTATUS[0]}", "-eq", "0", "]]"],
            ]
        cmd = [*cmd, "||", "echo", ERROR]
        exists = ["(", "test", "-f", path_q, "||", "test", "-L", path_q, ")"]
        return StringCommand(*exists, "&&", "(", *cmd, ")", "2>/dev/null", "||", "echo", MISSING)

    def output_to_entries(self, output: Iterable[str], regex: re.Pattern[str]) -> list[TocEntry]:
        result = []
        for line in output:
            if (match := regex.match(line)) is not None:
                ts = dateutil.parser.parse(match.group("datetime"))  # TODO handle convert errors
                result.append(TocEntry(match.group("name"), int(match.group("size")), ts))
            else:
                logger.warning(f"could not parse {self.fmt} table of contents entry: {line}")
        return result

    @override
    def process(self, output: Sequence[str]) -> list[TocEntry] | None:
        """
        Parse through the results.
        Return NONE if the file was MISSING and the empty list ([]) if there were errors with
        getting the list of files.
        """
        if output[0] == MISSING:
            return None

        if self.fmt != "zip":
            return [] if output[0] == ERROR else self.output_to_entries(output, TAR_REGEX)

        # for zip ignore first line which is Archive:  <path> when checking for error
        if any(output[idx] == ERROR for idx in [0, 1, -1]):  # seems ouput on both stdout & stderr
            return []
        # for zip, skip the first two lines and the last line
        return self.output_to_entries(output[2:-1], ZIP_REGEX)
