#!/usr/bin/env python3
"""Normalize one Cargo executable into a private single-link artifact."""

from __future__ import annotations

import argparse
import os
import stat


if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
    raise SystemExit("platform lacks descriptor-relative no-symlink traversal")

DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
READ_FLAGS = os.O_RDONLY | os.O_NOFOLLOW


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--require-root", action="store_true")
    parser.add_argument("cargo_home")
    parser.add_argument("target")
    parser.add_argument("built_binary")
    parser.add_argument("normalized_binary")
    return parser.parse_args()


def open_directory_from_root(path: str) -> int:
    """Open an absolute directory while rejecting every symlink component."""
    absolute = os.path.abspath(path)
    if not os.path.isabs(path) or os.path.normpath(path) != absolute:
        raise SystemExit("directory path is not canonical and absolute")
    descriptor = os.open(os.sep, DIRECTORY_FLAGS)
    try:
        for component in absolute.split(os.sep):
            if not component:
                continue
            if component in (".", ".."):
                raise SystemExit("unsafe directory path component")
            next_descriptor = os.open(
                component,
                DIRECTORY_FLAGS,
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def open_relative_file(base_descriptor: int, relative: str) -> int:
    """Open a regular-file candidate below a bound directory without symlinks."""
    components = relative.split(os.sep)
    if (
        not relative
        or os.path.isabs(relative)
        or any(component in ("", ".", "..") for component in components)
    ):
        raise SystemExit("unsafe Cargo artifact relative path")
    directory = os.dup(base_descriptor)
    try:
        for component in components[:-1]:
            next_directory = os.open(
                component,
                DIRECTORY_FLAGS,
                dir_fd=directory,
            )
            os.close(directory)
            directory = next_directory
        return os.open(components[-1], READ_FLAGS, dir_fd=directory)
    finally:
        os.close(directory)


def normalize(args: argparse.Namespace) -> None:
    effective_uid = os.geteuid()
    effective_gid = os.getegid()
    if args.require_root and (effective_uid != 0 or effective_gid != 0):
        raise SystemExit("artifact normalization did not run as root")

    cargo_home = os.path.abspath(args.cargo_home)
    target = os.path.abspath(args.target)
    built_binary = os.path.abspath(args.built_binary)
    normalized_binary = os.path.abspath(args.normalized_binary)
    guest_root = os.path.dirname(target)
    if os.path.basename(target) != "target":
        raise SystemExit("private target has an unexpected name")
    if cargo_home != os.path.join(guest_root, "cargo-home"):
        raise SystemExit("private CARGO_HOME escaped its guest root")
    if os.path.commonpath((target, built_binary)) != target:
        raise SystemExit("Cargo artifact escaped the private target")
    artifact_dir = os.path.join(guest_root, "artifact")
    expected_normalized = os.path.join(
        artifact_dir,
        os.path.basename(built_binary),
    )
    if normalized_binary != expected_normalized:
        raise SystemExit("normalized artifact path is outside its private boundary")

    guest_root_fd = open_directory_from_root(guest_root)
    try:
        guest_root_info = os.fstat(guest_root_fd)
        if (
            not stat.S_ISDIR(guest_root_info.st_mode)
            or guest_root_info.st_uid != effective_uid
            or guest_root_info.st_gid != effective_gid
        ):
            raise SystemExit("guest root is not an owned directory")
        target_fd = os.open("target", DIRECTORY_FLAGS, dir_fd=guest_root_fd)
        try:
            target_info = os.fstat(target_fd)
            if (
                not stat.S_ISDIR(target_info.st_mode)
                or target_info.st_uid != effective_uid
                or target_info.st_gid != effective_gid
            ):
                raise SystemExit("private target is not an owned directory")
            relative_built = os.path.relpath(built_binary, target)
            source_fd = open_relative_file(target_fd, relative_built)
            try:
                source_before = os.fstat(source_fd)
                if (
                    not stat.S_ISREG(source_before.st_mode)
                    or source_before.st_nlink < 1
                    or source_before.st_uid != effective_uid
                    or source_before.st_gid != effective_gid
                    or not (source_before.st_mode & 0o111)
                    or source_before.st_mode & 0o7000
                    or source_before.st_size < 1
                ):
                    raise SystemExit(
                        "Cargo build did not produce an owned, executable regular file"
                    )

                os.mkdir("artifact", 0o700, dir_fd=guest_root_fd)
                artifact_fd = os.open(
                    "artifact",
                    DIRECTORY_FLAGS,
                    dir_fd=guest_root_fd,
                )
                try:
                    artifact_info = os.fstat(artifact_fd)
                    if (
                        not stat.S_ISDIR(artifact_info.st_mode)
                        or artifact_info.st_uid != effective_uid
                        or artifact_info.st_gid != effective_gid
                        or stat.S_IMODE(artifact_info.st_mode) != 0o700
                    ):
                        raise SystemExit("private artifact directory is invalid")
                    destination_flags = (
                        os.O_WRONLY
                        | os.O_CREAT
                        | os.O_EXCL
                        | os.O_NOFOLLOW
                    )
                    destination_fd = os.open(
                        os.path.basename(normalized_binary),
                        destination_flags,
                        0o700,
                        dir_fd=artifact_fd,
                    )
                    try:
                        copied = 0
                        while True:
                            chunk = os.read(source_fd, 1024 * 1024)
                            if not chunk:
                                break
                            view = memoryview(chunk)
                            while view:
                                written = os.write(destination_fd, view)
                                if written < 1:
                                    raise SystemExit(
                                        "normalized artifact write made no progress"
                                    )
                                copied += written
                                view = view[written:]
                        os.fchmod(destination_fd, 0o755)
                        os.fsync(destination_fd)
                        destination = os.fstat(destination_fd)
                    finally:
                        os.close(destination_fd)
                    source_after = os.fstat(source_fd)
                    os.fsync(artifact_fd)
                finally:
                    os.close(artifact_fd)
            finally:
                os.close(source_fd)
        finally:
            os.close(target_fd)
    finally:
        os.close(guest_root_fd)

    source_identity_before = (
        source_before.st_dev,
        source_before.st_ino,
        source_before.st_mode,
        source_before.st_nlink,
        source_before.st_uid,
        source_before.st_gid,
        source_before.st_size,
        source_before.st_mtime_ns,
        source_before.st_ctime_ns,
    )
    source_identity_after = (
        source_after.st_dev,
        source_after.st_ino,
        source_after.st_mode,
        source_after.st_nlink,
        source_after.st_uid,
        source_after.st_gid,
        source_after.st_size,
        source_after.st_mtime_ns,
        source_after.st_ctime_ns,
    )
    if source_identity_before != source_identity_after:
        raise SystemExit("Cargo artifact changed while it was normalized")
    if (
        not stat.S_ISREG(destination.st_mode)
        or destination.st_nlink != 1
        or destination.st_uid != effective_uid
        or destination.st_gid != effective_gid
        or stat.S_IMODE(destination.st_mode) != 0o755
        or destination.st_size != source_before.st_size
        or copied != source_before.st_size
    ):
        raise SystemExit("normalized executable boundary is invalid")

    cargo_home_fd = open_directory_from_root(cargo_home)
    try:
        cargo_home_info = os.fstat(cargo_home_fd)
        if (
            not stat.S_ISDIR(cargo_home_info.st_mode)
            or cargo_home_info.st_uid != effective_uid
            or cargo_home_info.st_gid != effective_gid
        ):
            raise SystemExit("private CARGO_HOME is not an owned directory")
        entries = sorted(os.listdir(cargo_home_fd))
    finally:
        os.close(cargo_home_fd)
    if "config.toml" not in entries:
        raise SystemExit(
            "private CARGO_HOME lost its source replacement config"
        )
    print("cargo_build_frozen=true")
    print("cargo_source_replacement_cli=true")
    print("cargo_build_network_namespace=isolated")
    print("cargo_preexisting_cache_used=false")
    print(f"cargo_artifact_source_nlink={source_before.st_nlink}")
    print("normalized_artifact_regular=true")
    print("normalized_artifact_nlink=1")
    print("normalized_artifact_mode=0755")
    print(f"normalized_artifact_bytes={destination.st_size}")
    print(f"cargo_home_post_entries={len(entries)}")


def main() -> None:
    normalize(parse_args())


if __name__ == "__main__":
    main()
