#!/usr/bin/env python3
"""Fail-closed ZIP overlay installer for GitHub Actions.

Only allowlisted source trees may be updated; workflow files, Git metadata,
credentials and repository root settings must be installed via reviewed commits.
The install is staged and checks every archive entry before modifying files.
"""
from __future__ import annotations

import argparse
import os
import shutil
import stat
import sys
import tempfile
import zipfile
from pathlib import Path, PurePosixPath

DENIED_NAMES = {'.git', '.github', '__MACOSX', '.DS_Store', 'Thumbs.db', '.env', '.secrets', 'node_modules', '__pycache__'}
DENIED_SUFFIXES = ('.p8','.p12','.pem','.key','.mobileprovision','.sqlite','.sqlite3','.db','.pyc')
MAX_MEMBERS = 700
MAX_BYTES = 36 * 1024 * 1024
MAX_ONE_FILE = 9 * 1024 * 1024


def _safe_path(name: str, allowed: tuple[str,...]) -> str | None:
    if not name or '\\' in name or '\x00' in name or name.startswith('/') or name.startswith('~'):
        raise ValueError('unsafe_zip_path')
    p = PurePosixPath(name)
    if any(part in ('', '..', '.') for part in name.split('/')):
        raise ValueError('unsafe_zip_path')
    if p.parts[0].endswith(':') or any(part in DENIED_NAMES for part in p.parts) or name.lower().endswith(DENIED_SUFFIXES):
        raise ValueError('prohibited_file')
    if not any(name.startswith(prefix + '/') and len(name) > len(prefix)+1 for prefix in allowed):
        raise ValueError('outside_allowlist')
    return str(p)


def install(repo: Path, archive: Path, allowed: tuple[str,...]) -> int:
    repo = repo.resolve()
    archive = archive.resolve()
    if archive.parent != repo:
        raise ValueError('archive_must_be_in_repo_root')
    if archive.stat().st_size > MAX_BYTES:
        raise ValueError('archive_too_large')
    staged = []
    with zipfile.ZipFile(archive) as z:
        infos = [x for x in z.infolist() if not x.is_dir()]
        if not infos or len(infos) > MAX_MEMBERS:
            raise ValueError('invalid_archive_member_count')
        if sum(x.file_size for x in infos) > MAX_BYTES:
            raise ValueError('archive_uncompressed_too_large')
        seen = set()
        for item in infos:
            dest = _safe_path(item.filename, allowed)
            if item.file_size > MAX_ONE_FILE or item.compress_size == 0 and item.file_size != 0:
                raise ValueError('zip_bomb_or_large_file')
            if stat.S_IFMT(item.external_attr >> 16) == stat.S_IFLNK:
                raise ValueError('symlinks_not_allowed')
            if dest in seen:
                raise ValueError('duplicate_zip_entry')
            seen.add(dest)
            target = repo / dest
            # Existing symlinks in repo could otherwise escape the root on overwrite.
            for parent in (target, *target.parents):
                if parent == repo:
                    break
                if parent.is_symlink():
                    raise ValueError('destination_symlink')
            if not target.resolve().is_relative_to(repo):
                raise ValueError('destination_outside_repository')
            staged.append((item,target))
        with tempfile.TemporaryDirectory(prefix='spyderpay-install-') as tmp:
            tmp_path=Path(tmp)
            for item,target in staged:
                rel=target.relative_to(repo)
                destination=tmp_path / rel
                destination.parent.mkdir(parents=True,exist_ok=True)
                with z.open(item) as src, destination.open('wb') as dst:
                    shutil.copyfileobj(src,dst)
            # Stage successful; install source files. Clean files are never deleted.
            for _, target in staged:
                rel=target.relative_to(repo)
                target.parent.mkdir(parents=True,exist_ok=True)
                shutil.copyfile(tmp_path/rel,target)
    archive.unlink()  # Delete only successfully processed update ZIP.
    return len(staged)


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--repo', default='.')
    parser.add_argument('--pattern',required=True)
    parser.add_argument('--allow',action='append',required=True)
    args=parser.parse_args()
    repo=Path(args.repo).resolve()
    matches=sorted(repo.glob(args.pattern))
    if not matches:
        print('No matching update ZIP — nothing to do')
        return
    if len(matches)!=1:
        raise SystemExit('Exactly one update ZIP per push is required')
    count=install(repo,matches[0],tuple(args.allow))
    print(f'Installed {count} allowlisted files and removed {matches[0].name}')


if __name__=='__main__':
    try:
        main()
    except (OSError,zipfile.BadZipFile,ValueError) as exc:
        print(f'Safe ZIP unpack refused: {exc}',file=sys.stderr)
        raise SystemExit(2)
