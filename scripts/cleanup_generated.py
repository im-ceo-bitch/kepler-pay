#!/usr/bin/env python3
"""Delete ONLY known generated junk, never application source or arbitrary folders."""
from __future__ import annotations
from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parents[1]
FOLDERS={'__pycache__','__MACOSX','.pytest_cache','.mypy_cache','.ruff_cache'}
FILES={'.DS_Store','Thumbs.db'}


def clean(root:Path=ROOT)->int:
    count=0
    for p in list(root.rglob('*')):
        if p.is_symlink() or '.git' in p.relative_to(root).parts:continue
        if not p.exists():continue
        if p.is_file() and (p.name in FILES or p.suffix=='.pyc'):
            p.unlink();count+=1
    # Deepest-first so no parent directories are traversed after deletion.
    dirs=sorted((p for p in root.rglob('*') if p.is_dir() and not p.is_symlink()
                and '.git' not in p.relative_to(root).parts and p.name in FOLDERS),
                key=lambda p: len(p.parts),reverse=True)
    for p in dirs:
        if p.exists():shutil.rmtree(p);count+=1
    return count


if __name__=='__main__':print('Generated junk removed:',clean())
