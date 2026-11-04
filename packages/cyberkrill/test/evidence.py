#!/usr/bin/env python3
# Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
# Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
"""Atomically replace an evidence record with the supplied latest-run content."""
import os
from pathlib import Path
import tempfile


def write_record(path, serialized, encoding="utf-8"):
    path = Path(path)
    with tempfile.NamedTemporaryFile(mode="w", encoding=encoding, dir=path.parent,
                                     prefix=path.name + ".", delete=False) as output:
        temporary = Path(output.name)
        try:
            output.write(serialized)
            output.close()
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)
