"""
File Integrity Monitoring (FIM) Engine
Emulates Wazuh / OSSEC Syscheck functionality:
- Cryptographic hashing (MD5, SHA1, SHA256)
- File attribute tracking (Size, Permissions, Timestamps)
- Content Unified Diff generation (equivalent to Wazuh `report_changes="yes"`)
- Real-time delta detection across monitored directories
"""

import os
import sys
import time
import hashlib
import difflib
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any

class FIMFileSnapshot:
    """Represents the cryptographic and metadata state of a monitored file."""
    def __init__(self, path: str):
        self.path = os.path.abspath(path)
        self.filename = os.path.basename(self.path)
        self.exists = os.path.exists(self.path)
        self.size = 0
        self.md5 = ""
        self.sha1 = ""
        self.sha256 = ""
        self.mtime = 0.0
        self.permissions = ""
        self.is_binary = False
        self.content_lines: List[str] = []

        if self.exists and os.path.isfile(self.path):
            self._capture()

    def _capture(self):
        try:
            stat = os.stat(self.path)
            self.size = stat.st_size
            self.mtime = stat.st_mtime
            self.permissions = oct(stat.st_mode)[-3:]

            with open(self.path, "rb") as f:
                data = f.read()
                self.md5 = hashlib.md5(data).hexdigest()
                self.sha1 = hashlib.sha1(data).hexdigest()
                self.sha256 = hashlib.sha256(data).hexdigest()

            # Check if binary (contains null byte or fails strict utf-8 decode)
            if b"\x00" in data:
                self.is_binary = True
            else:
                try:
                    text = data.decode("utf-8")
                    self.content_lines = text.splitlines(keepends=True)
                except UnicodeDecodeError:
                    self.is_binary = True
        except (PermissionError, FileNotFoundError):
            self.exists = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "filename": self.filename,
            "exists": self.exists,
            "size": self.size,
            "md5": self.md5,
            "sha1": self.sha1,
            "sha256": self.sha256,
            "mtime": self.mtime,
            "permissions": self.permissions,
        }


class FIMEngine:
    """Core Syscheck engine performing baseline indexing and difference detection."""

    def __init__(self, monitored_paths: List[str]):
        self.monitored_paths = [os.path.abspath(p) for p in monitored_paths]
        self.database: Dict[str, FIMFileSnapshot] = {}
        self.ignore_patterns = [".git", "__pycache__", ".tmp", ".swp"]

    def build_baseline(self) -> int:
        """Scan all monitored paths and record initial cryptographic baseline."""
        self.database.clear()
        count = 0
        for root_path in self.monitored_paths:
            if not os.path.exists(root_path):
                continue
            if os.path.isfile(root_path):
                self.database[root_path] = FIMFileSnapshot(root_path)
                count += 1
            elif os.path.isdir(root_path):
                for dirpath, _, filenames in os.walk(root_path):
                    if any(ign in dirpath for ign in self.ignore_patterns):
                        continue
                    for fname in filenames:
                        full_path = os.path.abspath(os.path.join(dirpath, fname))
                        self.database[full_path] = FIMFileSnapshot(full_path)
                        count += 1
        return count

    def scan_for_changes(self) -> List[Dict[str, Any]]:
        """
        Compare current filesystem state against the baseline database.
        Returns a list of FIM events: FILE_CREATED, FILE_MODIFIED, FILE_DELETED.
        """
        events = []
        current_files: Dict[str, FIMFileSnapshot] = {}

        # 1. Discover all current files
        for root_path in self.monitored_paths:
            if not os.path.exists(root_path):
                continue
            if os.path.isfile(root_path):
                current_files[root_path] = FIMFileSnapshot(root_path)
            elif os.path.isdir(root_path):
                for dirpath, _, filenames in os.walk(root_path):
                    if any(ign in dirpath for ign in self.ignore_patterns):
                        continue
                    for fname in filenames:
                        full_path = os.path.abspath(os.path.join(dirpath, fname))
                        current_files[full_path] = FIMFileSnapshot(full_path)

        # 2. Check for newly created or modified files
        for path, current_snap in current_files.items():
            if path not in self.database:
                # NEW FILE CREATION
                event = {
                    "event_type": "FILE_CREATED",
                    "path": path,
                    "filename": current_snap.filename,
                    "timestamp": time.time(),
                    "size": current_snap.size,
                    "sha256": current_snap.sha256,
                    "md5": current_snap.md5,
                    "permissions": current_snap.permissions,
                    "diff": None
                }
                events.append(event)
                self.database[path] = current_snap
            else:
                baseline_snap = self.database[path]
                # Compare cryptographic hashes and permissions
                if current_snap.sha256 != baseline_snap.sha256 or current_snap.permissions != baseline_snap.permissions:
                    # Generate unified diff if text file (Wazuh report_changes="yes")
                    diff_text = None
                    if not current_snap.is_binary and not baseline_snap.is_binary:
                        diff = list(difflib.unified_diff(
                            baseline_snap.content_lines,
                            current_snap.content_lines,
                            fromfile=f"a/{current_snap.filename}",
                            tofile=f"b/{current_snap.filename}",
                            lineterm=""
                        ))
                        if diff:
                            diff_text = "\n".join(diff)
                    elif current_snap.is_binary or baseline_snap.is_binary:
                        diff_text = "[Binary or encrypted content changed - textual diff suppressed]"

                    event = {
                        "event_type": "FILE_MODIFIED",
                        "path": path,
                        "filename": current_snap.filename,
                        "timestamp": time.time(),
                        "size_before": baseline_snap.size,
                        "size_after": current_snap.size,
                        "sha256_before": baseline_snap.sha256,
                        "sha256_after": current_snap.sha256,
                        "md5_before": baseline_snap.md5,
                        "md5_after": current_snap.md5,
                        "permissions_before": baseline_snap.permissions,
                        "permissions_after": current_snap.permissions,
                        "diff": diff_text
                    }
                    events.append(event)
                    self.database[path] = current_snap

        # 3. Check for deleted files
        for path, baseline_snap in list(self.database.items()):
            if path not in current_files:
                event = {
                    "event_type": "FILE_DELETED",
                    "path": path,
                    "filename": baseline_snap.filename,
                    "timestamp": time.time(),
                    "sha256_before": baseline_snap.sha256,
                    "size_before": baseline_snap.size,
                    "diff": None
                }
                events.append(event)
                del self.database[path]

        return events
