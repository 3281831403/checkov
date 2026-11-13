from __future__ import annotations

import json
import os
import sys
from collections import defaultdict
from operator import itemgetter

from checkov.common.models.enums import CheckResult
from checkov.common.util.file_utils import convert_to_unix_path
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from checkov.common.output.record import Record
    from checkov.common.output.report import Report
    from checkov.common.typing import _BaselineFinding, _BaselineFailedChecks


def _normalize_path(path: str) -> str:
    """Normalize a path to a forward-slash representation for comparison.

    Check records carry a scan-root-relative path built with ``os.sep``, so on
    Windows it contains backslashes (e.g. ``\\main.tf``) while a baseline created
    on Linux stores forward slashes (e.g. ``/main.tf``). Normalizing both sides
    makes baselines portable across operating systems.

    Drive letters and paths are compared case-insensitively on case-insensitive
    filesystems (Windows, macOS).
    """
    normalized = str(convert_to_unix_path(path))
    if sys.platform.startswith("win") or sys.platform == "darwin":
        normalized = normalized.lower()
    return normalized


class Baseline:
    def __init__(self, output_skipped: bool = False) -> None:
        self.path = ""
        self.path_failed_checks_map: dict[str, list[_BaselineFinding]] = defaultdict(list)
        self.failed_checks: list[_BaselineFailedChecks] = []
        self.output_skipped = output_skipped
        # Absolute path of the scan root the baseline belongs to. Baselines are
        # written next to the scanned root/folder, so the baseline file's own
        # directory is its scan root.
        self.scan_root = ""

    def add_findings_from_report(self, report: Report) -> None:
        for check in report.failed_checks:
            try:
                existing = next(
                    x for x in self.path_failed_checks_map[check.file_path] if x["resource"] == check.resource
                )
            except StopIteration:
                existing = {"resource": check.resource, "check_ids": []}
                self.path_failed_checks_map[check.file_path].append(existing)
            existing["check_ids"].append(check.check_id)
            existing["check_ids"].sort()  # Sort the check IDs to be nicer to the eye

    def to_dict(self) -> dict[str, Any]:
        """
        The output of this class needs to be very explicit, hence the following structure of the dict:
        {
            "failed_checks": [
                {
                    "file": "path/to/file",
                    "findings: [
                        {
                            "resource": "aws_s3_bucket.this",
                            "check_ids": [
                                "CKV_AWS_1",
                                "CKV_AWS_2",
                                "CKV_AWS_3"
                            ]
                        }
                    ]
                }
            ]
        }
        """
        failed_checks_list = []
        for file, findings in self.path_failed_checks_map.items():
            formatted_findings = []
            for finding in findings:
                formatted_findings.append({"resource": finding["resource"], "check_ids": finding["check_ids"]})
            sorted_findings = sorted(formatted_findings, key=itemgetter("resource"))
            failed_checks_list.append({"file": file, "findings": sorted_findings})

        resp = {"failed_checks": sorted(failed_checks_list, key=itemgetter("file"))}
        return resp

    def compare_and_reduce_reports(self, scan_reports: list[Report], root_folder: str | None = None) -> None:
        if root_folder is not None and self.scan_root and not self._is_root_in_baseline(root_folder):
            # This baseline was generated from a different scan root, so none of
            # its findings can belong to the current reports - leave them untouched.
            return
        for scan_report in scan_reports:
            scan_report.passed_checks = [
                check for check in scan_report.passed_checks if self._is_check_in_baseline(check)
            ]
            scan_report.skipped_checks = [
                check for check in scan_report.skipped_checks if self._is_check_in_baseline(check)
            ]
            if self.output_skipped:
                for check in scan_report.failed_checks:
                    if self._is_check_in_baseline(check):
                        check.check_result["suppress_comment"] = "baseline-skipped"
                        check.check_result["result"] = CheckResult.SKIPPED
                        scan_report.skipped_checks.append(check)
            scan_report.failed_checks = [
                check for check in scan_report.failed_checks if not self._is_check_in_baseline(check)
            ]

    def _is_root_in_baseline(self, root_folder: str) -> bool:
        if not self.scan_root:
            return True
        return _normalize_path(os.path.abspath(root_folder)) == _normalize_path(self.scan_root)

    def _is_check_in_baseline(self, check: Record) -> bool:
        failed_check_id = check.check_id
        failed_check_resource = check.resource
        normalized_check_file_path = _normalize_path(check.file_path)
        for baseline_failed_check in self.failed_checks:
            # Match on the file as well, so identically named resources in
            # different files do not suppress each other. Paths are normalized to
            # forward slashes, so baselines are portable between Linux and Windows.
            if _normalize_path(baseline_failed_check["file"]) != normalized_check_file_path:
                continue
            for finding in baseline_failed_check["findings"]:
                if finding["resource"] == failed_check_resource and failed_check_id in finding["check_ids"]:
                    return True
        return False

    def from_json(self, file_path: str) -> None:
        self.path = file_path
        with open(file_path, "r") as f:
            baseline_raw = json.load(f)
            self.failed_checks = baseline_raw.get("failed_checks", {})
        # Baselines are created inside the scan root (or, in --file mode, inside
        # the scanned file's directory), which pins the baseline to that root.
        self.scan_root = os.path.abspath(os.path.dirname(file_path))
