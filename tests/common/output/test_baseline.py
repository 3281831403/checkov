import json
import shutil
from pathlib import Path

from checkov.common.output.baseline import Baseline
from checkov.runner_filter import RunnerFilter
from checkov.terraform.runner import Runner


def test_to_dict():
    # given
    test_folder = Path(__file__).parent / "fixtures"
    checks = ["CKV_AWS_18", "CKV_AWS_19", "CKV_AWS_21", "CKV2_AWS_6"]  # 1 pass, 2 fail, 1 skip
    report = Runner().run(root_folder=str(test_folder), runner_filter=RunnerFilter(checks=checks))

    baseline = Baseline()
    baseline.add_findings_from_report(report)

    # when
    output = baseline.to_dict()

    # then
    assert output == {
        "failed_checks": [
            {
                "file": "/main.tf",
                "findings": [
                    {
                        "resource": "aws_s3_bucket.destination",
                        "check_ids": ["CKV2_AWS_6", "CKV_AWS_18"],
                    }
                ],
            },
            {
                "file": "/main_2.tf",
                "findings": [
                    {
                        "resource": "aws_s3_bucket.destination_2",
                        "check_ids": ["CKV2_AWS_6", "CKV_AWS_18"],
                    },
                    {
                        "resource": "aws_s3_bucket.destination_3",
                        "check_ids": ["CKV2_AWS_6", "CKV_AWS_18"],
                    },
                ],
            },
        ]
    }


def _run_scan(root: Path) -> object:
    return Runner().run(root_folder=str(root), runner_filter=RunnerFilter(framework=["terraform"]))


def _copy_fixture_root(name: str, tmp_path: Path) -> Path:
    source = Path(__file__).parent / "baseline_scan_roots" / name
    target = tmp_path / name
    shutil.copytree(source, target)
    return target


def test_baseline_suppresses_only_matching_file(tmp_path: Path):
    # given - two scan roots, each with a main.tf containing aws_s3_bucket.this
    fixtures_root = Path(__file__).parent / "baseline_scan_roots"
    prod_report = _run_scan(fixtures_root / "prod")
    stage_report = _run_scan(fixtures_root / "stage")
    assert prod_report.failed_checks and stage_report.failed_checks
    stage_failed_count = len(stage_report.failed_checks)

    baseline = Baseline()
    baseline.add_findings_from_report(prod_report)
    baseline_path = tmp_path / ".checkov.baseline"
    baseline_path.write_text(json.dumps(baseline.to_dict()))

    loaded_baseline = Baseline()
    loaded_baseline.from_json(str(baseline_path))

    # when - the stage report holds identically named resources in an identically named file
    loaded_baseline.compare_and_reduce_reports([stage_report], root_folder=str(fixtures_root / "stage"))

    # then - nothing from a different scan root may be suppressed
    assert len(stage_report.failed_checks) == stage_failed_count


def test_baseline_suppresses_failures_within_its_scan_root(tmp_path: Path):
    # given - work on a copy, since the baseline must live inside the scan root
    prod_root = _copy_fixture_root("prod", tmp_path)
    prod_report = _run_scan(prod_root)
    expected_failed = len(prod_report.failed_checks)
    assert expected_failed > 0

    # Baseline files are written into the scan root, so mimic that location
    baseline_path = prod_root / ".checkov.baseline"
    baseline = Baseline()
    baseline.add_findings_from_report(prod_report)
    baseline_path.write_text(json.dumps(baseline.to_dict()))

    loaded_baseline = Baseline()
    loaded_baseline.from_json(str(baseline_path))

    # when
    fresh_report = _run_scan(prod_root)
    loaded_baseline.compare_and_reduce_reports([fresh_report], root_folder=str(prod_root))

    # then - all failures of the originating scan root are suppressed
    assert fresh_report.failed_checks == []

    # and a baseline loaded without root context still applies (backward compatible call)
    other_report = _run_scan(prod_root)
    loaded_baseline.compare_and_reduce_reports([other_report])
    assert other_report.failed_checks == []
    assert len(loaded_baseline.failed_checks) > 0  # sanity: baseline was actually populated


def test_same_named_resource_in_different_file_is_not_suppressed(tmp_path: Path):
    # given - one baseline covering /main.tf only, a second report with the same
    # resource name in a different file
    fixtures_root = Path(__file__).parent / "baseline_scan_roots"
    prod_report = _run_scan(fixtures_root / "prod")

    baseline = Baseline()
    baseline.add_findings_from_report(prod_report)
    baseline_path = tmp_path / ".checkov.baseline"
    baseline_path.write_text(json.dumps(baseline.to_dict()))

    loaded_baseline = Baseline()
    loaded_baseline.from_json(str(baseline_path))
    # same root context, so root scoping does not filter; file matching must do the work
    loaded_baseline.scan_root = ""

    other_report = _run_scan(fixtures_root / "stage")
    other_failed_count = len(other_report.failed_checks)
    for check in other_report.failed_checks:
        check.file_path = "/nested/other.tf"

    # when
    loaded_baseline.compare_and_reduce_reports([other_report])

    # then - identical resource/check names but a different file stay visible
    assert len(other_report.failed_checks) == other_failed_count


def test_windows_style_file_paths_match_posix_baseline(tmp_path: Path, monkeypatch):
    # given - a baseline created on Linux with forward-slash paths
    fixtures_root = Path(__file__).parent / "baseline_scan_roots"
    prod_report = _run_scan(fixtures_root / "prod")

    baseline = Baseline()
    baseline.add_findings_from_report(prod_report)
    baseline_path = tmp_path / ".checkov.baseline"
    baseline_path.write_text(json.dumps(baseline.to_dict()))

    loaded_baseline = Baseline()
    loaded_baseline.from_json(str(baseline_path))
    loaded_baseline.scan_root = ""

    windows_report = _run_scan(fixtures_root / "prod")
    for check in windows_report.failed_checks:
        check.file_path = check.file_path.replace("/", "\\")

    # when - simulate running on Windows, where os.sep makes record paths use backslashes
    monkeypatch.setattr("checkov.common.output.baseline.sys.platform", "win32")
    loaded_baseline.compare_and_reduce_reports([windows_report])

    # then - the Linux baseline still suppresses every failure
    assert windows_report.failed_checks == []


def test_output_baseline_as_skipped_only_marks_matching_entries(tmp_path: Path):
    # given - the baseline must live inside its scan root, so use a copied root
    fixtures_root = Path(__file__).parent / "baseline_scan_roots"
    prod_root = _copy_fixture_root("prod", tmp_path)
    prod_report = _run_scan(prod_root)
    expected_failed = len(prod_report.failed_checks)

    baseline = Baseline(output_skipped=True)
    baseline.add_findings_from_report(prod_report)
    baseline_path = prod_root / ".checkov.baseline"
    baseline_path.write_text(json.dumps(baseline.to_dict()))

    loaded_baseline = Baseline(output_skipped=True)
    loaded_baseline.from_json(str(baseline_path))

    # when - prod findings are suppressed-as-skipped, stage findings must not be touched
    fresh_prod_report = _run_scan(prod_root)
    stage_report = _run_scan(fixtures_root / "stage")
    stage_failed_count = len(stage_report.failed_checks)
    loaded_baseline.compare_and_reduce_reports([fresh_prod_report], root_folder=str(prod_root))
    loaded_baseline.compare_and_reduce_reports([stage_report], root_folder=str(fixtures_root / "stage"))

    # then
    assert fresh_prod_report.failed_checks == []
    assert len(fresh_prod_report.skipped_checks) == expected_failed
    assert all(
        check.check_result.get("suppress_comment") == "baseline-skipped"
        for check in fresh_prod_report.skipped_checks
    )
    assert len(stage_report.failed_checks) == stage_failed_count
    assert all(
        check.check_result.get("suppress_comment") != "baseline-skipped"
        for check in stage_report.failed_checks
    )


def test_legacy_baseline_without_root_context_applies_everywhere(tmp_path: Path):
    # given - an old baseline file, loaded without relying on its directory location
    fixtures_root = Path(__file__).parent / "baseline_scan_roots"
    prod_report = _run_scan(fixtures_root / "prod")

    baseline = Baseline()
    baseline.add_findings_from_report(prod_report)
    baseline_path = tmp_path / ".checkov.baseline"
    baseline_path.write_text(json.dumps(baseline.to_dict()))

    loaded_baseline = Baseline()
    loaded_baseline.from_json(str(baseline_path))
    loaded_baseline.scan_root = ""  # simulate legacy behavior explicitly

    # when / then - without root scoping the same file/resource/check still matches
    fresh_report = _run_scan(fixtures_root / "prod")
    loaded_baseline.compare_and_reduce_reports([fresh_report], root_folder="/some/other/root")
    assert fresh_report.failed_checks == []
