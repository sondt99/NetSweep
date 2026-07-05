"""Unit tests for main.py (input-prompt helpers, build_args_common, execute_scanner)."""
import subprocess

import pytest

import main
from config import get_config


@pytest.fixture
def cfg():
    return get_config()


class TestResolveNumericArg:
    def test_blank_input_returns_default(self):
        assert main._resolve_numeric_arg("", 50, int, "invalid", "non-positive") == 50

    def test_valid_positive_value_is_parsed(self):
        assert main._resolve_numeric_arg("10", 50, int, "invalid", "non-positive") == 10

    def test_non_positive_value_returns_none_and_warns(self):
        result = main._resolve_numeric_arg("-5", 50, int, "invalid", "non-positive")
        assert result is None

    def test_invalid_value_returns_none(self):
        result = main._resolve_numeric_arg("abc", 50, int, "invalid", "non-positive")
        assert result is None

    def test_works_with_float_cast(self):
        assert main._resolve_numeric_arg("1.5", 0.5, float, "invalid", "non-positive") == 1.5


class TestResolveOutputFormat:
    @pytest.mark.parametrize("fmt", ["json", "csv", "txt"])
    def test_valid_formats_pass_through(self, fmt):
        assert main._resolve_output_format(fmt, "json") == fmt

    def test_blank_input_returns_default_silently(self):
        assert main._resolve_output_format("", "json") == "json"

    def test_invalid_input_falls_back_to_default(self):
        assert main._resolve_output_format("xml", "json") == "json"


class TestResolveVerboseFlag:
    def test_explicit_yes(self):
        assert main._resolve_verbose_flag("y", False) is True

    def test_explicit_no_overrides_default(self):
        assert main._resolve_verbose_flag("n", True) is False

    def test_blank_uses_default_true(self):
        assert main._resolve_verbose_flag("", True) is True

    def test_blank_uses_default_false(self):
        assert main._resolve_verbose_flag("", False) is False

    def test_garbage_input_is_falsy(self):
        assert main._resolve_verbose_flag("maybe", True) is False


class TestBuildArgsCommon:
    def test_all_blank_uses_config_defaults(self, cfg):
        answers = iter(["", "", "", "", ""])
        result = main.build_args_common(input_func=lambda _prompt: next(answers))
        assert result == (
            f"-t {cfg.scan.max_workers} -T {cfg.scan.timeout} "
            f"-o {cfg.output.export_format} -d {cfg.output.default_output_dir}"
        )

    def test_custom_valid_values(self):
        answers = iter(["10", "1.5", "csv", "my_out", "y"])
        result = main.build_args_common(input_func=lambda _prompt: next(answers))
        assert result == "-t 10 -T 1.5 -o csv -d my_out -v"

    def test_invalid_thread_and_timeout_omit_flags(self, cfg):
        # Matches original (pre-refactor) behavior: an invalid/non-positive
        # thread or timeout value skips the flag entirely rather than
        # substituting the default.
        answers = iter(["-5", "abc", "xml", "", "n"])
        result = main.build_args_common(input_func=lambda _prompt: next(answers))
        tokens = result.split()
        assert "-t" not in tokens
        assert "-T" not in tokens
        assert f"-o json -d {cfg.output.default_output_dir}" in result

    def test_verbose_flag_omitted_when_not_requested(self):
        answers = iter(["", "", "", "", "n"])
        result = main.build_args_common(input_func=lambda _prompt: next(answers))
        assert "-v" not in result.split()


class TestExecuteScanner:
    def test_success_returns_completed_process(self, monkeypatch):
        captured = {}

        def fake_run(cmd, check, capture_output, text):
            captured["cmd"] = cmd
            return subprocess.CompletedProcess(cmd, returncode=0)

        monkeypatch.setattr(subprocess, "run", fake_run)
        result = main.execute_scanner("lan", ["python3", "lan_scanner.py"])
        assert result.returncode == 0
        assert captured["cmd"] == ["python3", "lan_scanner.py"]

    def test_called_process_error_is_reraised(self, monkeypatch):
        def fake_run(cmd, check, capture_output, text):
            raise subprocess.CalledProcessError(returncode=1, cmd=cmd)

        monkeypatch.setattr(subprocess, "run", fake_run)
        with pytest.raises(subprocess.CalledProcessError):
            main.execute_scanner("host", ["python3", "host_scanner.py"])

    def test_missing_scanner_script_raises_file_not_found(self, monkeypatch):
        def fake_run(cmd, check, capture_output, text):
            raise FileNotFoundError()

        monkeypatch.setattr(subprocess, "run", fake_run)
        with pytest.raises(FileNotFoundError):
            main.execute_scanner("lan", ["python3", "missing_scanner.py"])
