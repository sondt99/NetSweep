"""Unit tests for main.py (input-prompt helpers, build_args_common, execute_scanner)."""
import os
import subprocess

import pytest

import netsweep.cli.menu as main
from netsweep.config import get_config


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
        assert result == [
            "-t", str(cfg.scan.max_workers), "-T", str(cfg.scan.timeout),
            "-o", cfg.output.export_format, "-d", cfg.output.default_output_dir,
        ]

    def test_custom_valid_values(self):
        answers = iter(["10", "1.5", "csv", "my_out", "y"])
        result = main.build_args_common(input_func=lambda _prompt: next(answers))
        assert result == ["-t", "10", "-T", "1.5", "-o", "csv", "-d", "my_out", "-v"]

    def test_output_dir_with_spaces_survives_intact(self):
        # Regression test: build_args_common used to return a single string
        # joined with " ".join(args), which main() then re-split with
        # .split() before invoking the subprocess - corrupting any value
        # (like a custom output directory) that itself contained whitespace.
        # It now returns a list of argv tokens directly, so this must stay intact.
        answers = iter(["", "", "", "my scan results", ""])
        result = main.build_args_common(input_func=lambda _prompt: next(answers))
        assert "-d" in result
        assert result[result.index("-d") + 1] == "my scan results"

    def test_invalid_thread_and_timeout_omit_flags(self, cfg):
        # Matches original (pre-refactor) behavior: an invalid/non-positive
        # thread or timeout value skips the flag entirely rather than
        # substituting the default.
        answers = iter(["-5", "abc", "xml", "", "n"])
        result = main.build_args_common(input_func=lambda _prompt: next(answers))
        assert "-t" not in result
        assert "-T" not in result
        assert result == ["-o", "json", "-d", cfg.output.default_output_dir]

    def test_verbose_flag_omitted_when_not_requested(self):
        answers = iter(["", "", "", "", "n"])
        result = main.build_args_common(input_func=lambda _prompt: next(answers))
        assert "-v" not in result


class TestExecuteScanner:
    def test_success_runs_lan_in_process(self, monkeypatch):
        captured = {}

        def fake_lan(argv):
            captured["argv"] = list(argv)

        import netsweep.cli.lan as lan_cli

        monkeypatch.setattr(lan_cli, "run_from_argv", fake_lan)
        main.execute_scanner("lan", ["python3", "lan_scanner.py", "-n", "127.0.0.0/30"])
        assert captured["argv"] == ["-n", "127.0.0.0/30"]

    def test_host_in_process(self, monkeypatch):
        captured = {}

        def fake_host(argv):
            captured["argv"] = list(argv)

        import netsweep.cli.host as host_cli

        monkeypatch.setattr(host_cli, "run_from_argv", fake_host)
        main.execute_scanner("host", ["python3", "host_scanner.py", "-t", "127.0.0.1"])
        assert captured["argv"] == ["-t", "127.0.0.1"]

    def test_unknown_scanner_type_raises(self):
        with pytest.raises(ValueError, match="Unknown scanner"):
            main.execute_scanner("nope", [])


class TestScriptDirResolution:
    def test_script_dir_is_cli_package_dir(self):
        # After package refactor, scanners run in-process; SCRIPT_DIR points at
        # the netsweep.cli package directory (legacy path anchors retained).
        assert os.path.isdir(main.SCRIPT_DIR)
        assert os.path.isfile(os.path.join(main.SCRIPT_DIR, "menu.py"))
        assert os.path.isfile(os.path.join(main.SCRIPT_DIR, "lan.py"))
        assert os.path.isfile(os.path.join(main.SCRIPT_DIR, "host.py"))
