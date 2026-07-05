"""Unit tests for utils/error_handler.py."""
import pytest

from utils.error_handler import (
    ConfigurationError,
    ErrorHandler,
    ErrorSeverity,
    NetSweepError,
    NetworkError,
    PermissionError as NetSweepPermissionError,
    SecurityError,
    handle_errors,
    safe_execute,
)


@pytest.fixture
def handler(tmp_path):
    return ErrorHandler(log_file=str(tmp_path / "test.log"))


class TestNetSweepExceptions:
    def test_base_error_defaults_to_medium_severity(self):
        err = NetSweepError("boom")
        assert err.severity == ErrorSeverity.MEDIUM
        assert str(err) == "boom"

    def test_network_error_carries_target(self):
        err = NetworkError("unreachable", target="10.0.0.1")
        assert err.target == "10.0.0.1"

    def test_configuration_error_carries_config_key(self):
        err = ConfigurationError("bad value", config_key="scan.timeout")
        assert err.config_key == "scan.timeout"

    def test_security_error_forces_high_severity(self):
        err = SecurityError("unauthorized")
        assert err.severity == ErrorSeverity.HIGH

    def test_permission_error_forces_high_severity(self):
        err = NetSweepPermissionError("denied", operation="raw socket")
        assert err.severity == ErrorSeverity.HIGH
        assert err.operation == "raw socket"


class TestErrorHandler:
    def test_handle_error_counts_by_type(self, handler):
        handler.handle_error(ValueError("x"))
        handler.handle_error(ValueError("y"))
        handler.handle_error(TypeError("z"))

        summary = handler.get_error_summary()
        assert summary["total_errors"] == 3
        assert summary["error_types"] == {"ValueError": 2, "TypeError": 1}

    def test_handle_error_tracks_critical_netsweep_errors(self, handler):
        err = NetSweepError("fatal", severity=ErrorSeverity.CRITICAL)
        handler.handle_error(err)

        summary = handler.get_error_summary()
        assert summary["critical_errors_count"] == 1
        assert summary["critical_errors"][0]["error_type"] == "NetSweepError"

    def test_handle_error_reraises_security_errors(self, handler):
        with pytest.raises(SecurityError):
            handler.handle_error(SecurityError("nope"))

    def test_handle_error_reraises_when_requested(self, handler):
        with pytest.raises(ValueError):
            handler.handle_error(ValueError("explicit"), reraise=True)

    def test_handle_error_does_not_reraise_by_default_for_plain_errors(self, handler):
        # Should not raise.
        assert handler.handle_error(ValueError("swallowed")) is True

    def test_reset_error_counts(self, handler):
        handler.handle_error(ValueError("x"))
        handler.reset_error_counts()
        summary = handler.get_error_summary()
        assert summary["total_errors"] == 0
        assert summary["critical_errors"] == []

    def test_log_info_warning_debug_do_not_raise(self, handler):
        handler.log_info("info message")
        handler.log_warning("warning message")
        handler.log_debug("debug message")

    def test_log_file_is_created(self, handler, tmp_path):
        handler.log_info("hello")
        for h in handler.logger.handlers:
            h.flush()
        assert (tmp_path / "test.log").exists()


class TestHandleErrorsDecorator:
    def test_returns_default_on_exception(self):
        @handle_errors(default_return="fallback")
        def boom():
            raise ValueError("bad")

        assert boom() == "fallback"

    def test_returns_value_on_success(self):
        @handle_errors(default_return="fallback")
        def ok():
            return "real result"

        assert ok() == "real result"

    def test_only_catches_listed_error_types(self):
        @handle_errors(error_types=[ValueError], default_return="fallback")
        def raises_type_error():
            raise TypeError("not a ValueError")

        with pytest.raises(TypeError):
            raises_type_error()

    def test_reraise_flag_propagates_exception(self):
        @handle_errors(default_return="fallback", reraise=True)
        def boom():
            raise ValueError("bad")

        with pytest.raises(ValueError):
            boom()


class TestSafeExecute:
    def test_returns_function_result(self):
        assert safe_execute(lambda x: x * 2, 21) == 42

    def test_returns_default_on_exception(self):
        def boom():
            raise RuntimeError("bad")

        assert safe_execute(boom, default_return="safe") == "safe"
