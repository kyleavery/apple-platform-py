import pytest

import apple_platform as ap
from apple_platform import _ffi, errors


def test_unknown_request_field_is_rejected_with_field_name():
    # deny_unknown_fields end to end: serde names the offending field.
    with pytest.raises(errors.InvalidArgumentError) as exc_info:
        ap.sign_raw({"config": {}, "bogus_field": 1})
    err = exc_info.value
    assert err.code == 3
    assert "bogus_field" in err.message


def test_invalid_log_level_maps_to_invalid_argument():
    with pytest.raises(errors.InvalidArgumentError) as exc_info:
        ap.set_log_level(42)
    assert exc_info.value.code == 3
    # InvalidArgumentError doubles as ValueError for idiomatic handling.
    assert isinstance(exc_info.value, ValueError)


def test_unknown_code_degrades_to_base_class():
    exc = errors.exception_for(9999, None)
    assert type(exc) is errors.ApplePlatformError
    assert exc.code == 9999


def test_error_state_is_per_call():
    with pytest.raises(errors.ApplePlatformError):
        _ffi.call_json("apple_platform_bundle_info", b"/nonexistent/bundle")
    # A subsequent successful call must not resurface the old error.
    assert ap.versions()["abi_version"] == 1
