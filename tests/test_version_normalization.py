"""Unit tests for version normalization, comparison, and backport detection."""

import pytest
from sentinelrecon.vulnerability.normalization import (
    compare_versions,
    has_distro_backport_indicator,
    is_version_in_range,
    normalize_version_string,
    parse_version_tuple,
)


def test_normalize_version_string():
    assert normalize_version_string("v9.0.30") == "9.0.30"
    assert normalize_version_string("  9.0.30  ") == "9.0.30"
    assert normalize_version_string("") == ""


def test_parse_version_tuple():
    assert parse_version_tuple("9.0.30") == ((0, 9), (0, 0), (0, 30))
    assert parse_version_tuple("9.0.0.M1") == ((0, 9), (0, 0), (0, 0), (1, "m"), (0, 1))
    assert parse_version_tuple("8.5p1") == ((0, 8), (0, 5), (1, "p"), (0, 1))


def test_compare_versions():
    assert compare_versions("9.0.30", "9.0.31") == -1
    assert compare_versions("9.0.31", "9.0.30") == 1
    assert compare_versions("9.0.30", "9.0.30") == 0


def test_is_version_in_range():
    assert is_version_in_range("9.0.30", "9.0.0.M1", "9.0.30") is True
    assert is_version_in_range("9.0.31", "9.0.0.M1", "9.0.30") is False
    assert is_version_in_range("8.5.50", "8.5.0", "8.5.50") is True
    assert is_version_in_range("8.5.51", "8.5.0", "8.5.50") is False


def test_distro_backport_detection():
    assert has_distro_backport_indicator("7.2p2 Ubuntu 4ubuntu2.8") is True
    assert has_distro_backport_indicator("8.2p1-deb10u1") is True
    assert has_distro_backport_indicator("9.0.30") is False
