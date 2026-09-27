"""Tests for modules/target_io.py — import parsing, validation, caps, and
the export/re-import round trip."""
import json

import pytest

from modules.target_io import (
    MAX_IMPORTS,
    parse_target_import,
    parse_target_import_json,
    serialize_targets,
)


class TestParse:
    def test_valid_entries(self):
        items = [{"ip": "8.8.8.8", "method": "ICMP"},
                 {"ip": "1.1.1.1", "method": "TCP"}]
        assert parse_target_import(items) == [("8.8.8.8", "ICMP"), ("1.1.1.1", "TCP")]

    def test_malformed_json(self):
        with pytest.raises(ValueError):
            parse_target_import_json("{not json")

    def test_non_list_json(self):
        with pytest.raises(ValueError):
            parse_target_import({"ip": "8.8.8.8"})
        with pytest.raises(ValueError):
            parse_target_import("just a string")

    def test_malformed_entries_skipped(self):
        items = [
            "not a dict",
            {"no_ip": "8.8.8.8"},
            {"ip": "not a host!"},
            {"ip": ""},
            {"ip": "8.8.8.8; rm -rf /"},
            {"ip": "9.9.9.9"},  # the one valid entry
        ]
        assert parse_target_import(items) == [("9.9.9.9", "ICMP")]

    def test_unsupported_method_falls_back(self):
        items = [{"ip": "8.8.8.8", "method": "UDP"},
                 {"ip": "1.1.1.1", "method": "weird"}]
        assert parse_target_import(items) == [("8.8.8.8", "ICMP"), ("1.1.1.1", "ICMP")]

    def test_method_case_insensitive(self):
        assert parse_target_import([{"ip": "8.8.8.8", "method": "tcp"}]) == \
            [("8.8.8.8", "TCP")]

    def test_default_method(self):
        assert parse_target_import([{"ip": "8.8.8.8"}]) == [("8.8.8.8", "ICMP")]

    def test_import_size_limit(self):
        items = [{"ip": f"10.0.0.{i}"} for i in range(1, 200)]
        result = parse_target_import(items)
        assert len(result) == MAX_IMPORTS == 50

    def test_duplicates_skipped(self):
        items = [{"ip": "8.8.8.8"}, {"ip": "8.8.8.8"}, {"ip": "1.1.1.1"}]
        assert parse_target_import(items) == [("8.8.8.8", "ICMP"), ("1.1.1.1", "ICMP")]

    def test_existing_targets_skipped(self):
        items = [{"ip": "8.8.8.8"}, {"ip": "1.1.1.1"}]
        assert parse_target_import(items, existing={"8.8.8.8"}) == \
            [("1.1.1.1", "ICMP")]

    def test_hostname_entries_preserved(self):
        # Hostnames are kept; the monitor resolves them at add time.
        assert parse_target_import([{"ip": "example.com"}]) == \
            [("example.com", "ICMP")]

    def test_url_entries_normalized(self):
        assert parse_target_import([{"ip": "https://example.com/x"}]) == \
            [("example.com", "ICMP")]


class TestRoundTrip:
    def test_export_reimport(self):
        pairs = [("8.8.8.8", "ICMP"), ("1.1.1.1", "TCP"), ("2001:db8::1", "ICMP")]
        text = serialize_targets(pairs)
        # The serialized form must itself be valid JSON...
        assert json.loads(text) == [
            {"ip": "8.8.8.8", "method": "ICMP"},
            {"ip": "1.1.1.1", "method": "TCP"},
            {"ip": "2001:db8::1", "method": "ICMP"},
        ]
        # ...and re-importing it yields the same targets.
        assert parse_target_import_json(text) == pairs
