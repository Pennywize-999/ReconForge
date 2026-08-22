from pathlib import Path

from reconforge.core.analyzer import Analyzer


def test_random_value_and_hash_are_preserved(tmp_path: Path):
    sample = tmp_path / "response.txt"
    sample.write_text(
        "password = wintermelon\n"
        "5f4dcc3b5aa765d61d8327deb882cf99\n",
        encoding="utf-8",
    )

    target = Analyzer().analyze_file(str(sample))
    host = next(iter(target.hosts.values()))
    values = {(item.kind, item.value) for item in host.unclassified}

    assert any(value == "wintermelon" for _, value in values)
    assert any("5f4dcc3b5aa765d61d8327deb882cf99" == value for _, value in values)


def test_unknown_information_is_not_dropped(tmp_path: Path):
    sample = tmp_path / "unknown.txt"
    sample.write_text("mystery_value_2026\n", encoding="utf-8")
    target = Analyzer().analyze_file(str(sample))
    host = next(iter(target.hosts.values()))
    assert any(item.value == "mystery_value_2026" for item in host.unclassified)
