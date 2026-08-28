import pathlib

def test_no_mojibake_in_reporters():
    base_dir = pathlib.Path(__file__).parent.parent
    
    files_to_check = [
        base_dir / "reconforge" / "execution" / "backend.py",
        base_dir / "reconforge" / "reporters" / "terminal.py"
    ]
    
    for file_path in files_to_check:
        content = file_path.read_text(encoding="utf-8")
        assert "✓" not in content, f"Mojibake (checkmark) found in {file_path.name}"
        assert "✗" not in content, f"Mojibake (cross) found in {file_path.name}"
        assert "âœ“" not in content, f"Mojibake (encoded checkmark) found in {file_path.name}"
        assert "âœ—" not in content, f"Mojibake (encoded cross) found in {file_path.name}"
