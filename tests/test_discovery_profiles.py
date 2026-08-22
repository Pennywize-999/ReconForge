from reconforge.core.discovery import DiscoveryEngine


def test_profiles_are_distinct_and_deterministic():
    engine = DiscoveryEngine()
    common = engine.build("COMMON")
    extended = engine.build("EXTENDED")
    deep = engine.build("DEEP")

    assert common.name == "COMMON"
    assert extended.name == "EXTENDED"
    assert deep.name == "DEEP"
    assert len(common.candidates) <= len(extended.candidates) <= len(deep.candidates)
    assert [c.path for c in common.candidates] == [c.path for c in engine.build("COMMON").candidates]


def test_wordpress_category_is_selected_by_technology():
    profile = DiscoveryEngine().build("EXTENDED", technologies=["WordPress", "PHP"], services=["Apache"])
    assert "wordpress" in profile.categories
    assert any(c.path == "wp-login.php" for c in profile.candidates)
    assert any(c.path == ".htaccess" for c in profile.candidates)


def test_duplicate_candidates_are_removed():
    profile = DiscoveryEngine().build("DEEP", technologies=["WordPress", "Apache", "PHP"])
    values = [c.path.lower() for c in profile.candidates]
    assert len(values) == len(set(values))
