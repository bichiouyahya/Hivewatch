from app.http_routes import build_response


def test_root_path_serves_apache_default_page():
    status, content_type, body = build_response("/")
    assert status == 200
    assert "It works!" in body


def test_unknown_path_serves_404():
    status, _, body = build_response("/some/random/path")
    assert status == 404
    assert "Not Found" in body


def test_bait_path_is_case_insensitive():
    status, _, body = build_response("/WP-LOGIN.PHP")
    assert status == 200
    assert "loginform" in body


def test_query_string_is_ignored_for_matching():
    status, _, _ = build_response("/wp-login.php?redirect_to=%2Fwp-admin%2F")
    assert status == 200


def test_prefix_route_matches_any_subpath():
    status, _, body = build_response("/phpmyadmin/index.php?route=/database")
    assert status == 200
    assert "phpMyAdmin" in body
