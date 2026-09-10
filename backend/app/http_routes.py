"""Fake responses for the HTTP honeypot. Common scanner targets get bait
content, everything else gets a default Apache page or 404.
"""

SERVER_HEADER = "Apache/2.4.52 (Ubuntu)"

APACHE_DEFAULT_PAGE = """<html><body><h1>It works!</h1>
<p>This is the default web page for this server.</p>
<p>The web server software is running but no content has been added, yet.</p>
</body></html>
"""

APACHE_404_PAGE = """<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
<hr>
<address>Apache/2.4.52 (Ubuntu) Server</address>
</body></html>
"""

WP_LOGIN_PAGE = """<!DOCTYPE html>
<html><head><title>Log In &lsaquo; Sample Site &#8212; WordPress</title></head>
<body class="login">
<form name="loginform" id="loginform" action="wp-login.php" method="post">
<p><label>Username or Email Address<input type="text" name="log" id="user_login"></label></p>
<p><label>Password<input type="password" name="pwd" id="user_pass"></label></p>
<p class="submit"><input type="submit" name="wp-submit" value="Log In"></p>
</form>
</body></html>
"""

PHPMYADMIN_PAGE = """<!DOCTYPE html>
<html><head><title>phpMyAdmin</title></head>
<body>
<form method="post" action="index.php">
<input type="text" name="pma_username">
<input type="password" name="pma_password">
<input type="submit" value="Go">
</form>
</body></html>
"""

XMLRPC_FAULT = """<?xml version="1.0"?>
<methodResponse><fault><value><struct>
<member><name>faultCode</name><value><int>-32601</int></value></member>
<member><name>faultString</name><value><string>server error. requested method xmlrpc.php does not exist.</string></value></member>
</struct></value></fault></methodResponse>
"""

DOTENV_FILE = """DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=wordpress
DB_USERNAME=root
DB_PASSWORD=S3cr3tP@ss
APP_KEY=base64:8Jz3n9x7ZqW1vT5yU2rC4mB6oE0dF9gH1iJ2kL3mN4o=
APP_DEBUG=false
"""

GIT_CONFIG_FILE = """[core]
\trepositoryformatversion = 0
\tfilemode = true
\tbare = false
\tlogallrefupdates = true
[remote "origin"]
\turl = git@github.com:acme-corp/internal-api.git
\tfetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
\tremote = origin
\tmerge = refs/heads/main
"""

# path -> (status, content_type, body)
EXACT_ROUTES: dict[str, tuple[int, str, str]] = {
    "/": (200, "text/html", APACHE_DEFAULT_PAGE),
    "/wp-login.php": (200, "text/html", WP_LOGIN_PAGE),
    "/xmlrpc.php": (200, "text/xml", XMLRPC_FAULT),
    "/.env": (200, "text/plain", DOTENV_FILE),
    "/.git/config": (200, "text/plain", GIT_CONFIG_FILE),
}

# prefix -> (status, content_type, body), used if no exact match
PREFIX_ROUTES: list[tuple[str, tuple[int, str, str]]] = [
    ("/phpmyadmin", (200, "text/html", PHPMYADMIN_PAGE)),
    ("/wp-admin", (200, "text/html", WP_LOGIN_PAGE)),
]


def build_response(path: str) -> tuple[int, str, str]:
    """Returns (status, content_type, body) for a request path."""
    clean_path = path.split("?", 1)[0].lower() or "/"

    if clean_path in EXACT_ROUTES:
        return EXACT_ROUTES[clean_path]

    for prefix, response in PREFIX_ROUTES:
        if clean_path.startswith(prefix):
            return response

    return 404, "text/html", APACHE_404_PAGE
