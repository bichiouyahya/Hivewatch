"""Extract (username, password) pairs from SSH logins and HTTP login
form submissions.
"""

from urllib.parse import parse_qs

from app.schemas import Event

FORM_FIELD_PAIRS = (
    ("log", "pwd"),  # wordpress
    ("username", "password"),
    ("user", "pass"),
    ("email", "password"),
)


def extract(event: Event) -> tuple[str, str] | None:
    if event.service == "ssh" and event.event_type == "auth_attempt":
        username = event.payload.get("username")
        password = event.payload.get("password")
        if username is not None and password is not None:
            return username, password
        return None

    if event.service == "http" and event.event_type == "http_request":
        body = event.payload.get("body", "")
        if not body:
            return None
        fields = parse_qs(body)
        for user_key, pass_key in FORM_FIELD_PAIRS:
            if user_key in fields and pass_key in fields:
                return fields[user_key][0], fields[pass_key][0]
        return None

    return None
