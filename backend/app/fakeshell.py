"""Minimal fake filesystem and command handler for the SSH honeypot."""

HOSTNAME = "ip-10-0-1-42"

FILES: dict[str, str] = {
    "/etc/passwd": (
        "root:x:0:0:root:/root:/bin/bash\n"
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
        "sys:x:3:3:sys:/dev:/usr/sbin/nologin\n"
        "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
        "ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\n"
    ),
    "/etc/hostname": f"{HOSTNAME}\n",
    "/etc/os-release": (
        'NAME="Ubuntu"\n'
        'VERSION="22.04.3 LTS (Jammy Jellyfish)"\n'
        "ID=ubuntu\n"
        'ID_LIKE=debian\n'
        'PRETTY_NAME="Ubuntu 22.04.3 LTS"\n'
    ),
    "/etc/hosts": f"127.0.0.1\tlocalhost\n127.0.1.1\t{HOSTNAME}\n",
}

DIRS: dict[str, list[str]] = {
    "/": ["bin", "boot", "dev", "etc", "home", "lib", "proc", "root", "sbin", "tmp", "usr", "var"],
    "/root": [".bashrc", ".profile", ".ssh"],
    "/root/.ssh": [],
    "/home": ["ubuntu"],
    "/home/ubuntu": [],
    "/etc": ["passwd", "hostname", "os-release", "hosts"],
    "/tmp": [],
    "/var": ["log", "www"],
    "/var/log": [],
    "/var/www": [],
    "/usr": ["bin", "local"],
    "/usr/bin": [],
    "/usr/local": [],
}


def normalize_path(cwd: str, target: str) -> str:
    base = target if target.startswith("/") else f"{cwd.rstrip('/')}/{target}"
    parts: list[str] = []
    for part in base.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            if parts:
                parts.pop()
            continue
        parts.append(part)
    return "/" + "/".join(parts)


def run_command(line: str, cwd: str, username: str) -> tuple[str, str, bool]:
    """Interpret one command line. Returns (output, new_cwd, should_exit)."""
    parts = line.strip().split()
    if not parts:
        return "", cwd, False
    cmd, *args = parts

    if cmd in ("exit", "logout", "quit"):
        return "", cwd, True

    if cmd == "pwd":
        return cwd + "\n", cwd, False

    if cmd == "whoami":
        return f"{username}\n", cwd, False

    if cmd == "id":
        return f"uid=0({username}) gid=0({username}) groups=0({username})\n", cwd, False

    if cmd == "uname":
        if "-a" in args:
            return (
                f"Linux {HOSTNAME} 5.15.0-91-generic #101-Ubuntu SMP "
                "x86_64 GNU/Linux\n",
                cwd,
                False,
            )
        return "Linux\n", cwd, False

    if cmd == "echo":
        return " ".join(args) + "\n", cwd, False

    if cmd == "cd":
        target = normalize_path(cwd, args[0]) if args else "/root"
        if target in DIRS:
            return "", target, False
        return f"-bash: cd: {args[0] if args else target}: No such file or directory\n", cwd, False

    if cmd == "ls":
        path_args = [a for a in args if not a.startswith("-")]
        target = normalize_path(cwd, path_args[0]) if path_args else cwd
        entries = DIRS.get(target)
        if entries is None:
            return f"ls: cannot access '{path_args[0]}': No such file or directory\n", cwd, False
        return ("  ".join(sorted(entries)) + "\n") if entries else "", cwd, False

    if cmd == "cat":
        if not args:
            return "", cwd, False
        target = normalize_path(cwd, args[0])
        if target in FILES:
            return FILES[target], cwd, False
        if target in DIRS:
            return f"cat: {args[0]}: Is a directory\n", cwd, False
        return f"cat: {args[0]}: No such file or directory\n", cwd, False

    if cmd in ("wget", "curl"):
        url = next((a for a in args if "://" in a), None)
        if url is None:
            return f"{cmd}: missing URL\n", cwd, False
        host = url.split("://", 1)[1].split("/", 1)[0]
        # never download anything, just pretend DNS failed
        if cmd == "wget":
            return (
                f"--2026-01-01 00:00:00--  {url}\n"
                f"Resolving {host} ({host})... failed: Temporary failure in name resolution.\n"
                f"wget: unable to resolve host address '{host}'\n"
            ), cwd, False
        return f"curl: (6) Could not resolve host: {host}\n", cwd, False

    return f"-bash: {cmd}: command not found\n", cwd, False
