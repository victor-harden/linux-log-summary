#!/usr/bin/env python3
"""Summarize SSH and sudo activity from an auth log."""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path

FAILED = re.compile(r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+)")
INVALID = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>\S+)")
ACCEPTED = re.compile(r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>\S+)")
SUDO = re.compile(r"sudo:\s+(?P<user>\S+) : .*COMMAND=(?P<command>.+)")


def summarize(lines):
    failed_users = Counter()
    failed_ips = Counter()
    accepted_users = Counter()
    invalid_users = Counter()
    sudo_commands = Counter()

    for line in lines:
        match = FAILED.search(line)
        if match:
            failed_users[match.group("user")] += 1
            failed_ips[match.group("ip")] += 1
        match = INVALID.search(line)
        if match:
            invalid_users[match.group("user")] += 1
        match = ACCEPTED.search(line)
        if match:
            accepted_users[match.group("user")] += 1
        match = SUDO.search(line)
        if match:
            sudo_commands[match.group("command").strip()] += 1

    return {
        "failed_logins": sum(failed_users.values()),
        "accepted_logins": sum(accepted_users.values()),
        "invalid_users": sum(invalid_users.values()),
        "failed_by_user": failed_users.most_common(),
        "failed_by_ip": failed_ips.most_common(),
        "accepted_by_user": accepted_users.most_common(),
        "invalid_user_names": invalid_users.most_common(),
        "sudo_commands": sudo_commands.most_common(),
    }


def render(summary: dict, top: int) -> str:
    lines = [
        f"failed logins:   {summary['failed_logins']}",
        f"accepted logins: {summary['accepted_logins']}",
        f"invalid users:   {summary['invalid_users']}",
        "",
        "top failed users:",
    ]
    lines += [f"  {user}: {count}" for user, count in summary["failed_by_user"][:top]] or ["  none"]
    lines.append("top source IPs:")
    lines += [f"  {ip}: {count}" for ip, count in summary["failed_by_ip"][:top]] or ["  none"]
    lines.append("sudo commands:")
    lines += [f"  {cmd}: {count}" for cmd, count in summary["sudo_commands"][:top]] or ["  none"]
    return "\n".join(lines)


def read_lines(source: str):
    if source == "-":
        return sys.stdin.read().splitlines()
    return Path(source).read_text(encoding="utf-8", errors="replace").splitlines()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Summarize auth log activity")
    parser.add_argument("source", help="log file, or - for stdin")
    parser.add_argument("--top", type=int, default=10)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    try:
        lines = read_lines(args.source)
    except OSError as exc:
        print(f"cannot read log: {exc}", file=sys.stderr)
        return 2

    summary = summarize(lines)
    print(json.dumps(summary, indent=2) if args.json else render(summary, args.top))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
