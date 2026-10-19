# linux-log-summary

Read an authentication log (`/var/log/auth.log`, `/var/log/secure` or a copy) and
summarize the parts that matter for a quick review: failed SSH logins by user and
source IP, successful logins, invalid-user attempts and sudo commands.

## Features

- Parses common `sshd` and `sudo` log lines with regular expressions.
- Top-N tables for failed users and source addresses.
- `--json` for ingestion into a SIEM or a report.
- Fixture-based tests: no access to the host logs required.

## Installation

```bash
git clone https://github.com/victor-harden/linux-log-summary.git
cd linux-log-summary
```

## Usage

```bash
python3 log_summary.py /var/log/auth.log
python3 log_summary.py tests/sample_auth.log --top 5
python3 log_summary.py tests/sample_auth.log --json
sudo cat /var/log/auth.log | python3 log_summary.py -
```

## Tests

```bash
python3 -m unittest discover -s tests -v
```

## Privacy

Logs contain usernames and IP addresses. Treat output as sensitive and avoid
committing real logs to a repository.

## License

MIT — see [LICENSE](LICENSE).
