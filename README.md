# threat-ipblock-list

Threat IP / CIDR blocklist (`THREAT.txt`) plus a sync script that updates it from a local source file and pushes to git when content changes.

## Sync script

`sync_threat_list.py` compares a configured **source** file to `THREAT.txt` by SHA-256. If content differs (or the repo file is missing), it copies the source onto the current filename, then optionally `git commit` and `git push`.

### Setup

```bash
cp sync_threat_list.default.var.example sync_threat_list.default.var
```

Edit `sync_threat_list.default.var` and set at least:

```
SOURCE_FILE=/path/to/incoming/THREAT.txt
```

`*.var` files are gitignored. Optional overrides: `--var-file path/to/custom.var`.

### Run

```bash
python3 sync_threat_list.py
```

Useful flags:

- `--dry-run` — print intended copy/commit/push without changing anything
- `--verbose` — extra progress on stderr
- `--no-git-commit` / `--no-git-push` — skip git steps
- `--source-file`, `--current-file`, `--repo-dir` — override VAR paths

### Tests

```bash
python3 -m unittest test_sync_threat_list.py
```
