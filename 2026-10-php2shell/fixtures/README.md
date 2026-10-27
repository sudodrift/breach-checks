# Fixtures for 2026-10-php2shell

All files are harmless stand-ins. None contains an exploit.

- `phpbins/php-unfixed`, `php-fixed`, `php-eol`: tiny shell scripts that print a
  fake `php -v` / `PHP_SAPI` line.
- `logs-hit/*`: log lines matching Datadog's documented memory-exhaustion and
  AH00052 signals. `logs-clean/*` has a normal PHP notice only.
- `proc/shell-spawn.fixture`: a fake `ps` listing where `www-data` runs `sh`.
- `audit/hit.fixture`: a fake audit line associating `/bin/sh` with `www-data`.
- `web-hit/html/shell.php.fixture`: a one-line PHP file used as a recently
  modified web-root stand-in. `web-clean` holds a normal index file.
