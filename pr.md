# Align yeswehack-mcp with the official YesWeHack API, add tests, docs and build targets

## Summary

This change set makes the MCP server talk to the YesWeHack API the way the
official OpenAPI specification (`https://api.yeswehack.com/doc.json`,
version 25.24.0) and the official `yeswehack` Python SDK describe it. Seven of
the twelve tools were calling endpoints or reading fields that do not exist;
they now use the documented ones. Around that fix the repository gains an
offline test suite, a read-only live test suite, API documentation, a
Makefile, and several security hardenings.

A full source audit found no malicious code. All changes were verified against
the real API with a Program Auditor Personal Access Token using GET requests
only.

## API changes in the Python files

### server.py: tools

| Tool | Before | After |
|---|---|---|
| `get_hacktivity` | `GET /hacktivity` (returns 404; the tool always failed). | `GET /v2/hacktivity` (public, no token). Parameter `results_per_page` removed because the API ignores it; only `page` remains. Output: `date | hunter | bug type | status` per line. |
| `list_report_comments` | `GET /reports/{id}/comments` (405), with fallbacks to `/messages` and `/activities` (404). The 405 escaped as an exception. | `GET /reports/{id}/logs`. Shows log entries of type `comment`; new parameter `include_history` adds status, CVSS and reward entries. `raw=true` output redacts `tracker_token` and `claim_email`. |
| `list_reports` | Sent `status=<value>`, which the API ignores. Printed the `status` dict raw and `severity` as `?`. | Sends `filter[status][]` (comma-separated values accepted), `page` and the new `results_per_page` parameter. Prints `status.workflow_state` and `cvss.criticity (score)`. A 400 for an unknown status is returned as text. Header shows page and total counts from `pagination`. |
| `get_report` | Read `severity` and `cvss_vector` (do not exist), so both printed `N/A`. | Reads `cvss.criticity`, `cvss.score`, `cvss.vector`, `status.workflow_state`, `bug_type.name`, `scope`, `tracking_status`, `created_at`. `CVSS` prints `N/A` when the score is null. |
| `get_program` | Read `reward_policy`, `guidelines`, `policy`, `pgp_key`, `languages`, `disabled_vulnerability_types`, `asset_label` (none exist). Output was mostly `N/A`. | Reads `rules`, `bounty_reward_min` / `bounty_reward_max`, `reward_grid_default.bounty_{low,medium,high,critical}`, `supported_languages`, `qualifying_vulnerability`, `non_qualifying_vulnerability`, `account_access`, scope fields `scope_type_name` and `asset_value`; `out_of_scope` is a list of strings. |
| `get_program_credentials` | Tried `/programs/{slug}/credentials`, `/credential-pools`, `/credentials-pools`, `/credentials/requests`. `include_secrets` defaulted to `True`. | `GET /programs/{slug}/hunter/credentials` (hunter view: `items.credentials` and `items.credential_requests`). `include_secrets` defaults to `False`; `raw=true` honours it by redacting `password`. A 403 for a non-hunter token returns a message. |
| `request_program_credentials` | Six guessed POST paths, body `{"email": ...}`. Could never succeed. | `POST /programs/{slug}/hunter/ask-credentials/{pool_slug}/{pool_type}` with `pool_type` in `classic`, `email`, `email-alias`. Body `{"emails": [email]}` only for `email` pools; `classic` and `email-alias` send no body. Parameters renamed: `pool_id` is now `pool_slug` (required), `pool_type` added. |
| `get_current_user` | A 403 or 404 from `/user` raised an exception. | Returns a message. `/user` is a web-session route; a Personal Access Token receives 403. |
| `list_email_aliases` | Tried five guessed paths through a fallback helper. | Direct `GET /user/email-aliases` (web-session route, 403 for a Personal Access Token) with the same error messages as `get_current_user`. |
| `authenticate` | API login sent `otp` in the `/login` body and expected `{"totp": true}`. | Follows the official SDK: `POST /login` returns `token` or `totp_token`; with a `totp` argument the code is sent to `POST /account/totp` as `{"token": <totp_token>, "code": <totp>}`. |
| `list_programs`, `yeswehack_api_get` | Correct endpoints; unexpected statuses raised. | Unchanged endpoints; errors now return messages (see below). |

Tool count is unchanged (12). Tool names are unchanged. Parameter changes:
`list_reports(+page, +results_per_page)`, `list_report_comments(+include_history)`,
`get_program_credentials(include_secrets default True -> False)`,
`request_program_credentials(pool_id -> pool_slug, +pool_type)`,
`get_hacktivity(-results_per_page)`.

### server.py: internals

- Added `_tool_errors`, a decorator applied under `@mcp.tool()` on every tool
  that uses the authenticated client. It converts `NotAuthenticatedError`,
  `ForbiddenError`, `NotFoundError`, `BadRequestError`, `ConflictError`,
  `ValueError`, `httpx.HTTPStatusError` (405, 5xx) and other `httpx.HTTPError`
  into a message string. Response bodies of unexpected statuses are not echoed.
- Added `_redacted` (deep copy with secret keys replaced by `(hidden)`),
  `_workflow_state`, `_cvss_summary`, `_username`, `_format_log`,
  `_public_client` (unauthenticated client for the public hacktivity feed).
- Removed `_get_with_fallback` and `_post_with_fallback` (endpoint guessing).
- `_format_credential_item` now reads the `credential_pool` object and no
  longer treats the boolean `email_alias` as a login.

### auth.py

- `api_login(email, password, totp=None, *, transport=None)`: new keyword-only
  `transport` for tests; implements the `/login` plus `/account/totp` flow.
  Added `_json_or_empty`.
- Removed the automatic loading of Windows browser extensions (1Password,
  Bitwarden, MetaMask) into the Playwright Chromium used for browser login.
  Extensions load only when listed in `~/.config/yeswehack-mcp/extensions.json`.
- Token storage: the config directory is created with mode `0700`, the token
  file is written with mode `0600` (also re-tightened if it already existed).

### client.py

- `YesWeHackClient(token, *, transport=None)`: new keyword-only `transport`
  so tests can inject `httpx.MockTransport`. No behaviour change otherwise.
  Header selection is unchanged: JWTs use `Authorization: Bearer`, Personal
  Access Tokens use `X-AUTH-TOKEN`.

## Tests

- `tests/conftest.py`: fake API served through `httpx.MockTransport` with the
  response shapes from the OpenAPI spec and live observations.
- `tests/test_tools.py`: 39 offline tests covering every tool, the error
  decorator, raw-mode redaction, the TOTP flow, token file permissions and the
  registered tool schema.
- `tests/test_auth_extensions.py`: guards that extension auto-detection stays
  removed.
- `tests/test_live.py`: 9 read-only tests (10 test cases) against the real
  API. Marked `live`, skipped unless `YWH_PAT` is set, and skipped when
  `YWH_TOKEN` is set so a session JWT never drives the suite. Only GET
  requests; assertions use pre-bound booleans so a failure cannot print report
  contents.

## Build, docs and configuration

- `Makefile`: `help` (default), `build` (`uv build`), `test` (offline suite,
  deselects `live`), `test-live` (sources `.env`, runs the read-only live
  suite), `clean`.
- `pyproject.toml`: `mcp[cli]>=1.2.0,<2` (mcp 2.x removed `mcp.server.fastmcp`),
  `[dependency-groups] dev` with `pytest>=8,<9.2` and `pytest-asyncio>=0.24`,
  pytest options (`asyncio_mode = "auto"`, `addopts = "-m 'not live'"`,
  `live` marker), anchored wheel includes (`/server.py`, `/auth.py`,
  `/client.py`), sdist excludes for `.superpowers`, `.codex`, `.env`, `dist`,
  `.venv`.
- `uv.lock`: refreshed for the pin and the dev group.
- `docs/API.md`: links to the OpenAPI spec, Redoc, the Personal Access Token
  help-center article and the official SDK; authentication, pagination,
  tool-to-endpoint map, report filter enums.
- `README.md`: features, tool table and examples aligned with the code;
  Development section; link to `docs/API.md`.
- `.gitignore`: `dist/`, `build/`, `*.egg-info/`, `.pytest_cache/`.
- `.github/workflows/test.yml`: GitHub Actions workflow on pushes to `main`
  and on pull requests, matrix Python 3.10 and 3.13. Steps: checkout,
  `astral-sh/setup-uv` with a cache keyed on `uv.lock`, `uv python install`,
  `uv sync --locked` (runtime dependencies plus the `dev` group; fails if the
  lock file is stale), then `make test`. Live tests are deselected by the
  pytest `addopts`, so CI needs no YesWeHack token.

## Verification

- `make test`: 40 passed, 1 skipped, 0 warnings.
- `make test-live`: 10 passed against `api.yeswehack.com`, 12 requests, all GET.
- `make build`: wheel contains exactly `server.py`, `auth.py`, `client.py`.
- CI (`.github/workflows/test.yml`) runs the same `uv sync --locked` and
  `make test` sequence; verified locally with the identical commands.

## Not included

- `~/.config/yeswehack-mcp` directories created by earlier versions keep their
  existing permissions; only the token file inside is re-tightened.
- A `/programs/{slug}` 404 followed by a listing 404 reports the listing path
  rather than the requested slug.
