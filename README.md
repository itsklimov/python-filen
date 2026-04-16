# python-filen

`python-filen` is an early-stage Python client for Filen focused on authentication and login flows.

The current codebase is intentionally small. It explores how to:

- fetch Filen auth metadata such as `authVersion` and `salt`
- derive the login password hash expected by the API
- perform a login request, including a two-factor code

## Status

- Experimental and incomplete
- Not published to PyPI
- API coverage is currently limited to auth/login helpers
- Interface and package layout may change

## Current Surface

The main working code lives in [`src/api/api.py`](src/api/api.py) and currently exposes:

- `get_auth_info(email)`
- `calculate_filen_password(raw_password, salt=None)`
- `filen_login(email, sent_password, two_factor_code, auth_version)`
- `get_logged_in()`

## Setup

Install dependencies with Poetry:

```bash
poetry install
```

Create `src/config/.env` with your Filen credentials:

```dotenv
email=you@example.com
password=your-password
two_factor_code=
```

## Quick Start

Run the included login flow:

```bash
python main.py
```

Or call the helpers directly:

```python
from src.api.api import calculate_filen_password, get_auth_info

auth_info = get_auth_info("you@example.com")
master_key, sent_password = calculate_filen_password(
    "your-password",
    auth_info["salt"],
)
```

## Roadmap

- wrap more Filen endpoints behind a cleaner client surface
- replace one-off script flow with a proper package API
- add tests and examples for the supported auth workflow
- document request/response behavior more thoroughly

## Repository Intent

This repository stays public because it is independent library work, but it should be read as an experimental implementation note rather than a finished SDK.
