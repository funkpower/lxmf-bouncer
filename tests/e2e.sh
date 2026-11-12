#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-Reticulum
# End-to-end test: builds the bouncer and runs tests/e2e.py on a private
# Reticulum network of its own (127.0.0.1, port 4360-4369).
#
# Needs a Python environment with the reference RNS and LXMF:
#   python -m venv /path/to/venv && /path/to/venv/bin/pip install rns lxmf
#   LXMF_TEST_VENV=/path/to/venv tests/e2e.sh
# Logs and state go to $LXMF_TEST_WORK (default /tmp/lxmf-bouncer-e2e),
# cleared at the start of each run and kept afterwards.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
venv="${LXMF_TEST_VENV:?set LXMF_TEST_VENV to a venv with rns and lxmf installed}"
work="${LXMF_TEST_WORK:-/tmp/lxmf-bouncer-e2e}"
cargo build --manifest-path "$here/../Cargo.toml" --quiet
target="${CARGO_TARGET_DIR:-$here/../target}"
exec "$venv/bin/python" -u "$here/e2e.py" \
    --work "$work" \
    --python "$venv/bin/python" \
    --rnsd "$venv/bin/rnsd" \
    --bouncer "$target/debug/lxmf-bouncer"
