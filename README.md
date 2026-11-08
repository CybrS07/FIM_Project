# FIM: File Integrity Monitor (Rust + React)

## Setup
- Backend: install Rust (https://rustup.rs), then `cd backend`
- Frontend: install Node 18+, then `cd frontend && npm install`

## CLI (backend folder)
    cargo run -- init                # asks for the folder path (or: cargo run -- init /path/to/folder)
    cargo run -- check               # prints [ADDED] / [MODIFIED] / [DELETED], exit code 1 on warning
    cargo run -- encrypt             # baseline.json -> baseline.enc (password prompt, hidden)
    cargo run -- verify-enc          # proves the password decrypts to the plain baseline
    cargo run -- accept              # approve changes: re-baseline (do NOT use between assignment tests)

## Web UI
    cd backend  && cargo run -- serve     # API on 127.0.0.1:8080
    cd frontend && npm run dev            # open http://localhost:5173

Green banner = all files match. Red warning = unapproved changes; press "Approve and update baseline" only for changes you made.

## Assignment tests
Create the baseline once, then add a file, edit a file and delete a file, running `check` after each action. Screenshot each with the date/time visible. Restore the files between tests without re-running `init`.

## Limitations
- Checks on demand only (no real-time watching). Symlinks are not specially handled.
- baseline.json is not signed: encryption gives confidentiality, not proof of authenticity. An attacker who can edit it could hide changes. Keep a protected backup (or add an HMAC/signature).
- The API is bound to localhost and has no login; do not expose it.

## Tool / AI disclosure
Fill in: Rust/cargo, sha2, argon2, chacha20poly1305, React/Vite, terminal, editor. If AI helped (Claude), state how, and make sure you can explain the code.
