# Private deck

GitHub Pages serves a password gate and ciphertext. The deck itself is not in this repository.

Nothing sensitive belongs in git. Edit a local `plaintext/` directory, encrypt it, and commit only the gate, the service worker, `vault.json`, and `d/`.

## Edit

`plaintext/` is gitignored. It holds `index.html`, `calculator.html`, `img/`, and any other files the deck links to.

If you only have this repo, recover that directory with the password:

```bash
DECK_PASSWORD='…' node scripts/build.mjs --decrypt
```

`--force` overwrites an existing `plaintext/`.

After editing:

```bash
DECK_PASSWORD='…' node scripts/build.mjs
```

Commit `vault.json` and `d/`. Do not commit `plaintext/`.

The script reads the password from the `DECK_PASSWORD` environment variable and does not write it into the output. Node 20 or newer is required. Encryption is PBKDF2-HMAC-SHA256 (1,000,000 iterations) and AES-256-GCM. The iteration count is high so a short password is slower to guess offline; a short password is still a weak secret.

## Links

The gate and the deck share one URL fragment, because a URL has only one hash.

- Password prompt, or `#k=<password>` to unlock without typing. The fragment is not sent to the server.
- Scenario links stay in the deck's existing form, `#pf?name=value&…`.
- Both at once: `#k=<password>&pf?sale=1600`. A normal in-page hash works the same way: `#k=<password>&design`.
- After a successful unlock the key is dropped from the address bar. The tab remembers the derived key in `sessionStorage` until it is closed.

`#pf?…` on its own still opens the matching scenario after the password is entered.

## History

This repository's history was rewritten so older commits are not on `main`. Do not push the plaintext tree back onto the default branch.
