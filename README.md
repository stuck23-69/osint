# osint

Small CLI for public lookups. One file, `osint.py`. Uses the Python standard library and `requests`.

`ip` asks [ipwho.is](https://ipwho.is) about a public address. `user` checks the username against the sites in `PLATFORMS` at the top of `osint.py`. A hit means that public URL responded like a profile. It does not mean the accounts belong to the same person. `ask` sends the last result to Ollama on this machine.

```bash
pip install requests
```

## Examples

```bash
python osint.py ip 1.1.1.1
python osint.py --no-banner user torvalds
python osint.py ask "What is public here, and what is still unknown?"
python osint.py --auto ip 8.8.8.8
```

`--no-banner` skips the intro animation. The animation also stays off when stdout is not a terminal.

`--auto` runs a short privacy-focused question after `ip` or `user`. The default model is `qwen2.5:1.5b` at `http://localhost:11434`. If Ollama is down, the lookup still prints and a short warning follows.

```bash
ollama serve
ollama pull qwen2.5:1.5b
```

The last result is saved at `~/.local/share/osint/last_result.txt`, which is what `ask` reads.

## Tor

`--tor` sends `ip` and `user` requests through the Tor SOCKS5 proxy at `127.0.0.1:9050`. Ollama stays on localhost.

Install Tor and start the daemon (port 9050, not the Tor Browser port):

```bash
# Arch
sudo pacman -S tor
sudo systemctl start tor

# Debian or Ubuntu
sudo apt install tor
sudo systemctl start tor

# or in the foreground
tor
```

```bash
python osint.py --tor ip 1.1.1.1
python osint.py --tor --no-banner user someuser
```

If nothing is listening:

```text
Tor SOCKS proxy not running on 127.0.0.1:9050
```

## What to edit

In `osint.py`:

- `PLATFORMS` — add or remove a site. A value is a URL with `{u}`, or a dict with `url`, optional `missing` text, and optional `absent` status codes.
- `SYSTEM_PROMPT` and `AUTO_QUESTION` — what the local model is told.
- `OLLAMA_MODEL` — default `qwen2.5:1.5b`.

A `404` means the name was not there. A normal `200` means the page responded like a profile, unless `missing` shows up in the body. Sites that return a challenge page are listed as unclear.
