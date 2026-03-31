# SSH Manager — Claude Code Plugin

Secure SSH connections for Claude Code. Save encrypted host passwords, unlock with a master passcode.

## Tools

| Tool | Description |
|------|-------------|
| `ssh_setup` | Create the encrypted vault with a master passcode |
| `ssh_unlock` | Unlock the vault (Claude will ask you for your passcode) |
| `ssh_run` | Run a command on a remote host |
| `ssh_add_host` | Add/update a host profile (name, IP, user, password) |
| `ssh_list_hosts` | List saved hosts |
| `ssh_remove_host` | Remove a host |

## Usage

```
> Set up SSH vault
Claude: What passcode would you like to use?
> mySecurePass123

> Add steel server: 100.94.187.56 user joshuag password mypass
Claude: I'll need your vault passcode first...
> mySecurePass123
Claude: Added steel (100.94.187.56)

> Run "uptime" on steel
Claude: I need your vault passcode to connect...
> mySecurePass123
Claude: steel uptime: 14:23:01 up 42 days...
```

## Security

- Passwords encrypted with AES-256-CBC (via OpenSSL)
- Key derived from passcode using PBKDF2 (100k iterations)
- Vault file: `~/.config/claude-ssh/hosts.json.enc` (mode 600)
- Passcode never stored — must be entered each session
- Requires `sshpass` for password-based SSH (`sudo apt install sshpass`)

## Install

```bash
/plugin install claude-ssh
```

Or test locally:
```bash
claude --plugin-dir /opt/claude-ssh-plugin
```
