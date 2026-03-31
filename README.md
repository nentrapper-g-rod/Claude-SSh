# SSH Manager - Claude Code Plugin

A Claude Code MCP plugin that gives Claude secure SSH access to your remote machines. Passwords are stored in an AES-256 encrypted vault that requires a master passcode to unlock each session.

## How It Works

```
You -> Claude Code -> MCP Protocol (stdio) -> ssh_server.py -> sshpass/ssh -> Remote Host
                                                    |
                                          ~/.config/claude-ssh/
                                            hosts.json.enc  (AES-256 encrypted)
                                            .salt           (PBKDF2 salt)
```

1. You ask Claude to do something on a remote machine (e.g. "check disk space on steel")
2. Claude asks for your vault passcode to decrypt saved credentials
3. Claude connects via SSH, runs the command, and returns the output

## Tools

| Tool | Description |
|------|-------------|
| `ssh_setup` | Create the encrypted vault with a new master passcode |
| `ssh_unlock` | Unlock the vault for the current session |
| `ssh_run` | Run a command on a saved remote host |
| `ssh_add_host` | Save a host profile (name, IP, user, password) |
| `ssh_list_hosts` | List saved hosts (passwords are never shown) |
| `ssh_remove_host` | Delete a host from the vault |

## Quick Start

### Prerequisites

- Python 3.8+
- OpenSSL (pre-installed on Linux/macOS)
- `sshpass` for password-based SSH:
  ```bash
  sudo apt install sshpass    # Debian/Ubuntu
  brew install sshpass         # macOS (via Homebrew)
  ```

### Install

Clone the repo and point Claude Code at it:

```bash
git clone https://github.com/nentrapper-g-rod/-opt-claude-ssh.git
claude --plugin-dir /path/to/-opt-claude-ssh
```

### Usage

**Set up the vault:**
```
> Set up my SSH vault
Claude: What passcode would you like to use?
> mySecurePass123
Claude: Vault created.
```

**Add a host:**
```
> Add server "steel" at 192.168.1.10, user joshuag, password hunter2
Claude: I need your vault passcode first.
> mySecurePass123
Claude: Added steel (192.168.1.10).
```

**Run commands remotely:**
```
> Run "df -h" on steel
Claude: I need your vault passcode to connect.
> mySecurePass123
Claude: Here's the disk usage on steel...
```

## Security

- **Encryption**: AES-256-CBC via the OpenSSL CLI (zero Python crypto dependencies)
- **Key Derivation**: PBKDF2 with SHA-256, 100,000 iterations, random 16-byte salt
- **Storage**: `~/.config/claude-ssh/hosts.json.enc` with file permissions `600`
- **Passcode**: Never written to disk - you enter it once per session
- **Session**: Decrypted credentials are held in memory only while the MCP server is running
- **Auth**: Uses `sshpass` for password auth, falls back to SSH key-based auth

## Project Structure

```
.claude-plugin/
  plugin.json             # Plugin metadata and MCP server config
  mcp/
    ssh_server.py         # MCP server implementation (no pip dependencies)
README.md                 # This file
DEVELOPMENT.md            # Developer notes and architecture details
```

## Future Ideas

- SSH key management (import/generate keys)
- SCP file transfer
- SSH tunnel and port forwarding
- Multi-hop / jump host support

## License

MIT
