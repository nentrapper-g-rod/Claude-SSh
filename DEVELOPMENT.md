# SSH Manager — Development Notes

## What It Does

An MCP server plugin that gives Claude Code secure SSH access. Passwords are saved in an AES-256 encrypted vault. Claude asks the user for a master passcode before any SSH operation.

## Architecture

```
User → Claude Code → MCP Protocol (stdio) → ssh_server.py → sshpass/ssh → Remote Host
                                                  ↓
                                        ~/.config/claude-ssh/
                                          hosts.json.enc  (AES encrypted)
                                          .salt           (PBKDF2 salt)
```

## Tools Provided

| Tool | Auth Required | Description |
|------|:---:|-------------|
| `ssh_setup` | No | Create vault with master passcode |
| `ssh_unlock` | Passcode | Decrypt vault for this session |
| `ssh_run` | Unlocked | Run command on remote host |
| `ssh_add_host` | Unlocked | Add/update host profile |
| `ssh_list_hosts` | Unlocked | List hosts (no passwords shown) |
| `ssh_remove_host` | Unlocked | Delete a host profile |

## Security Design

- **Encryption**: AES-256-CBC via OpenSSL CLI (no Python crypto dependencies)
- **Key Derivation**: PBKDF2 with SHA-256, 100k iterations, random 16-byte salt
- **Storage**: `~/.config/claude-ssh/hosts.json.enc` (file mode 600)
- **Passcode**: Never stored on disk — entered by user each session
- **Session**: Decrypted hosts held in memory only while MCP server runs
- **SSH**: Uses `sshpass` for password auth, falls back to key-based auth

## File Structure

```
/opt/claude-ssh/
  README.md              — User-facing docs
  DEVELOPMENT.md         — This file
  .claude-plugin/
    plugin.json           — Plugin metadata + MCP server config
    mcp/
      ssh_server.py       — MCP server (Python, no pip deps)
```

## Data Files (created at runtime)

```
~/.config/claude-ssh/
  hosts.json.enc    — Encrypted host profiles (AES-256-CBC)
  .salt             — Random salt for key derivation (16 bytes)
```

## Dependencies

- Python 3.8+
- OpenSSL CLI (`openssl` — pre-installed on Linux/macOS)
- sshpass (`sudo apt install sshpass` — for password-based SSH)

## How Claude Uses It

1. User says "SSH into steel and check disk space"
2. Claude calls `ssh_unlock` — realizes vault is locked
3. Claude asks user: "I need your SSH vault passcode to connect"
4. User types passcode
5. Claude calls `ssh_unlock(passcode=...)` — vault decrypts
6. Claude calls `ssh_run(host="steel", command="df -h")`
7. Plugin connects via sshpass, returns output
8. Claude shows the disk usage to the user

## Testing

```bash
# Test locally
claude --plugin-dir /opt/claude-ssh

# Then say:
# "Set up SSH vault" → creates vault
# "Add host steel 100.94.187.56 user joshuag password mypass" → saves host
# "Run uptime on steel" → asks for passcode, then runs
```

## Future Ideas

- SSH key management (import/generate keys)
- SCP file transfer tool
- SSH tunnel management
- Port forwarding
- Multi-hop/jump host support
- Import hosts from VS Code Nav connections
