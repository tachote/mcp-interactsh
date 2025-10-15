# A vibe code MCP Interactsh Bridge

This project exposes [ProjectDiscovery's interactsh](https://github.com/projectdiscovery/interactsh) as a [Model Context Protocol](https://modelcontextprotocol.io/) server implemented in Node.js. It lets MCP-compatible IDEs or agents provision interactsh sessions, poll for out-of-band interactions, and tear them down without modifying the upstream interactsh codebase.

## Features

- **Session provisioning** – Generates RSA key pairs, registers with the public interactsh fleet, and returns ready-to-use callback domains.
- **Polling & decryption** – Retrieves encrypted interaction data and decrypts it locally using the session's private key.
- **Lifecycle management** – Lists cached sessions and deregisters them when finished.
- **Demo script** – `npm run demo` spins up a session, issues a real HTTP probe, and prints the captured DNS/HTTP events.

## Requirements

- Node.js 18 or newer (tested on Node 20.19)
- Network access to the interactsh fleet (defaults to `https://oast.pro`)

## Installation (local)

```bash
git clone https://github.com/tachote/mcp-interactsh
cd mcp-interactsh
npm install
```

### Run via npx


```bash
npx -y mcp-interactsh
```

You can also pass environment variables inline:

```bash
INTERACTSH_BASE_URL=https://oast.pro \
INTERACTSH_DOMAIN_SUFFIX=oast.pro \
npx -y mcp-interactsh
```
## Usage

### Run the MCP server

The MCP server communicates over stdio. Configure your MCP-compatible client (e.g. Claude Code, VS Code MCP, Cursor) to launch:

```bash
node src/server.js
```

Optional environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `INTERACTSH_BASE_URL` | `https://oast.pro` | Base URL of the interactsh server to target. |
| `INTERACTSH_DOMAIN_SUFFIX` | host derived from `INTERACTSH_BASE_URL` | Domain suffix used to build callback hosts. Override when using a custom interactsh deployment. |
| `INTERACTSH_TOKEN` | _(unset)_ | Authorization token if your interactsh server enforces auth. |

### Available MCP tools

1. `create_interactsh_session` – Registers a new session and returns correlation ID, secret key, PEM private key, callback domain, server URL, plus explicit probe instructions.
   - Probing rules:
     - Build host as `<correlation_id><nonce13>.<domain>`.
     - `correlation_id` is exactly 20 lowercase hex chars; do not alter or truncate.
     - `nonce13` is exactly 13 lowercase alphanumeric chars `[a-z0-9]`.
     - The label before the first dot must be 33 chars total (20 + 13).
     - Requests to `<correlation_id>.<domain>` (no nonce) are ignored by interactsh.
     - Prefer plain HTTP for probes. Wait 2–3 seconds, then poll for events.
2. `list_interactsh_sessions` – Lists all sessions cached in memory for the current MCP process.
3. `poll_interactsh_session` – Polls interactsh for new interactions, returning decrypted events. Optional arguments let you filter by `method`, `path_contains`, `query_contains`, `protocol`, or `text_contains` to focus on specific callbacks.
4. `deregister_interactsh_session` – Deregisters the session and removes it from local state.

## Configure in Claude Code (JSON)

Claude Code supports MCP servers over stdio. If you prefer to configure via JSON, add an entry like the following in your Claude Code settings (Settings → MCP Servers or the equivalent config file):

```json
{
  "mcpServers": {
    "interactsh": {
      "transport": "stdio",
      "command": "npx",
      "args": ["-y", "mcp-interactsh"],
      "env": {
        "INTERACTSH_BASE_URL": "https://oast.pro",
        "INTERACTSH_DOMAIN_SUFFIX": "oast.pro"
        // "INTERACTSH_TOKEN": "your_server_token_if_required"
      }
    }
  }
}
```

If you prefer to use a local path (without npx), use:

```json
{
  "mcpServers": {
    "interactsh": {
      "transport": "stdio",
      "command": "node",
      "args": ["/absolute/path/to/src/server.js"],
      "env": {
        "INTERACTSH_BASE_URL": "https://oast.pro",
        "INTERACTSH_DOMAIN_SUFFIX": "oast.pro"
      }
    }
  }
}
```

Or you can add it with:

```bash
claude mcp add --transport stdio interactsh \
    -e INTERACTSH_BASE_URL=https://oast.pro \
    -e INTERACTSH_DOMAIN_SUFFIX=oast.pro \
    -- npx -y mcp-interactsh
```

## Configure in Codex (TOML)

Codex reads MCP server configuration from `~/.codex/config.toml`. Add an entry like the following:

```toml
[mcp_servers.interactsh]
command = "npx"
args = ["-y", "mcp-interactsh"]
env = { INTERACTSH_BASE_URL = "https://oast.pro", INTERACTSH_DOMAIN_SUFFIX = "oast.pro" }
```

If you prefer to reference a local clone instead of npx:

```toml
[mcp_servers.interactsh]
command = "node"
args = ["/absolute/path/to/src/server.js"]
env = { INTERACTSH_BASE_URL = "https://oast.pro", INTERACTSH_DOMAIN_SUFFIX = "oast.pro" }
```
Or you can add it with:

```bash
codex mcp add --env INTERACTSH_BASE_URL=https://oast.pro --env INTERACTSH_DOMAIN_SUFFIX=oast.pro interactsh -- npx -y mcp-interactsh
```

You can verify the configuration with:

```bash
codex mcp list
codex mcp get interactsh --json
```
## License

Released under the MIT License. See `LICENSE` for details.

## Credits

This bridge builds on the excellent work by ProjectDiscovery. See the original interactsh project:

- Interactsh repository: https://github.com/projectdiscovery/interactsh
