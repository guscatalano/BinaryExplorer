# BinaryExplorer MCP server

A small MCP (Model Context Protocol) server that exposes BinaryExplorer's PE
inspectors as tools, so an MCP client (e.g. Claude Code) can examine binaries.

## Build

```pwsh
dotnet build BinaryExplorer.Mcp -c Release
```

The binary is `bin\Release\net10.0\be-mcp.exe`.

## Configure in Claude Code

Add to your Claude Code MCP settings (`claude_desktop_config.json` or equivalent):

```json
{
  "mcpServers": {
    "binary-explorer": {
      "command": "C:\\path\\to\\BinaryExplorer.Mcp\\bin\\Release\\net10.0\\be-mcp.exe"
    }
  }
}
```

## Tools

| Tool        | Arguments                          | Returns                                                     |
| ----------- | ---------------------------------- | ----------------------------------------------------------- |
| `pe_info`   | `{ path }`                         | machine, subsystem, image base, entry, sections             |
| `hashes`    | `{ path }`                         | md5, sha1, sha256, sha512, imphash                          |
| `imports`   | `{ path }`                         | imported DLLs + functions per DLL                           |
| `exports`   | `{ path }`                         | named exports with RVAs                                     |
| `strings`   | `{ path, max? }`                   | ASCII + UTF-16LE strings (len >= 6)                         |
| `signature` | `{ path }`                         | Authenticode subject/issuer/thumbprint/validity (if signed) |

All tools take a `path` argument pointing to a Windows PE binary on the local filesystem.

## Transports

### Stdio (default)

Line-delimited JSON-RPC 2.0 over stdio. Each request/response is one line of JSON.

```pwsh
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' | be-mcp.exe
echo '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' | be-mcp.exe
```

### HTTP

`be-mcp.exe --http 8080` starts an HTTP listener on `http://localhost:8080/`.

- **POST any path** with a JSON-RPC 2.0 request body — returns the JSON-RPC response synchronously.
- **GET /tools** — returns the same tool descriptors as `tools/list` for quick inspection.
- CORS-permissive (`Access-Control-Allow-Origin: *`) for browser-based clients.

```pwsh
# initialize
curl -s http://localhost:8080/ -H "Content-Type: application/json" `
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}'

# list tools (also: GET /tools)
curl -s http://localhost:8080/ -H "Content-Type: application/json" `
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'

# call a tool
curl -s http://localhost:8080/ -H "Content-Type: application/json" `
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"hashes","arguments":{"path":"C:/Windows/System32/notepad.exe"}}}'
```
