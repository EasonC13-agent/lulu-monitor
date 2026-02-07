# LuLu Monitor

A local service that monitors [LuLu Firewall](https://objective-see.org/products/lulu.html) alerts and forwards them to OpenClaw for AI-powered analysis.

## Architecture

```
LuLu Alert → lulu-monitor (detects via AppleScript) → OpenClaw Gateway → Claude analyzes → CLI action
```

Instead of a standalone app with its own API key, this service:
- Monitors for LuLu alert windows using macOS Accessibility API
- Extracts all text from the alert (process name, path, pid, connection details)
- Sends to OpenClaw via Gateway API
- OpenClaw (Claude) analyzes and decides Allow/Block
- You execute: `~/clawd/lulu-monitor/scripts/lulu-action.sh allow|block`

## Installation

```bash
# Clone/copy to your workspace
cd ~/clawd/lulu-monitor

# Install launchd service (auto-start on boot)
./scripts/setup.sh
```

## Usage

### Automatic (via launchd)
The service starts automatically on login and runs in the background.

### Manual
```bash
# Start manually
node src/index.js --verbose

# Check status
curl http://127.0.0.1:4441/status

# Execute action on current alert
./scripts/lulu-action.sh allow
./scripts/lulu-action.sh block
```

### Commands

| Command | Description |
|---------|-------------|
| `launchctl load ~/Library/LaunchAgents/com.openclaw.lulu-monitor.plist` | Start service |
| `launchctl unload ~/Library/LaunchAgents/com.openclaw.lulu-monitor.plist` | Stop service |
| `tail -f ~/clawd/lulu-monitor/logs/stdout.log` | View logs |
| `curl http://127.0.0.1:4441/status` | Check status |

## How It Works

1. **Polling**: Checks every 1 second if a LuLu alert window exists
2. **Detection**: Uses AppleScript to query System Events for LuLu process windows
3. **Extraction**: Gets all static text from the alert window
4. **Forwarding**: Sends to OpenClaw Gateway via `/tools/invoke` API
5. **Action**: OpenClaw analyzes and tells you to run the action script

## Files

```
lulu-monitor/
├── src/
│   └── index.js           # Main monitor service
├── scripts/
│   ├── check-alert.scpt   # AppleScript: check if alert exists
│   ├── extract-alert.scpt # AppleScript: get alert text
│   ├── click-allow.scpt   # AppleScript: click Allow
│   ├── click-block.scpt   # AppleScript: click Block
│   ├── lulu-action.sh     # CLI helper for OpenClaw
│   └── setup.sh           # Install launchd service
├── logs/
│   └── stdout.log         # Service logs
└── com.openclaw.lulu-monitor.plist  # launchd config
```

## Requirements

- macOS with LuLu Firewall installed
- Node.js 18+
- OpenClaw Gateway running
- Accessibility permission for Terminal/iTerm (to run AppleScript)

## Configuration

The service automatically reads from `~/.openclaw/openclaw.json`:
- `port`: Gateway port
- `gateway.auth.token`: Authentication token

## Troubleshooting

**Service not detecting alerts?**
- Check if LuLu is running: `ps aux | grep -i lulu`
- Check logs: `tail -f ~/clawd/lulu-monitor/logs/stdout.log`
- Verify Accessibility permission for your terminal app

**Gateway connection failed?**
- Ensure OpenClaw Gateway is running
- Check token in `~/.openclaw/openclaw.json`
- Try manual test: `curl http://127.0.0.1:<port>/tools/invoke -H "Authorization: Bearer <token>"`
