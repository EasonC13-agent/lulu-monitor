#!/bin/bash
# Setup script for LuLu Monitor

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
PLIST_NAME="com.openclaw.lulu-monitor.plist"
PLIST_SRC="$PROJECT_DIR/$PLIST_NAME"
PLIST_DST="$HOME/Library/LaunchAgents/$PLIST_NAME"

echo "🔧 Setting up LuLu Monitor..."
echo ""

# Create logs directory
mkdir -p "$PROJECT_DIR/logs"

# Make CLI executable
chmod +x "$PROJECT_DIR/bin/lulu-monitor.js"

# Install/update launchd plist
echo "📦 Installing launchd service..."

# Unload if already loaded
launchctl unload "$PLIST_DST" 2>/dev/null || true

# Copy plist
cp "$PLIST_SRC" "$PLIST_DST"

# Load the service
launchctl load "$PLIST_DST"

echo "✅ LuLu Monitor installed and started!"
echo ""
echo "Commands:"
echo "  Start:   launchctl load ~/Library/LaunchAgents/$PLIST_NAME"
echo "  Stop:    launchctl unload ~/Library/LaunchAgents/$PLIST_NAME"
echo "  Logs:    tail -f $PROJECT_DIR/logs/stdout.log"
echo "  Status:  launchctl list | grep lulu"
echo ""
