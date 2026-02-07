#!/bin/bash
# Helper script for OpenClaw to control LuLu alerts
# Usage: lulu-action.sh allow|block

ACTION="$1"

if [ -z "$ACTION" ]; then
  echo "Usage: lulu-action.sh allow|block"
  exit 1
fi

if [ "$ACTION" != "allow" ] && [ "$ACTION" != "block" ]; then
  echo "Invalid action. Use 'allow' or 'block'"
  exit 1
fi

# Try via HTTP first (if lulu-monitor is running)
RESPONSE=$(curl -s -X POST http://127.0.0.1:4441/action \
  -H "Content-Type: application/json" \
  -d "{\"action\": \"$ACTION\"}" 2>/dev/null)

if echo "$RESPONSE" | grep -q '"success":true'; then
  echo "✅ LuLu alert: $ACTION"
  exit 0
fi

# Fallback: direct AppleScript
BUTTON_NAME=$([ "$ACTION" = "allow" ] && echo "Allow" || echo "Block")

osascript -e "
tell application \"System Events\"
  tell process \"LuLu\"
    set alertWindow to first window whose name contains \"Alert\"
    click button \"$BUTTON_NAME\" of alertWindow
  end tell
end tell
" 2>/dev/null

if [ $? -eq 0 ]; then
  echo "✅ LuLu alert: $ACTION (via AppleScript)"
  exit 0
else
  echo "❌ Failed to $ACTION LuLu alert"
  exit 1
fi
