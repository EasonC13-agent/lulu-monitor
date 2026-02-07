#!/bin/bash
# Handle LuLu callback from Telegram
# Usage: handle-callback.sh <callback_data>
# Example: handle-callback.sh "lulu:allow:abc123"

CALLBACK="$1"

# Parse callback data
if [[ "$CALLBACK" =~ ^lulu:(allow|block):(.+)$ ]]; then
    ACTION="${BASH_REMATCH[1]}"
    HASH="${BASH_REMATCH[2]}"
    
    echo "Processing: $ACTION (hash: $HASH)"
    
    # Get current message ID from lulu-monitor
    STATUS=$(curl -s http://127.0.0.1:4441/status)
    MSG_ID=$(echo "$STATUS" | grep -o '"lastMessageId":"[^"]*"' | cut -d'"' -f4)
    
    # Call the callback endpoint
    RESULT=$(curl -s -X POST http://127.0.0.1:4441/callback \
        -H "Content-Type: application/json" \
        -d "{\"action\":\"$ACTION\",\"messageId\":\"$MSG_ID\"}")
    
    echo "$RESULT"
else
    echo "Invalid callback format: $CALLBACK"
    exit 1
fi
