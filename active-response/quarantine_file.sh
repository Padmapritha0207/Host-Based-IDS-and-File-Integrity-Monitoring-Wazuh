#!/bin/bash
# ==============================================================================
# Wazuh Active Response: Automated File Quarantine
# Triggered when Rule 100011 (Web Shell Creation) or malicious file drop fires
# ==============================================================================

ACTION=$1
USER=$2
IP=$3
RULE_ID=$4
ALERT_FILE=$5

QUARANTINE_DIR="/var/ossec/quarantine"
LOG_FILE="/var/ossec/logs/active-responses.log"
DATE=$(date "+%Y-%m-%d %H:%M:%S")

# Ensure quarantine directory exists with restricted permissions
if [ ! -d "$QUARANTINE_DIR" ]; then
    mkdir -p "$QUARANTINE_DIR"
    chmod 700 "$QUARANTINE_DIR"
fi

# Read JSON alert passed via stdin by Wazuh Manager / Agent
read -r INPUT_JSON

# Extract target file path using jq or sed
TARGET_FILE=$(echo "$INPUT_JSON" | grep -o '"path":"[^"]*' | cut -d'"' -f4)

if [ -z "$TARGET_FILE" ] && [ -n "$ALERT_FILE" ]; then
    TARGET_FILE="$ALERT_FILE"
fi

echo "$DATE [quarantine_file.sh] Initiating response for file: $TARGET_FILE (Rule: $RULE_ID)" >> "$LOG_FILE"

if [ -f "$TARGET_FILE" ]; then
    # Calculate SHA256 before quarantine for chain of custody
    FILE_SHA256=$(sha256sum "$TARGET_FILE" | awk '{print $1}')
    FILENAME=$(basename "$TARGET_FILE")
    QUARANTINED_PATH="$QUARANTINE_DIR/${FILENAME}_$(date +%s).quarantined"

    # Move file to quarantine storage
    mv "$TARGET_FILE" "$QUARANTINED_PATH"

    # Strip all execution and read permissions
    chmod 000 "$QUARANTINED_PATH"

    # Record forensic artifact metadata
    echo "$DATE [quarantine_file.sh] SUCCESS: Moved '$TARGET_FILE' -> '$QUARANTINED_PATH' | SHA256: $FILE_SHA256" >> "$LOG_FILE"
    echo "{\"status\":\"quarantined\", \"original_path\":\"$TARGET_FILE\", \"quarantined_path\":\"$QUARANTINED_PATH\", \"sha256\":\"$FILE_SHA256\"}"
    exit 0
else
    echo "$DATE [quarantine_file.sh] ERROR: Target file '$TARGET_FILE' does not exist or was already removed." >> "$LOG_FILE"
    exit 1
fi
