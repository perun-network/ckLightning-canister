#!/bin/bash
# Kill all ckLightning-related processes to prepare for a clean test run.
# Usage: bash kill_all.sh

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WORKSPACE="$(cd "$SCRIPT_DIR/../.." && pwd)"

echo "Killing ckLightning test processes..."

# Kill relay and LDK nodes
killall -9 ldk-sample 2>/dev/null && echo "  Killed ldk-sample processes" || echo "  No ldk-sample processes"
killall -9 ic-lightning-relay 2>/dev/null && echo "  Killed ic-lightning-relay processes" || echo "  No ic-lightning-relay processes"

# Kill ckLightning client
pkill -9 -f "ckLightning-client" 2>/dev/null && echo "  Killed ckLightning-client processes" || echo "  No ckLightning-client processes"

# Clean Lightning data directories
rm -rf "$WORKSPACE/ic-lightning-relay/ldk_data_canister" \
       "$WORKSPACE/ldk-sample/ldk_data_standard" \
       "$WORKSPACE/ldk-sample/ldk_data_user2" 2>/dev/null
echo "  Cleaned Lightning data directories"

# Wait for ports to be released
sleep 1

# Verify
remaining=$(pgrep -f "ldk-sample|ic-lightning-relay|ckLightning-client" | wc -l)
if [ "$remaining" -eq 0 ]; then
    echo "All clean."
else
    echo "WARNING: $remaining processes still running:"
    pgrep -af "ldk-sample|ic-lightning-relay|ckLightning-client"
fi
