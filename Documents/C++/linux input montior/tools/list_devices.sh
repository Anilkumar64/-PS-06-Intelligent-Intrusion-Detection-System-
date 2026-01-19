#!/bin/bash

echo "Listing available input devices:"
echo "---------------------------------"

# Check if input devices exist
if [ ! -d /dev/input ]; then
    echo "/dev/input does not exist on this system"
    exit 1
fi

# Parse /proc/bus/input/devices to map names to event files
awk '
BEGIN {
    RS=""
}
{
    name=""
    event=""
    for (i=1; i<=NF; i++) {
        if ($i ~ /^N:/) {
            sub(/^N: Name="/, "", $i)
            sub(/"$/, "", $i)
            name=$i
        }
        if ($i ~ /event[0-9]+/) {
            match($i, /event[0-9]+/)
            event=substr($i, RSTART, RLENGTH)
        }
    }
    if (name != "" && event != "") {
        printf "%-30s -> /dev/input/%s\n", name, event
    }
}
' /proc/bus/input/devices
