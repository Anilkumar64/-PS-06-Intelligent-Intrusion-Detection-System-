#!/bin/bash

# ==============================================================================
# PROFESSIONAL UBUNTU SYSTEM MAINTENANCE SCRIPT (STABLE V5)
# ==============================================================================
# Description: Automated system maintenance with reliable TUI.
# Author:      Anil (Fixed & Polished + Static Pipeline at Top)
# Created:     2025-08-01
# Updated:     2025-11-27
# ==============================================================================

# --- Configuration ---
REAL_USER=${SUDO_USER:-$USER}
USER_HOME=$(getent passwd "$REAL_USER" | cut -d: -f6)

# Colors
R='\033[0;31m' # Red
G='\033[0;32m' # Green
Y='\033[1;33m' # Yellow
B='\033[0;34m' # Blue
C='\033[0;36m' # Cyan
W='\033[1;37m' # White
NC='\033[0m'   # No Color

# Steps Definition (short names used in pipeline UI)
STEPS=(
    "Pre-Check"    # Internet & Locks
    "FixBroken"    # Dpkg config/fix
    "BackupAPT"    # Backup configs
    "SysUpdate"    # Update & Full Upgrade
    "Cleanup"      # Autoremove & Clean
    "SnapFresh"    # Snap refresh
    "UserClean"    # Cache & Trash
    "LogTrunc"     # Journal vacuum
)
TOTAL_STEPS=${#STEPS[@]}
CURRENT_STEP_IDX=0    # index into STEPS (0-based)
SUCCESS_COUNT=0
FAIL_COUNT=0
SPACE_BEFORE=0

# ==============================================================================
# HELPER FUNCTIONS
# ==============================================================================

# Header (top of screen)
draw_header() {
    echo -e "${B}============================================================${NC}"
    echo -e "${W}   UBUNTU SYSTEM MAINTENANCE UTILITY ${NC}"
    echo -e "${B}============================================================${NC}"
    echo -e "Host:    ${C}$(hostname)${NC}"
    echo -e "Kernel:  ${C}$(uname -r)${NC}"
    echo -e "User:    ${C}$REAL_USER${NC} (Running as Root)"
    echo -e "${B}============================================================${NC}"
}

# Pipeline Visualization (single place, under header)
draw_pipeline() {
    local active_idx=$1
    echo
    echo -e "${W}Maintenance Pipeline:${NC}"

    for i in "${!STEPS[@]}"; do
        local name="${STEPS[$i]}"

        if (( i < active_idx )); then
            printf "${G}✔ %s${NC}" "$name"        # completed
        elif (( i == active_idx )); then
            printf "${C}● %s${NC}" "$name"        # current
        else
            printf "${Y}○ %s${NC}" "$name"        # pending
        fi

        if (( i < TOTAL_STEPS - 1 )); then
            printf "${B} ── ${NC}"
        fi
    done
    echo -e "\n"
}

# Re-render full top area (header + pipeline) in one place
render_top() {
    clear
    draw_header
    draw_pipeline "$CURRENT_STEP_IDX"
}

# Command Runner with per-step progress bar (but pipeline fixed at top)
run_task() {
    local name="$1"
    shift
    local cmd=("$@")

    # Redraw header + pipeline at top; pipeline now shows current state
    render_top

    echo -e "${B}────────────────────────────────────────────────────────────${NC}"
    echo -e "${C}Step $((CURRENT_STEP_IDX+1))/${TOTAL_STEPS}: ${W}$name${NC}"
    echo -e "${B}────────────────────────────────────────────────────────────${NC}"

    # Helper: read total rx+tx bytes
    get_bytes() {
        awk '/:/{sum+=$2+$10} END{print sum}' /proc/net/dev
    }

    local START_BYTES START_TIME
    START_BYTES=$(get_bytes)
    START_TIME=$(date +%s)

    # Run command in background, discard stdout/stderr (no log file)
    ( "${cmd[@]}" >/dev/null 2>&1 ) &
    local pid=$!

    local PERCENT=0

    while kill -0 "$pid" 2>/dev/null; do
        sleep 0.5

        local NOW_BYTES NOW_TIME DIFF_BYTES DIFF_TIME SPEED_BYTES SPEED_PRINT ETA BAR SPACE
        NOW_BYTES=$(get_bytes)
        NOW_TIME=$(date +%s)

        DIFF_BYTES=$((NOW_BYTES - START_BYTES))
        DIFF_TIME=$((NOW_TIME - START_TIME))
        (( DIFF_TIME == 0 )) && DIFF_TIME=1

        SPEED_BYTES=$((DIFF_BYTES / DIFF_TIME))

        if (( SPEED_BYTES > 1048576 )); then
            SPEED_PRINT="$((SPEED_BYTES / 1048576)) MB/s"
        elif (( SPEED_BYTES > 1024 )); then
            SPEED_PRINT="$((SPEED_BYTES / 1024)) KB/s"
        else
            SPEED_PRINT="${SPEED_BYTES} B/s"
        fi

        # Simple time-based fake percentage
        PERCENT=$(( (DIFF_TIME * 4) % 100 ))
        (( PERCENT < 1 )) && PERCENT=1
        ETA=$((100 - PERCENT))

        BAR=$(printf "%0.s█" $(seq 1 $((PERCENT/4))))
        SPACE=$(printf "%0.s░" $(seq 1 $(((100-PERCENT)/4))))

        echo -ne "[${BAR}${SPACE}] ${PERCENT}% | ${SPEED_PRINT} | ETA: ${ETA}s\r"
    done

    wait "$pid"
    local exit_code=$?

    # Final full bar
    local FULL_BAR
    FULL_BAR=$(printf "%0.s█" $(seq 1 25))
    echo -ne "[${FULL_BAR}] 100% | 0 B/s | ETA: 0s\r"
    echo

    if [ $exit_code -eq 0 ]; then
        echo -e "${G}[DONE]${NC}"
        ((SUCCESS_COUNT++))
    else
        echo -e "${R}[FAIL]${NC}"
        ((FAIL_COUNT++))
    fi

    ((CURRENT_STEP_IDX++))
}

# ==============================================================================
# MAIN LOGIC
# ==============================================================================

# 1. ROOT CHECK (Must be first)
if [[ $EUID -ne 0 ]]; then
   clear
   echo -e "${R}============================================================${NC}"
   echo -e "${R}   PERMISSION DENIED${NC}"
   echo -e "${R}============================================================${NC}"
   echo -e "This script performs system updates and cleans system logs."
   echo -e "You must run it with sudo privileges:"
   echo
   echo -e "    ${G}sudo $0${NC}"
   echo
   exit 1
fi

# Init
clear

# Header + initial pipeline (all pending)
draw_header
draw_pipeline "$CURRENT_STEP_IDX"

# 🚀 No confirmation – start directly
echo -e "${Y}Starting system maintenance now (no confirmation).${NC}"
sleep 1

# Measure disk space before (Available blocks)
SPACE_BEFORE=$(df / | tail -1 | awk '{print $4}')

# --- STEP 1: Pre-Checks (locks & internet) ---
render_top     # show header + pipeline with Pre-Check current

echo -e "${B}────────────────────────────────────────────────────────────${NC}"
echo -e "${C}Step 1/${TOTAL_STEPS}: ${W}Pre-Check (locks & network)${NC}"
echo -e "${B}────────────────────────────────────────────────────────────${NC}"

# Wait for locks
while fuser /var/lib/dpkg/lock >/dev/null 2>&1 || fuser /var/lib/apt/lists/lock >/dev/null 2>&1; do
    echo -ne "${Y}Waiting for other package managers to finish...${NC}\r"
    sleep 2
done
echo -ne "                                                  \r"

# Check Internet
if ! ping -c 1 8.8.8.8 &> /dev/null; then
    echo -e "${R}✖ No Internet connection detected. Aborting update tasks.${NC}"
    ((FAIL_COUNT++))
    exit 1
else
    echo -e "${G}✔ Pre-Check passed (locks free, internet OK).${NC}"
    ((SUCCESS_COUNT++))
fi
((CURRENT_STEP_IDX++))   # mark Pre-Check as done

# --- STEP 2: Fix Broken Packages ---
run_task "Fixing Broken Packages" dpkg --configure -a --force-confold


# --- STEP 4: System Update ---
run_task "Updating System Packages" \
    bash -c "DEBIAN_FRONTEND=noninteractive apt-get update && DEBIAN_FRONTEND=noninteractive apt-get full-upgrade -y"

# --- STEP 5: Cleanup ---
run_task "Removing Unused Packages" \
    bash -c "apt-get autoremove -y && apt-get autoclean"

# --- STEP 6: Snap Refresh ---
if command -v snap &> /dev/null; then
    run_task "Refreshing Snap Packages" snap refresh
else
    CURRENT_STEP_IDX=$((CURRENT_STEP_IDX+1))
    render_top
    echo -e "${Y}⚠ Snap not installed, skipping step.${NC}"
fi

# --- STEP 7: User Cache Cleaning ---
clean_cmds="
rm -rf \"$USER_HOME/.cache/thumbnails/*\";
rm -rf \"$USER_HOME/.local/share/Trash/*\";
"
run_task "Cleaning User Cache & Trash" bash -c "$clean_cmds"

# --- STEP 8: Journal Cleanup ---
# Hard-coded to 2 days; no KEEP_LOGS_DAYS variable
run_task "Vacuuming System Logs" journalctl --vacuum-time=2d

# ==============================================================================
# SUMMARY & EXIT
# ==============================================================================

# Measure disk space after
SPACE_AFTER=$(df / | tail -1 | awk '{print $4}')
FREED_SPACE=$((SPACE_AFTER - SPACE_BEFORE))

if [ $FREED_SPACE -gt 0 ]; then
    FREED_MB=$(awk -v val="$FREED_SPACE" 'BEGIN { printf "%.2f", val / 1024 }')
else
    FREED_MB="0"
fi

# Final top region with full ticks
CURRENT_STEP_IDX=$TOTAL_STEPS
render_top

echo -e "${B}============================================================${NC}"
echo -e "${G}✔ Maintenance Completed!${NC}"
echo -e "${B}============================================================${NC}"
echo -e "Tasks Defined:   ${TOTAL_STEPS}"
echo -e "Successful:      ${G}${SUCCESS_COUNT}${NC}"
echo -e "Failed:          ${R}${FAIL_COUNT}${NC}"
echo -e "Space Reclaimed: ${Y}~${FREED_MB} MB${NC}"
echo -e "Log:             ${C}No log file created (screen-only output).${NC}"

# Reboot Check
if [ -f /var/run/reboot-required ]; then
    echo -e "${R}⚠ A SYSTEM REBOOT IS REQUIRED (Kernel/critical updates installed)${NC}"
    read -rp "🔄 Reboot now? [y/N]: " rb
    if [[ "$rb" =~ ^[Yy]$ ]]; then
        reboot
    fi
fi

exit 0

