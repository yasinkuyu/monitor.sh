#!/bin/bash
#
# WebShell Monitor v2.1 – Smart Heuristic & Interactive
# Repo: https://github.com/yasinkuyu/monitor.sh
# Tested on: CentOS 7, Ubuntu 20.04+, Debian
#
# USAGE EXAMPLES:
# -----------------------------------------------------------
# 1. Interactive Menu (Panel):
#    ./monitor.sh
#
# 2. Fast Scan (Only PHP files, last 30 days):
#    ./monitor.sh --path /var/www/vhosts --mode fast --days 30
#
# 3. Deep Scan (All files, no time limit):
#    ./monitor.sh --path /home --mode deep
#
# 4. View Log (Read previous report):
#    ./monitor.sh --view-log
# -----------------------------------------------------------

### ================== SETTINGS & COLORS ==================
LOG_FILE="/tmp/webshell_scan.log"
MAX_FILE_SIZE="5M"  # Skip files larger than 5MB (performance)

RED="\033[31m"; GREEN="\033[32m"; YELLOW="\033[33m"
BLUE="\033[34m"; CYAN="\033[36m"; WHITE="\033[37m"
BOLD="\033[1m"; RESET="\033[0m"

### ================== REGEX PATTERNS (SIGNATURES) ==================
# Whitelist (Directories)
WHITELIST_DIRS='/(vendor|wp-includes|wp-admin/css|wp-admin/images|node_modules|cache|logs)/'

# Ignore Extensions
IGNORE_EXT='\.(css|js|jpg|jpeg|png|gif|svg|woff|woff2|ttf|eot|xml|txt|zip|tar|gz|rar|pdf|sql)$'

# Dangerous Functions (Score: 5-7)
PATTERN_EXEC='(system|exec|shell_exec|passthru|proc_open|popen|pcntl_exec|eval|assert)\s*\('

# Variable Functions (e.g., $a($b) -> Favorite of WebShells) (Score: 7)
PATTERN_VARFUNC='\$[a-zA-Z_][a-zA-Z0-9_]{0,20}\s*\('

# Backtick Operator (shell execution) (Score: 7)
PATTERN_BACKTICK='`.*`'

# Obfuscation Methods (Base64, Hex, Rot13) (Score: 5)
PATTERN_OBFUSCATE='(base64_decode|gzinflate|str_rot13|convert_uudecode)\s*\('

# Hex/Octal Character Stacks (e.g., \x45\x76\x61\x6C) (Score: 10)
PATTERN_HEX='\\x[0-9a-fA-F]{2}.{0,5}\\x[0-9a-fA-F]{2}'

# User Input with Eval/Exec (Critical)
PATTERN_INPUT='\$_(GET|POST|REQUEST|COOKIE|SERVER)'

### ================== FUNCTIONS ==================

function print_banner() {
    clear
    echo -e "${CYAN}${BOLD}"
    echo "  __  __  ___  _   _ ___ _____ ___  ____  "
    echo " |  \/  |/ _ \| \ | |_ _|_   _/ _ \|  _ \ "
    echo " | |\/| | | | |  \| || |  | || | | | |_) |"
    echo " | |  | | |_| | |\  || |  | || |_| |  _ < "
    echo " |_|  |_|\___/|_| \_|___| |_| \___/|_| \_\\"
    echo -e "       WebShell Monitor v2.1${RESET}"
    echo -e "${WHITE}    https://github.com/yasinkuyu/monitor.sh${RESET}"
    echo "----------------------------------------"
}

function show_help() {
    print_banner
    echo -e "${YELLOW}Usage:${RESET} ./monitor.sh [OPTIONS]"
    echo ""
    echo "  --path <dir>     Directory to scan (Default: Current dir)"
    echo "  --mode <mode>    fast (only .php) | deep (all files)"
    echo "  --days <days>    Files modified in the last X days"
    echo "  --view-log       Show the last scan report"
    echo ""
    exit 0
}

function scan_engine() {
    TARGET_DIR="$1"
    SCAN_MODE="$2"
    DAYS_ARG="$3"

    echo -e "${CYAN}[*] Scan Started...${RESET}"
    echo -e "    Target : ${TARGET_DIR}"
    echo -e "    Mode   : ${SCAN_MODE}"
    
    # Reset log file
    echo "Scan Date: $(date)" > "$LOG_FILE"
    echo "Target: $TARGET_DIR" >> "$LOG_FILE"
    echo "----------------------------------------" >> "$LOG_FILE"

    # Build Find Command
    FIND_CMD="find \"$TARGET_DIR\" -type f -size -${MAX_FILE_SIZE}"

    # Time Filter
    if [[ -n "$DAYS_ARG" ]]; then
        FIND_CMD="$FIND_CMD -mtime -$DAYS_ARG"
        echo -e "    Time   : Last ${DAYS_ARG} days"
    fi

    # Mode Filter
    if [[ "$SCAN_MODE" == "fast" ]]; then
        FIND_CMD="$FIND_CMD -name \"*.php*\""
    fi

    # Count files (Informational, ignore errors)
    TOTAL_FILES=$(eval "$FIND_CMD" 2>/dev/null | wc -l)
    echo -e "${CYAN}[*] Approx. ${TOTAL_FILES} files to scan...${RESET}\n"

    COUNTER=0
    SUSPICIOUS_COUNT=0

    # ================== MAIN LOOP ==================
    # Using 'while read' is memory safe for large file sets
    eval "$FIND_CMD" 2>/dev/null | while read -r FILE; do
        ((COUNTER++))
        
        # Progress bar (One dot every 100 files)
        if (( COUNTER % 100 == 0 )); then echo -ne "${CYAN}.${RESET}"; fi

        # Skip whitelist directories
        if [[ "$FILE" =~ $WHITELIST_DIRS ]]; then continue; fi

        # Skip binary/image files (Double check for Deep mode)
        if [[ "$FILE" =~ $IGNORE_EXT ]]; then continue; fi

        SCORE=0
        REASON=""

        # Get File Owner & Permissions (Linux compatible)
        FILE_OWNER=$(stat -c %U "$FILE" 2>/dev/null)
        FILE_PERM=$(stat -c %a "$FILE" 2>/dev/null)

        # Read first 500 lines (Webshells are usually at the top or small)
        # tr -d '\0' cleans null bytes to prevent grep errors
        CONTENT=$(head -n 500 "$FILE" | tr -d '\0')

        # --- HEURISTIC ANALYSIS ---

        # 1. Dangerous Functions
        if grep -Eiq "$PATTERN_EXEC" <<< "$CONTENT"; then
            SCORE=$((SCORE + 5))
            REASON="${REASON},Exec"
        fi

        # 2. Variable Functions ($x($y)) + Input
        if grep -Eiq "$PATTERN_VARFUNC" <<< "$CONTENT"; then
            if grep -Eiq "$PATTERN_INPUT" <<< "$CONTENT"; then
                SCORE=$((SCORE + 10))
                REASON="${REASON},VarFunc+Input"
            else
                SCORE=$((SCORE + 3))
            fi
        fi

        # 3. Obfuscation
        if grep -Eiq "$PATTERN_OBFUSCATE" <<< "$CONTENT"; then
            SCORE=$((SCORE + 5))
            REASON="${REASON},Obfuscated"
        fi

        # 4. Hex/Octal (Heavy encoding)
        if grep -Eiq "$PATTERN_HEX" <<< "$CONTENT"; then
            SCORE=$((SCORE + 10))
            REASON="${REASON},HexPack"
        fi

        # 5. Permission Anomaly (777)
        if [[ "$FILE_PERM" == "777" ]]; then
            SCORE=$((SCORE + 5))
            REASON="${REASON},Perm777"
        fi

        # 6. Owner Anomaly (apache/nobody usually shouldn't own files in /home)
        if [[ "$FILE_OWNER" =~ ^(apache|www-data|nginx|nobody)$ ]]; then
            SCORE=$((SCORE + 5))
            REASON="${REASON},BadOwner($FILE_OWNER)"
        fi

        # 7. Critical Filenames
        FILENAME=$(basename "$FILE")
        if [[ "$FILENAME" =~ ^(adminer|wso|b374k|indoxploit|c99).*\.php$ ]]; then
            SCORE=$((SCORE + 20))
            REASON="${REASON},KnownShellName"
        fi

        # --- REPORTING ---
        if (( SCORE >= 10 )); then
            # Newline for clean output
            echo "" 
            echo -e "${RED}${BOLD}[DANGER] Score: ${SCORE} ${RESET} -> $FILE"
            echo -e "   ${YELLOW}Reason:${RESET} ${REASON:1}"
            echo -e "   ${YELLOW}Info:${RESET}   Owner: $FILE_OWNER | Perm: $FILE_PERM"
            
            # Write to log
            echo "[$(date +'%T')] SCORE:$SCORE FILE:$FILE REASON:${REASON:1}" >> "$LOG_FILE"
            ((SUSPICIOUS_COUNT++))
        fi

    done

    echo -e "\n${GREEN}${BOLD}[✔] Scan Finished.${RESET}"
    echo -e "Total Scanned   : $COUNTER"
    echo -e "Suspicious Files: ${RED}$SUSPICIOUS_COUNT${RESET}"
    echo -e "Log File        : ${BOLD}$LOG_FILE${RESET}"
}

### ================== MAIN MENU / ARGUMENTS ==================

# If no arguments provided, SHOW MENU
if [[ $# -eq 0 ]]; then
    print_banner
    echo -e "${BOLD}Please select a scan mode:${RESET}"
    echo ""
    echo "1) Fast Scan (Only .php files)"
    echo "2) Deep Scan (All text files, slower)"
    echo "3) Changed in Last 7 Days (PHP)"
    echo "4) View Last Scan Log"
    echo "5) Exit"
    echo ""
    read -p "Your choice [1-5]: " CHOICE

    case "$CHOICE" in
        1)
            read -p "Directory to scan [/home]: " T_DIR
            T_DIR=${T_DIR:-/home}
            scan_engine "$T_DIR" "fast" ""
            ;;
        2)
            read -p "Directory to scan [/home]: " T_DIR
            T_DIR=${T_DIR:-/home}
            scan_engine "$T_DIR" "deep" ""
            ;;
        3)
            read -p "Directory to scan [/home]: " T_DIR
            T_DIR=${T_DIR:-/home}
            scan_engine "$T_DIR" "fast" "7"
            ;;
        4)
            if [ -f "$LOG_FILE" ]; then
                less "$LOG_FILE"
            else
                echo -e "${RED}No log file found.${RESET}"
            fi
            ;;
        *)
            echo "Exiting."
            exit 0
            ;;
    esac

else
    # Process arguments (Automation/Cron)
    MODE="fast"
    ROOT="."
    DAYS=""

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --mode) MODE="$2"; shift ;;
            --path) ROOT="$2"; shift ;;
            --days) DAYS="$2"; shift ;;
            --view-log) cat "$LOG_FILE"; exit 0 ;;
            --help) show_help ;;
            *) echo -e "${RED}Unknown parameter: $1${RESET}"; show_help ;;
        esac
        shift
    done

    scan_engine "$ROOT" "$MODE" "$DAYS"
fi
