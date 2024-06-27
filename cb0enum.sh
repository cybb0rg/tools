#!/bin/bash

# Check for correct usage
if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <target> <output_directory>"
    exit 1
fi

# Variables
TARGET=$1
OUTPUT_DIR=$2
TIMESTAMP=$(date +%d%m%y%H%M%S)
WORDLIST_SUBDOMAIN="/usr/share/wordlists/ctf-wordlist/subdomains-top1mil-20000.txt"  # Replace with the path to your directory wordlist
WORDLIST_DIRECTORIES="/usr/share/wordlists/ctf-wordlist/directories1.txt" # Replace with the path to your directory wordlist
WORDLIST_FILES="/usr/share/wordlists/dirbuster/directory-list-1.0.txt" # Replace with the path to your file wordlist
EXTENTIONS=".php,.html,.xml,.txt" # Replace with your desired file extentions
TELEGRAM_BOT_TOKEN="" # Replace with your telegram bot token
TELEGRAM_CHAT_ID="" # Replace with your telegram chat ID

# Create output directory
mkdir -p $OUTPUT_DIR

# Function to send a message to Telegram
send_telegram_message() {
    local message=$1
    curl -s -X POST https://api.telegram.org/bot$TELEGRAM_BOT_TOKEN/sendMessage -d chat_id=$TELEGRAM_CHAT_ID -d text="$message"
}

# Nmap scans
echo "Starting Nmap scans..."
nmap -sS -A -T4 -p- -Pn -oN $OUTPUT_DIR/nmap_syn_scan_${TIMESTAMP}_${TARGET}.txt $TARGET
sleep 2
nmap -sT -A -T4 -p- -Pn -oN $OUTPUT_DIR/nmap_tcp_scan_${TIMESTAMP}_${TARGET}.txt $TARGET
sleep 2
nmap -sT -A --min-rate 5000 -T4 -p- -Pn -oN $OUTPUT_DIR/nmap_tcpversion_scan_${TIMESTAMP}_${TARGET}.txt $TARGET
sleep 2
map -sU -A -T4 --top-ports 500 -Pn -oN $OUTPUT_DIR/nmap_udp_scan_${TIMESTAMP}_${TARGET}.txt $TARGET
sleep 2
nmap -sT --script=vuln -T4 -oN $OUTPUT_DIR/nmap_vuln_scan_${TIMESTAMP}_${TARGET}.txt $TARGET
echo "Nmap scans completed."

# Subdomain fuzzing
echo "Starting subdomain fuzzing..."
ffuf -w $WORDLIST_SUBDOMAIN -u http://$TARGET -H "Host: FUZZ.$TARGET" -o $OUTPUT_DIR/subdomain_fuzzing_${TIMESTAMP}_${TARGET}.json
echo "Subdomain fuzzing completed."

# Directory and file fuzzing
echo "Starting directory and file fuzzing..."
ffuf -w $WORDLIST_DIRECTORIES -u http://$TARGET/FUZZ -o $OUTPUT_DIR/directory_fuzzing_${TIMESTAMP}_${TARGET}.json
ffuf -w $WORDLIST_FILES -u http://$TARGET/FUZZ -e ${EXTENTIONS} -o $OUTPUT_DIR/file_fuzzing_${TIMESTAMP}_${TARGET}.json
echo "Directory and file fuzzing completed."

# Send completion message to Telegram
send_telegram_message "Scanning of $TARGET completed. Check the results in the $OUTPUT_DIR directory."

echo "Script completed."
