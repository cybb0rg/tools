#!/bin/bash

# Check if the script is being run as root
if [ "$EUID" -ne 0 ]; then
  echo "This script must be run as root. Please use sudo."
  exit 1
fi

# Check for correct usage
if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <target> <output_directory>"
    exit 1
fi

# Constants
INFO_VAR="[STEP]"
CURRENT_DIR=$(pwd)
TARGET=$1
OUTPUT_DIR=$CURRENT_DIR/$2
TIMESTAMP=$(date +%d%m%y%H%M%S)
WORDLIST_SUBDOMAIN="/usr/share/wordlists/ctf-wordlist/subdomains-top1mil-20000.txt"  # Replace with the path to your directory wordlist
WORDLIST_DIRECTORIES="/usr/share/wordlists/ctf-wordlist/directories1.txt" # Replace with the path to your directory wordlist
WORDLIST_FILES="/usr/share/wordlists/dirbuster/directory-list-1.0.txt" # Replace with the path to your file wordlist
EXTENTIONS=".php,.html,.xml,.txt" # Replace with your desired file extentions
TELEGRAM_BOT_TOKEN="" # Replace with your telegram bot token
TELEGRAM_CHAT_ID="" # Replace with your telegram chat ID

echo "             ________________________________________________"
sleep 0.2
echo "            /                                                \\"
sleep 0.2
echo "           |    _________________________________________     |"
sleep 0.2
echo "           |   |                                         |    |"
sleep 0.2
echo "           |   |  C:\\> cb0enum.sh _                      |    |"
sleep 0.2
echo "           |   |                                         |    |"
sleep 0.2
echo "           |   |                                         |    |"
sleep 0.2
echo "           |   |                                         |    |"
sleep 0.2
echo "           |   |                                         |    |"
sleep 0.2
echo "           |   |                                         |    |"
sleep 0.2
echo "           |   |                                         |    |"
sleep 0.2
echo "           |   |                                         |    |"
sleep 0.2
echo "           |   |                                         |    |"
sleep 0.2
echo "           |   |                                         |    |"
sleep 0.2
echo "           |   |                                         |    |"
sleep 0.2
echo "           |   |                                         |    |"
sleep 0.2
echo "           |   |_________________________________________|    |"
sleep 0.2
echo "           |                                                  |"
sleep 0.2
echo "            \\_________________________________________________/"
sleep 0.2
echo "                   \\___________________________________/"
sleep 0.2
echo "                ___________________________________________"
sleep 0.2
echo "             _-'    .-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.  --- \`-_"
sleep 0.2
echo "          _-'.-.-. .---.-.-.-.-.-.-.-.-.-.-.-.-.-.-.--.  .-.-.\`-_"
sleep 0.2
echo "       _-'.-.-.-. .---.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-\`__\`. .-.-.-.\`-_"
sleep 0.2
echo "    _-'.-.-.-.-. .-----.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-----. .-.-.-.-.\`-_"
sleep 0.2
echo " _-'.-.-.-.-.-. .---.-. .-------------------------. .-.---. .---.-.-.-.\`-_"
sleep 0.2
echo ":-------------------------------------------------------------------------:"
sleep 0.2
echo "\`---._.-------------------------------------------------------------._.---'"
sleep 0.2
echo "                              -Art by: Roland Hangg-"
sleep 0.2
echo "                        -Script by: CybB0rg - cybb0rg.com-"
sleep 0.2
echo "                                                                            "
sleep 0.2
echo "INFO: This bash script uses nmap and ffuf to enumerate a given target and then sends a telegram message to a telegram channel."
sleep 0.2

echo "$INFO_VAR Creating output directory..."
# Create output directory
mkdir -p $OUTPUT_DIR

# Function to send a message to Telegram
send_telegram_message() {
	local message=$1
	echo "$INFO_VAR Sending telegram message..."
	curl -s -X POST https://api.telegram.org/bot$TELEGRAM_BOT_TOKEN/sendMessage -d chat_id=$TELEGRAM_CHAT_ID -d text="$message"
}

# Nmap scans
echo "$INFO_VAR Starting Nmap scans..."
echo "$INFO_VAR SYN SCAN"
nmap -sS -A -T4 -p- -Pn -oN $OUTPUT_DIR/nmap_syn_scan_${TIMESTAMP}_${TARGET}.txt $TARGET
sleep 2
echo "$INFO_VAR TCP SCAN"
nmap -sT -A -T4 -p- -Pn -oN $OUTPUT_DIR/nmap_tcp_scan_${TIMESTAMP}_${TARGET}.txt $TARGET
sleep 2
echo "$INFO_VAR TCPVERSION SCAN"
nmap -sT -A --min-rate 5000 -T4 -p- -Pn -oN $OUTPUT_DIR/nmap_tcpversion_scan_${TIMESTAMP}_${TARGET}.txt $TARGET
sleep 2
echo "$INFO_VAR UDP SCAN"
map -sU -A -T4 --top-ports 500 -Pn -oN $OUTPUT_DIR/nmap_udp_scan_${TIMESTAMP}_${TARGET}.txt $TARGET
sleep 2
echo "$INFO_VAR VULN SCAN"
nmap -sT --script=vuln -T4 -oN $OUTPUT_DIR/nmap_vuln_scan_${TIMESTAMP}_${TARGET}.txt $TARGET
echo "$INFO_VAR Nmap scans completed..."

# Subdomain fuzzing
echo "$INFO_VAR Starting subdomain fuzzing..."
ffuf -w $WORDLIST_SUBDOMAIN -u http://$TARGET -H "Host: FUZZ.$TARGET" -o $OUTPUT_DIR/subdomain_fuzzing_${TIMESTAMP}_${TARGET}.json
echo "$INFO_VAR Subdomain fuzzing completed..."

# Directory and file fuzzing
echo "$INFO_VAR Starting directory fuzzing..."
ffuf -w $WORDLIST_DIRECTORIES -u http://$TARGET/FUZZ -o $OUTPUT_DIR/directory_fuzzing_${TIMESTAMP}_${TARGET}.json
echo "$INFO_VAR Directory fuzzing completed..."
echo "$INFO_VAR Starting file fuzzing..."
ffuf -w $WORDLIST_FILES -u http://$TARGET/FUZZ -e ${EXTENTIONS} -o $OUTPUT_DIR/file_fuzzing_${TIMESTAMP}_${TARGET}.json
echo "$INFO_VAR File fuzzing completed..."

echo "$INFO_VAR All scans completed..."

# Send completion message to Telegram
send_telegram_message "Scanning of $TARGET completed. Check the results in the $OUTPUT_DIR directory."
echo "             "
echo "<!--END--!>"
