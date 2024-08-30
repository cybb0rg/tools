#!/bin/bash

# Check if the user provided a parameter
if [ -z "$1" ]; then
  echo "Usage: $0 <mainfolder>"
  exit 1
fi

# Main folder name
mainfolder="$1"

# Create the folder structure
mkdir -p "$mainfolder/enum/ports"
mkdir -p "$mainfolder/enum/portscanners/nmap"
mkdir -p "$mainfolder/enum/portscanners/cb0"
mkdir -p "$mainfolder/enum/services"
mkdir -p "$mainfolder/loot"
mkdir -p "$mainfolder/privesc/local_files"
mkdir -p "$mainfolder/privesc/creds"
mkdir -p "$mainfolder/privesc/tools"
mkdir -p "$mainfolder/exploit"

echo "Folder structure created under $mainfolder"
