# Check if the user provided a parameter
if ($args.Count -eq 0) {
    Write-Host "Usage: .\script.ps1 <mainfolder>"
    exit
}

# Main folder name
$mainfolder = $args[0]

# Create the folder structure
New-Item -ItemType Directory -Path "$mainfolder\enum\ports" -Force
New-Item -ItemType Directory -Path "$mainfolder\enum\portscanners\nmap" -Force
New-Item -ItemType Directory -Path "$mainfolder\enum\portscanners\cb0" -Force
New-Item -ItemType Directory -Path "$mainfolder\enum\services" -Force
New-Item -ItemType Directory -Path "$mainfolder\loot" -Force
New-Item -ItemType Directory -Path "$mainfolder\privesc\local_files" -Force
New-Item -ItemType Directory -Path "$mainfolder\privesc\creds" -Force
New-Item -ItemType Directory -Path "$mainfolder\privesc\tools" -Force
New-Item -ItemType Directory -Path "$mainfolder\exploit" -Force

Write-Host "Folder structure created under $mainfolder"
