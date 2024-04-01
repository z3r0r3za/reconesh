#!/bin/bash

# recone.sh - Some basic automated scanning.
# ##############################################
# Some need to be uncommented if you want to use
# them. Tools on github used in this script:
# nmap (open ports), whois, subfinder, sublist3r, 
# bbot, assetfinder, amass, httprobe, gowitness.

# Store 200 header status code as true or false.
up=$(wget --spider --server-response $1 2>&1 | grep '200\ OK' | wc -l)
# Does first argument exist? If not, print usage and exit.
# Is the domain up? If not, inform user, print usage and exit.
if [ $# -eq 0 ]; then
    echo "A domain wasn't specified."
    echo "Usage: recone.sh domain.com"
    exit 1
elif [ "$up" = 0 ]; then
    echo "That domain is down or doesn't exist. "
    echo "Usage: recone.sh domain.com"
    exit 1
fi

# Get first argument, the domain and save it.
domain=$1
# Set some colors
RED="\033[1;31m"
GREEN="\033[1;32m"
RESET="\033[0m"
# Set up directories. Add timestamp to base directory. 
base_directory="${domain}_$(date +'%Y%m%dT%H%M%S')"
nmap="$base_directory/nmap"
ferox="$base_directory/ferox"
information="$base_directory/info"
subdomains="$base_directory/subdomains"
screenshots="$base_directory/screenshots"
dirs=("$nmap" "$ferox" "$information" "$subdomains" "$screenshots")
validate_domain="^([a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]\.)+[a-zA-Z]{2,}$"

# Check if domain is valid.
if [[ "$domain" =~ $validate_domain ]]; then
    # Create directories for domain.
    echo "Creating directories for the domain..."
    #for path in "$nmap" "$ferox" "$information" "$subdomains" "$screenshots"; do
    for path in ${dirs[@]}; do
        if [ ! -d "$path" ]; then
            mkdir -p "$path"
            echo "$path"
        fi
    done
else
    echo "$domain is not a valid domain."
    exit 1
fi

# Get IP address and run nmap to get open ports.
# Uncomment nmap if open ports are needed.
# #############################################
echo -e "${GREEN} [+]${RED} Run dig for IP and nmap for ports...${RESET}"
dig +short $domain > "$nmap/ip_address.txt"
ip=$(dig +short $domain | head -n 1)
echo "IP address is: ${ip}"
#nmap -p- --min-rate 10000 -oA "$nmap/open" $ip

# Run whois.
# #############################################
echo -e "${GREEN} [+]${RED} Check whois...${RESET}"
whois $domain > "$information/whois.txt"

# Run subfinder or sublist3r below.
# https://github.com/projectdiscovery/subfinder
# Example: subfinder -d domain.com > domain.com/subdomains/subfinder_domains.txt
# #############################################
echo -e "${GREEN} [+]${RED} Run subfinder...${RESET}"
subfinder -d $domain > "$subdomains/found.txt"

# Run sublist3r and remove characters from output.
# ORIGINAL: https://github.com/aboul3la/Sublist3r
# The newer fork hasn't been tested with this script.
# NEWER FORK: https://github.com/RoninNakomoto/Sublist3r2
# The sed commands may need adjustments if sublist3r output changes.
# subfinder might find more. sublist3r hasn't been finding every subdomain.
# Example: sublist3r -d domain.com > domain.com/subdomains/sublist3r_results.txt
# #############################################
#echo -e "${GREEN} [+]${RED} Run sublist3r...${RESET}"
#dom=".${domain}"
#sublist3r -d $domain > $subdomains/sublist3r_results.txt
#sed -n '/\'"$dom"'/p' "$subdomains/sublist3r_results.txt" | tee "$subdomains/sublist3r_domains.txt" >/dev/null
#sed -i 's/....$//' "$subdomains/sublist3r_domains.txt"
#sed -i 's/^.....//' "$subdomains/sublist3r_domains.txt"
#cp -a "$subdomains/sublist3r_domains.txt" "$subdomains/found.txt"

# Run bbot
# https://github.com/blacklanternsecurity/bbot
# dir - Get and save newest directory and subdomains scan bbot created.
# May not work if your user is root, or might ask for password. Not tested.
# #############################################
#echo -e "${GREEN} [+]${RED} Run bbot...${RESET}"
#bbot -s -t $domain -f subdomain-enum -rf passive
#dir=$(ls -td $HOME/.bbot/scans/*/ | head -1)
#cp -a $dir/subdomains.txt $subdomains/bbot_domains.txt
#cp -a $dir/output.txt $subdomains/bbot_output.txt

# Run assetfinder.
# https://github.com/tomnomnom/assetfinder
# Example: assetfinder domain.com | grep domain.com > domain.com/subdomains/assetfinder_found.txt
# #############################################
echo -e "${GREEN} [+]${RED} Run assetfinder...${RESET}"
assetfinder $domain | grep $domain >> "$subdomains/found.txt"

# Run amass.
# https://github.com/owasp-amass/amass
# It can take a long time to run so uncomment if you want to run it.
# #############################################
#echo -e "${GREEN} [+]${RED} Run Amass. This could take a while...${RESET}"
#amass enum -d $domain >> "$subdomains/found.txt"

# Run httprobe or cat the output of just subdomains to httprobe.
# https://github.com/tomnomnom/httprobe
# #############################################
echo -e "${GREEN} [+]${RED} Run httprobe, see what's accessible...${RESET}"
cat "$subdomains/found.txt" | grep $domain | sort -u | httprobe -prefer-https | grep https | sed 's/https\?:\/\///' | tee -a "$subdomains/alive.txt"

# Run gowitness using httprobe output.
# https://github.com/sensepost/gowitness
# #############################################
echo -e "${GREEN} [+]${RED} Run gowitness, taking screenshots...${RESET}"
gowitness file -f "$subdomains/alive.txt" -P "$screenshots/" --no-http

# Run feroxbuster and extract accessible files.
# https://github.com/epi052/feroxbuster
# This is unfinished and not tested that much yet.
# #############################################
#echo -e "${GREEN} [+]${RED} Run feroxbuster, save status 200s...${RESET}"
#if [[ $(wget -S --spider https://$domain  2>&1 | grep 'HTTP/1.1 200 OK') ]]; then  
#    echo "HTTPS: true"
#    feroxbuster -u "https://$domain" -o "$ferox/directories.txt"
#elif [[ $(wget -S --spider  http://$domain  2>&1 | grep 'HTTP/1.1 200 OK') ]]; then
#    echo "HTTP: true"
#    feroxbuster -u "http://$domain" -o "$ferox/directories.txt"
#fi
#grep -E '^[2][0]{2}' "$ferox/directories.txt" > "$ferox/accessible_dirs1.txt"
#sed 's@.*//@@' "$ferox/accessible_dirs1.txt" > "$ferox/accessible_dirs2.txt"
