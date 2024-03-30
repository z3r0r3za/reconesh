#!/bin/bash

# Check if first argument exists and print usage.
if [ $# -eq 0 ]; then
 echo "A domain wasn't specified."
 echo "Usage: recon.sh domain.com"
 exit 1
fi

# Get first argument, the domain and save it.
domain=$1
# Set some colors
RED="\033[1;31m"
GREEN="\033[1;32m"
RESET="\033[0m"
# Set up directories.
base_dir="${domain}_$(date +'%Y%m%dT%H%M%S')"
nmap="$base_dir/nmap"
information="$base_dir/info"
subdomains="$base_dir/subdomains"
screenshots="$base_dir/screenshots"
validate_domain="^([a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]\.)+[a-zA-Z]{2,}$"

# Check if domain is valid.
if [[ "$domain" =~ $validate_domain ]]; then
    # Create directories for domain.
    echo "Creating directories..."
    for path in "$nmap" "$information" "$subdomains" "$screenshots"; do
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
# Example: subfinder -d domain.com > domain.com/subdomains/subfinder_domains.txt
# #############################################
echo -e "${GREEN} [+]${RED} Run subfinder...${RESET}"
subfinder -d $domain > "$subdomains/found.txt"

# Run sublist3r and remove characters from output.
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
# dir - Get and save newest directory and subdomains scan bbot created.
# May not work if your user is root, or might ask for password. Not tested.
# #############################################
#echo -e "${GREEN} [+]${RED} Run bbot...${RESET}"
#bbot -s -t $domain -f subdomain-enum -rf passive
#dir=$(ls -td $HOME/.bbot/scans/*/ | head -1)
#cp -a $dir/subdomains.txt $subdomains/bbot_domains.txt
#cp -a $dir/output.txt $subdomains/bbot_output.txt

# Run assetfinder.
# Example: assetfinder domain.com | grep domain.com > domain.com/subdomains/assetfinder_found.txt
# #############################################
echo -e "${GREEN} [+]${RED} Run assetfinder...${RESET}"
assetfinder $domain | grep $domain >> "$subdomains/found.txt"

# Run amass.
# It can take a long time to run so uncomment if you want to run it.
# #############################################
#echo -e "${GREEN} [+]${RED} Run Amass. This could take a while...${RESET}"
#amass enum -d $domain >> "$subdomains/found.txt"

# Run httprobe or cat the output of just subdomains to httprobe.
# #############################################
echo -e "${GREEN} [+]${RED} Run httprobe, see what's accessible...${RESET}"
cat "$subdomains/found.txt" | grep $domain | sort -u | httprobe -prefer-https | grep https | sed 's/https\?:\/\///' | tee -a "$subdomains/alive.txt"

# Run gowitness using httprobe output.
# #############################################
echo -e "${GREEN} [+]${RED} Run gowitness, taking screenshots...${RESET}"
gowitness file -f "$subdomains/alive.txt" -P "$screenshots/" --no-http
