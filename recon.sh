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
info_path="$base_dir/info"
subdomain_path="$base_dir/subdomains"
screenshot_path="$base_dir/screenshots"

# Create directories.
for path in "$info_path" "$subdomain_path" "$screenshot_path"; do
    if [ ! -d "$path" ]; then
        mkdir -p "$path"
        echo "Creating directory: $path"
    fi
done

# Run whois.
# #############################################
echo -e "${GREEN} [+]${RED} Check whois...${RESET}"
whois $domain > "$info_path/whois.txt"

# Run subfinder or sublist3r below.
# Example: subfinder -d domain.com > domain.com/subdomains/subfinder_domains.txt
# #############################################
echo -e "${GREEN} [+]${RED} Run subfinder...${RESET}"
subfinder -d $domain > "$subdomain_path/found.txt"

# Run sublist3r and remove characters from output.
# The sed commands may need adjustments if sublist3r output changes.
# subfinder might find more. sublist3r hasn't been finding every subdomain.
# Example: sublist3r -d domain.com > domain.com/subdomains/sublist3r_results.txt
# #############################################
#echo -e "${GREEN} [+]${RED} Run sublist3r...${RESET}"
#dom=".${domain}"
#sublist3r -d $domain > $subdomain_path/sublist3r_results.txt
#sed -n '/\'"$dom"'/p' "$subdomain_path/sublist3r_results.txt" | tee "$subdomain_path/sublist3r_domains.txt" >/dev/null
#sed -i 's/....$//' "$subdomain_path/sublist3r_domains.txt"
#sed -i 's/^.....//' "$subdomain_path/sublist3r_domains.txt"
#cp -a "$subdomain_path/sublist3r_domains.txt" "$subdomain_path/found.txt"

# Run bbot
# dir - Get and save newest directory and subdomains scan bbot created.
# May not work if your user is root, or might ask for password. Not tested.
# #############################################
#echo -e "${GREEN} [+]${RED} Run bbot...${RESET}"
#bbot -s -t $domain -f subdomain-enum -rf passive
#dir=$(ls -td $HOME/.bbot/scans/*/ | head -1)
#cp -a $dir/subdomains.txt $subdomain_path/bbot_domains.txt
#cp -a $dir/output.txt $subdomain_path/bbot_output.txt

# Run assetfinder.
# Example: assetfinder domain.com | grep domain.com > domain.com/subdomains/assetfinder_found.txt
# #############################################
echo -e "${GREEN} [+]${RED} Run assetfinder...${RESET}"
assetfinder $domain | grep $domain >> "$subdomain_path/found.txt"

# Run amass.
# It can take a long time to run so uncomment if you want to run it.
# #############################################
#echo -e "${GREEN} [+]${RED} Run Amass. This could take a while...${RESET}"
#amass enum -d $domain >> "$subdomain_path/found.txt"

# Run httprobe or cat the output of just subdomains to httprobe.
# #############################################
echo -e "${GREEN} [+]${RED} Run httprobe, see what's accessible...${RESET}"
cat "$subdomain_path/found.txt" | grep $domain | sort -u | httprobe -prefer-https | grep https | sed 's/https\?:\/\///' | tee -a "$subdomain_path/alive.txt"

# Run gowitness using httprobe output.
# #############################################
echo -e "${GREEN} [+]${RED} Run gowitness, taking screenshots...${RESET}"
gowitness file -f "$subdomain_path/alive.txt" -P "$screenshot_path/" --no-http

