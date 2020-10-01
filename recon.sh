#!/bin/bash 

# Tools used:
# assertfinder
# amass
# httprobe
# subjack
# nmap
# waybackurls
#tomnomnom/unfurl
# gowitness

url=$1

if [ $# == 1 ];then

if [ ! -d "$url" ];then
	mkdir "$url"
fi

if [ ! -d "$url/recon" ];then
	mkdir "$url/recon"
fi

if [ ! -d "$url/recon/gowitness" ];then
	mkdir "$url/recon/gowitness"
fi

if [ ! -d "$url/recon/scans" ];then
	mkdir "$url/recon/scans"
fi

if [ ! -d "$url/recon/httprobe" ];then
	mkdir "$url/recon/httprobe"
fi

if [ ! -d "$url/recon/potential_takeovers" ];then
	mkdir "$url/recon/potential_takeovers"
fi

if [ ! -d "$url/recon/wayback" ];then
	mkdir "$url/recon/wayback"
fi

if [ ! -d "$url/recon/wayback/params" ];then
	mkdir "$url/recon/wayback/params"
fi

if [ ! -d "$url/recon/wayback/extensions" ];then
	mkdir "$url/recon/wayback/extensions"
fi

if [ ! -d "$url/recon/httprobe/alive.txt" ];then
	touch "$url/recon/httprobe/alive.txt"
fi

if [ ! -d "$url/recon/final.txt" ];then
	touch "$url/recon/final.txt"
fi

if [ ! -f "$url/recon/potential_takeovers/potential_takeovers.txt" ];then
	touch "$url/recon/potential_takeovers/potential_takeovers.txt"
fi  

tput setaf 150 && echo "[+] Harvesting subdomains with assertfinder...."

assetfinder $url >> $url/recon/assets.txt
cat $url/recon/assets.txt | grep $url >> $url/recon/final.txt

tput setaf 2 && echo "[+] Harvesting subdomains with amass...."

amass enum -d $url >> $url/recon/amass.txt
sort -u $url/recon/amass.txt >> $url/recon/final.txt

tput setaf 4 && echo "[+] Probing for alive domains...."

cat $url/recon/final.txt | sort -u | httprobe > $url/recon/httprobe/alive.txt
 
tput setaf 5 && echo "[+] Checking for possible domain takeover...."
  
subjack -w $url/recon/final.txt -t 100 -timeout 30 -ssl -c ~/go/src/github.com/haccer/subjack/fingerprints.json -v 3 -o $url/recon/potential_takeovers/potential_takeovers.txt

tput setaf 6 && echo "[+] Scraping wayback data...."

touch $url/recon/wayback/extensions/js.txt
touch $url/recon/wayback/extensions/php.txt
touch $url/recon/wayback/extensions/aspx.txt
touch $url/recon/wayback/extensions/jsp.txt
touch $url/recon/wayback/extensions/html.txt
touch $url/recon/wayback/extensions/json.txt

cat $url/recon/final.txt | waybackurls > $url/recon/wayback/wayback_output.txt

tput setaf 7 && echo "[+] Pulling and compiling all possible programs found in wayback data...."

cat $url/recon/wayback/wayback_output.txt  | sort -u | unfurl --unique keys > $url/recon/wayback/params/wayback_params.txt
[ -s $url/recon/wayback/params/wayback_params.txt ]

tput setaf 9 && echo "[+] Pulling and compiling js/php/aspx/jsp/json files fom wayback output...."

cat $url/recon/wayback/wayback_output.txt  | sort -u | grep -P "\w+\.js(\?|$)" | sort -u > $url/recon/wayback/extensions/js.txt
[ -s $url/recon/wayback/extensions/js.txt ] 

cat $url/recon/wayback/wayback_output.txt  | sort -u | grep -P "\w+\.php(\?|$) | sort -u " > $url/recon/wayback/extensions/php.txt
[ -s $url/recon/wayback/extensions/php.txt ] 

cat $url/recon/wayback/wayback_output.txt  | sort -u | grep -P "\w+\.aspx(\?|$) | sort -u " > $url/recon/wayback/extensions/aspx.txt
[ -s url/recon/wayback/extensions/aspx.txt ] 

cat $url/recon/wayback/wayback_output.txt  | sort -u | grep -P "\w+\.jsp(\?|$) | sort -u " > $url/recon/wayback/extensions/jsp.txt
[ -s $url/recon/wayback/extensions/jsp.txt ]

cat $url/recon/wayback/wayback_output.txt  | sort -u | grep -P "\w+\.html(\?|$)" | sort -u > $url/recon/wayback/extensions/html.txt
[ -s $url/recon/wayback/extensions/html.txt ]

cat $url/recon/wayback/wayback_output.txt  | sort -u | grep -P "\w+\.json(\?|$)" | sort -u > $url/recon/wayback/extensions/json.txt
[ -s $url/recon/wayback/extensions/json.txt ]

tput setaf 10 && echo "[+] Running gowitness against all alive domains...."
gowitness file -s $url/recon/httprobe/alive.txt -d $url/recon/gowitness

tput setaf 11 && echo "[+] Probing for alive domains on port 443...."

cat $url/recon/final.txt | sort -u | httprobe -s -p https:443 | sed 's/https\?:\/\///' | tr -d ':443' | tee -a $url/recon/httprobe/a.txt
sort -u $url/recon/httprobe/a.txt > $url/recon/httprobe/alive_on_443.txt
rm $url/recon/httprobe/a.txt

tput setaf 12 && echo "[+] Scanning for open ports...."

nmap -iL $url/recon/httprobe/alive_on_443.txt -T4 -oA $url/recon/scans/scanned.txt

chmod 777 $url -R

else
tput setaf 1 && echo "[-] Incorrect syntax"
tput setaf 10 && echo "Usage: ./script.sh <Domain>"
fi
