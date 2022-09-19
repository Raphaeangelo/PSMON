#!/bin/bash

###################################
# Clean-up if any old files exist #
###################################

rm -f running_processes_file_location_raw.txt
rm -f bad_process_locations.txt
rm -f bad_running_process_hashes.txt
rm -f sha1_hashes_of_running_processes_file_location.txt
rm -f running_processes_file_location.txt
rm -f running_process_hash_uniq.txt
rm -f running_process_hash_only_raw.txt

while :
do
clear
cat << "EOF"
  _____   _____ __  __  ____  _   _ 
 |  __ \ / ____|  \/  |/ __ \| \ | |
 | |__) | (___ | \  / | |  | |  \| |
 |  ___/ \___ \| |\/| | |  | | . ` |
 | |     ____) | |  | | |__| | |\  |
 |_|    |_____/|_|  |_|\____/|_| \_|
                                    
By: Raphaeangelo 
EOF

echo "======================================================================="
echo -ne 'Scanning running processes                 [#####               ] (25%)\r'

###########################################################################
# Create list of all running processes and remove lines that do not begin #
# with "/" because those aren't directories                               #
###########################################################################

ps -ewwo comm > running_processes_file_location_raw.txt
sed '/^[^/]/d' running_processes_file_location_raw.txt > running_processes_file_location.txt
rm -f running_processes_file_location_raw.txt

###############################################
# Create sha1 hashes of all running processes #
###############################################

while read -r list; do
	openssl sha1 "$list" >> sha1_hashes_of_running_processes_file_location.txt 2> /dev/null
done < running_processes_file_location.txt
rm -f running_processes_file_location.txt
echo -ne 'Scanning running processes                 [##########          ] (50%)\r'

################################
# Trim hashlist to only hashes #
################################

cat sha1_hashes_of_running_processes_file_location.txt | cut -d"=" -f2 | cut -d" " -f2 > running_process_hash_only_raw.txt

###########################################################################              
# Remove duplicate process hashes                                         #
###########################################################################

sort running_process_hash_only_raw.txt | uniq > running_process_hash_uniq.txt
rm -f running_process_hash_only_raw.txt

##########################################################              
# Check if hash.cymru.com malware database is accessible #
##########################################################

if [[ $(dig +short 8a62d103168974fba9c61edab336038c.hash.cymru.com A) = ";; connection timed out; no servers could be reached" ]]; then
	echo 'Scanning running processes                [####################] (100%)'
	echo "======================================================================="
	echo "No internet connection detected." 
	echo "PSMON needs to reach hash.cymru.com malware database."
	echo "Connect to the internet and make sure you can reach hash.cymru.com"
	echo "======================================================================="
	rm -f running_processes_file_location_raw.txt
	rm -f sha1_hashes_of_running_processes_file_location.txt
	rm -f running_processes_file_location.txt
	rm -f running_process_hash_uniq.txt
	rm -f running_process_hash_only_raw.txt
	exit
fi

###########################################################################              
# Lookup running_process_hash_uniq.txt to hash.cymru.com malware database #
###########################################################################

while read -r list; do
	if [[ $(dig +short "$list".hash.cymru.com A) = "127.0.0.2" ]]; then
		echo "$list" >> bad_running_process_hashes.txt
	fi
done < running_process_hash_uniq.txt
echo -ne 'Scanning running processes                 [###############     ] (75%)\r'
rm -f running_process_hash_uniq.txt

#########################################################################              
# If a "bad" hash is detected ask user if they want to kill the process #
#########################################################################

if [ -f bad_running_process_hashes.txt ] && [ -s bad_running_process_hashes.txt ]; then
	while read -r list; do
		cat sha1_hashes_of_running_processes_file_location.txt | grep "$list" | cut -d"(" -f 2 | cut -d")" -f 1 >> bad_process_locations.txt 2> /dev/null
	done < bad_running_process_hashes.txt
	rm -f bad_running_process_hashes.txt
	rm -f sha1_hashes_of_running_processes_file_location.txt
	echo 'Scanning running processes                [####################] (100%)'
	echo "======================================================================="
	while read -r list; do
		BADPID=$(ps -ef | grep "$list" | awk '{print $2}')
		BADPNAME=$(ps -axf | grep "$list" | head -n 1 |rev | cut -d'/' -f 1 | rev)
		tput bel
		echo "Malicious process detected!"
		echo "Process name:\"$BADPNAME\""
		echo "Location:\"$list\""
		echo "======================================================================="
		killty="$(osascript -e 'display dialog "Malicious process detected!\n\nProcess name: \"'"${BADPNAME//\"/}"'\"\n\nLocation: \"'"${list//\"/}"'\"" with title "Malicious process detected!" with icon file "System:Library:CoreServices:CoreTypes.bundle:Contents:Resources:AlertStopIcon.icns" buttons {"Allow process for 15 minutes", "Kill process"} giving up after 300 default button "Kill process"')"
		if [ "$killty" = "button returned:, gave up:true" ]; then
			:
		fi
		if [ "$killty" = "button returned:Allow process for 5 minutes, gave up:false" ]; then
			:
		fi
		if [ "$killty" = "button returned:Kill process, gave up:false" ]; then
			kill -9 $BADPID 2> /dev/null
		fi
	done < bad_process_locations.txt
	rm -f bad_process_locations.txt
else
	rm -f sha1_hashes_of_running_processes_file_location.txt
	echo 'Scanning running processes                [####################] (100%)'
	echo "======================================================================="
	echo "No malicious processes detected. Your system is clean."
	echo "======================================================================="
fi

#######
# End #
#######

echo "Scan complete. New scan will start in 5 minutes"
echo "======================================================================="
sleep 300
done
