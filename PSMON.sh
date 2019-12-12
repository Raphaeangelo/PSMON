#!/bin/bash

###################################
# Clean-up if any old files exist #
###################################

rm -f running_processes_file_location_raw.txt
rm -f running_processes_file_location.txt
rm -f md5_hashes_of_running_processes_file_location.txt
rm -f running_process_hash_only.txt
rm -f running_process_hash_only_diff.txt
rm -f bad_running_process_hashes.txt
rm -f bad_process_locations.txt
rm -f list.txt

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
echo -ne 'Creating list of all running processes    [                    ] (0%)\r'

###########################################################################
# Create list of all running processes and remove lines that do not begin #
# with "/" because those aren't directories                               #
###########################################################################

ps -ewwo comm | sort -u > running_processes_file_location_raw.txt && sed '/^[^/]/d' running_processes_file_location_raw.txt > running_processes_file_location.txt
echo -ne 'Creating list of all running processes    [####################] (100%)\n'

##############################################
# Create md5 hashes of all running processes #
##############################################

echo -ne 'Creating hash for all running processes   [                    ] (0%)\r'
while read -r list; do
	md5 "$list" >> md5_hashes_of_running_processes_file_location.txt 2> /dev/null
done < running_processes_file_location.txt
echo -ne 'Creating hash for all running processes   [####################] (100%)\n'

################################
# Trim hashlist to only hashes #
################################

cat md5_hashes_of_running_processes_file_location.txt | cut -d"=" -f2 | cut -d" " -f2  > running_process_hash_only.txt

###########################################################################              
# Compare running_process_hash_only.txt against known_good_hases.txt if   #
# there is a match exclude them from the scan because we know these       #
# hashes are already good and doesn't need to be scanned again 		  #
###########################################################################

if [ -f known_good_hashes.txt ] && [ -s known_good_hashes.txt ]; then
	grep -v -f known_good_hashes.txt running_process_hash_only.txt > running_process_hash_only_diff.txt
else
	mv running_process_hash_only.txt running_process_hash_only_diff.txt
fi

#########################################################################              
# Compare running_process_hash_only_diff.txt to hash.cymru.com		#
#########################################################################

echo -ne 'Checking hashes in Cymru Malware Database [                    ] (0%)\r'
if [ -f running_process_hash_only_diff.txt ] && [ -s running_process_hash_only_diff.txt ]; then
	nc hash.cymru.com 43 < running_process_hash_only_diff.txt > list.txt
	sed -i "" "/NO_DATA/d" list.txt 2> /dev/null
	cut -d" " -f1 list.txt > bad_running_process_hashes.txt
fi
echo -ne 'Checking hashes in Cymru Malware Database [####################] (100%)\n'


########################################################              
# If a "bad" running hash is detected kill the process #
########################################################

if [ -f bad_running_process_hashes.txt ] && [ -s bad_running_process_hashes.txt ]; then
	
	################################################################
	# Kill bad processes or alert that no bad process was detected #
	################################################################

	echo "======================================================================="
	while read -r list; do
		cat md5_hashes_of_running_processes_file_location.txt | grep "$list" | cut -d"(" -f 2 | cut -d")" -f 1 >> bad_process_locations.txt 2> /dev/null
	done < bad_running_process_hashes.txt

	while read -r list; do
		BADPID=$(ps -ef | grep "$list" | awk '{print $2}')
		BADPNAME=$(ps -axf | grep "$list" | head -n 1 |rev | cut -d'/' -f 1 | rev)
		tput bel
		echo "Malicious process detected!"
		echo "Process name:\"$BADPNAME\""
		echo "Location:\"$list\""
		echo "======================================================================="
		killty="$(osascript -e 'display dialog "Malicious process detected!\n\nProcess name: \"'"${BADPNAME//\"/}"'\"\n\nLocation: \"'"${list//\"/}"'\"" with title "Malicious process detected!" with icon file "System:Library:CoreServices:CoreTypes.bundle:Contents:Resources:AlertStopIcon.icns" buttons {"Allow process for 5 minutes", "Allow process forever", "Kill process"} giving up after 300 default button "Kill process"')"
		if [ "$killty" = "button returned:, gave up:true" ]; then
			:
		fi
		if [ "$killty" = "button returned:Allow process for 5 minutes, gave up:false" ]; then
			:
		fi
		if [ "$killty" = "button returned:Allow process forever, gave up:false" ]; then
			grep "$list" md5_hashes_of_running_processes_file_location.txt | cut -d"=" -f2 | cut -d" " -f2 >> known_good_hashes.txt
		fi
		if [ "$killty" = "button returned:Kill process, gave up:false" ]; then
			kill -9 $BADPID 2> /dev/null
		fi
	done < bad_process_locations.txt

	##########################################################################################              
	# Remove "bad running hashes" and add "good running hashes" to the known_good_hashes.txt #
	##########################################################################################

	while read -r list; do
		sed -i "" "/$list/d" running_process_hash_only_diff.txt 2> /dev/null
	done < bad_running_process_hashes.txt
	
	while read -r list; do
		echo "$list" >> known_good_hashes.txt 2> /dev/null
	done < running_process_hash_only_diff.txt

	echo -ne 'Scan complete                             [####################] (100%)\n'
	echo "======================================================================="

else
	##########################################################              
	# Add "good" running hashes to the known_good_hashes.txt #
	##########################################################

	while read -r list; do
		echo "$list" >> known_good_hashes.txt 2> /dev/null
	done < running_process_hash_only_diff.txt

	echo -ne 'Scan complete                             [####################] (100%)\n'
	echo "======================================================================="
	echo "No malicious processes detected. Your system is clean."
	echo "======================================================================="
	
fi

############
# Clean-up #
############

rm -f running_processes_file_location_raw.txt
rm -f running_processes_file_location.txt
rm -f md5_hashes_of_running_processes_file_location.txt
rm -f running_process_hash_only.txt
rm -f running_process_hash_only_diff.txt
rm -f bad_running_process_hashes.txt
rm -f bad_process_locations.txt
rm -f list.txt

echo "New scan will start in 5 minutes"
echo "======================================================================="
sleep 300
done
