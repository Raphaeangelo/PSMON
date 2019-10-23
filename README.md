# PSMON

Only tested on:

Mac OS X

Debian 8


PSMON is a bash script that lists your running processes, produces a hash value of those processes, compares your running processes hashes to known bad hashes (using cymru malware database project "netcat hash.cymru.com < HASHES.txt > HASHESRESPONSE.txt" explained here https://www.team-cymru.com/mhr.html). 


If there is a match PSMON will ask you if you want to "kill the process" (issue a "kill -9") or allow the process (add the hash to the "known_good_hashes.txt" so it will be skipped next time the script is ran). PSMON will also display the name of the malicious process and the file location so you can remove the malicious file if you desire.

How to use. Download PSMON.sh

```chmod +x psmon.sh```

Run command

```./psmon.sh```
