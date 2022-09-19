# PSMON

Only tested on:

Mac OS X


PSMON is a bash script that lists your running processes, produces a hash value of those processes, and compares your running processes hashes to known bad hashes (using the Cymru malware database project explained here https://www.team-cymru.com/mhr.html). 


If there is a match, PSMON will ask you if you want to "kill the process" (issue a "kill -9") or allow the process (The process will continue to run). PSMON will also display the name of the malicious process and the file location so you can remove the file if you desire.

How to use. Download PSMON.sh

```chmod +x psmon.sh```

Run command

```./psmon.sh```
