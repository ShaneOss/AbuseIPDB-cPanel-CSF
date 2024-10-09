# AbuseIPDB-cPanel-CSF
Bash Script to parse the IPs in the  cPanel Apache error log. Check them against AbuseIPDB and add to CSF deny list if certain criteria is met. 

Requirements:
- AbuseIPDB API key required. One can be obtained at: https://www.abuseipdb.com/account/api (free version limited to 1000 checks per day)
- jq - required for parsing JSON responses
- grepcidr - required for checking ips are within a cidr range.

Files generated from the script:
- ABUSEIPDB_CHECKED_IPS_NOT_REPORTED.txt (IP addresses added to the file weren't reported at AbuseIPDB)
- ABUSEIPDB_CHECKED_IPS_NOT_SUSPECT.txt (IP addresses added to the file that had an abuse confidence score of less than or equal to 10%)
- ABUSEIPDB_CHECK_CHANGES.txt (If changes to CSF.deny are made then it's recorded in this file a change has been done and a restart of CSF+LFD is required)

Criteria for IP addresses to be added to CSF.deny:
- AbuseIPDB abuse confidence score greater than 10% AND
- IP address is a public IP.
- IP address is not whitelisted at AbuseIPDB

Script can be scheduled to run daily. Initial run may take a few days or more to parse all the IPs in the log. Once your daily check limit has been exceeded, the script will detect and complete. If there were any changes it will then restart CSF+LFD and then you can re-run the next day in 24hrs.

To run daily at 23:00:
- Create a new directory called "abuseipdbcheck" in /usr/local/cpanel/scripts/
- Copy the script checkipabuseipdb.sh into the new directory
- Edit crontab and add a line "0 23 * * * /usr/local/cpanel/scripts/abuseipdbcheck/checkipabuseipdb.sh > /dev/null 2>&1"
- Restart cron. service crond restart



