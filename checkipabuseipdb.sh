#!/bin/bash

# Your own AbuseIPDB API Key
abuseipdbAPIKey="YOURAPIKEYHERE"
logfile="/usr/local/apache/logs/error_log"
csf_deny="/etc/csf/csf.deny"
changes_file="ABUSEIPDB_CHECK_CHANGES.txt"
not_reported_file="ABUSEIPDB_CHECKED_IPS_NOT_REPORTED.txt"
not_suspect_file="ABUSEIPDB_CHECKED_IPS_NOT_SUSPECT.txt"

# Function to check if an IP is within any denied ranges using grepcidr
check_ip_in_cidr() {
    local ip=$1
    echo "$ip" | grepcidr -f "$csf_deny" > /dev/null 2>&1
    return $?
}

# Initialize files
echo "ABUSEIPDB_CHECK_CHANGES='0'" > "$changes_file"
touch "$not_reported_file" "$not_suspect_file"

# Process IP addresses
grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' "$logfile" | sort -u | while read -r ip
do
    if grep -q "$ip" "$csf_deny"; then
        echo "$ip already blocked in csf.deny."
    elif check_ip_in_cidr "$ip"; then
        echo "$ip is within a denied IP range in csf.deny."
    elif grep -q "$ip" "$not_reported_file"; then
        echo "$ip previously checked, zero reports."
    elif grep -q "$ip" "$not_suspect_file"; then
        echo "$ip previously checked, not suspected of abuse."
    else
        echo "$ip IP not already blocked or previously checked."
        
        # Check IP address against AbuseIPDB
        result=$(curl --silent -G https://api.abuseipdb.com/api/v2/check \
         --data-urlencode "ipAddress=$ip" \
          -d maxAgeInDays=90 \
          -d verbose \
          -H "Key: $abuseipdbAPIKey" \
          -H "Accept: application/json" \
          | jq -r '.data | "\(.totalReports) \(.abuseConfidenceScore) \(.isPublic) \(.isWhitelisted) \(.countryName) \(.lastReportedAt) \(.isp) \(.usageType) \(.domain)"')

        if [ $? -ne 0 ]; then
            echo "Error: Failed to query AbuseIPDB API. Please check your internet connection and API key."
            continue
        fi

        read abuseipdbtotalReports abuseipdbconfidenceScore abuseipdbisPublic abuseipdbisWhitelisted abuseipdbcountryName abuseipdblastReportedAt abuseipdbisp abuseipdbusageType abuseipdbdomain <<< "$result"
        
        if [[ $abuseipdbconfidenceScore -gt 10 && $abuseipdbisPublic == "true" && $abuseipdbisWhitelisted == "false" ]]; then
            entry=$(printf "%s # AbuseIPDB: Reported %s times. Last Reported: %s (Domain: %s Country: %s ISP: %s Usage Type: %s) - %s" \
                "$ip" "$abuseipdbtotalReports" "$abuseipdblastReportedAt" "$abuseipdbdomain" "$abuseipdbcountryName" "$abuseipdbisp" "$abuseipdbusageType" "$(date +'%c')" | xargs)
            echo "$entry" >> "$csf_deny"
            echo "$ip added to csf.deny. $abuseipdbtotalReports reports at AbuseIPDB."
            echo "ABUSEIPDB_CHECK_CHANGES='1'" > "$changes_file"
        elif [ "$abuseipdbtotalReports" == "null" ]; then
            echo "AbuseIPDB API quota check limit may be exceeded. Please try again in 24hrs."
            break
        elif [ "$abuseipdbtotalReports" -eq 0 ]; then
            echo "$ip IP not recorded at AbuseIPDB."
            echo "$ip" >> "$not_reported_file"
        elif [ "$abuseipdbisWhitelisted" == "true" ]; then
            echo "$ip IP address whitelisted at AbuseIPDB."
        elif [ "$abuseipdbisPublic" == "false" ]; then
            echo "$ip IP is within a private address range and not public."
        elif [[ $abuseipdbconfidenceScore -le 10 ]]; then
            echo "$ip AbuseIPDB abuse confidence score <= 10%."
            echo "$ip" >> "$not_suspect_file"
        else
            echo "Condition not matched for $ip."
            echo "totalReports: $abuseipdbtotalReports abuseConfidenceScore: $abuseipdbconfidenceScore isPublic: $abuseipdbisPublic isWhitelisted: $abuseipdbisWhitelisted countryName: $abuseipdbcountryName lastReportedAt: $abuseipdblastReportedAt isp: $abuseipdbisp usageType: $abuseipdbusageType domain: $abuseipdbdomain"
        fi
    fi
done

# Restart CSF+LFD if changes to csf.deny
if grep -q "ABUSEIPDB_CHECK_CHANGES='1'" "$changes_file"; then
    echo "Restarting CSF + LFD."
    csf -ra
fi

# Remove temp file
echo "Removing temporary file."
rm -f "$changes_file"
