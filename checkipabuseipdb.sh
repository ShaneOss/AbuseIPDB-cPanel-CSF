#!/bin/bash

# Your own AbuseIPDB API Key
abuseipdbAPIKey="------------------------------- YOUR API KEY -----------------------------------"
logfile="/usr/local/apache/logs/error_log"
logfile=

echo "ABUSEIPDB_CHECK_CHANGES='0'" > ABUSEIPDB_CHECK_CHANGES.txt

if [[ ! -e ABUSEIPDB_CHECKED_IPS_NOT_REPORTED.txt ]];
then
        touch ABUSEIPDB_CHECKED_IPS_NOT_REPORTED.txt
fi

if [[ ! -e ABUSEIPDB_CHECKED_IPS_NOT_SUSPECT.txt ]];
then
        touch ABUSEIPDB_CHECKED_IPS_NOT_SUSPECT.txt
fi

cat /usr/local/apache/logs/error_log | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort | uniq | while read ip
do

# Check if IP address already exists in csf.deny
if grep -q "$ip" /etc/csf/csf.deny; then
    echo $ip "already blocked in csf.deny."
elif grep -q "$ip" ABUSEIPDB_CHECKED_IPS_NOT_REPORTED.txt; then
    echo $ip "previously checked, zero reports."
elif grep -q "$ip" ABUSEIPDB_CHECKED_IPS_NOT_SUSPECT.txt; then
    echo $ip "previously checked, not suspected of abuse."
else
    echo $ip "IP not already blocked or previously checked."
        # If IP isn't already blocked.
        # Check IP address against AbuseIPDB.
        read abuseipdbtotalReports abuseipdbconfidenceScore abuseipdbisPublic abuseipdbisWhitelisted abuseipdbcountryName abuseipdblastReportedAt abuseipdbisp abuseipdbusageType abuseipdomain < <(echo $(curl --silent -G https://api.abuseipdb.com/api/v2/check \
         --data-urlencode "ipAddress=$ip" \
          -d maxAgeInDays=90 \
          -d verbose \
          -H "Key: $abuseipdbAPIKey" \
          -H "Accept: application/json" --stderr - \
          | jq -r '.data.totalReports,.data.abuseConfidenceScore,.data.isPublic,.data.isWhitelisted,.data.countryName,.data.lastReportedAt,.data.isp,.data.usageType,.data.domain'))
        #echo "totalReports:" $abuseipdbtotalReports "abuseConfidenceScore:" $abuseipdbconfidenceScore "isPublic:" $abuseipdbisPublic "isWhitelisted:" $abuseipdbisWhitelisted "countryName:" $abuseipdbcountryName "lastReportedAt:" $abuseipdblastReportedAt "isp:" $abuseipdbisp "usageType:" $abuseipdbusageType "domain:" $abuseipdomain

        # If IP address is found at AbuseIPDB and abuseConfidenceScore > 10 && isPublic:true && isWhitelisted:false
        if [[ $abuseipdbconfidenceScore -gt 10 && $abuseipdbisPublic -eq "true" && $abuseipdbisWhitelisted -eq "false" ]];
        then
        # Add IP address to csf.deny
                echo $ip "# AbuseIPDB: Reported" $abuseipdbtotalReports "times. Last Reported:" $abuseipdblastReportedAt "(Domain:" $abuseipdbdomain "Country:" $abuseipdbcountryName "ISP:" $abuseipdbisp "Usage Type:" $abuseipdbusageType")-" $(date +'%c') >> /etc/csf/csf.deny;
                echo $ip "added to csf.deny." $abuseipdbtotalReports "reports at AbuseIPDB.";
                echo "ABUSEIPDB_CHECK_CHANGES='1'" > ABUSEIPDB_CHECK_CHANGES.txt;
        elif [ "$abuseipdbtotalReports" == "null" ];
        then
                echo "AbuseIPDB API quota check limit may be exceeded. Please try again in 24hrs.";
                break;
        elif [ $abuseipdbtotalReports -eq 0 ];
        then
                echo $ip "IP not recorded at AbuseIPDB.";
                echo $ip >> ABUSEIPDB_CHECKED_IPS_NOT_REPORTED.txt;
        elif [ "$abuseipdbWhitelisted" = "true" ];
        then
                echo $ip "IP address whitelisted at AbuseIPDB.";
        elif [ "$abuseipdbisPublic" = "false" ];
        then
                echo $ip "IP is within a private address range and not public.";
        elif [[ $abuseipdbconfidenceScore -le 10 ]];
        then
                echo $ip "AbuseIPDB abuse confidence score < 10%).";
                 echo $ip >> ABUSEIPDB_CHECKED_IPS_NOT_SUSPECT.txt;
        else
                echo "Condition not matched.";
                echo "totalReports:" $abuseipdbtotalReports "abuseConfidenceScore:" $abuseipdbconfidenceScore "isPublic:" $abuseipdbisPublic "isWhitelisted:" $abuseipdbisWhitelisted "countryName:" $abuseipdbcountryName "lastReportedAt:" $abuseipdblastReportedAt "isp:" $abuseipdbisp "usageType:" $abuseipdbusageType "domain:" $abuseipdomain;
        fi
fi
done

# Restart CSF+LFD if changes to csf.deny
if grep -q "ABUSEIPDB_CHECK_CHANGES='1'" ABUSEIPDB_CHECK_CHANGES.txt;
then
        echo "Restarting CSF + LFD."
        csf -ra
fi

# Remove temp file
echo "Removing temporary file."
rm -rf ABUSEIPDB_CHECK_CHANGES.txt

