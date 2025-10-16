#!/usr/bin/bash
# Features:
#   Detects suspicious authentication attempts
#   Anonymizes IPs for privacy
#   Counts and sorts by frequency
#   Displays top offenders
#   Saves detailed results to a report file
#   optional summary of usernames involved
#

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 logfile1 [logfile2 ...]"
  exit 1
fi

# Define suspicious patterns (can be customized)
PATTERN="Failed password|Invalid user|authentication failure|sudo: authentication failure"

# Report output file
REPORT_FILE="sus_rep_$(date +%F_%H-%M-%S).csv"

echo "Analyzed logs for suspicious activity..."
echo "--------------------------------------------"

grep -E -H "$PATTERN" "$@" 2>/dev/null \
  | sed -E '
      # Anonymize IP addresses
      s/([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\.[0-9]{1,3}/\1.xxx/g
    ' \
  | awk -F: '
    {
      # Extract fields
      ip="unknown"
      user="unknown"
      line = $0

      # Extract anonymized IP (x.x.x.xxx)
      if (match(line, /[0-9]+\.[0-9]+\.[0-9]+\.xxx/)) {
        ip = substr(line, RSTART, RLENGTH)
      }

      # Extract username if present ("user" or "for invalid user")
      if (match(line, /user [a-zA-Z0-9_-]+/)) {
        user = substr(line, RSTART+5, RLENGTH-5)
      } else if (match(line, /invalid user [a-zA-Z0-9_-]+/)) {
        user = substr(line, RSTART+13, RLENGTH-13)
      }

      # Counters
      count[ip]++
      usercount[user]++
    }
    END {
      print "Anonymized_IP, Suspicious_Event_Count" > "'"$REPORT_FILE"'"
      for (ip in count) {
        print ip ", " count[ip] >> "'"$REPORT_FILE"'"
      }

      print "\n===== Suspicious IP Summary ====="
      for (ip in count) {
        printf "%-20s %d\n", ip, count[ip]
      }

      print "\n===== Top 5 Users with Failed Attempts ====="
      n=0
      for (u in usercount) {
        users[n]=u
        counts[n]=usercount[u]
        n++
      }

      # Sort user counts (simple bubble sort for awk)
      for (i=0; i<n; i++) {
        for (j=i+1; j<n; j++) {
          if (counts[i] < counts[j]) {
            tmp=counts[i]; counts[i]=counts[j]; counts[j]=tmp
            tmpu=users[i]; users[i]=users[j]; users[j]=tmpu
          }
        }
      }

      limit = (n < 5) ? n : 5
      for (i=0; i<limit; i++) {
        printf "%-15s %d\n", users[i], counts[i]
      }

      print "\nCSV report saved to: '"$REPORT_FILE"'"
    }
  '
