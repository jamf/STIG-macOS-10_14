#!/bin/bash

# STIG Security Reporting - Count Risks

auditfile=/Library/Application\ Support/SecurityScoring/STIG_audit
echo "<result>$(cat "$auditfile" | grep "*" | wc -l | tr -d '[:space:]')</result>"