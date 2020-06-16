#!/bin/bash

# STIG Security Reporting - List Risks

auditfile=/Library/Application\ Support/SecurityScoring/STIG_audit
echo "<result>$(cat "$auditfile")</result>"