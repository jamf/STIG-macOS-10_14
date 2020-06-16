#!/bin/bash
#
# root check
if [ "$(/usr/bin/whoami)" != "root" ]; then
  /bin/echo "This script must be run as root or sudo."
  exit 0
fi
#
####################################################################################################
#
# The Apple Software is provided by Apple on an "AS IS" basis.  APPLE
# MAKES NO WARRANTIES, EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION
# THE IMPLIED WARRANTIES OF NON-INFRINGEMENT, MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE, REGARDING THE APPLE SOFTWARE OR ITS USE AND
# OPERATION ALONE OR IN COMBINATION WITH YOUR PRODUCTS.
#
# IN NO EVENT SHALL APPLE BE LIABLE FOR ANY SPECIAL, INDIRECT, INCIDENTAL
# OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) ARISING IN ANY WAY OUT OF THE USE, REPRODUCTION,
# MODIFICATION AND/OR DISTRIBUTION OF THE APPLE SOFTWARE, HOWEVER CAUSED
# AND WHETHER UNDER THEORY OF CONTRACT, TORT (INCLUDING NEGLIGENCE),
# STRICT LIABILITY OR OTHERWISE, EVEN IF APPLE HAS BEEN ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
#####################################################################################################
#
# DESCRIPTION
#
# UNCLASSIFIED 
#
# Apple macOS 10.14 (Mojave) Security Technical Implementation Guide (STIG)
# These scripts audit and remediate the U_Apple_OS_X_10-14_V1R2_STIG
#
# The STIG is available on IASE at:
# https://public.cyber.mil/stigs/downloads/?_dl_facet_stigs=operating-systems,mac-os
#
# The STIG viewer is available on IASE at:
# https://public.cyber.mil/stigs/srg-stig-tools/
#
# These scripts are used to Audit and Remediate STIG compliance.
# They should be audited whenever the STIG is updated for macOS.
#
# Once these scripts are run, several of the settings cannot be easily rolled back.
#
# CAT I		Any vulnerability, the exploitation of which will directly and immediately result in loss of Confidentiality, Availability, or Integrity. (Most severe)
# CAT II	Any vulnerability, the exploitation of which has a potential to result in loss of Confidentiality, Availability, or Integrity.
# CAT III	Any vulnerability, the existence of which degrades measures to protect against loss of Confidentiality, Availability, or Integrity.
# 
#####################################################################################################
#
# Revision History:
# Date			Version	Notes
# ----			-------	-----
# 2019-11-20 	1.0		Script created for U_Apple_OS_X_10-14_V1R1_STIG
# 2020-02-13 	1.1		Script created for U_Apple_OS_X_10-14_V1R2_STIG
#
#####################################################################################################
#
# USAGE
# Reads from plist at $LogDir/STIG_security_score.plist by default.
# For "true" items, runs query for current computer/user compliance.
# Non-compliant items are logged to $LogDir/STIG_audit
LogDir="/Library/Application Support/SecurityScoring"
plistlocation="$LogDir/STIG_security_score.plist"
auditfilelocation="$LogDir/STIG_audit"
currentUser=$(/bin/echo 'show State:/Users/ConsoleUser' | /usr/sbin/scutil | /usr/bin/awk '/Name / { print $3 }')
hardwareUUID="$(/usr/sbin/system_profiler SPHardwareDataType | grep "Hardware UUID" | /usr/bin/awk -F ": " '{print $2}' | /usr/bin/xargs)"
logFile="$LogDir/STIGremediation.log"

# Append to existing logFile
/bin/echo "$(/bin/date -u)" "Beginning remediation" >> "$logFile"
# Create new logFile
# /bin/echo "$(/bin/date -u)" "Beginning remediation" > "$logFile"	

if [[ ! -e $plistlocation ]]; then
	/bin/echo "No scoring file present"
	exit 0
fi

#####################################################################################################
# AOSX_14_000001 Configuration Profile - The macOS system must be configured to prevent Apple Watch from terminating a session lock.
# Configuration Profile - Security & Privacy Payload > General > Allow user to unlock the Mac using an Apple Watch (unchecked)
#####################################################################################################

#####################################################################################################
# AOSX_14_000002 Configuration Profile - Users must be prompted to enter their passwords when unlocking the screen saver.
# Configuration Profile - Security & Privacy Payload > General > Require password after sleep or screen saver begins (checked)
#####################################################################################################

#####################################################################################################
# AOSX_14_000003 Configuration Profile - The macOS system must initiate the session lock no more than five seconds after a screen saver is started.
# Configuration Profile - Security & Privacy Payload > General > Require password * after sleep or screen saver begins (select * time no more than five seconds)
#####################################################################################################

#####################################################################################################
# AOSX_14_000004 Configuration Profile - A screen saver must be enabled and set to require a password to unlock. The timeout should be set to 15 minutes of inactivity. 
# Configuration Profile - Login Window payload > Options > Start screen saver after: (checked) > 15 Minutes of Inactivity (or less) 
#####################################################################################################

#####################################################################################################
# AOSX_14_000005 Configuration Profile - The macOS system must be configured to lock the user session when a smart token is removed.
# Configuration Profile - Smart Card payload > Enable Screen Saver on Smart Card removal (checked)
#####################################################################################################

#####################################################################################################
# AOSX_14_000006 Configuration Profile - A default screen saver must be configured for all users.
# Configuration Profile - Login Window payload > Options > Start screen saver after: (checked) > USE SCREEN SAVER MODULE AT PATH: (path to screensaver)
#####################################################################################################

#####################################################################################################
# AOSX_14_000007 Configuration Profile - The macOS system must be configured to disable hot corners.
# Configuration Profile - Custom payload > com.apple.dock > wvous-tl-corner=0, wvous-br-corner=0, wvous-bl-corner=0, wvous-tr-corner=0
#####################################################################################################

#####################################################################################################
# AOSX_14_000008 The macOS system must be configured with Wi-Fi support software disabled.
# Verify organizational score
AOSX_14_000008="$(defaults read "$plistlocation" AOSX_14_000008)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_14_000008" = "1" ]; then
	/usr/sbin/networksetup -setnetworkserviceenabled "Wi-Fi" off
	/bin/echo $(/bin/date -u) "AOSX_14_000008 remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# DUPLICATE check to AOSX_14_004010 and AOSX_14_004011
# AOSX_14_000010 Enable remote access through SSH.
# Verify organizational score
AOSX_14_000010="$(defaults read "$plistlocation" AOSX_14_000010)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_14_000010" = "1" ]; then
	/bin/launchctl enable system/com.openssh.sshd
	/usr/sbin/systemsetup -f -setremotelogin on
	/bin/echo $(/bin/date -u) "AOSX_14_000010 remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# DUPLICATE check to AOSX_14_004010 and AOSX_14_004011
# AOSX_14_000010off Disable remote access through SSH.
# Verify organizational score
AOSX_14_000010off="$(defaults read "$plistlocation" AOSX_14_000010off)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_14_000010off" = "1" ]; then
	/bin/launchctl disable system/com.openssh.sshd
	/usr/sbin/systemsetup -f -setremotelogin off
	/bin/echo $(/bin/date -u) "AOSX_14_000010off remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# DUPLICATE check to AOSX_14_000040
# AOSX_14_000011 ssh -V must report OpenSSH_7.9p1 or greater.
#####################################################################################################

#####################################################################################################
# AOSX_14_000012 Active Directory – The macOS system must automatically remove or disable temporary user accounts after 72 hours. Ensure the system is integrated into a directory services infrastructure.
# Managed by a directory server (AD).
#####################################################################################################

#####################################################################################################
# AOSX_14_000013 Active Directory – The macOS system must automatically remove or disable emergency accounts after the crisis is resolved or within 72 hours. Ensure the system is integrated into a directory services infrastructure.
# Managed by a directory server (AD).
#####################################################################################################

#####################################################################################################
# AOSX_14_000014 The macOS system must compare internal information system clocks at least every 24 with an NTP server. Set usingnetworktime to on.
# Verify organizational score
AOSX_14_000014="$(defaults read "$plistlocation" AOSX_14_000014)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_14_000014" = "1" ]; then
	/usr/sbin/systemsetup -setusingnetworktime on
	/bin/echo $(/bin/date -u) "AOSX_14_000014 remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# AOSX_14_000015 Managed by McAfee EPO Agent - The macOS system must employ automated mechanisms to determine the state of system components.
# The DoD recommended system is the McAfee HBSS.
#####################################################################################################

#####################################################################################################
# AOSX_14_000016 Active Directory – The macOS system must be integrated into a directory services infrastructure.
# Managed by a directory server (AD).
#####################################################################################################

#####################################################################################################
# AOSX_14_000020 Configuration Profile - The macOS system must enforce account lockout after the limit of three consecutive invalid logon attempts by a user.
# Configuration Profile - Passcode payload > MAXIMUM NUMBER OF FAILED ATTEMPTS 3
#####################################################################################################

#####################################################################################################
# AOSX_14_000021 Configuration Profile - The macOS system must enforce an account lockout time period of 15 minutes in which a user makes three consecutive invalid logon attempts.
# Configuration Profile - Passcode payload > DELAY AFTER FAILED LOGIN ATTEMPTS 15 (NOT COMPATIBLE WITH MACOS V10.11 OR LATER)
#####################################################################################################

#####################################################################################################
# REDUNDANT to AOSX_14_000020 and AOSX_14_000021
# AOSX_14_000022 Configuration Profile - The macOS system must enforce the limit of three consecutive invalid logon attempts by a user before the user account is locked.
# Configuration Profile - Passcode payload > MAXIMUM NUMBER OF FAILED ATTEMPTS 3
# Configuration Profile - Passcode payload > DELAY AFTER FAILED LOGIN ATTEMPTS 15 (NOT COMPATIBLE WITH MACOS V10.11 OR LATER)
#####################################################################################################

#####################################################################################################
# AOSX_14_000023 The macOS system must display the Standard Mandatory DoD Notice and Consent Banner before granting access to the operating system.
BannerText="You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By using this IS (which includes any device attached to this IS), you consent to the following conditions:
- The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.
- At any time, the USG may inspect and seize data stored on this IS.
- Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.
- This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.
- Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."
# Verify organizational score
AOSX_14_000023="$(defaults read "$plistlocation" AOSX_14_000023)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_14_000023" = "1" ]; then
	/bin/echo "$BannerText" > "/etc/banner"
	/bin/chmod 755 "/etc/banner" 
	# create a symbolic link for Message of the Day (motd) – This appears when a new terminal window or session is opened.
	/bin/ln -s /etc/banner /etc/motd
	/bin/chmod 755 "/etc/motd" 
	#
	/bin/echo $(/bin/date -u) "AOSX_14_000023 remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# AOSX_14_000024 The macOS system must display the Standard Mandatory DoD Notice and Consent Banner before granting access to the system via SSH.
# Verify organizational score
AOSX_14_000024="$(defaults read "$plistlocation" AOSX_14_000024)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_14_000024" = "1" ]; then
	/usr/bin/sed -i.bak 's/^[\#]*#Banner\ none.*/Banner \/etc\/banner/' /etc/ssh/sshd_config
	/bin/echo $(/bin/date -u) "AOSX_14_000024 remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# AOSX_14_000025 The macOS system must be configured so that any connection to the system must display the Standard Mandatory DoD Notice and Consent Banner before granting access to the system.
PolicyBannerText="You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By using this IS (which includes any device attached to this IS), you consent to the following conditions:
- The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.
- At any time, the USG may inspect and seize data stored on this IS.
- Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.
- This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.
- Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."
# Verify organizational score
AOSX_14_000025="$(defaults read "$plistlocation" AOSX_14_000025)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_14_000025" = "1" ]; then
	/bin/echo "$PolicyBannerText" > "/Library/Security/PolicyBanner.txt"
	/bin/chmod 755 "/Library/Security/PolicyBanner."* 
	#
	/bin/echo $(/bin/date -u) "AOSX_14_000025 remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# AOSX_14_000030 The macOS system must be configured so that log files must not contain access control lists (ACLs).
# Verify organizational score
AOSX_14_000030="$(defaults read "$plistlocation" AOSX_14_000030)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_14_000030" = "1" ]; then
	/bin/chmod -N $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}')/*
	/bin/echo $(/bin/date -u) "AOSX_14_000030 remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# AOSX_14_000031 The macOS system must be configured so that log folders must not contain access control lists (ACLs).
# Verify organizational score
AOSX_14_000031="$(defaults read "$plistlocation" AOSX_14_000031)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_14_000031" = "1" ]; then
	/bin/chmod -N $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}')
	/bin/echo $(/bin/date -u) "AOSX_14_000031 remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# AOSX_14_000032 Configuration Profile - Ensure that only one FileVault user is defined and verify that password forwarding has been disabled on the system.
# Configuration Profile - Custom payload > com.apple.loginwindow > DisableFDEAutologin=true
#####################################################################################################

#####################################################################################################
# DUPLICATE check to AOSX_14_000011
# AOSX_14_000040 ssh -V must report OpenSSH_7.9p1 or greater.
#####################################################################################################

#####################################################################################################
# AOSX_14_000050 The macOS system must limit the number of concurrent SSH sessions to 10 for all accounts and/or account types.
# Verify organizational score
AOSX_14_000050="$(defaults read "$plistlocation" AOSX_14_000050)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_14_000050" = "1" ]; then
	/usr/bin/sudo /usr/bin/sed -i.bak 's/^[\#]*MaxSessions.*/MaxSessions 10/' /etc/ssh/sshd_config
	/bin/echo $(/bin/date -u) "AOSX_14_000050 remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# AOSX_14_000051 The macOS system must be configured with the SSH daemon ClientAliveInterval option set to 900 or less.
# Verify organizational score
AOSX_14_000051="$(defaults read "$plistlocation" AOSX_14_000051)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_14_000051" = "1" ]; then
	/usr/bin/sed -i.bak 's/.*ClientAliveInterval.*/ClientAliveInterval 900/' /etc/ssh/sshd_config
	/bin/echo $(/bin/date -u) "AOSX_14_000051 remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# AOSX_14_000052 The macOS system must be configured with the SSH daemon ClientAliveCountMax option set to 0.
# Verify organizational score
AOSX_14_000052="$(defaults read "$plistlocation" AOSX_14_000052)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_14_000052" = "1" ]; then
	/usr/bin/sed -i.bak 's/.*ClientAliveCountMax.*/ClientAliveCountMax 0/' /etc/ssh/sshd_config
	/bin/echo $(/bin/date -u) "AOSX_14_000052 remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# AOSX_14_000053 The macOS system must be configured with the SSH daemon LoginGraceTime set to 30 or less.
# Verify organizational score
AOSX_14_000053="$(defaults read "$plistlocation" AOSX_14_000053)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_14_000053" = "1" ]; then
	/usr/bin/sed -i.bak 's/.*LoginGraceTime.*/LoginGraceTime 30/' /etc/ssh/sshd_config
	/bin/echo $(/bin/date -u) "AOSX_14_000053 remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# AOSX_14_001001 Ensure the appropriate flags are enabled for /etc/security/audit_control - ad.
# Verify organizational score
AOSX_14_001001="$(defaults read "$plistlocation" AOSX_14_001001)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_14_001001" = "1" ]; then
	/usr/bin/sed -i.bak '/^flags/ s/$/,ad/' /etc/security/audit_control; /usr/sbin/audit -s
	/bin/echo $(/bin/date -u) "AOSX_14_001001 remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# AOSX_14_001002 Ensure the appropriate flags are enabled for /etc/security/audit_control - lo.
# Verify organizational score
AOSX_14_001002="$(defaults read "$plistlocation" AOSX_14_001002)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_14_001002" = "1" ]; then
	/usr/bin/sed -i.bak '/^flags/ s/$/,lo/' /etc/security/audit_control; /usr/sbin/audit -s
	/bin/echo $(/bin/date -u) "AOSX_14_001002 remediated" | /usr/bin/tee -a "$logFile"
fi
#
#####################################################################################################

#####################################################################################################
# AOSX_14_001003 The macOS system must initiate session audits at system startup.
# Verify organizational score
AOSX_14_001003="$(defaults read "$plistlocation" AOSX_14_001003)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_14_001003" = "1" ]; then
	/bin/launchctl enable system/com.apple.auditd
	/bin/echo $(/bin/date -u) "AOSX_14_001003 remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# AOSX_14_001010 The macOS system must shut down by default upon audit failure (unless availability is an overriding concern).
# Verify organizational score
AOSX_14_001010="$(defaults read "$plistlocation" AOSX_14_001010)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_14_001010" = "1" ]; then
	/usr/bin/sed -i.bak '/^policy/ s/$/,ahlt/' /etc/security/audit_control; /usr/sbin/audit -s
	/bin/echo $(/bin/date -u) "AOSX_14_001010 remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# AOSX_14_001012 The macOS system must be configured with audit log files owned by root.
# Verify organizational score
AOSX_14_001012="$(defaults read "$plistlocation" AOSX_14_001012)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_14_001012" = "1" ]; then
	/usr/sbin/chown root $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}')/*
	/bin/echo $(/bin/date -u) "AOSX_14_001012 remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# AOSX_14_001013 The macOS system must be configured with audit log folders owned by root.
# Verify organizational score
AOSX_14_001013="$(defaults read "$plistlocation" AOSX_14_001013)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_14_001013" = "1" ]; then
	/usr/sbin/chown root $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}')
	/bin/echo $(/bin/date -u) "AOSX_14_001013 remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# AOSX_14_001014 The macOS system must be configured with audit log files group-owned by wheel.
# Verify organizational score
AOSX_14_001014="$(defaults read "$plistlocation" AOSX_14_001014)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_14_001014" = "1" ]; then
	/usr/bin/chgrp wheel $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}')/*
	/bin/echo $(/bin/date -u) "AOSX_14_001014 remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# AOSX_14_001015 The macOS system must be configured with audit log folders group-owned by wheel.
# Verify organizational score
AOSX_14_001015="$(defaults read "$plistlocation" AOSX_14_001015)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_14_001015" = "1" ]; then
	/usr/bin/chgrp wheel $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}')
	/bin/echo $(/bin/date -u) "AOSX_14_001015 remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# AOSX_14_001016 The macOS system must be configured with audit log files set to mode 440 or less permissive.
# Verify organizational score
AOSX_14_001016="$(defaults read "$plistlocation" AOSX_14_001016)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_14_001016" = "1" ]; then
	/bin/chmod 440 $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}')/*
	/bin/echo $(/bin/date -u) "AOSX_14_001016 remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# AOSX_14_001017 The macOS system must be configured with audit log folders set to mode 700 or less permissive.
# Verify organizational score
AOSX_14_001017="$(defaults read "$plistlocation" AOSX_14_001017)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_14_001017" = "1" ]; then
	/bin/chmod 700 $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}')
	/bin/echo $(/bin/date -u) "AOSX_14_001017 remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# AOSX_14_001020 The macOS system must audit the enforcement actions used to restrict access associated with changes to the system.
# Verify organizational score
AOSX_14_001020="$(defaults read "$plistlocation" AOSX_14_001020)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_14_001020" = "1" ]; then
	/usr/bin/sed -i.bak '/^flags/ s/$/,fm,-fr,-fw/' /etc/security/audit_control; /usr/sbin/audit -s
	/bin/echo $(/bin/date -u) "AOSX_14_001020 remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# AOSX_14_001029 Change the value for /etc/security/audit_control - expire-after to 7d.
# Verify organizational score
AOSX_14_001029="$(defaults read "$plistlocation" AOSX_14_001029)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_14_001029" = "1" ]; then
	/usr/bin/sed -i.bak 's/.*expire-after.*/expire-after:7d/' /etc/security/audit_control; /usr/sbin/audit -s
	/bin/echo $(/bin/date -u) "AOSX_14_001029 remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# AOSX_14_001030 Change the value for /etc/security/audit_control - minfree to 25.
# Verify organizational score
AOSX_14_001030="$(defaults read "$plistlocation" AOSX_14_001030)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_14_001030" = "1" ]; then
	/usr/bin/sed -i.bak 's/.*minfree.*/minfree:25/' /etc/security/audit_control; /usr/sbin/audit -s
	/bin/echo $(/bin/date -u) "AOSX_14_001030 remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# AOSX_14_001031 Change the value for /etc/security/audit_control - logger to -s.
# Verify organizational score
AOSX_14_001031="$(defaults read "$plistlocation" AOSX_14_001031)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_14_001031" = "1" ]; then
	/usr/bin/sed -i.bak 's/logger -p/logger -s -p/' /etc/security/audit_warn; /usr/sbin/audit -s
	/bin/echo $(/bin/date -u) "AOSX_14_001031 remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# AOSX_14_001044 Ensure the appropriate flags are enabled for /etc/security/audit_control - aa.
# Verify organizational score
AOSX_14_001044="$(defaults read "$plistlocation" AOSX_14_001044)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_14_001044" = "1" ]; then
	/usr/bin/sed -i.bak '/^flags/ s/$/,aa/' /etc/security/audit_control; /usr/sbin/audit -s
	/bin/echo $(/bin/date -u) "AOSX_14_001044 remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# DUPLICATE check to AOSX_14_003002
# AOSX_14_001060 Configuration Profile - The macOS system must accept and verify Personal Identity Verification (PIV) credentials.
# Configuration Profile - Smart Card Payload > VERIFY CERTIFICATE TRUST = Check Certificate
#####################################################################################################

#####################################################################################################
# AOSX_14_001100 The macOS system must require individuals to be authenticated with an individual authenticator prior to using a group authenticator.
# Verify organizational score
AOSX_14_001100="$(defaults read "$plistlocation" AOSX_14_001100)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_14_001100" = "1" ]; then
	/usr/bin/sed -i.bak 's/^[\#]*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
	/bin/echo $(/bin/date -u) "AOSX_14_001100 remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# AOSX_14_002001 The macOS system must be configured to disable SMB File Sharing unless it is required.
# Verify organizational score
AOSX_14_002001="$(defaults read "$plistlocation" AOSX_14_002001)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_14_002001" = "1" ]; then
	/bin/launchctl disable system/com.apple.smbd
	/bin/launchctl unload -wF /System/Library/LaunchDaemons/com.apple.smbd.plist 2> /dev/null # legacy command
	/bin/echo $(/bin/date -u) "AOSX_14_002001 remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# AOSX_14_002002 The macOS system must be configured to disable Apple File (AFP) Sharing.
# Verify organizational score
AOSX_14_002002="$(defaults read "$plistlocation" AOSX_14_002002)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_14_002002" = "1" ]; then
	/bin/launchctl disable system/com.apple.AppleFileServer
	/bin/launchctl unload -wF /System/Library/LaunchDaemons/com.apple.AppleFileServer.plist 2> /dev/null # legacy command
	/bin/echo $(/bin/date -u) "AOSX_14_002002 remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# AOSX_14_002003 The macOS system must be configured to disable the Network File System (NFS) daemon unless it is required.
# Verify organizational score
AOSX_14_002003="$(defaults read "$plistlocation" AOSX_14_002003)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_14_002003" = "1" ]; then
	/bin/launchctl disable system/com.apple.nfsd
	/bin/launchctl unload -wF /System/Library/LaunchDaemons/com.apple.nfsd.plist 2> /dev/null # legacy command
	/bin/echo $(/bin/date -u) "AOSX_14_002003 remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# AOSX_14_002004 The macOS system must be configured to disable Location Services.
# Verify organizational score
AOSX_14_002004="$(defaults read "$plistlocation" AOSX_14_002004)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_14_002004" = "1" ]; then
	/usr/bin/sudo -u _locationd /usr/bin/defaults -currentHost write com.apple.locationd LocationServicesEnabled -bool FALSE 2> /dev/null
	/bin/echo $(/bin/date -u) "AOSX_14_002004 remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# AOSX_14_002005 Configuration Profile - The macOS system must be configured to disable Bonjour multicast advertising.
# Configuration Profile - Custom payload > com.apple.mDNSResponder > NoMulticastAdvertisements=true
#####################################################################################################

#####################################################################################################
# AOSX_14_002006 The macOS system must be configured to disable the UUCP service.
# Verify organizational score
AOSX_14_002006="$(defaults read "$plistlocation" AOSX_14_002006)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_14_002006" = "1" ]; then
	/bin/launchctl disable system/com.apple.uucp
	/bin/launchctl unload -wF /System/Library/LaunchDaemons/com.apple.uucp.plist 2> /dev/null # legacy command
	/bin/echo $(/bin/date -u) "AOSX_14_002006 remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# AOSX_14_002007 Configuration Profile - The macOS system must be configured to disable Bonjour multicast advertising.
# Configuration Profile - Custom payload > com.apple.mDNSResponder > NoMulticastAdvertisements=true
#####################################################################################################

#####################################################################################################
# AOSX_14_002008 The macOS system must be configured to disable Web Sharing.
# Verify organizational score
AOSX_14_002008="$(defaults read "$plistlocation" AOSX_14_002008)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_14_002008" = "1" ]; then
	/bin/launchctl disable system/org.apache.httpd
	/bin/echo $(/bin/date -u) "AOSX_14_002008 remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# AOSX_14_002009 Configuration Profile - The macOS system must be configured to disable AirDrop.
# Configuration Profile - Restrictions payload > Media > Allow AirDrop (unchecked)
#####################################################################################################

#####################################################################################################
# AOSX_14_002010 Configuration Profile - The macOS system must be configured to disable the application FaceTime.
# Configuration Profile - Restrictions payload > Applications > Disallow "/Applications/FaceTime.app/"
#####################################################################################################

#####################################################################################################
# AOSX_14_002011 Configuration Profile - The macOS system must be configured to disable the application Messages.
# Configuration Profile - Restrictions payload > Applications > Disallow "/Applications/Messages.app/"
#####################################################################################################

#####################################################################################################
# AOSX_14_002012 Configuration Profile - The macOS system must be configured to disable the iCloud Calendar services.
# Configuration Profile - Restrictions payload > Functionality > Allow iCloud Calendar (unchecked)
#####################################################################################################

#####################################################################################################
# AOSX_14_002013 Configuration Profile - The macOS system must be configured to disable the iCloud Reminders services.
# Configuration Profile - Restrictions payload > Functionality > Allow iCloud Reminders (unchecked)
#####################################################################################################

#####################################################################################################
# AOSX_14_002014 Configuration Profile - The macOS system must be configured to disable iCloud Address Book services.
# Configuration Profile - Restrictions payload > Functionality > Allow iCloud Contacts (unchecked)
#####################################################################################################

#####################################################################################################
# AOSX_14_002015 Configuration Profile - The macOS system must be configured to disable the iCloud Mail services.
# Configuration Profile - Restrictions payload > Functionality > Allow iCloud Mail (unchecked)
#####################################################################################################

#####################################################################################################
# AOSX_14_002016 Configuration Profile - The macOS system must be configured to disable the iCloud Notes services.
# Configuration Profile - Restrictions payload > Functionality > Allow iCloud Notes (unchecked)
#####################################################################################################

#####################################################################################################
# AOSX_14_002017 Configuration Profile - The macOS system must be configured to disable the camera.
# Configuration Profile - Restrictions payload > Functionality > Allow use of Camera (unchecked)
#####################################################################################################

#####################################################################################################
# AOSX_14_002019 Configuration Profile - The macOS system must be configured to disable the application Mail.
# Configuration Profile - Restrictions payload > Applications > Disallow "/Applications/Mail.app/"
#####################################################################################################

#####################################################################################################
# AOSX_14_002020 Configuration Profile - The macOS system must be configured to disable Siri and dictation.
# Configuration Profile - Custom payload > com.apple.ironwood.support > Ironwood Allowed=false
# Configuration Profile - Custom payload > com.apple.ironwood.support > Assistant Allowed=false
#####################################################################################################

#####################################################################################################
# AOSX_14_002021 Configuration Profile - The macOS system must be configured to disable sending diagnostic and usage data to Apple.
# Configuration Profile - Security & Privacy payload > Privacy > Allow sending diagnostic and usage data to Apple... (unchecked)
#####################################################################################################

#####################################################################################################
# AOSX_14_002022 The macOS system must be configured to disable Remote Apple Events.
# Verify organizational score
AOSX_14_002022="$(defaults read "$plistlocation" AOSX_14_002022)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_14_002022" = "1" ]; then
	/bin/launchctl disable system/com.apple.AEServer
	/bin/echo $(/bin/date -u) "AOSX_14_002022 remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# AOSX_14_002023 Configuration Profile - The macOS system must be configured to disable the application Calendar.
# Configuration Profile - Restrictions payload > Applications > Disallow "/Applications/Calendar.app/"
#####################################################################################################

#####################################################################################################
# AOSX_14_002031 Configuration Profile - The macOS system must be configured to disable the system preference pane for iCloud.
# Configuration Profile - Restrictions payload > Preferences > disable selected items "iCloud"
#####################################################################################################

#####################################################################################################
# AOSX_14_002032 Configuration Profile - The macOS system must be configured to disable the system preference pane for Internet Accounts.
# Configuration Profile - Restrictions payload > Preferences > disable selected items "Internet Accounts"
#####################################################################################################

#####################################################################################################
# DUPLICATE check to AOSX_14_002039
# AOSX_14_002034 Configuration Profile - The macOS system must disable Siri pop-ups.
# Configuration Profile - Login Window payload > Options > Disable Siri setup during login (checked)
#####################################################################################################

#####################################################################################################
# AOSX_14_002035 Configuration Profile - The macOS system must be configured to disable the Cloud Setup services.
# Configuration Profile - Login Window payload > Options > Disable Apple ID setup during login (checked)
#####################################################################################################

#####################################################################################################
# AOSX_14_002036 Configuration Profile - The macOS system must be configured to disable the Privacy Setup services.
# Configuration Profile - Login Window payload > Options > Disable Privacy setup during login (checked)
# or
# Configuration Profile - Custom payload > com.apple.SetupAssistant.managed > SkipPrivacySetup=true
#####################################################################################################

#####################################################################################################
# AOSX_14_002037 Configuration Profile - The macOS system must be configured to disable the Cloud Storage Setup services.
# Configuration Profile - Login Window payload > Options > Disable iCloud Storage setup during login (checked)
# or
# Configuration Profile - Custom payload > com.apple.SetupAssistant.managed > SkipiCloudStorageSetup=true
#####################################################################################################

#####################################################################################################
# AOSX_14_002038 The macOS system must unload tftpd.
# Verify organizational score
AOSX_14_002038="$(defaults read "$plistlocation" AOSX_14_002038)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_14_002038" = "1" ]; then
	/bin/launchctl disable system/com.apple.tftpd
	/bin/echo $(/bin/date -u) "AOSX_14_002038 remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# DUPLICATE check to AOSX_14_002034
# AOSX_14_002039 Configuration Profile - The macOS system must disable Siri pop-ups.
# Configuration Profile - Login Window payload > Options > Disable Siri setup during login (checked)
#####################################################################################################

#####################################################################################################
# AOSX_14_002040 Configuration Profile - The macOS system must disable iCloud Keychain synchronization.
# Configuration Profile - Restrictions payload > Functionality > Allow iCloud Keychain (unchecked)
#####################################################################################################

#####################################################################################################
# DUPLICATE AOSX_14_002049
# AOSX_14_002041 Configuration Profile - The macOS system must disable iCloud document synchronization.
# Configuration Profile - Restrictions payload > Functionality > Allow iCloud Drive (unchecked)
#####################################################################################################

#####################################################################################################
# AOSX_14_002042 Configuration Profile - The macOS system must disable iCloud bookmark synchronization.
# Configuration Profile - Restrictions payload > Functionality > Allow iCloud Bookmarks (unchecked)
#####################################################################################################

#####################################################################################################
# AOSX_13_000561 Configuration Profile - The macOS system must disable iCloud Photo Library.
# Configuration Profile - Restrictions payload > Functionality > Allow iCloud Photos (unchecked)
# or
# Configuration Profile - Custom payload > com.apple.applicationaccess > allowCloudPhotoLibrary=false
#####################################################################################################

#####################################################################################################
# DUPLICATE AOSX_14_002041
# AOSX_14_002049 Configuration Profile - The macOS system must disable iCloud document synchronization.
# Configuration Profile - Restrictions payload > Functionality > Allow iCloud Drive (unchecked)
#####################################################################################################

#####################################################################################################
# AOSX_14_002050 The macOS system must disable the Screen Sharing feature.
# Verify organizational score
AOSX_14_002050="$(defaults read "$plistlocation" AOSX_14_002050)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_14_002050" = "1" ]; then
	/System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -deactivate -stop
	/bin/launchctl disable system/com.apple.screensharing
	/bin/echo $(/bin/date -u) "AOSX_14_002050 remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# AOSX_14_002060 Configuration Profile - The macOS system must allow only applications downloaded from the App Store and identified developers to run.
# Configuration Profile - Security & Privacy payload > General > Mac App Store and identified developers (selected)
#####################################################################################################

#####################################################################################################
# AOSX_14_002061 Configuration Profile - The macOS system must be configured so that end users cannot override Gatekeeper settings.
# Configuration Profile - Security & Privacy payload > General > Do not allow user to override Gatekeeper setting (checked)
#####################################################################################################

#####################################################################################################
# AOSX_14_002062 Configuration Profile - The macOS system must be configured with Bluetooth turned off.
# Configuration Profile - Custom payload > com.apple.MCXBluetooth > DisableBluetooth=true
#####################################################################################################

#####################################################################################################
# AOSX_14_002063 Configuration Profile - The macOS system must disable the guest account.
# Configuration Profile - Login Window payload > Options > Allow Guest User (unchecked)
#####################################################################################################

#####################################################################################################
# AOSX_14_002064 The macOS system must have the security assessment policy subsystem enabled.
# Verify organizational score
AOSX_14_002064="$(defaults read "$plistlocation" AOSX_14_002064)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_14_002064" = "1" ]; then
	/usr/sbin/spctl --master-enable
	/bin/echo $(/bin/date -u) "AOSX_14_002064 remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# REDUNDANT to AOSX_14_002068
# AOSX_14_002065 The macOS system must have the security assessment policy subsystem enabled.
# Verify organizational score
AOSX_14_002065="$(/usr/bin/defaults read "$plistlocation" AOSX_14_002065)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_002065" = "1" ]; then
	IFS=$'\n'
	for userDirs in $(/bin/ls -d /Users/* 2> /dev/null | /usr/bin/cut -f3 -d'/' | /usr/bin/grep -v "Shared" | /usr/bin/grep -v "Guest"); do
		userID=$(/usr/bin/id -u $userDirs 2> /dev/null)
		/bin/echo "resetUserPermissions for $userDirs $userID"
		/usr/sbin/diskutil resetUserPermissions / "$userID"
	done
	unset IFS
	/bin/echo $(/bin/date -u) "AOSX_14_002065 remediated" | /usr/bin/tee -a "$logFile"
	#/usr/bin/defaults write "$plistlocation" AOSX_14_002065 -bool false
fi
# 
#####################################################################################################

#####################################################################################################
# AOSX_14_002066 Configuration Profile - The macOS system must not allow an unattended or automatic logon to the system.
# Configuration Profile - Login Window payload > Options > Disable automatic login (checked)
#####################################################################################################

#####################################################################################################
# AOSX_14_002067 Configuration Profile - The macOS system must prohibit user installation of software without explicit privileged status.
# Configuration Profile - Restrictions payload > Applications > Disallow "/Users/"
#####################################################################################################

#####################################################################################################
# AOSX_14_002065 is redundant to this
# AOSX_14_002068 The macOS system must set permissions on user home directories to prevent users from having access to read or modify another users files.
# Verify organizational score
AOSX_14_002068="$(/usr/bin/defaults read "$plistlocation" AOSX_14_002068)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_002068" = "1" ]; then
	IFS=$'\n'
	for userDirs in $(/bin/ls -d /Users/* 2> /dev/null | /usr/bin/cut -f3 -d'/' | /usr/bin/grep -v "Shared" | /usr/bin/grep -v "Guest"); do
		userID=$(/usr/bin/id -u $userDirs 2> /dev/null)
		/bin/chmod +a "group:everyone deny delete" /Users/$userDirs/*
		/bin/chmod go-rwx /Users/$userDirs/*
		/usr/sbin/chown $userDirs /Users/$userDirs/*
		/bin/echo "resetUserPermissions for $userDirs $userID"
		/usr/sbin/diskutil resetUserPermissions / "$userID"
	done
	unset IFS
	/bin/echo $(/bin/date -u) "AOSX_14_002068 remediated" | /usr/bin/tee -a "$logFile"
	#/usr/bin/defaults write "$plistlocation" AOSX_14_002068 -bool false
fi
# 
#####################################################################################################

#####################################################################################################
# AOSX_14_002069 The macOS system must uniquely identify peripherals before establishing a connection.
# Verify organizational score
AOSX_14_002069="$(defaults read "$plistlocation" AOSX_14_002069)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_14_002069" = "1" ]; then
	security authorizationdb read system.preferences > /tmp/system.preferences.plist
	/usr/libexec/PlistBuddy -c "Set :shared false" /tmp/system.preferences.plist
	security authorizationdb write system.preferences < /tmp/system.preferences.plist
	/bin/echo $(/bin/date -u) "AOSX_14_002069 remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# AOSX_14_002070 Managed by McAfee EPO Agent - The macOS system must use an approved antivirus program.
#####################################################################################################

#####################################################################################################
# AOSX_14_003001 Configuration Profile - The macOS system must issue or obtain public key certificates under an appropriate certificate policy from an approved service provider.
# Configuration Profile - Certificate payload
#####################################################################################################

#####################################################################################################
# DUPLICATE check to AOSX_14_001060
# AOSX_14_003002 Configuration Profile - The macOS system must enable certificate for smartcards.
# Configuration Profile - Smart Card payload > VERIFY CERTIFICATE TRUST (Check Certificate)
#####################################################################################################

#####################################################################################################
# DUPLICATE check to AOSX_14_003025
# AOSX_14_003005 Configuration Profile - The macOS system must map the authenticated identity to the user or group account for PKI-based authentication.
# Configuration Profile - Smart Card payload > Enforce Smart Card use (checked)
#####################################################################################################

#####################################################################################################
# AOSX_14_003007 Configuration Profile - The macOS system must enforce password complexity by requiring that at least one numeric character be used.
# Configuration Profile - Passcode payload > Require alphanumeric value (checked)
#####################################################################################################

#####################################################################################################
# AOSX_14_003008 Configuration Profile - The macOS system must enforce a 60-day maximum password lifetime restriction.
# Configuration Profile - Passcode payload > MAXIMUM PASSCODE AGE 60
#####################################################################################################

#####################################################################################################
# AOSX_14_003009 Configuration Profile - The macOS system must prohibit password reuse for a minimum of five generations.
# Configuration Profile - Passcode payload > PASSCODE HISTORY 5
#####################################################################################################

#####################################################################################################
# AOSX_14_003010 Configuration Profile - The macOS system must enforce a minimum 15-character password length.
# Configuration Profile - Passcode payload > MINIMUM PASSCODE LENGTH 15
#####################################################################################################

#####################################################################################################
# AOSX_14_003011 Configuration Profile - The macOS system must enforce password complexity by requiring that at least one special character be used.
# Configuration Profile - Passcode payload > MINIMUM NUMBER OF COMPLEX CHARACTERS 1
# Configuration Profile - Passcode payload > Allow simple value (unchecked)
#####################################################################################################

#####################################################################################################
# AOSX_14_003012 Configuration Profile - The macOS system must be configured to prevent displaying password hints.
# Configuration Profile - Login Window payload > Options > Show password hint when needed and available (unchecked)
#####################################################################################################

#####################################################################################################
# AOSX_14_003013 Enable Firmware Password – macOS must be configured with a firmware password to prevent access to single user mode and booting from alternative media.
# Enabled via a Jamf Policy to "Configure Open Firmware/EFI Password".
#####################################################################################################

#####################################################################################################
# DUPLICATE check to AOSX_14_003024
# AOSX_14_003020 The macOS system must use multifactor authentication for local and network access to privileged and non-privileged accounts. Disable password based authentication in SSHD.
# Verify organizational score
AOSX_14_003020="$(defaults read "$plistlocation" AOSX_14_003020)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_14_003020" = "1" ]; then
	# The following commands must be run to disable passcode based authentication for SSHD:
	/usr/bin/sudo /usr/bin/sed -i.bak 's/^[\#]*ChallengeResponseAuthentication.*/ChallengeResponseAuthentication no/' /etc/ssh/sshd_config
	/usr/bin/sudo /usr/bin/sed -i.bak 's/^[\#]*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config  
	/bin/echo $(/bin/date -u) "AOSX_14_003020 remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# DUPLICATE AOSX_14_003020
# AOSX_14_003024 The macOS system must use multifactor authentication in the establishment of nonlocal maintenance and diagnostic sessions. Ensure that passcode based logins are disabled in sshd.
# Verify organizational score
AOSX_14_003024="$(defaults read "$plistlocation" AOSX_14_003024)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_14_003024" = "1" ]; then
	# The following commands must be run to disable passcode based authentication for SSHD:
	/usr/bin/sudo /usr/bin/sed -i.bak 's/^[\#]*ChallengeResponseAuthentication.*/ChallengeResponseAuthentication no/' /etc/ssh/sshd_config
	/usr/bin/sudo /usr/bin/sed -i.bak 's/^[\#]*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config  
	/bin/echo $(/bin/date -u) "AOSX_14_003024 remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# DUPLICATE AOSX_14_003005
# AOSX_14_003025 Configuration Profile - The macOS system must implement multifactor authentication for remote access to privileged accounts.
# Configuration Profile - Smart Card payload > Enforce Smart Card use (checked)
#####################################################################################################

#####################################################################################################
# AOSX_14_003050 The macOS system must be configured so that the login command requires smart card authentication.
# Verify organizational score
AOSX_14_003050="$(defaults read "$plistlocation" AOSX_14_003050)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_14_003050" = "1" ]; then
/bin/cp /etc/pam.d/login /etc/pam.d/login_backup_$(date "+%Y-%m-%d_%H:%M")
/bin/cat > /etc/pam.d/login << LOGIN_END
# login: auth account password session
auth        sufficient    pam_smartcard.so
auth        optional      pam_krb5.so use_kcminit
auth        optional      pam_ntlm.so try_first_pass
auth        optional      pam_mount.so try_first_pass
auth        required      pam_opendirectory.so try_first_pass
auth        required      pam_deny.so
account     required      pam_nologin.so
account     required      pam_opendirectory.so
password    required      pam_opendirectory.so
session     required      pam_launchd.so
session     required      pam_uwtmp.so
session     optional      pam_mount.so
LOGIN_END
/bin/chmod 644 /etc/pam.d/login
/usr/sbin/chown root:wheel /etc/pam.d/login
/bin/echo $(/bin/date -u) "AOSX_14_003050 remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# AOSX_14_003051 The macOS system must be configured so that the su command requires smart card authentication.
# Verify organizational score
AOSX_14_003051="$(defaults read "$plistlocation" AOSX_14_003051)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_14_003051" = "1" ]; then
/bin/cp /etc/pam.d/su /etc/pam.d/su_backup_$(date "+%Y-%m-%d_%H:%M")
/bin/cat > /etc/pam.d/su << LOGIN_END
# su: auth account session
auth        sufficient    pam_smartcard.so
#auth       required      pam_opendirectory.so
auth        required      pam_deny.so
account     required      pam_permit.so
password    required      pam_deny.so
session     required      pam_permit.so  
LOGIN_END
/bin/chmod 644 /etc/pam.d/su
/usr/sbin/chown root:wheel /etc/pam.d/su
/bin/echo $(/bin/date -u) "AOSX_14_003051 remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# AOSX_14_003052 The macOS system must be configured so that the sudo command requires smart card authentication.
# Verify organizational score
AOSX_14_003052="$(defaults read "$plistlocation" AOSX_14_003052)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_14_003052" = "1" ]; then
/bin/cp /etc/pam.d/sudo /etc/pam.d/sudo_backup_$(date "+%Y-%m-%d_%H:%M")
/bin/cat > /etc/pam.d/sudo << LOGIN_END
# sudo: auth account password session
auth        sufficient    pam_smartcard.so
#auth       required      pam_opendirectory.so
auth        required      pam_deny.so
account     required      pam_permit.so
password    required      pam_deny.so
session     required      pam_permit.so  
LOGIN_END
/bin/chmod 644 /etc/pam.d/sudo
/usr/sbin/chown root:wheel /etc/pam.d/sudo
/bin/echo $(/bin/date -u) "AOSX_14_003052 remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# AOSX_14_004001 The macOS system must be configured with system log files owned by root and group-owned by wheel or admin.
# Verify organizational score
AOSX_14_004001="$(defaults read "$plistlocation" AOSX_14_004001)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_14_004001" = "1" ]; then
	cd /var/log
	grep_asl=$(/usr/bin/grep -e '^>' /etc/asl.conf /etc/asl/* | awk '{ print $2 }') 2> /dev/null
	grep_newsylog=$(/usr/bin/grep -v '^#' /etc/newsyslog.conf | awk '{ print $1 }') 2> /dev/null
	for i in $grep_asl $grep_newsylog; do
		if [ -e $i ]; then
		/usr/sbin/chown root:admin $i
		#/bin/ls -al $i
		fi
	done
	/bin/echo $(date -u) "AOSX_14_004001 remediated" | /usr/bin/tee -a "$logFile"
	/usr/bin/defaults write "$plistlocation" AOSX_13_002105 -bool false
fi
#####################################################################################################

#####################################################################################################
# AOSX_14_004002 The macOS system must be configured with system log files set to mode 640 or less permissive.
# Verify organizational score
AOSX_14_004002="$(defaults read "$plistlocation" AOSX_14_004002)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_14_004002" = "1" ]; then
	cd /var/log
	grep_asl=$(/usr/bin/grep -e '^>' /etc/asl.conf /etc/asl/* | awk '{ print $2 }') 2> /dev/null
	grep_newsylog=$(/usr/bin/grep -v '^#' /etc/newsyslog.conf | awk '{ print $1 }') 2> /dev/null
	for i in $grep_asl $grep_newsylog; do
		if [ -e $i ]; then
		/bin/chmod 640 $i
		#/bin/ls -al $i
		fi
	done
	/bin/echo $(date -u) "AOSX_14_004002 remediated" | /usr/bin/tee -a "$logFile"
	/usr/bin/defaults write "$plistlocation" AOSX_14_004002 -bool false
fi
#####################################################################################################

#####################################################################################################
# DUPLICATE AOSX_14_000010 and AOSX_14_004011
# AOSX_14_004010 Enable remote access through SSH.
# Verify organizational score
AOSX_14_004010="$(defaults read "$plistlocation" AOSX_14_004010)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_14_004010" = "1" ]; then
	/bin/launchctl enable system/com.openssh.sshd
	/usr/sbin/systemsetup -f -setremotelogin on
	/bin/echo $(/bin/date -u) "AOSX_14_004010 remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# DUPLICATE AOSX_14_000010 and AOSX_14_004011
# AOSX_14_004010off Disable remote access through SSH.
# Verify organizational score
AOSX_14_004010off="$(defaults read "$plistlocation" AOSX_14_004010off)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_14_004010off" = "1" ]; then
	/bin/launchctl disable system/com.openssh.sshd
	/usr/sbin/systemsetup -f -setremotelogin off
	/bin/echo $(/bin/date -u) "AOSX_14_004010off remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# DUPLICATE AOSX_14_000010 and AOSX_14_004010
# AOSX_14_004011 Enable remote access through SSH.
# Verify organizational score
AOSX_14_004011="$(defaults read "$plistlocation" AOSX_14_004011)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_14_004011" = "1" ]; then
	/bin/launchctl enable system/com.openssh.sshd
	/usr/sbin/systemsetup -f -setremotelogin on
	/bin/echo $(/bin/date -u) "AOSX_14_004011 remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# DUPLICATE AOSX_14_000010 and AOSX_14_004010
# AOSX_14_004011off Disable remote access through SSH.
# Verify organizational score
AOSX_14_004011off="$(defaults read "$plistlocation" AOSX_14_004011off)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_14_004011off" = "1" ]; then
	/bin/launchctl disable system/com.openssh.sshd
	/usr/sbin/systemsetup -f -setremotelogin off
	/bin/echo $(/bin/date -u) "AOSX_14_004011off remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# DUPLICATE check to AOSX_14_000008
# AOSX_14_004020 The macOS system must authenticate all endpoint devices before establishing a local, 
# remote, and/or network connection using bidirectional authentication that is cryptographically based.
# Verify organizational score
AOSX_14_004020="$(defaults read "$plistlocation" AOSX_14_004020)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_14_004020" = "1" ]; then
	/usr/sbin/networksetup -setnetworkserviceenabled "Wi-Fi" off
	/bin/echo $(/bin/date -u) "AOSX_14_004020 remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# AOSX_14_004021 The macOS system must be configured with the sudoers file configured to authenticate users on a per -tty basis.
# Verify organizational score
AOSX_14_004021="$(defaults read "$plistlocation" AOSX_14_004021)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_14_004021" = "1" ]; then
	/bin/echo "Defaults tty_tickets" >> /etc/sudoers
	/bin/echo $(date -u) "AOSX_14_004021 remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# AOSX_14_005001 The macOS system must enable System Integrity Protection. To reenable System Integrity Protection, 
# boot the affected system into Recovery mode, launch Terminal from the Utilities menu, and run the following command: 
# "/usr/bin/csrutil enable". Alternatively zap the PRAM (reboot then hold down command option p r)
#####################################################################################################

#####################################################################################################
# AOSX_14_005020 Enable FileVault – The macOS system must implement cryptographic mechanisms to protect the confidentiality and integrity of all information at rest.
#####################################################################################################

#####################################################################################################
# AOSX_14_005050 The macOS Application Firewall must be enabled.
# Verify organizational score
AOSX_14_005050="$(defaults read "$plistlocation" AOSX_14_005050)"
# If organizational score is 1 or true, check status of client
# If client fails, then remediate
if [ "$AOSX_14_005050" = "1" ]; then
	/usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on
	/bin/echo $(date -u) "AOSX_14_005050 remediated" | /usr/bin/tee -a "$logFile"
fi
#####################################################################################################

#####################################################################################################
# AOSX_14_005051 Managed by McAfee EPO Agent - The macOS system firewall must be configured with a default-deny policy.
# Install McAfee EPO Agent. The recommended system is the McAfee HBSS.
#####################################################################################################

/bin/echo $(date -u) "Remediation complete" | /usr/bin/tee -a "$logFile"
/bin/echo "Re-run 2_STIG_Audit_Compliance"
exit 0