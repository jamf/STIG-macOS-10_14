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
hardwareUUID="$(/usr/sbin/system_profiler SPHardwareDataType | /usr/bin/grep "Hardware UUID" | /usr/bin/awk -F ": " '{print $2}' | /usr/bin/xargs)"
logFile="$LogDir/STIGremediation.log"

if [[ $(/usr/bin/tail -n 1 "$logFile") = *"Remediation complete" ]]; then
	/bin/echo "Append to existing logFile"
 	/bin/echo "$(/bin/date -u)" "Beginning Audit" >> "$logFile"; else
 	/bin/echo "Create new logFile"
 	/bin/echo "$(/bin/date -u)" "Beginning Audit" > "$logFile"	
fi

if [[ ! -e $plistlocation ]]; then
	/bin/echo "No scoring file present"
	exit 0
fi

# Cleanup audit file to start fresh
[ -f "$auditfilelocation" ] && /bin/rm "$auditfilelocation"
/usr/bin/touch "$auditfilelocation"

#####################################################################################################
#
# Group ID (Vulid): V-95787
# Group Title: SRG-OS-000028-GPOS-00009
# Rule ID: SV-104925r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_000001
# Rule Title: The macOS system must be configured to prevent Apple Watch from terminating a session lock.
# 
# Vulnerability Discussion: Users must be prompted to enter their passwords when unlocking the screen saver. The screen saver acts as a session lock and
# prevents unauthorized users from accessing the current user's account.
# 
# Check Content: 
# To check if the system is configured to prevent Apple Watch from terminating a session lock, run the following command:
# 
# /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep "allowAutoUnlock = 0;"
# 
# If there is no result, this is a finding.
# 
# Fix Text: This setting is enforced using the “Restrictions Policy" configuration profile.  
# 
# CCI: CCI-000056
#
# Configuration Profile - Security & Privacy Payload > General > Allow user to unlock the Mac using an Apple Watch (unchecked)
# Verify organizational score
AOSX_14_000001="$(/usr/bin/defaults read "$plistlocation" AOSX_14_000001)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_000001" = "1" ]; then
	AOSX_14_000001_Audit="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'allowAutoUnlock = 0;')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_14_000001_Audit" > "0" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_000001 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_000001 -bool false; else
		/bin/echo "* AOSX_14_000001 Configuration Profile - The macOS system must be configured to prevent Apple Watch from terminating a session lock." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_000001 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-95789
# Group Title: SRG-OS-000028-GPOS-00009
# Rule ID: SV-104927r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_000002
# Rule Title: The macOS system must retain the session lock until the user reestablishes access using established identification and authentication procedures.
# 
# Vulnerability Discussion: Users must be prompted to enter their passwords when unlocking the screen saver. The screen saver acts as a session lock and
# prevents unauthorized users from accessing the current user's account.
# 
# Check Content: 
# To check if the system will prompt users to enter their passwords to unlock the screen saver, run the following command:
# 
# /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep askForPassword
# 
# If there is no result, or if "askForPassword" is not set to "1", this is a finding.
# 
# Fix Text: This setting is enforced using the "Login Window Policy" configuration profile.  
# 
# CCI: CCI-000056
#
# Configuration Profile - Security & Privacy Payload > General > Require password after sleep or screen saver begins (checked)
# Verify organizational score
AOSX_14_000002="$(/usr/bin/defaults read "$plistlocation" AOSX_14_000002)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_000002" = "1" ]; then
	AOSX_14_000002_Audit="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'askForPassword = 1')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_14_000002_Audit" > "0" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_000002 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_000002 -bool false; else
		/bin/echo "* AOSX_14_000002 Configuration Profile - Users must be prompted to enter their passwords when unlocking the screen saver." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_000002 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
#
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-95791
# Group Title: SRG-OS-000028-GPOS-00009
# Rule ID: SV-104929r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_000003
# Rule Title: The macOS system must initiate the session lock no more than five seconds after a screen saver is started.
# 
# Vulnerability Discussion: A screen saver must be enabled and set to require a password to unlock. An excessive grace period impacts the ability for a session
# to be truly locked, requiring authentication to unlock.
# 
# Check Content: 
# To check if the system will prompt users to enter their passwords to unlock the screen saver, run the following command:
# 
# /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep askForPasswordDelay
# 
# If there is no result, or if "askForPasswordDelay" is not set to "5.0" or less, this is a finding.
# 
# Fix Text: This setting is enforced using the "Login Window Policy" configuration profile.  
# 
# CCI: CCI-000056
# 
# Configuration Profile - Security & Privacy Payload > General > Require password * after sleep or screen saver begins (select * time no more than five seconds)
# Verify organizational score
AOSX_14_000003="$(/usr/bin/defaults read "$plistlocation" AOSX_14_000003)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_000003" = "1" ]; then
	AOSX_14_000003_Audit="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep askForPasswordDelay | /usr/bin/awk '{print $3-0}')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_14_000003_Audit" -le "5" ]] && [[ "$AOSX_14_000003_Audit" != "" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_000003 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_000003 -bool false; else
		/bin/echo "* AOSX_14_000003 Configuration Profile - The macOS system must initiate the session lock no more than five seconds after a screen saver is started." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_000003 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
#
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-95793
# Group Title: SRG-OS-000029-GPOS-00010
# Rule ID: SV-104931r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_000004
# Rule Title: The macOS system must initiate a session lock after a 15-minute period of inactivity.
# 
# Vulnerability Discussion: A screen saver must be enabled and set to require a password to unlock. The timeout should be set to 15 minutes of inactivity.
# This mitigates the risk that a user might forget to manually lock the screen before stepping away from the computer.
# 
# A session time-out lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but
# does not log out because of the temporary nature of the absence. Rather than relying on the user to manually lock their operating system session prior to
# vacating the vicinity, operating systems need to be able to identify when a user's session has idled and take action to initiate the session lock.
# 
# Check Content: 
# To check if the system has a configuration profile configured to enable the screen saver after a time-out period, run the following command:
# 
# /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep idleTime
# 
# If there is no result, or if "idleTime" is not set to "900" seconds or less, this is a finding.
# 
# Fix Text: This setting is enforced using the "Login Window Policy" configuration profile.  
# 
# CCI: CCI-000057
#
# Configuration Profile - Login Window payload > Options > Start screen saver after: (checked) > 15 Minutes of Inactivity (or less) 
# Verify organizational score
AOSX_14_000004="$(/usr/bin/defaults read "$plistlocation" AOSX_14_000004)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_000004" = "1" ]; then
	AOSX_14_000004_Audit="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep idleTime | /usr/bin/awk '{print $3-0}')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_14_000004_Audit" -le "900" ]] && [[ "$AOSX_14_000004_Audit" != "" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_000004 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_000004 -bool false; else
		/bin/echo "* AOSX_14_000004 Configuration Profile - A screen saver must be enabled and set to require a password to unlock. The timeout should be set to 15 minutes of inactivity." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_000004 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-95795
# Group Title: SRG-OS-000030-GPOS-00011
# Rule ID: SV-104933r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_000005
# Rule Title: The macOS system must be configured to lock the user session when a smart token is removed.
# 
# Vulnerability Discussion: A session lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the
# information system but does not want to log out because of the temporary nature of the absence.
# 
# The session lock is implemented at the point where session activity can be determined. Rather than be forced to wait for a period of time to expire before the
# user session can be locked, operating systems need to provide users with the ability to manually invoke a session lock so users may secure their session
# should they need to temporarily vacate the immediate physical vicinity.
# 
# Check Content: 
# To check if support for session locking with removal of a token is enabled, run the following command:
# 
# /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep "tokenRemovalAction = 1;"
# 
# If there is no result, this is a finding.
# 
# Fix Text: This setting is enforced using the "Smart Card Policy" configuration profile.
# 
# Note: Before applying the "Smart Card Policy", the supplemental guidance provided with the STIG should be consulted to ensure continued access to the
# operating system.  
# 
# CCI: CCI-000058
#
# Configuration Profile - Smart Card payload > Enable Screen Saver on Smart Card removal (checked)
# Verify organizational score
AOSX_14_000005="$(/usr/bin/defaults read "$plistlocation" AOSX_14_000005)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_000005" = "1" ]; then
	AOSX_14_000005_Audit="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'tokenRemovalAction = 1')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_14_000005_Audit" > "0" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_000005 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_000005 -bool false; else
		/bin/echo "* AOSX_14_000005 Configuration Profile - The macOS system must be configured to lock the user session when a smart token is removed." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_000005 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-95797
# Group Title: SRG-OS-000031-GPOS-00012
# Rule ID: SV-104935r1_rule
# Severity: CAT III
# Rule Version (STIG-ID): AOSX_14_000006
# Rule Title: The macOS system must conceal, via the session lock, information previously visible on the display with a publicly viewable image.
# 
# Vulnerability Discussion: A default screen saver must be configured for all users, as the screen saver will act as a session time-out lock for the system and
# must conceal the contents of the screen from unauthorized users. The screen saver must not display any sensitive information or reveal the contents of the
# locked session screen. Publicly viewable images can include static or dynamic images such as patterns used with screen savers, photographic images, solid
# colors, a clock, a battery life indicator, or a blank screen.
# 
# Check Content: 
# To view the currently selected screen saver for the logged-on user, run the following command:
# 
# /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep modulePath
# 
# If there is no result or defined "modulePath", this is a finding.
# 
# Fix Text: This setting is enforced using the "Login Window Policy" configuration profile.  
# 
# CCI: CCI-000060
#
# Configuration Profile - Login Window payload > Options > Start screen saver after: (checked) > USE SCREEN SAVER MODULE AT PATH: (path to screensaver)
# Verify organizational score
AOSX_14_000006="$(/usr/bin/defaults read "$plistlocation" AOSX_14_000006)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_000006" = "1" ]; then
	AOSX_14_000006_Audit="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -ci 'modulePath')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_14_000006_Audit" > "0" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_000006 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_000006 -bool false; else
		/bin/echo "* AOSX_14_000006 Configuration Profile - A default screen saver must be configured for all users." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_000006 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-95799
# Group Title: SRG-OS-000031-GPOS-00012
# Rule ID: SV-104937r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_000007
# Rule Title: The macOS system must be configured to disable hot corners.
# 
# Vulnerability Discussion: Although hot corners can be used to initiate a session lock or launch useful applications, they can also be configured to disable an
# automatic session lock from initiating. Such a configuration introduces the risk that a user might forget to manually lock the screen before stepping away
# from the computer.
# 
# A session time-out lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but
# does not log out because of the temporary nature of the absence. Rather than relying on the user to manually lock their operating system session prior to
# vacating the vicinity, operating systems need to be able to identify when a user's session has idled and take action to initiate the session lock.
# 
# Check Content: 
# To check if the system is configured to disable hot corners, run the following commands:
# 
# /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep wvous
# 
# If the return is null or does not equal the following, this is a finding:
# "wvous-bl-corner = 0
# wvous-br-corner = 0;
# wvous-tl-corner = 0;
# wvous-tr-corner = 0;"
# 
# Fix Text: This setting is enforced using the "Custom Policy" configuration profile.  
# 
# CCI: CCI-000060
#
# Configuration Profile - Custom payload > com.apple.dock > wvous-tl-corner=0, wvous-br-corner=0, wvous-bl-corner=0, wvous-tr-corner=0
# Verify organizational score
AOSX_14_000007="$(/usr/bin/defaults read "$plistlocation" AOSX_14_000007)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_000007" = "1" ]; then
	AOSX_14_000007_Audit1="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep wvous)"
	AOSX_14_000007_Audit2="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c '\"wvous-bl-corner\" = 0')"
	AOSX_14_000007_Audit3="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c '\"wvous-br-corner\" = 0')"
	AOSX_14_000007_Audit4="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c '\"wvous-tl-corner\" = 0')"
	AOSX_14_000007_Audit5="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c '\"wvous-tr-corner\" = 0')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_14_000007_Audit1" != "" ]] && [[ "$AOSX_14_000007_Audit2" > "0" ]] && [[ "$AOSX_14_000007_Audit3" > "0" ]] && [[ "$AOSX_14_000007_Audit4" > "0" ]] && [[ "$AOSX_14_000007_Audit5" > "0" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_000007 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_000007 -bool false; else
		/bin/echo "* AOSX_14_000007 Configuration Profile - The macOS system must be configured to disable hot corners." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_000007 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
#
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-95801
# Group Title: SRG-OS-000299-GPOS-00117
# Rule ID: SV-104939r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_000008
# Rule Title: The macOS system must be configured with Wi-Fi support software disabled.
# 
# Vulnerability Discussion: Allowing devices and users to connect to or from the system without first authenticating them allows untrusted access and can lead
# to a compromise or attack. Since wireless communications can be intercepted, it is necessary to use encryption to protect the confidentiality of information
# in transit.
# 
# Wireless technologies include, for example, microwave, packet radio (UHF/VHF), 802.11x, and Bluetooth. Wireless networks use authentication protocols (e.g.,
# EAP/TLS, PEAP), which provide credential protection and mutual authentication.
# 
# Satisfies: SRG-OS-000299-GPOS-00117, SRG-OS-000300-GPOS-00118
# 
# Check Content: 
# If the system requires Wi-Fi to connect to an authorized network, this is Not Applicable.
# 
# To check if the Wi-Fi network device is disabled, run the following command:
# 
# /usr/bin/sudo /usr/sbin/networksetup -listallnetworkservices
# 
# A disabled device will have an asterisk in front of its name.
# 
# If the Wi-Fi device is missing this asterisk, this is a finding.
# 
# Fix Text: To disable the Wi-Fi network device, run the following command:
# 
# /usr/bin/sudo /usr/sbin/networksetup -setnetworkserviceenabled "Wi-Fi" off  
# 
# CCI: CCI-001443
# CCI: CCI-001444
# 
# Verify organizational score
AOSX_14_000008="$(/usr/bin/defaults read "$plistlocation" AOSX_14_000008)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_000008" = "1" ]; then
	AOSX_14_000008_Audit="$(/usr/sbin/networksetup -listallnetworkservices | /usr/bin/grep 'Wi-Fi')"
	# If client fails, then note category in audit file
	if [[ $AOSX_14_000008_Audit = "*"* ]] || [[ $AOSX_14_000008_Audit = "" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_000008 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_000008 -bool false; else
		/bin/echo "* AOSX_14_000008 The macOS system must be configured with Wi-Fi support software disabled." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_000008 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
#
#####################################################################################################

#####################################################################################################
# 
# DUPLICATE check to AOSX_14_004010 and AOSX_14_004011
#
# Group ID (Vulid): V-95803
# Group Title: SRG-OS-000033-GPOS-00014
# Rule ID: SV-104941r1_rule
# Severity: CAT I
# Rule Version (STIG-ID): AOSX_14_000010
# Rule Title: The macOS system must implement DoD-approved encryption to protect the confidentiality and integrity of remote access sessions including
# transmitted data and data during preparation for transmission.
# 
# Vulnerability Discussion: Without confidentiality and integrity protection mechanisms, unauthorized individuals may gain access to sensitive information via a
# remote access session.
# 
# Remote access is access to DoD non-public information systems by an authorized user (or an information system) communicating through an external,
# non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.
# 
# Encryption provides a means to secure the remote connection to prevent unauthorized access to the data traversing the remote access connection (e.g., Remote
# Desktop Protocol [RDP]), thereby providing a degree of confidentiality. The encryption strength of a mechanism is selected based on the security
# categorization of the information.
# 
# Check Content: 
# For systems that allow remote access through SSH, run the following command:
# 
# /usr/bin/sudo /bin/launchctl print-disabled system | /usr/bin/grep com.openssh.sshd
# 
# If the results do not show the following, this is a finding.
# 
# "com.openssh.sshd" => false
# 
# Fix Text: To enable the SSH service, run the following command:
# 
# /usr/bin/sudo /bin/launchctl enable system/com.openssh.sshd
# 
# The system may need to be restarted for the update to take effect.  
# 
# CCI: CCI-000068
#
# Enable remote access through SSH
# Verify organizational score
AOSX_14_000010="$(/usr/bin/defaults read "$plistlocation" AOSX_14_000010)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_000010" = "1" ]; then
	AOSX_14_000010_Audit1="$(/bin/launchctl print-disabled system | /usr/bin/grep com.openssh.sshd)"
	AOSX_14_000010_Audit2="$(/usr/sbin/systemsetup -getremotelogin)"
	# If client fails, then note category in audit file
	if [[ $AOSX_14_000010_Audit1 = *"false"* ]] || [[ $AOSX_14_000010_Audit2 = *"On"* ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_000010 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_000010 -bool false; else
		/bin/echo "* AOSX_14_000010 Enable remote access through SSH." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_000010 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
#
# Disable remote access through SSH
# Verify organizational score
AOSX_14_000010off="$(/usr/bin/defaults read "$plistlocation" AOSX_14_000010off)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_000010off" = "1" ]; then
	AOSX_14_000010off_Audit1="$(/bin/launchctl print-disabled system | /usr/bin/grep com.openssh.sshd)"
	AOSX_14_000010off_Audit2="$(/usr/sbin/systemsetup -getremotelogin)"
	# If client fails, then note category in audit file
	if [[ $AOSX_14_000010off_Audit1 = *"true"* ]] || [[ $AOSX_14_000010off_Audit2 = *"Off"* ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_000010off passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_000010off -bool false; else
		/bin/echo "* AOSX_14_000010off Disable remote access through SSH." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_000010off fix" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
# DUPLICATE check to AOSX_14_000040
#
# Group ID (Vulid): V-95377
# Group Title: SRG-OS-000250-GPOS-00093
# Rule ID: SV-104709r2_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_000011
# Rule Title: The macOS system must implement DoD-approved encryption to protect the confidentiality and integrity of remote access sessions including
# transmitted data and data during preparation for transmission.
# 
# Vulnerability Discussion: Without confidentiality and integrity protection mechanisms, unauthorized individuals may gain access to sensitive information via a
# remote access session.
# 
# Remote access is access to DoD non-public information systems by an authorized user (or an information system) communicating through an external,
# non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.
# 
# Encryption provides a means to secure the remote connection to prevent unauthorized access to the data traversing the remote access connection (e.g., Remote
# Desktop Protocol [RDP]), thereby providing a degree of confidentiality. The encryption strength of a mechanism is selected based on the security
# categorization of the information.
# 
# SSHD should be enabled to facilitate secure remote access.
# 
# Check Content: 
# To verify that the installed version of SSH is correct, run the following command:
# 
# ssh -V
# 
# If the string that is returned does not include "OpenSSH_7.9p1" or greater, this is a finding.
# 
# To check if the "SSHD" service is enabled, use the following commands:
# 
# /usr/bin/sudo launchctl print-disabled system | grep sshd
# 
# If the results do not show "com.openssh.sshd => false", this is a finding.
# 
# To check that "SSHD" is currently running, use the following command:
# 
# /usr/bin/sudo launchctl print system/com.openssh.sshd
# 
# If the result is the following, "Could not find service "com.openssh.sshd" in domain for system", this is a finding.
# 
# Fix Text: To update SSHD to the minimum required version, run Software Update to update to the latest version of macOS.
# 
# To enable the SSHD service, run the following command:
# 
# /usr/bin/sudo /bin/launchctl enable system/com.openssh.sshd
# 
# The system may need to be restarted for the update to take effect.  
# 
# CCI: CCI-001453
#
# Check Content: Just check to see if the version is correct - report if not
#
# Verify organizational score
AOSX_14_000011="$(/usr/bin/defaults read "$plistlocation" AOSX_14_000011)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_000011" = "1" ]; then
	AOSX_14_000011_Audit="$(ssh -V 2>&1)"
	# If client fails, then note category in audit file
	if [[ "$AOSX_14_000011_Audit" = "OpenSSH_7.9p1"* ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_000011 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_000011 -bool false; else
		/bin/echo "* AOSX_14_000011 ssh -V must report OpenSSH_7.9p1 or greater. Current version is $AOSX_14_000011_Audit." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_000011 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-95805
# Group Title: SRG-OS-000002-GPOS-00002
# Rule ID: SV-104943r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_000012
# Rule Title: The macOS system must automatically remove or disable temporary user accounts after 72 hours.
# 
# Vulnerability Discussion: If temporary user accounts remain active when no longer needed or for an excessive period, these accounts may be targeted by
# attackers to gain unauthorized access. To mitigate this risk, automated termination of all temporary accounts must be set upon account creation.
# 
# Temporary accounts are established as part of normal account activation procedures when there is a need for short-term accounts without the demand for
# immediacy in account activation.
# 
# If temporary accounts are used, the operating system must be configured to automatically terminate these types of accounts after a DoD-defined time period of
# 72 hours.
# 
# To address access requirements, many operating systems may be integrated with enterprise-level authentication/access mechanisms that meet or exceed access
# control policy requirements.
# 
# Check Content: 
# Verify if a password policy is enforced by a directory service by asking the System Administrator (SA) or Information System Security Officer (ISSO).
# 
# If no policy is enforced by a directory service, a password policy can be set with the "pwpolicy" utility. The variable names may vary depending on how the
# policy was set.
# 
# If there are no temporary accounts defined on the system, this is Not Applicable.
# 
# To check if the password policy is configured to disable a temporary account after 72 hours, run the following command to output the password policy to the
# screen, substituting the correct user name in place of username:
# 
# /usr/bin/sudo /usr/bin/pwpolicy -u username getaccountpolicies | tail -n +2
# 
# If there is no output, and password policy is not controlled by a directory service, this is a finding.
# 
# Otherwise, look for the line "<key>policyCategoryAuthentication</key>".
# 
# In the array that follows, there should be a <dict> section that contains a check <string> that allows users to log in if "policyAttributeCurrentTime" is less
# than the result of adding "policyAttributeCreationTime" to 72 hours (259299 seconds). The check might use a variable defined in its "policyParameters" section.
# 
# If the check does not exist or if the check adds too great an amount of time to "policyAttributeCreationTime", this is a finding.
# 
# Fix Text: This setting may be enforced using local policy or by a directory service.
# 
# To set local policy to disable a temporary user, create a plain text file containing the following:
# 
# <dict>
# <key>policyCategoryAuthentication</key>
# <array>
# <dict>
# <key>policyContent</key>
# <string>policyAttributeCurrentTime &lt; policyAttributeCreationTime+259299</string>
# <key>policyIdentifier</key>
# <string>Disable Tmp Accounts </string>
# </dict>
# </array>
# </dict>
# 
# After saving the file and exiting to the command prompt, run the following command to load the new policy file, substituting the correct user name in place of
# "username" and the path to the file in place of "/path/to/file".
# 
# /usr/bin/sudo /usr/bin/pwpolicy -u username setaccountpolicies /path/to/file  
# 
# CCI: CCI-000016
#
# Managed by a directory server (AD)
# Verify organizational score
AOSX_14_000012="$(/usr/bin/defaults read "$plistlocation" AOSX_14_000012)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_000012" = "1" ]; then
	AOSX_14_000012_Audit="$(/usr/bin/sudo /usr/bin/dscl localhost -list . | /usr/bin/grep -vE '(Contact | Search | Local)')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_14_000012_Audit" = *"Active Directory"* ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_000012 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_000012 -bool false; else
		/bin/echo "* AOSX_14_000012 Active Directory – The macOS system must automatically remove or disable temporary user accounts after 72 hours. Managed by a directory server (AD). Ensure the system is integrated into a directory services infrastructure." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_000012 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-95807
# Group Title: SRG-OS-000123-GPOS-00064
# Rule ID: SV-104945r2_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_000013
# Rule Title: The macOS system must automatically remove or disable emergency accounts after the crisis is resolved or within 72 hours.
# 
# Vulnerability Discussion: Emergency administrator accounts are privileged accounts established in response to crisis situations where the need for rapid
# account activation is required. Therefore, emergency account activation may bypass normal account authorization processes. If these accounts are automatically
# disabled, system maintenance during emergencies may not be possible, thus adversely affecting system availability.
# 
# Emergency administrator accounts are different from infrequently used accounts (i.e., local logon accounts used by system administrators when network or
# normal logon/access is not available). Infrequently used accounts also remain available and are not subject to automatic termination dates. However, an
# emergency administrator account is normally a different account created for use by vendors or system maintainers.
# 
# To address access requirements, many operating systems can be integrated with enterprise-level authentication/access mechanisms that meet or exceed access
# control policy requirements.
# 
# Check Content: 
# If an emergency account has been created on the system, check the expiration settings of a local account using the following command, replacing "username"
# with the correct value:
# 
# /usr/bin/sudo /usr/bin/pwpolicy -u username getaccountpolicies | tail -n +2
# 
# If there is output, verify that the account policies do not restrict the ability to log in after a certain date or amount of time.
# 
# If they do, this is a finding.
# 
# Fix Text: To remove all "pwpolicy" settings for an emergency account, run the following command, replacing "username" with the correct value:
# 
# /usr/bin/sudo /usr/bin/pwpolicy -u username clearaccountpolicies
# 
# Otherwise, to change the passcode policy for an emergency account and only remove some policy sections, run the following command to save a copy of the
# current policy file for the specified username:
# 
# /usr/bin/sudo /usr/bin/pwpolicy -u username getaccountpolicies | tail -n +2 > pwpolicy.plist
# 
# Open the resulting passcode policy file in a text editor and remove any policyContent sections that would restrict the ability to log in after a certain date
# or amount of time.
# 
# To remove the section cleanly, remove the entire text that begins with <dict>, contains <key>policyContent<'/key>, and ends with </dict>.
# 
# After saving the file and exiting to the command prompt, run the following command to load the new policy file:
# 
# /usr/bin/sudo /usr/bin/pwpolicy -u username setaccountpolicies pwpolicy.plist  
# 
# CCI: CCI-001682
# 
# Managed by a directory server (AD)
# Verify organizational score
AOSX_14_000013="$(/usr/bin/defaults read "$plistlocation" AOSX_14_000013)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_000013" = "1" ]; then
	AOSX_14_000013_Audit="$(/usr/bin/sudo /usr/bin/dscl localhost -list . | /usr/bin/grep -vE '(Contact | Search | Local)')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_14_000013_Audit" = *"Active Directory"* ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_000013 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_000013 -bool false; else
		/bin/echo "* AOSX_14_000013 Active Directory – The macOS system must automatically remove or disable emergency accounts after the crisis is resolved or within 72 hours. Managed by a directory server (AD). Ensure the system is integrated into a directory services infrastructure." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_000013 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
#
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-95809
# Group Title: SRG-OS-000355-GPOS-00143
# Rule ID: SV-104947r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_000014
# Rule Title: The macOS system must, for networked systems, compare internal information system clocks at least every 24 hours with a server that is
# synchronized to one of the redundant United States Naval Observatory (USNO) time servers or a time server designated for the appropriate DoD network
# (NIPRNet/SIPRNet) and/or the Global Positioning System (GPS).
# 
# Vulnerability Discussion: Inaccurate time stamps make it more difficult to correlate events and can lead to an inaccurate analysis. Determining the correct
# time a particular event occurred on a system is critical when conducting forensic analysis and investigating system events. Sources outside of the configured
# acceptable allowance (drift) may be inaccurate.
# 
# Synchronizing internal information system clocks provides uniformity of time stamps for information systems with multiple system clocks and systems connected
# over a network.
# 
# Organizations should consider endpoints that may not have regular access to the authoritative time server (e.g., mobile, teleworking, and tactical endpoints).
# 
# Satisfies: SRG-OS-000355-GPOS-00143, SRG-OS-000356-GPOS-00144
# 
# Check Content: 
# The TIMED (NTP replacement in Mojave) service must be enabled on all networked systems. To check if the service is running, use the following command:
# 
# sudo systemsetup -getusingnetworktime
# 
# If the following in not returned, this is a finding:
# Network Time: On
# 
# To verify that an authorized Time Server is configured, run the following command:
# systemsetup -getnetworktimeserver
# 
# Only approved time servers should be configured for use.
# 
# If no server is configured, or if an unapproved time server is in use, this is a finding.
# 
# Fix Text: To enable the TIMED service, run the following command:
# 
# /usr/bin/sudo systemsetup -setusingnetworktime on
# 
# To configure a time server, use the following command:
# /usr/bin/sudo systemsetup -setnetworktimeserver "server"  
# 
# CCI: CCI-001891
# CCI: CCI-002046
#
# Verify organizational score
AOSX_14_000014="$(/usr/bin/defaults read "$plistlocation" AOSX_14_000014)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_000014" = "1" ]; then
	AOSX_14_000014_Audit2="$(/usr/sbin/systemsetup -getusingnetworktime)"
	# If client fails, then note category in audit file
	if [[ $AOSX_14_000014_Audit2 = *"On"* ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_000014 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_000014 -bool false; else
		/bin/echo "* AOSX_14_000014 The macOS system must compare internal information system clocks at least every 24 with an NTP server. Set usingnetworktime to on." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_000014 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
#
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-95811
# Group Title: SRG-OS-000191-GPOS-00080
# Rule ID: SV-104949r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_000015
# Rule Title: The macOS system must utilize an HBSS solution and implement all DoD required modules.
# 
# Vulnerability Discussion: The macOS system must employ automated mechanisms to determine the state of system components. The DoD requires the installation and
# use of an approved HBSS solution to be implemented on the operating system. For additional information, reference all applicable HBSS OPORDs and FRAGOs on
# SIPRNet.
# 
# Check Content: 
# Verify that there is an approved HBSS solution installed on the system.
# 
# If there is not an approved HBSS solution installed, this is a finding.
# 
# Verify that all installed components of the HBSS Solution are at the DoD approved minimal version.
# 
# If the installed components are not at the DoD approved minimal versions, this is a finding.
# 
# Fix Text: Install an approved HBSS solution onto the system and ensure that all components are at least updated to their DoD approved minimal versions.  
# 
# CCI: CCI-001233
#
# Verify organizational score
AOSX_14_000015="$(/usr/bin/defaults read "$plistlocation" AOSX_14_000015)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_000015" = "1" ]; then
	# If client fails, then note category in audit file
	if [[ -f "/Library/McAfee/agent/bin/cmdagent" ]]; then # Check for the McAfee cmdagent
		/bin/echo $(/bin/date -u) "AOSX_14_000015 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_000015 -bool false; else
		/bin/echo "* AOSX_14_000015 Managed by McAfee EPO Agent - The macOS system must employ automated mechanisms to determine the state of system components." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_000015 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-95385
# Group Title: SRG-OS-000480-GPOS-00227
# Rule ID: SV-104711r1_rule
# Severity: CAT I
# Rule Version (STIG-ID): AOSX_14_000016
# Rule Title: The macOS system must be integrated into a directory services infrastructure.
# 
# Vulnerability Discussion: Distinct user account databases on each separate system cause problems with username and password policy enforcement. Most approved
# directory services infrastructure solutions allow centralized management of users and passwords.
# 
# Check Content: 
# If the system is using a mandatory Smart Card Policy, this is Not Applicable.
# 
# To determine if the system is integrated to a directory service, ask the System Administrator (SA) or Information System Security Officer (ISSO) or run the
# following command:
# 
# /usr/bin/sudo dscl localhost -list . | /usr/bin/grep -vE '(Contact | Search | Local)'
# 
# If nothing is returned, or if the system is not integrated into a directory service infrastructure, this is a finding.
# 
# Fix Text: Integrate the system into an existing directory services infrastructure.  
# 
# CCI: CCI-000366
#
# Verify organizational score
AOSX_14_000016="$(/usr/bin/defaults read "$plistlocation" AOSX_14_000016)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_000016" = "1" ]; then
	AOSX_14_000016_Audit="$(/usr/bin/sudo /usr/bin/dscl localhost -list . | /usr/bin/grep -vE '(Contact | Search | Local)')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_14_000016_Audit" = *"Active Directory"* ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_000016 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_000016 -bool false; else
		/bin/echo "* AOSX_14_000016 Active Directory – The macOS system must be integrated into a directory services infrastructure." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_000016 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-95813
# Group Title: SRG-OS-000021-GPOS-00005
# Rule ID: SV-104951r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_000020
# Rule Title: The macOS system must enforce the limit of three consecutive invalid logon attempts by a user.
# 
# Vulnerability Discussion: By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known
# as brute forcing, is reduced. Limits are imposed by locking the account.
# 
# Check Content: The password policy is set with a configuration profile. Run the following command to check if the system has the correct setting for the
# number of permitted failed logon attempts:
# 
# /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep maxFailedAttempts
# 
# If the return is null, or not, “maxFailedAttempts = 3”, this is a finding.
# 
# Fix Text: This setting is enforced using the “Passcode Policy" configuration profile.  
# 
# CCI: CCI-000044
#
# Configuration Profile - Passcode payload > MAXIMUM NUMBER OF FAILED ATTEMPTS 3
# Verify organizational score
AOSX_14_000020="$(/usr/bin/defaults read "$plistlocation" AOSX_14_000020)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_000020" = "1" ]; then
	AOSX_14_000020_Audit="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'maxFailedAttempts = 3')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_14_000020_Audit" > "0" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_000020 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_000020 -bool false; else
		/bin/echo "* AOSX_14_000020 Configuration Profile - The macOS system must enforce account lockout after the limit of three consecutive invalid logon attempts by a user." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_000020 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-95815
# Group Title: SRG-OS-000329-GPOS-00128
# Rule ID: SV-104953r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_000021
# Rule Title: The macOS system must enforce an account lockout time period of 15 minutes in which a user makes three consecutive invalid logon attempts.
# 
# Vulnerability Discussion: Setting a lockout time period of 15 minutes is an effective deterrent against brute forcing that also makes allowances for
# legitimate mistakes by users. When three invalid logon attempts are made, the account will be locked.
# 
# Check Content: Password policy can be set with a configuration profile or the "pwpolicy" utility. If password policy is set with a configuration profile, run
# the following command to check if the system has the correct setting for the logon reset timer:
# 
# /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep minutesUntilFailedLoginReset
# 
# If the return is null or not “minutesUntilFailedLoginReset = 15”, this is a finding.
# 
# If password policy is set with the "pwpolicy" utility, the variable names may vary depending on how the policy was set. To check if the password policy is
# configured to disable an account for 15 minutes after 3 unsuccessful logon attempts, run the following command to output the password policy to the screen:
# 
# /usr/bin/sudo /usr/bin/pwpolicy getaccountpolicies
# 
# Look for the line "<key>policyCategoryAuthentication</key>".
# 
# If this does not exist, and password policy is not controlled by a directory service, this is a finding.
# 
# In the array that follows, there should be one or more <dict> sections that describe policy checks. One should contain a <string> that allows users to log on if
# "policyAttributeFailedAuthentications" is less than "policyAttributeMaximumFailedAuthentications". Under policyParameters,
# "policyAttributeMaximumFailedAuthentications" should be set to "3".
# 
# If "policyAttributeMaximumFailedAuthentications" is not set to "3", this is a finding.
# 
# In the same check or in another <dict> section, there should be a <string> that allows users to log on if the "policyAttributeCurrentTime" is greater than the
# result of adding "15" minutes (900 seconds) to "policyAttributeLastFailedAuthenticationTime". The check might use a variable defined in its "policyParameters"
# section.
# 
# If the check does not exist or if the check adds too great an amount of time, this is a finding.
# 
# Fix Text: This setting may be enforced using the "Passcode Policy" configuration profile or by a directory service.
# 
# The following two lines within the configuration enforce lockout expiration to "15" minutes:
# 
# <key>autoEnableInSeconds</key>
# <integer>900</integer>
# 
# To set the passcode policy without a configuration profile, run the following command to save a copy of the current "pwpolicy" account policy file:
# 
# /usr/bin/sudo /usr/bin/pwpolicy getaccountpolicies | tail -n +2 > pwpolicy.plist
# 
# Open the generated file in a text editor and ensure it contains the following text after the opening <dict> tag and before the closing </dict> tag.
# 
# Replace <dict/> first with <dict></dict> if necessary.
# 
# <key>policyCategoryAuthentication</key>
# <array>
# <dict>
# <key>policyContent</key>
# <string>(policyAttributeFailedAuthentications < policyAttributeMaximumFailedAuthentications) OR (policyAttributeCurrentTime > (policyAttributeLastFailedAuthenticationTime + autoEnableInSeconds))</string>
# <key>policyIdentifier</key>
# <string>Authentication Lockout</string>
# <key>policyParameters</key>
# <dict>
# <key>autoEnableInSeconds</key>
# <integer>900</integer>
# <key>policyAttributeMaximumFailedAuthentications</key>
# <integer>3</integer>
# </dict>
# </dict>
# </array>
# 
# If the line "<key>policyCategoryAuthentication</key>" already exists, the following text should be used instead and inserted after the first <array> tag that
# follows it:
# 
# <dict>
# <key>policyContent</key>
# <string>(policyAttributeFailedAuthentications < policyAttributeMaximumFailedAuthentications) OR (policyAttributeCurrentTime > (policyAttributeLastFailedAuthenticationTime + autoEnableInSeconds))</string>
# <key>policyIdentifier</key>
# <string>Authentication Lockout</string>
# <key>policyParameters</key>
# <dict>
# <key>autoEnableInSeconds</key>
# <integer>900</integer>
# <key>policyAttributeMaximumFailedAuthentications</key>
# <integer>3</integer>
# </dict>
# </dict>
# 
# After saving the file and exiting to the command prompt, run the following command to load the new policy file:
# 
# /usr/bin/sudo /usr/bin/pwpolicy setaccountpolicies pwpolicy.plist
# 
# Note: Updates to passcode restrictions must be thoroughly evaluated in a test environment. Mistakes in configuration may block password change and local user
# creation operations, as well as lock out all local users, including administrators.  
# 
# CCI: CCI-002238
#
# Configuration Profile - Passcode payload > DELAY AFTER FAILED LOGIN ATTEMPTS 15 (NOT COMPATIBLE WITH MACOS V10.11 OR LATER)
# Verify organizational score
AOSX_14_000021="$(/usr/bin/defaults read "$plistlocation" AOSX_14_000021)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_000021" = "1" ]; then
	AOSX_14_000021_Audit="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'minutesUntilFailedLoginReset = 15')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_14_000021_Audit" > "0" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_000021 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_000021 -bool false; else
		/bin/echo "* AOSX_14_000021 Configuration Profile - The macOS system must enforce an account lockout time period of 15 minutes in which a user makes three consecutive invalid logon attempts." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_000021 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
# NULL - REDUNDANT to AOSX_14_000020 and AOSX_14_000021
# 
# Group ID (Vulid): V-95393
# Group Title: SRG-OS-000329-GPOS-00128
# Rule ID: SV-104713r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_000022
# Rule Title: The macOS system must enforce the limit of three consecutive invalid logon attempts by a user before the user account is locked.
# 
# Vulnerability Discussion: By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known
# as brute forcing, is reduced. Limits are imposed by locking the account.
# 
# Check Content: 
# Password policy can be set with a configuration profile or the "pwpolicy" utility. If password policy is set with a configuration profile, run the following
# command to check if the system has the correct setting for the number of permitted failed logon attempts and the logon reset timer:
# 
# /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep 'maxFailedAttempts\|minutesUntilFailedLoginReset'
# 
# If "maxFailedAttempts" is not set to "3" and "minutesUntilFailedLoginReset" is not set to "15", this is a finding.
# 
# If password policy is set with the "pwpolicy" utility, the variable names may vary depending on how the policy was set. To check if the password policy is
# configured to disable an account for 15 minutes after 3 unsuccessful logon attempts, run the following command to output the password policy to the screen:
# 
# /usr/bin/sudo /usr/bin/pwpolicy getaccountpolicies
# 
# Look for the line "<key>policyCategoryAuthentication</key>".
# 
# If this does not exist, and password policy is not controlled by a directory service, this is a finding.
# 
# In the array that follows, there should be one or more <dict> sections that describe policy checks. One should contain a <string> that allows users to log on
# if "policyAttributeFailedAuthentications" is less than "policyAttributeMaximumFailedAuthentications". Under policyParameters,
# "policyAttributeMaximumFailedAuthentications" should be set to "3".
# 
# If "policyAttributeMaximumFailedAuthentications" is not set to "3", this is a finding.
# 
# In the same check or in another <dict> section, there should be a <string> that allows users to log on if the "policyAttributeCurrentTime" is greater than the
# result of adding "15" minutes (900 seconds) to "policyAttributeLastFailedAuthenticationTime". The check might use a variable defined in its "policyParameters"
# section.
# 
# If the check does not exist or if the check adds too great an amount of time, this is a finding.
# 
# Fix Text: This setting may be enforced using the "Passcode Policy" configuration profile or by a directory service.
# 
# To set the passcode policy without a configuration profile, run the following command to save a copy of the current "pwpolicy" account policy file:
# 
# /usr/bin/sudo /usr/bin/pwpolicy getaccountpolicies | tail -n +2 > pwpolicy.plist
# 
# Open the generated file in a text editor and ensure it contains the following text after the opening <dict> tag and before the closing </dict> tag.
# 
# Replace <dict/> first with <dict></dict> if necessary.
# 
# <key>policyCategoryAuthentication</key>
# <array>
# <dict>
# <key>policyContent</key>
# <string>(policyAttributeFailedAuthentications < policyAttributeMaximumFailedAuthentications) OR (policyAttributeCurrentTime > (policyAttributeLastFailedAuthenticationTime + autoEnableInSeconds))</string>
# <key>policyIdentifier</key>
# <string>Authentication Lockout</string>
# <key>policyParameters</key>
# <dict>
# <key>autoEnableInSeconds</key>
# <integer>900</integer>
# <key>policyAttributeMaximumFailedAuthentications</key>
# <integer>3</integer>
# </dict>
# </dict>
# </array>
# 
# If the line "<key>policyCategoryAuthentication</key>" already exists, the following text should be used instead and inserted after the first <array> tag that
# follows it:
# 
# <dict>
# <key>policyContent</key>
# <string>(policyAttributeFailedAuthentications < policyAttributeMaximumFailedAuthentications) OR (policyAttributeCurrentTime > (policyAttributeLastFailedAuthenticationTime + autoEnableInSeconds))</string>
# <key>policyIdentifier</key>
# <string>Authentication Lockout</string>
# <key>policyParameters</key>
# <dict>
# <key>autoEnableInSeconds</key>
# <integer>900</integer>
# <key>policyAttributeMaximumFailedAuthentications</key>
# <integer>3</integer>
# </dict>
# </dict>
# 
# After saving the file and exiting to the command prompt, run the following command to load the new policy file:
# 
# /usr/bin/sudo /usr/bin/pwpolicy setaccountpolicies pwpolicy.plist
# 
# Note: Updates to passcode restrictions must be thoroughly evaluated in a test environment. Mistakes in configuration or bugs in OS X may block password change
# and local user creation operations, as well as lock out all local users, including administrators.  
# 
# CCI: CCI-002238
#
# Configuration Profile - Passcode payload > MAXIMUM NUMBER OF FAILED ATTEMPTS 3
# Configuration Profile - Passcode payload > DELAY AFTER FAILED LOGIN ATTEMPTS 15 (NOT COMPATIBLE WITH MACOS V10.11 OR LATER)
# Verify organizational score
AOSX_14_000022="$(/usr/bin/defaults read "$plistlocation" AOSX_14_000022)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_000022" = "1" ]; then
	AOSX_14_000022_Audit1="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'maxFailedAttempts = 3')"
	AOSX_14_000022_Audit2="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'minutesUntilFailedLoginReset = 15')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_14_000022_Audit1" > "0" ]] && [[ "$AOSX_14_000022_Audit2" > "0" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_000022 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_000022 -bool false; else
		/bin/echo "* AOSX_14_000022 Configuration Profile - The macOS system must enforce the limit of three consecutive invalid logon attempts by a user before the user account is locked." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_000022 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
# 
# Group ID (Vulid): V-95817
# Group Title: SRG-OS-000023-GPOS-00006
# Rule ID: SV-104955r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_000023
# Rule Title: The macOS system must display the Standard Mandatory DoD Notice and Consent Banner before granting remote access to the operating system.
# 
# Vulnerability Discussion: Display of a standardized and approved use notification before granting access to the operating system ensures privacy and security
# notification verbiage used is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.
# 
# System use notifications are required only for access via logon interfaces with human users and are not required when such human interfaces do not exist.
# 
# The banner must be formatted in accordance with DTM-08-060.
# 
# Check Content: 
# Verify the operating system displays the Standard Mandatory DoD Notice and Consent Banner before granting access to the operating system.
# 
# Check to see if the operating system has the correct text listed in the "/etc/banner" file with the following command:
# 
# # more /etc/banner
# 
# The command should return the following text:
# "You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.
# 
# By using this IS (which includes any device attached to this IS), you consent to the following conditions:
# 
# -The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring,
# network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.
# 
# -At any time, the USG may inspect and seize data stored on this IS.
# 
# -Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used
# for any USG-authorized purpose.
# 
# -This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.
# 
# -Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged
# communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such
# communications and work product are private and confidential. See User Agreement for details."
# 
# If the operating system does not display a graphical logon banner or the banner does not match the Standard Mandatory DoD Notice and Consent Banner, this is a
# finding.
# 
# If the text in the "/etc/banner" file does not match the Standard Mandatory DoD Notice and Consent Banner, this is a finding.
# 
# Fix Text: Create a text file containing the required DoD text.
# 
# Name the file "banner" and place it in "/etc/".  
# 
# CCI: CCI-000048
# CCI: CCI-000048
#
# Verify organizational score
AOSX_14_000023="$(/usr/bin/defaults read "$plistlocation" AOSX_14_000023)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_000023" = "1" ]; then
	# If client fails, then note category in audit file
	if [ -f "/etc/banner" ]; then
		/bin/echo $(/bin/date -u) "AOSX_14_000023 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_000023 -bool false; else
		/bin/echo "* AOSX_14_000023 The macOS system must display the Standard Mandatory DoD Notice and Consent Banner before granting remote access to the operating system." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_000023 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
#
#####################################################################################################

#####################################################################################################
# 
# Group ID (Vulid): V-95819
# Group Title: SRG-OS-000023-GPOS-00006
# Rule ID: SV-104957r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_000024
# Rule Title: The macOS system must display the Standard Mandatory DoD Notice and Consent Banner before granting access to the system via SSH.
# 
# Vulnerability Discussion: Display of a standardized and approved use notification before granting access to the operating system ensures privacy and security
# notification verbiage used is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.
# 
# System use notifications are required only for access via logon interfaces with human users and are not required when such human interfaces do not exist.
# 
# The banner must be formatted in accordance with DTM-08-060.
# 
# Satisfies: SRG-OS-000023-GPOS-00006, SRG-OS-000024-GPOS-00007
# 
# Check Content: 
# For systems that allow remote access through SSH, run the following command to verify that "/etc/banner" is displayed before granting access:
# 
# # /usr/bin/grep Banner /etc/ssh/sshd_config
# 
# If the sshd Banner configuration option does not point to "/etc/banner", this is a finding.
# 
# Fix Text: For systems that allow remote access through SSH, modify the "/etc/ssh/sshd_config" file to add or update the following line:
# 
# Banner /etc/banner  
# 
# CCI: CCI-000048
# CCI: CCI-000050
#
# Verify organizational score
AOSX_14_000024="$(/usr/bin/defaults read "$plistlocation" AOSX_14_000024)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_000024" = "1" ]; then
	AOSX_14_000024_Audit="$(/usr/bin/grep ^"Banner /etc/banner" /etc/ssh/sshd_config)"
	# If client fails, then note category in audit file
	if [[ $AOSX_14_000024_Audit = "Banner /etc/banner" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_000024 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_000024 -bool false; else
		/bin/echo "* AOSX_14_000024 The macOS system must display the Standard Mandatory DoD Notice and Consent Banner before granting access to the system via SSH." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_000024 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
#
#####################################################################################################

#####################################################################################################
# 
# Group ID (Vulid): V-95821
# Group Title: SRG-OS-000023-GPOS-00006
# Rule ID: SV-104959r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_000025
# Rule Title: The macOS system must be configured so that any connection to the system must display the Standard Mandatory DoD Notice and Consent Banner before
# granting GUI access to the system.
# 
# Vulnerability Discussion: Display of a standardized and approved use notification before granting access to the operating system ensures privacy and security
# notification verbiage used is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.
# 
# System use notifications are required only for access via logon interfaces with human users and are not required when such human interfaces do not exist.
# 
# The banner must be formatted in accordance with DTM-08-060.
# 
# Satisfies: SRG-OS-000023-GPOS-00006, SRG-OS-000024-GPOS-00007, SRG-OS-000228-GPOS-00088
# 
# Check Content: 
# The policy banner will show if a "PolicyBanner.rtf" or "PolicyBanner.rtfd" exists in the "/Library/Security" folder. Run this command to show the contents of
# that folder:
# 
# /bin/ls -l /Library/Security/PolicyBanner.rtf*
# 
# If neither "PolicyBanner.rtf" nor "PolicyBanner.rtfd" exists, this is a finding.
# 
# The banner text of the document MUST read:
# 
# "You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By using this IS (which includes any device
# attached to this IS), you consent to the following conditions:
# -The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring,
# network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.
# -At any time, the USG may inspect and seize data stored on this IS.
# -Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used
# for any USG authorized purpose.
# -This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.
# -Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged
# communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such
# communications and work product are private and confidential. See User Agreement for details."
# 
# If the text is not worded exactly this way, this is a finding.
# 
# Fix Text: Create an RTF file containing the required text. Name the file "PolicyBanner.rtf" or "PolicyBanner.rtfd" and place it in "/Library/Security/".  
# 
# CCI: CCI-000048
# CCI: CCI-000050
# CCI: CCI-001384
# CCI: CCI-001385
# CCI: CCI-001386
# CCI: CCI-001387
# CCI: CCI-001388
#
# Verify organizational score
AOSX_14_000025="$(/usr/bin/defaults read "$plistlocation" AOSX_14_000025)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_000025" = "1" ]; then
	# If client fails, then note category in audit file
	if [ -f "/Library/Security/PolicyBanner."* ]; then
		/bin/echo $(/bin/date -u) "AOSX_14_000025 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_000025 -bool false; else
		/bin/echo "* AOSX_14_000025 The macOS system must be configured so that any connection to the system must display the Standard Mandatory DoD Notice and Consent Banner before granting GUI access to the system." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_000025 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
#
#####################################################################################################

#####################################################################################################
# 
# Group ID (Vulid): V-95823
# Group Title: SRG-OS-000057-GPOS-00027
# Rule ID: SV-104961r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_000030
# Rule Title: The macOS system must be configured so that log files must not contain access control lists (ACLs).
# 
# Vulnerability Discussion: The audit service must be configured to create log files with the correct permissions to prevent normal users from reading audit
# logs. Audit logs contain sensitive data about the system and users. If log files are set to be readable and writable only by root or administrative users with
# sudo, the risk is mitigated.
# 
# Satisfies: SRG-OS-000057-GPOS-00027, SRG-OS-000206-GPOS-00084
# 
# Check Content: 
# To check if a log file contains ACLs, run the following commands:
# 
# /usr/bin/sudo ls -le $(/usr/bin/sudo /usr/bin/grep '^dir' /etc/security/audit_control | awk -F: '{print $2}') | /usr/bin/grep -v current
# 
# In the output from the above commands, ACLs will be listed under any file that may contain them (e.g., "0: group:admin allow
# list,readattr,reaadextattr,readsecurity").
# 
# If any such line exists, this is a finding.
# 
# Fix Text: For any log file that contains ACLs, run the following command:
# 
# /usr/bin/sudo chmod -N [audit log file]  
# 
# CCI: CCI-000162
# CCI: CCI-001314
# 
# Verify organizational score
AOSX_14_000030="$(/usr/bin/defaults read "$plistlocation" AOSX_14_000030)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_000030" = "1" ]; then
	AOSX_14_000030_Audit="$(/bin/ls -le $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}') | /usr/bin/grep -v current | /usr/bin/grep -v total | /usr/bin/grep '+')"
	# If client fails, then note category in audit file
	if [[ $AOSX_14_000030_Audit = "" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_000030 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_000030 -bool false; else
		/bin/echo "* AOSX_14_000030 The macOS system must be configured so that log files must not contain access control lists (ACLs)." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_000030 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
# 
# Group ID (Vulid): V-95825
# Group Title: SRG-OS-000057-GPOS-00027
# Rule ID: SV-104963r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_000031
# Rule Title: The macOS system must be configured so that log folders must not contain access control lists (ACLs).
# 
# Vulnerability Discussion: The audit service must be configured to create log folders with the correct permissions to prevent normal users from reading audit
# logs. Audit logs contain sensitive data about the system and users. If log folders are set to be readable and writable only by root or administrative users
# with sudo, the risk is mitigated.
# 
# Check Content: 
# To check if a log folder contains ACLs, run the following commands:
# 
# /usr/bin/sudo ls -lde $(/usr/bin/sudo /usr/bin/grep '^dir' /etc/security/audit_control | awk -F: '{print $2}')
# 
# In the output from the above commands, ACLs will be listed under any folder that may contain them (e.g., "0: group:admin allow
# list,readattr,reaadextattr,readsecurity").
# 
# If any such line exists, this is a finding.
# 
# Fix Text: For any log folder that contains ACLs, run the following command:
# 
# /usr/bin/sudo chmod -N [audit log folder]  
#  
# CCI: CCI-000162
# 
# Verify organizational score
AOSX_14_000031="$(/usr/bin/defaults read "$plistlocation" AOSX_14_000031)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_000031" = "1" ]; then
	AOSX_14_000031_Audit="$(/bin/ls -lde $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}') | /usr/bin/grep '+')"
	# If client fails, then note category in audit file
	if [[ $AOSX_14_000031_Audit = "" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_000031 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_000031 -bool false; else
		/bin/echo "* AOSX_14_000031 The macOS system must be configured so that log folders must not contain access control lists (ACLs)." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_000031 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-95597
# Group Title: SRG-OS-000480-GPOS-00227
# Rule ID: SV-104735r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_000032
# Rule Title: The macOS system must be configured with a dedicated user account to decrypt the hard disk upon startup.
# 
# Vulnerability Discussion: When "FileVault" and Multifactor Authentication are configured on the operating system, a dedicated user must be configured to
# ensure that the implemented Multifactor Authentication rules are enforced. If a dedicated user is not configured to decrypt the hard disk upon startup, the
# system will allow a user to bypass Multifactor Authentication rules during initial startup and first login.
# 
# Check Content: 
# Ensure that only one FileVault user is defined:
# 
# sudo fdesetup list
# 
# fvuser,85F41F44-22B3-6CB7-85A1-BCC2EA2B887A
# 
# If more than one user is defined, this is a finding.
# 
# Verify that the defined FileVault user has been disabled:
# 
# sudo dscl . read /Users/<FileVault_User> AuthenticationAuthority | grep "DisabledUser"
# 
# AuthenticationAuthority: ;ShadowHash;HASHLIST:<SALTED-SHA512-PBKDF2,SRP-RFC5054-4096-SHA512-PBKDF2> 
# ;Kerberosv5;;unlock@LKDC:SHA1.20BABA05A6B1A86A8C57581A8487596640A3E37B;LKDC:SHA1.20CEBE04A5B1D92D8C58189D8487593350D3A40A; ;SecureToken; DisabledUser
# 
# If the FileVault user is not disabled, this is a finding.
# 
# Verify that password forwarding has been disabled on the system:
# 
# sudo defaults read /Library/Preferences/com.apple.loginwindow | grep "DisableFDEAutoLogin"
# 
# DisableFDEAutoLogin = 1;
# 
# If "DisableFDEAutoLogin" is not set to a value of "1", this is a finding.
# 
# Fix Text: Create a new user account that will be used to unlock the disk on startup.
# 
# Disable the login ability of the newly created user account:
# 
# sudo dscl . append /Users/<FileVault_User> AuthenticationAuthority DisabledUser
# 
# Disable FileVaults Auto-login feature:
# 
# sudo defaults write /Library/Preferences/com.apple.loginwindow DisableFDEAutoLogin -bool YES
# 
# Remove all FileVault login access from each user account defined on the system that is not the designated FileVault user:
# 
# sudo fdesetup remove -user <username>  
# 
# CCI: CCI-000014
#
# Configuration Profile - Custom payload > com.apple.loginwindow > DisableFDEAutoLogin=true
# Verify organizational score
AOSX_14_000032="$(/usr/bin/defaults read "$plistlocation" AOSX_14_000032)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_000032" = "1" ]; then
	AOSX_14_000032_Audit1="$(/usr/bin/fdesetup list | /usr/bin/wc -l | /usr/bin/xargs)"
	AOSX_14_000032_Audit2="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'DisableFDEAutoLogin = 1')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_14_000032_Audit1" = "1" ]] && [[ "$AOSX_14_000032_Audit2" > "0" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_000032 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_000032 -bool false; else
		/bin/echo "* AOSX_14_000032 Configuration Profile - Verify that password forwarding has been disabled on the system and Ensure that only one FileVault user is defined." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_000032 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
# DUPLICATE check to AOSX_14_000011
# 
# Group ID (Vulid): V-95405
# Group Title: SRG-OS-000393-GPOS-00173
# Rule ID: SV-104715r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_000040
# Rule Title: The macOS system must use replay-resistant authentication mechanisms and implement cryptographic mechanisms to protect the integrity of and verify
# remote disconnection at the termination of nonlocal maintenance and diagnostic communications, when used for nonlocal maintenance sessions.
# 
# Vulnerability Discussion: Privileged access contains control and configuration information and is particularly sensitive, so additional protections are
# necessary. This is maintained by using cryptographic mechanisms, such as a hash function or digital signature, to protect integrity.
# 
# Nonlocal maintenance and diagnostic activities are those activities conducted by individuals communicating through a network, either an external network
# (e.g., the Internet) or an internal network.
# 
# Use of weak or untested encryption algorithms undermines the purposes of using encryption to protect data. The operating system must implement cryptographic
# modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.
# 
# The operating system can meet this requirement through leveraging a cryptographic module. This requirement does not cover hardware/software components that
# may support information system maintenance, yet are a part of the system (e.g., the software implementing "ping," "ls," "ipconfig," or the hardware and
# software implementing the monitoring port of an Ethernet switch).
# 
# Satisfies: SRG-OS-000393-GPOS-00173, SRG-OS-000394-GPOS-00174, SRG-OS-000112-GPOS-00057, SRG-OS-000113-GPOS-00058
# 
# Check Content: 
# To verify that the installed version of SSH is correct, run the following command:
# 
# ssh -V
# 
# If the string that is returned does not include "OpenSSH_7.9p1" or greater, this is a finding.
# 
# To check if the "SSHD" service is enabled, use the following commands:
# 
# /usr/bin/sudo launchctl print-disabled system | grep sshd
# 
# If the results do not show "com.openssh.sshd => false", this is a finding.
# 
# To check that "SSHD" is currently running, use the following command:
# 
# /usr/bin/sudo launchctl print system/com.openssh.sshd
# 
# If the result is the following, "Could not find service "com.openssh.sshd" in domain for system", this is a finding.
# 
# Fix Text: To update SSHD to the minimum required version, run Software Update to update to the latest version of macOS.
# 
# To enable the SSHD service, run the following command:
# 
# /usr/bin/sudo /bin/launchctl enable system/com.openssh.sshd
# 
# The system may need to be restarted for the update to take effect.  
# 
# CCI: CCI-001941
# CCI: CCI-001942
# CCI: CCI-002890
# CCI: CCI-003123
#
# Check Content: Just check to see if the version is correct - report if not
#
# Verify organizational score
AOSX_14_000040="$(/usr/bin/defaults read "$plistlocation" AOSX_14_000040)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_000040" = "1" ]; then
	AOSX_14_000040_Audit="$(/usr/bin/ssh -V 2>&1)"
	# If client fails, then note category in audit file
	if [[ "$AOSX_14_000040_Audit" = "OpenSSH_7.9p1"* ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_000040 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_000040 -bool false; else
		/bin/echo "* AOSX_14_000040 ssh -V must report OpenSSH_7.9p1 or greater. Current version is $AOSX_14_000040_Audit." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_000040 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
# 
# Group ID (Vulid): V-95407
# Group Title: SRG-OS-000027-GPOS-00008
# Rule ID: SV-104717r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_000050
# Rule Title: The macOS system must limit the number of concurrent SSH sessions to 10 for all accounts and/or account types.
# 
# Vulnerability Discussion: Operating system management includes the ability to control the number of users and user sessions that utilize an operating system.
# Limiting the number of allowed users and sessions per user is helpful in reducing the risks related to DoS attacks.
# 
# This requirement addresses concurrent sessions for information system accounts and does not address concurrent sessions by single users via multiple system
# accounts. The maximum number of concurrent sessions should be defined based upon mission needs and the operational environment for each system.
# 
# Check Content: 
# To verify that SSHD is limited to 10 sessions, use the following command:
# 
# /bin/cat /etc/ssh/sshd_config | grep MaxSessions
# 
# The command must return "MaxSessions 10". If it returns null, or a commented value, or the value is greater than "10", this is a finding.
# 
# Fix Text: To configure SSHD to limit the number of sessions, use the following command:
# 
# /usr/bin/sudo /usr/bin/sed -i.bak 's/^[\#]*MaxSessions.*/MaxSessions 10/' /etc/ssh/sshd_config  
# 
# CCI: CCI-000054
#
# Verify organizational score
AOSX_14_000050="$(/usr/bin/defaults read "$plistlocation" AOSX_14_000050)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_000050" = "1" ]; then
	AOSX_14_000050_Audit="$(/bin/cat /etc/ssh/sshd_config | /usr/bin/grep MaxSessions)"
	# If client fails, then note category in audit file
	if [[ "$AOSX_14_000050_Audit" = "MaxSessions 10" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_000050 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_000050 -bool false; else
		/bin/echo "* AOSX_14_000050 The macOS system must limit the number of concurrent SSH sessions to 10 for all accounts and/or account types." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_000050 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
# 
# Group ID (Vulid): V-95827
# Group Title: SRG-OS-000163-GPOS-00072
# Rule ID: SV-104965r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_000051
# Rule Title: The macOS system must be configured with the SSH daemon ClientAliveInterval option set to 900 or less.
# 
# Vulnerability Discussion: SSH should be configured to log users out after a 15-minute interval of inactivity and to wait only 30 seconds before timing out
# logon attempts. Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a
# management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session or an incomplete
# logon attempt will also free up resources committed by the managed network element.
# 
# Check Content: 
# The SSH daemon "ClientAliveInterval" option must be set correctly. To check the idle timeout setting for SSH sessions, run the following:
# 
# /usr/bin/sudo /usr/bin/grep ^ClientAliveInterval /etc/ssh/sshd_config
# 
# If the setting is not "900" or less, this is a finding.
# 
# Fix Text: To ensure that "ClientAliveInterval" is set correctly, run the following command:
# 
# /usr/bin/sudo /usr/bin/sed -i.bak 's/.*ClientAliveInterval.*/ClientAliveInterval 900/' /etc/ssh/sshd_config  
# 
# CCI: CCI-001133
#
# Verify organizational score
AOSX_14_000051="$(/usr/bin/defaults read "$plistlocation" AOSX_14_000051)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_000051" = "1" ]; then
	AOSX_14_000051_Audit="$(/usr/bin/grep ^ClientAliveInterval /etc/ssh/sshd_config)"
	# If client fails, then note category in audit file
	if [[ "$AOSX_14_000051_Audit" = "ClientAliveInterval 900" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_000051 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_000051 -bool false; else
		/bin/echo "* AOSX_14_000051 The macOS system must be configured with the SSH daemon ClientAliveInterval option set to 900 or less." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_000051 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
# 
# Group ID (Vulid): V-95829
# Group Title: SRG-OS-000163-GPOS-00072
# Rule ID: SV-104967r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_000052
# Rule Title: The macOS system must be configured with the SSH daemon ClientAliveCountMax option set to 0.
# 
# Vulnerability Discussion: SSH should be configured with an Active Client Alive Maximum Count of 0. Terminating an idle session within a short time period
# reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left
# unattended. In addition, quickly terminating an idle session or an incomplete logon attempt will also free up resources committed by the managed network
# element.
# 
# Check Content: 
# The SSH daemon "ClientAliveCountMax" option must be set correctly. To verify the SSH idle timeout will occur when the "ClientAliveCountMax" is set, run the
# following command:
# 
# /usr/bin/sudo /usr/bin/grep ^ClientAliveCountMax /etc/ssh/sshd_config
# 
# If the setting is not "ClientAliveCountMax 0", this is a finding.
# 
# Fix Text: To ensure that the SSH idle timeout occurs precisely when the "ClientAliveCountMax" is set, run the following command:
# 
# /usr/bin/sudo /usr/bin/sed -i.bak 's/.*ClientAliveCountMax.*/ClientAliveCountMax 0/' /etc/ssh/sshd_config  
# 
# CCI: CCI-001133
#
# Verify organizational score
AOSX_14_000052="$(/usr/bin/defaults read "$plistlocation" AOSX_14_000052)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_000052" = "1" ]; then
	AOSX_14_000052_Audit="$(/usr/bin/grep ^ClientAliveCountMax /etc/ssh/sshd_config)"
	# If client fails, then note category in audit file
	if [[ "$AOSX_14_000052_Audit" = "ClientAliveCountMax 0" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_000052 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_000052 -bool false; else
		/bin/echo "* AOSX_14_000052 The macOS system must be configured with the SSH daemon ClientAliveCountMax option set to 0." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_000052 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
# 
# Group ID (Vulid): V-95831
# Group Title: SRG-OS-000163-GPOS-00072
# Rule ID: SV-104969r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_000053
# Rule Title: The macOS system must be configured with the SSH daemon LoginGraceTime set to 30 or less.
# 
# Vulnerability Discussion: SSH should be configured to log users out after a 15-minute interval of inactivity and to wait only 30 seconds before timing out
# logon attempts. Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a
# management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session or an incomplete
# logon attempt will also free up resources committed by the managed network element.
# 
# Check Content: 
# The SSH daemon "LoginGraceTime" must be set correctly. To check the amount of time that a user can log on through SSH, run the following command:
# 
# /usr/bin/sudo /usr/bin/grep ^LoginGraceTime /etc/ssh/sshd_config
# 
# If the value is not set to "30" or less, this is a finding.
# 
# Fix Text: To ensure that "LoginGraceTime" is configured correctly, run the following command:
# 
# /usr/bin/sudo /usr/bin/sed -i.bak 's/.*LoginGraceTime.*/LoginGraceTime 30/' /etc/ssh/sshd_config  
# 
# CCI: CCI-001133
#
# Verify organizational score
AOSX_14_000053="$(/usr/bin/defaults read "$plistlocation" AOSX_14_000053)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_000053" = "1" ]; then
	AOSX_14_000053_Audit="$(/usr/bin/grep ^LoginGraceTime /etc/ssh/sshd_config)"
	# If client fails, then note category in audit file
	if [[ "$AOSX_14_000053_Audit" = "LoginGraceTime 30" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_000053 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_000053 -bool false; else
		/bin/echo "* AOSX_14_000053 The macOS system must be configured with the SSH daemon LoginGraceTime set to 30 or less." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_000053 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
# 
# Group ID (Vulid): V-95833
# Group Title: SRG-OS-000004-GPOS-00004
# Rule ID: SV-104971r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_001001
# Rule Title: The macOS system must generate audit records for all account creations, modifications, disabling, and termination events; privileged activities or
# other system-level access; all kernel module load, unload, and restart actions; all program initiations; and organizationally defined events for all non-local
# maintenance and diagnostic sessions.
# 
# Vulnerability Discussion: Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to
# establish, correlate, and investigate the events relating to an incident or identify those responsible for one. Audit records can be generated from various
# components within the information system (e.g., module or policy filter). If events associated with nonlocal administrative access or diagnostic sessions are
# not logged, a major tool for assessing and investigating attacks would not be available.
# 
# This requirement addresses auditing-related issues associated with maintenance tools used specifically for diagnostic and repair actions on organizational
# information systems.
# 
# Nonlocal maintenance and diagnostic activities are those activities conducted by individuals communicating through a network, either an external network
# (e.g., the Internet) or an internal network. Local maintenance and diagnostic activities are those activities carried out by individuals physically present at
# the information system or information system component and not communicating across a network connection.
# 
# This requirement applies to hardware/software diagnostic test equipment or tools. This requirement does not cover hardware/software components that may
# support information system maintenance, yet are a part of the system, for example, the software implementing "ping," "ls," "ipconfig," or the hardware and
# software implementing the monitoring port of an Ethernet switch.
# 
# Satisfies: SRG-OS-000004-GPOS-00004, SRG-OS-000239-GPOS-00089, SRG-OS-000240-GPOS-00090, SRG-OS-000241-GPOS-00091, SRG-OS-000327-GPOS-00127,
# SRG-OS-000392-GPOS-00172, SRG-OS-000471-GPOS-00215, SRG-OS-000471-GPOS-00216, SRG-OS-000476-GPOS-00221, SRG-OS-000477-GPOS-00222
# 
# Check Content: 
# To view the currently configured flags for the audit daemon, run the following command:
# 
# /usr/bin/sudo /usr/bin/grep ^flags /etc/security/audit_control
# 
# Administrative and Privileged access, including administrative use of the command line tools "kextload" and "kextunload" and changes to configuration settings
# are logged by way of the "ad" flag.
# 
# If "ad" is not listed in the result of the check, this is a finding.
# 
# Fix Text: To ensure the appropriate flags are enabled for auditing, run the following command:
# 
# /usr/bin/sudo /usr/bin/sed -i.bak '/^flags/ s/$/,ad/' /etc/security/audit_control; /usr/bin/sudo /usr/sbin/audit -s
# 
# A text editor may also be used to implement the required updates to the "/etc/security/audit_control" file.  
# 
# CCI: CCI-000018
# CCI: CCI-000172
# CCI: CCI-001403
# CCI: CCI-001404
# CCI: CCI-001405
# CCI: CCI-002234
# CCI: CCI-002884
# 
# Verify organizational score
AOSX_14_001001="$(/usr/bin/defaults read "$plistlocation" AOSX_14_001001)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_001001" = "1" ]; then
	AOSX_14_001001_Audit="$(/usr/bin/grep ^flags /etc/security/audit_control)"
	# If client fails, then note category in audit file
	if [[ $AOSX_14_001001_Audit = *"ad"* ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_001001 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_001001 -bool false; else
		/bin/echo "* AOSX_14_001001 Ensure the appropriate flags are enabled for /etc/security/audit_control - ad." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_001001 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
#
#####################################################################################################

#####################################################################################################
# 
# Group ID (Vulid): V-95835
# Group Title: SRG-OS-000032-GPOS-00013
# Rule ID: SV-104973r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_001002
# Rule Title: The macOS system must monitor remote access methods and generate audit records when successful/unsuccessful attempts to access/modify privileges occur.
# 
# Vulnerability Discussion: Frequently, an attacker that successfully gains access to a system has only gained access to an account with limited privileges,
# such as a guest account or a service account. The attacker must attempt to change to another user account with normal or elevated privileges in order to
# proceed. Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish,
# correlate, and investigate the events relating to an incident or identify those responsible for one.
# 
# Audit records can be generated from various components within the information system (e.g., module or policy filter).
# 
# Satisfies: SRG-OS-000032-GPOS-00013, SRG-OS-000462-GPOS-00206
# 
# Check Content: 
# To view the currently configured flags for the audit daemon, run the following command:
# 
# /usr/bin/sudo /usr/bin/grep ^flags /etc/security/audit_control
# 
# Attempts to log in as another user are logged by way of the "lo" flag.
# 
# If "lo" is not listed in the result of the check, this is a finding.
# 
# Fix Text: To ensure the appropriate flags are enabled for auditing, run the following command:
# 
# /usr/bin/sudo sed -i.bak '/^flags/ s/$/,lo/' /etc/security/audit_control; /usr/bin/sudo /usr/sbin/audit -s
# 
# A text editor may also be used to implement the required updates to the "/etc/security/audit_control" file.  
# 
# CCI: CCI-000067
# CCI: CCI-000172
# 
# Verify organizational score
AOSX_14_001002="$(/usr/bin/defaults read "$plistlocation" AOSX_14_001002)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_001002" = "1" ]; then
	AOSX_14_001002_Audit="$(/usr/bin/grep ^flags /etc/security/audit_control)"
	# If client fails, then note category in audit file
	if [[ $AOSX_14_001002_Audit = *"lo"* ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_001002 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_001002 -bool false; else
		/bin/echo "* AOSX_14_001002 Ensure the appropriate flags are enabled for /etc/security/audit_control - lo." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_001002 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
#
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-95837
# Group Title: SRG-OS-000037-GPOS-00015
# Rule ID: SV-104975r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_001003
# Rule Title: The macOS system must initiate session audits at system startup, using internal clocks with time stamps for audit records that meet a minimum
# granularity of one second and can be mapped to Coordinated Universal Time (UTC) or Greenwich Mean Time (GMT), in order to generate audit records containing
# information to establish what type of events occurred, the identity of any individual or process associated with the event, including individual identities of
# group account users, establish where the events occurred, source of the event, and outcome of the events including all account enabling actions, full-text
# recording of privileged commands, and information about the use of encryption for access wireless access to and from the system.
# 
# Vulnerability Discussion: Without establishing what type of events occurred, when they occurred, and by whom it would be difficult to establish, correlate,
# and investigate the events leading up to an outage or attack.
# 
# Audit record content that may be necessary to satisfy this requirement includes, for example, time stamps, source and destination addresses, user/process
# identifiers, event descriptions, success/fail indications, filenames involved, and access control or flow control rules invoked.
# 
# Associating event types with detected events in the operating system audit logs provides a means of investigating an attack, recognizing resource utilization
# or capacity thresholds, or identifying an improperly configured operating system.
# 
# Satisfies: SRG-OS-000037-GPOS-00015, SRG-OS-000038-GPOS-00016, SRG-OS-000039-GPOS-00017, SRG-OS-000040-GPOS-00018, SRG-OS-000041-GPOS-00019,
# SRG-OS-000042-GPOS-00020, SRG-OS-000042-GPOS-00021, SRG-OS-000055-GPOS-00026, SRG-OS-000254-GPOS-00095, SRG-OS-000255-GPOS-00096, SRG-OS-000303-GPOS-00120,
# SRG-OS-000337-GPOS-00129, SRG-OS-000358-GPOS-00145, SRG-OS-000359-GPOS-00146
# 
# Check Content: 
# To check if the audit service is running, use the following command:
# 
# launchctl print-disabled system| grep auditd
# 
# If the return is not:
# "com.apple.auditd" => false"
# the audit service is disabled, and this is a finding.
# 
# Fix Text: To enable the audit service, run the following command:
# 
# /usr/bin/sudo /bin/launchctl enable system/com.apple.auditd
# 
# The system may need to be restarted for the update to take effect.  
# 
# CCI: CCI-000130
# CCI: CCI-000131
# CCI: CCI-000132
# CCI: CCI-000133
# CCI: CCI-000134
# CCI: CCI-000135
# CCI: CCI-000159
# CCI: CCI-001464
# CCI: CCI-001487
# CCI: CCI-001889
# CCI: CCI-001890
# CCI: CCI-001914
# CCI: CCI-002130
#
# Verify organizational score
AOSX_14_001003="$(/usr/bin/defaults read "$plistlocation" AOSX_14_001003)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_001003" = "1" ]; then
	AOSX_14_001003_Audit="$(/bin/launchctl print-disabled system | /usr/bin/grep com.apple.auditd)"
	# If client fails, then note category in audit file
	if [[ $AOSX_14_001003_Audit = *"false"* ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_001003 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_001003 -bool false; else
		/bin/echo "* AOSX_14_001003 The macOS system must initiate session audits at system startup." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_001003 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
#
#####################################################################################################

#####################################################################################################
# 
# Group ID (Vulid): V-95839
# Group Title: SRG-OS-000047-GPOS-00023
# Rule ID: SV-104977r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_001010
# Rule Title: The macOS system must shut down by default upon audit failure (unless availability is an overriding concern).
# 
# Vulnerability Discussion: The audit service should shut down the computer if it is unable to audit system events. Once audit failure occurs, user and system
# activity is no longer recorded and malicious activity could go undetected. Audit processing failures include software/hardware errors, failures in the audit
# capturing mechanisms, and audit storage capacity being reached or exceeded. Responses to audit failure depend on the nature of the failure mode.
# 
# When availability is an overriding concern, other approved actions in response to an audit failure are as follows:
# 
# (i) If the failure was caused by the lack of audit record storage capacity, the operating system must continue generating audit records if possible
# (automatically restarting the audit service if necessary), overwriting the oldest audit records in a first-in-first-out manner.
# 
# (ii) If audit records are sent to a centralized collection server and communication with this server is lost or the server fails, the operating system must
# queue audit records locally until communication is restored or until the audit records are retrieved manually. Upon restoration of the connection to the
# centralized collection server, action should be taken to synchronize the local audit data with the collection server.
# 
# Check Content: 
# To view the setting for the audit control system, run the following command:
# 
# sudo /usr/bin/grep ^policy /etc/security/audit_control | /usr/bin/grep ahlt
# 
# If there is no result, this is a finding.
# 
# Fix Text: Edit the "/etc/security/audit_control file" and change the value for policy to include the setting "ahlt". To do this programmatically, run the
# following command:
# 
# sudo /usr/bin/sed -i.bak '/^policy/ s/$/,ahlt/' /etc/security/audit_control; sudo /usr/sbin/audit -s  
# 
# CCI: CCI-000140
#
# Verify organizational score
AOSX_14_001010="$(/usr/bin/defaults read "$plistlocation" AOSX_14_001010)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_001010" = "1" ]; then
	AOSX_14_001010_Audit="$(/usr/bin/grep ^policy /etc/security/audit_control)"
	# If client fails, then note category in audit file
	if [[ "$AOSX_14_001010_Audit" = *"ahlt"* ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_001010 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_001010 -bool false; else
		/bin/echo "* AOSX_14_001010 The macOS system must shut down by default upon audit failure (unless availability is an overriding concern)." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_001010 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
# 
# Group ID (Vulid): V-95841
# Group Title: SRG-OS-000057-GPOS-00027
# Rule ID: SV-104979r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_001012
# Rule Title: The macOS system must be configured with audit log files owned by root.
# 
# Vulnerability Discussion: The audit service must be configured to create log files with the correct ownership to prevent normal users from reading audit logs.
# Audit logs contain sensitive data about the system and users. If log files are set to only be readable and writable by root or administrative users with sudo,
# the risk is mitigated.
# 
# Check Content: 
# To check the ownership of the audit log files, run the following command:
# 
# /usr/bin/sudo ls -le $(/usr/bin/sudo /usr/bin/grep '^dir' /etc/security/audit_control | awk -F: '{print $2}') | grep -v current
# 
# The results should show the owner (third column) to be "root".
# 
# If they do not, this is a finding.
# 
# Fix Text: For any log file that returns an incorrect owner, run the following command:
# 
# /usr/bin/sudo chown root [audit log file]
# 
# [audit log file] is the full path to the log file in question.  
# 
# CCI: CCI-000162
#
# Verify organizational score
AOSX_14_001012="$(/usr/bin/defaults read "$plistlocation" AOSX_14_001012)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_001012" = "1" ]; then
	AOSX_14_001012_Audit="$(/bin/ls -le $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}') | /usr/bin/grep -v current | /usr/bin/grep -v total | /usr/bin/grep -v root)"
	# If client fails, then note category in audit file
	if [[ $AOSX_14_001012_Audit = "" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_001012 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_001012 -bool false; else
		/bin/echo "* AOSX_14_001012 The macOS system must be configured with audit log files owned by root." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_001012 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
# 
# Group ID (Vulid): V-95843
# Group Title: SRG-OS-000057-GPOS-00027
# Rule ID: SV-104981r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_001013
# Rule Title: The macOS system must be configured with audit log folders owned by root.
# 
# Vulnerability Discussion: The audit service must be configured to create log files with the correct ownership to prevent normal users from reading audit logs.
# Audit logs contain sensitive data about the system and about users. If log files are set to be readable and writable only by root or administrative users with
# sudo, the risk is mitigated.
# 
# Check Content: 
# To check the ownership of the audit log folder, run the following command:
# 
# /usr/bin/sudo ls -lde $(/usr/bin/sudo /usr/bin/grep '^dir' /etc/security/audit_control | awk -F: '{print $2}')
# 
# The results should show the owner (third column) to be "root".
# 
# If it does not, this is a finding.
# 
# Fix Text: For any log folder that has an incorrect owner, run the following command:
# 
# /usr/bin/sudo chown root [audit log folder]
# 
# CCI: CCI-000162
# 
# Verify organizational score
AOSX_14_001013="$(/usr/bin/defaults read "$plistlocation" AOSX_14_001013)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_001013" = "1" ]; then
	AOSX_14_001013_Audit="$(/bin/ls -lde $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}') | /usr/bin/grep -v root)"
	# If client fails, then note category in audit file
	if [[ $AOSX_14_001013_Audit = "" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_001013 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_001013 -bool false; else
		/bin/echo "* AOSX_14_001013 The macOS system must be configured with audit log folders owned by root." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_001013 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
# 
# Group ID (Vulid): V-95845
# Group Title: SRG-OS-000057-GPOS-00027
# Rule ID: SV-104983r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_001014
# Rule Title: The macOS system must be configured with audit log files group-owned by wheel.
# 
# Vulnerability Discussion: The audit service must be configured to create log files with the correct group ownership to prevent normal users from reading audit
# logs. Audit logs contain sensitive data about the system and users. If log files are set to be readable and writable only by root or administrative users with
# sudo, the risk is mitigated.
# 
# Check Content: 
# To check the group ownership of the audit log files, run the following command:
# 
# /usr/bin/sudo ls -le $(/usr/bin/sudo /usr/bin/grep '^dir' /etc/security/audit_control | awk -F: '{print $2}') | /usr/bin/grep -v current
# 
# The results should show the group owner (fourth column) to be "wheel".
# 
# If they do not, this is a finding.
# 
# Fix Text: For any log file that returns an incorrect group owner, run the following command:
# 
# /usr/bin/sudo chgrp wheel [audit log file]
# 
# [audit log file] is the full path to the log file in question.  
# 
# CCI: CCI-000162
#
# Verify organizational score
AOSX_14_001014="$(/usr/bin/defaults read "$plistlocation" AOSX_14_001014)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_001014" = "1" ]; then
	AOSX_14_001014_Audit="$(/bin/ls -le $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}') | /usr/bin/grep -v current | /usr/bin/grep -v total | /usr/bin/grep -v wheel)"
	# If client fails, then note category in audit file
	if [[ $AOSX_14_001014_Audit = "" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_001014 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_001014 -bool false; else
		/bin/echo "* AOSX_14_001014 The macOS system must be configured with audit log files group-owned by wheel." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_001014 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
# 
# Group ID (Vulid): V-95847
# Group Title: SRG-OS-000057-GPOS-00027
# Rule ID: SV-104985r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_001015
# Rule Title: The macOS system must be configured with audit log folders group-owned by wheel.
# 
# Vulnerability Discussion: The audit service must be configured to create log files with the correct group ownership to prevent normal users from reading audit
# logs. Audit logs contain sensitive data about the system and about users. If log files are set to be readable and writable only by root or administrative
# users with sudo, the risk is mitigated.
# 
# Check Content: 
# To check the group ownership of the audit log folder, run the following command:
# 
# /usr/bin/sudo ls -lde $(/usr/bin/sudo /usr/bin/grep '^dir' /etc/security/audit_control | awk -F: '{print $2}')
# 
# The results should show the group (fourth column) to be "wheel".
# 
# If they do not, this is a finding.
# 
# Fix Text: For any log folder that has an incorrect group, run the following command:
# 
# /usr/bin/sudo chgrp wheel [audit log folder]  
# 
# CCI: CCI-000162
# 
# Verify organizational score
AOSX_14_001015="$(/usr/bin/defaults read "$plistlocation" AOSX_14_001015)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_001015" = "1" ]; then
	AOSX_14_001015_Audit="$(/bin/ls -lde $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}') | /usr/bin/grep -v wheel)"
	# If client fails, then note category in audit file
	if [[ $AOSX_14_001015_Audit = "" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_001015 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_001015 -bool false; else
		/bin/echo "* AOSX_14_001015 The macOS system must be configured with audit log folders group-owned by wheel." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_001015 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
# 
# Group ID (Vulid): V-95849
# Group Title: SRG-OS-000057-GPOS-00027
# Rule ID: SV-104987r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_001016
# Rule Title: The macOS system must be configured with audit log files set to mode 440 or less permissive.
# 
# Vulnerability Discussion: The audit service must be configured to create log files with the correct permissions to prevent normal users from reading audit
# logs. Audit logs contain sensitive data about the system and about users. If log files are set to be readable and writable only by root or administrative
# users with sudo, the risk is mitigated.
# 
# Check Content: 
# To check the permissions of the audit log files, run the following command:
# 
# /usr/bin/sudo ls -le $(/usr/bin/sudo /usr/bin/grep '^dir' /etc/security/audit_control | awk -F: '{print $2}') | /usr/bin/grep -v current
# 
# The results should show the permissions (first column) to be "440" or less permissive.
# 
# If they do not, this is a finding.
# 
# Fix Text: For any log file that returns an incorrect permission value, run the following command:
# 
# /usr/bin/sudo chmod 440 [audit log file]
# 
# [audit log file] is the full path to the log file in question.  
# 
# CCI: CCI-000162
# 
# Verify organizational score
AOSX_14_001016="$(/usr/bin/defaults read "$plistlocation" AOSX_14_001016)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_001016" = "1" ]; then
	AOSX_14_001016_Audit="$(/bin/ls -le $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}') | /usr/bin/grep -v current | /usr/bin/grep -v total | /usr/bin/grep -v 'r--r-----')"
	# If client fails, then note category in audit file
	if [[ $AOSX_14_001016_Audit = "" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_001016 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_001016 -bool false; else
		/bin/echo "* AOSX_14_001016 The macOS system must be configured with audit log files set to mode 440 or less permissive." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_001016 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
# 
# Group ID (Vulid): V-95851
# Group Title: SRG-OS-000057-GPOS-00027
# Rule ID: SV-104989r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_001017
# Rule Title: The macOS system must be configured with audit log folders set to mode 700 or less permissive.
# 
# Vulnerability Discussion: The audit service must be configured to create log folders with the correct permissions to prevent normal users from reading audit
# logs. Audit logs contain sensitive data about the system and users. If log folders are set to be readable and writable only by root or administrative users
# with sudo, the risk is mitigated.
# 
# Satisfies: SRG-OS-000057-GPOS-00027, SRG-OS-000058-GPOS-00028, SRG-OS-000059-GPOS-00029
# 
# Check Content: 
# To check the permissions of the audit log folder, run the following command:
# 
# /usr/bin/sudo ls -lde $(/usr/bin/sudo /usr/bin/grep '^dir' /etc/security/audit_control | awk -F: '{print $2}')
# 
# The results should show the permissions (first column) to be "700" or less permissive.
# 
# if they do not, this is a finding.
# 
# Fix Text: For any log folder that returns an incorrect permission value, run the following command:
# 
# /usr/bin/sudo chmod 700 [audit log folder]  
# 
# CCI: CCI-000162
# CCI: CCI-000163
# CCI: CCI-000164
# 
# Verify organizational score
AOSX_14_001017="$(/usr/bin/defaults read "$plistlocation" AOSX_14_001017)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_001017" = "1" ]; then
	AOSX_14_001017_Audit="$(/bin/ls -lde $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}') | /usr/bin/grep -v 'drwx------')"
	# If client fails, then note category in audit file
	if [[ $AOSX_14_001017_Audit = "" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_001017 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_001017 -bool false; else
		/bin/echo "* AOSX_14_001017 The macOS system must be configured with audit log folders set to mode 700 or less permissive." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_001017 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
# 
# Group ID (Vulid): V-95853
# Group Title: SRG-OS-000064-GPOS-00033
# Rule ID: SV-104991r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_001020
# Rule Title: The macOS system must audit the enforcement actions used to restrict access associated with changes to the system.
# 
# Vulnerability Discussion: By auditing access restriction enforcement, changes to application and OS configuration files can be audited. Without auditing the
# enforcement of access restrictions, it will be difficult to identify attempted attacks and an audit trail will not be available for forensic investigation.
# 
# Enforcement actions are the methods or mechanisms used to prevent unauthorized changes to configuration settings. Enforcement action methods may be as simple
# as denying access to a file based on the application of file permissions (access restriction). Audit items may consist of lists of actions blocked by access
# restrictions or changes identified after the fact.
# 
# Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and
# investigate the events relating to an incident or identify those responsible for one.
# 
# Audit records can be generated from various components within the information system (e.g., module or policy filter).
# 
# Satisfies: SRG-OS-000064-GPOS-00033, SRG-OS-000365-GPOS-00152, SRG-OS-000458-GPOS-00203, SRG-OS-000461-GPOS-00205, SRG-OS-000463-GPOS-00207,
# SRG-OS-000465-GPOS-00209, SRG-OS-000466-GPOS-00210, SRG-OS-000467-GPOS-00211, SRG-OS-000468-GPOS-00212, SRG-OS-000474-GPOS-00219
# 
# Check Content: 
# To view the currently configured flags for the audit daemon, run the following command:
# 
# /usr/bin/sudo /usr/bin/grep ^flags /etc/security/audit_control
# 
# Enforcement actions are logged by way of the "fm" flag, which audits permission changes, and "-fr" and "-fw", which denote failed attempts to read or write to
# a file.
# 
# If "fm", "-fr", and "-fw" are not listed in the result of the check, this is a finding.
# 
# Fix Text: To set the audit flags to the recommended setting, run the following command to add the flags "fm", "-fr", and "-fw" all at once:
# 
# /usr/bin/sudo /usr/bin/sed -i.bak '/^flags/ s/$/,fm,-fr,-fw/' /etc/security/audit_control; /usr/bin/sudo /usr/sbin/audit -s
# 
# A text editor may also be used to implement the required updates to the "/etc/security/audit_control" file.  
# 
# CCI: CCI-000172
# CCI: CCI-001814
#
# Verify organizational score
AOSX_14_001020="$(/usr/bin/defaults read "$plistlocation" AOSX_14_001020)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_001020" = "1" ]; then
	AOSX_14_001020_Audit="$(/usr/bin/grep ^flags /etc/security/audit_control)"
	# If client fails, then note category in audit file
	if [[ "$AOSX_14_001020_Audit" = *"fm"* ]] && [[ "$AOSX_14_001020_Audit" = *"-fr"* ]] && [[ "$AOSX_14_001020_Audit" = *"-fw"* ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_001020 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_001020 -bool false; else
		/bin/echo "* AOSX_14_001020 The macOS system must audit the enforcement actions used to restrict access associated with changes to the system." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_001020 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
# 
# Group ID (Vulid): V-95437
# Group Title: SRG-OS-000341-GPOS-00132
# Rule ID: SV-104719r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_001029
# Rule Title: The macOS system must allocate audit record storage capacity to store at least one weeks worth of audit records when audit records are not
# immediately sent to a central audit record storage facility.
# 
# Vulnerability Discussion: The audit service must be configured to require that records are kept for seven days or longer before deletion when there is no
# central audit record storage facility. When "expire-after" is set to "7d", the audit service will not delete audit logs until the log data is at least seven
# days old.
# 
# Check Content: The check displays the amount of time the audit system is configured to retain audit log files. The audit system will not delete logs until the
# specified condition has been met. To view the current setting, run the following command:
# 
# /usr/bin/sudo /usr/bin/grep ^expire-after /etc/security/audit_control
# /# 
# If this returns no results, or does not contain "7d" or a larger value, this is a finding.
# 
# Fix Text: Edit the "/etc/security/audit_control" file and change the value for "expire-after" to the amount of time audit logs should be kept for the system.
# Use the following command to set the "expire-after" value to "7d":
# 
# /usr/bin/sudo /usr/bin/sed -i.bak 's/.*expire-after.*/expire-after:7d/' /etc/security/audit_control; /usr/bin/sudo /usr/sbin/audit -s
# 
# A text editor may also be used to implement the required updates to the "/etc/security/audit_control" file.  
# 
# CCI: CCI-001849
# 
# Verify organizational score
AOSX_14_001029="$(/usr/bin/defaults read "$plistlocation" AOSX_14_001029)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_001029" = "1" ]; then
	AOSX_14_001029_Audit="$(/usr/bin/grep ^expire-after /etc/security/audit_control)"
	# If client fails, then note category in audit file
	if [[ $AOSX_14_001029_Audit = *"7d"* ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_001029 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_001029 -bool false; else
		/bin/echo "* AOSX_14_001029 Change the value for /etc/security/audit_control - expire-after to 7d." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_001029 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
#
#####################################################################################################

#####################################################################################################
# 
# Group ID (Vulid): V-95855
# Group Title: SRG-OS-000343-GPOS-00134
# Rule ID: SV-104993r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_001030
# Rule Title: The macOS system must provide an immediate warning to the System Administrator (SA) and Information System Security Officer (ISSO) (at a minimum)
# when allocated audit record storage volume reaches 75 percent of repository maximum audit record storage capacity.
# 
# Vulnerability Discussion: The audit service must be configured to require a minimum percentage of free disk space in order to run. This ensures that audit
# will notify the administrator that action is required to free up more disk space for audit logs.
# 
# When "minfree" is set to 25 percent, security personnel are notified immediately when the storage volume is 75 percent full and are able to plan for audit
# record storage capacity expansion.
# 
# Check Content: The check displays the "% free" to leave available for the system. The audit system will not write logs if the volume has less than this
# percentage of free disk space. To view the current setting, run the following command:
# 
# /usr/bin/sudo /usr/bin/grep ^minfree /etc/security/audit_control
# 
# If this returns no results, or does not contain "25", this is a finding.
# 
# Fix Text: Edit the "/etc/security/audit_control" file and change the value for "minfree" to "25" using the following command:
# 
# /usr/bin/sudo /usr/bin/sed -i.bak 's/.*minfree.*/minfree:25/' /etc/security/audit_control; /usr/bin/sudo /usr/sbin/audit -s
# 
# A text editor may also be used to implement the required updates to the "/etc/security/audit_control file".  
# 
# CCI: CCI-001855
# 
# Verify organizational score
AOSX_14_001030="$(/usr/bin/defaults read "$plistlocation" AOSX_14_001030)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_001030" = "1" ]; then
	AOSX_14_001030_Audit="$(/usr/bin/grep ^minfree /etc/security/audit_control)"
	# If client fails, then note category in audit file
	if [[ $AOSX_14_001030_Audit = *"25"* ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_001030 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_001030 -bool false; else
		/bin/echo "* AOSX_14_001030 Change the value for /etc/security/audit_control - minfree to 25." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_001030 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
#
#####################################################################################################

#####################################################################################################
# 
# Group ID (Vulid): V-95857
# Group Title: SRG-OS-000344-GPOS-00135
# Rule ID: SV-104995r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_001031
# Rule Title: The macOS system must provide an immediate real-time alert to the System Administrator (SA) and Information System Security Officer (ISSO), at a
# minimum, of all audit failure events requiring real-time alerts.
# 
# Vulnerability Discussion: The audit service should be configured to immediately print messages to the console or email administrator users when an auditing
# failure occurs. It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without a
# real-time alert, security personnel may be unaware of an impending failure of the audit capability and system operation may be adversely affected.
# 
# Check Content: 
# By default, "auditd" only logs errors to "syslog". To see if audit has been configured to print error messages to the console, run the following command:
# 
# /usr/bin/sudo /usr/bin/grep logger /etc/security/audit_warn
# 
# If the argument "-s" is missing, or if "audit_warn" has not been otherwise modified to print errors to the console or send email alerts to the SA and ISSO,
# this is a finding.
# 
# Fix Text: To make "auditd" log errors to standard error as well as "syslogd", run the following command:
# 
# /usr/bin/sudo /usr/bin/sed -i.bak 's/logger -p/logger -s -p/' /etc/security/audit_warn; /usr/bin/sudo /usr/sbin/audit -s  
# 
# CCI: CCI-001858
# 
# Verify organizational score
AOSX_14_001031="$(/usr/bin/defaults read "$plistlocation" AOSX_14_001031)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_001031" = "1" ]; then
	AOSX_14_001031_Audit="$(/usr/bin/grep logger /etc/security/audit_warn)"
	# If client fails, then note category in audit file
	if [[ $AOSX_14_001031_Audit = *"-s"* ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_001031 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_001031 -bool false; else
		/bin/echo "* AOSX_14_001031 Change the value for /etc/security/audit_control - logger to -s." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_001031 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
#
#####################################################################################################

#####################################################################################################
# 
# Group ID (Vulid): V-95859
# Group Title: SRG-OS-000470-GPOS-00214
# Rule ID: SV-104997r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_001044
# Rule Title: The macOS system must generate audit records for DoD-defined events such as successful/unsuccessful logon attempts, successful/unsuccessful direct
# access attempts, starting and ending time for user access, and concurrent logons to the same account from different sources.
# 
# Vulnerability Discussion: Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to
# establish, correlate, and investigate the events relating to an incident or identify those responsible for one.
# 
# Audit records can be generated from various components within the information system (e.g., module or policy filter).
# 
# Satisfies: SRG-OS-000470-GPOS-00214, SRG-OS-000472-GPOS-00217, SRG-OS-000473-GPOS-00218, SRG-OS-000475-GPOS-00220
# 
# Check Content: 
# To view the currently configured flags for the audit daemon, run the following command:
# 
# /usr/bin/sudo /usr/bin/grep ^flags /etc/security/audit_control
# 
# Logon events are logged by way of the "aa" flag.
# 
# If "aa" is not listed in the result of the check, this is a finding.
# 
# Fix Text: To ensure the appropriate flags are enabled for auditing, run the following command:
# 
# /usr/bin/sudo /usr/bin/sed -i.bak '/^flags/ s/$/,aa/' /etc/security/audit_control; /usr/bin/sudo /usr/sbin/audit -s
# 
# A text editor may also be used to implement the required updates to the "/etc/security/audit_control" file.  
# 
# CCI: CCI-000172
# 
# Verify organizational score
AOSX_14_001044="$(/usr/bin/defaults read "$plistlocation" AOSX_14_001044)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_001044" = "1" ]; then
	AOSX_14_001044_Audit="$(/usr/bin/grep ^flags /etc/security/audit_control)"
	# If client fails, then note category in audit file
	if [[ $AOSX_14_001044_Audit = *"aa"* ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_001044 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_001044 -bool false; else
		/bin/echo "* AOSX_14_001044 Ensure the appropriate flags are enabled for /etc/security/audit_control - aa." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_001044 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
#
#####################################################################################################

#####################################################################################################
# DUPLICATE check to AOSX_14_003002
# 
# Group ID (Vulid): V-95861
# Group Title: SRG-OS-000376-GPOS-00161
# Rule ID: SV-104999r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_001060
# Rule Title: The macOS system must accept and verify Personal Identity Verification (PIV) credentials, implement a local cache of revocation data to support
# path discovery and validation in case of the inability to access revocation information via the network, and only allow the use of DoD PKI-established
# certificate authorities for verification of the establishment of protected sessions.
# 
# Vulnerability Discussion: The use of PIV credentials facilitates standardization and reduces the risk of unauthorized access.
# 
# Without configuring a local cache of revocation data, there is the potential to allow access to users who are no longer authorized (users with revoked
# certificates).
# 
# Untrusted Certificate Authorities (CA) can issue certificates, but they may be issued by organizations or individuals that seek to compromise DoD systems or
# by organizations with insufficient security controls. If the CA used for verifying the certificate is not a DoD-approved CA, trust of this CA has not been
# established.
# 
# DoD has mandated the use of the CAC to support identity management and personal authentication for systems covered under Homeland Security Presidential
# Directive (HSPD) 12, as well as making the CAC a primary component of layered protection for national security systems.
# 
# The DoD will only accept PKI-certificates obtained from a DoD-approved internal or external certificate authority. Reliance on CAs for the establishment of
# secure sessions includes, for example, the use of SSL/TLS certificates.
# 
# Satisfies: SRG-OS-000376-GPOS-00161, SRG-OS-000377-GPOS-00162, SRG-OS-000384-GPOS-00167, SRG-OS-000403-GPOS-00182
# 
# Check Content: 
# To verify that certificate checks are occurring, run the following command.
# 
# /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep checkCertificateTrust
# 
# If the output is null or the value returned, "checkCertificateTrust = 0", is not equal to (0) or greater, this is a finding.
# 
# Fix Text: This setting is enforced using the "Smart Card Policy" configuration profile.
# 
# Note: Before applying the "Smart Card Policy", the supplemental guidance provided with the STIG should be consulted to ensure continued access to the
# operating system.  
# 
# CCI: CCI-001953
# CCI: CCI-001954
# CCI: CCI-001991
# CCI: CCI-002470
#
# Configuration Profile - Smart Card Payload > VERIFY CERTIFICATE TRUST = Check Certificate
# Verify organizational score
AOSX_14_001060="$(/usr/bin/defaults read "$plistlocation" AOSX_14_001060)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_001060" = "1" ]; then
	AOSX_14_001060_Audit="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'checkCertificateTrust = 1')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_14_001060_Audit" > "0" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_001060 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_001060 -bool false; else
		/bin/echo "* AOSX_14_001060 Configuration Profile - The macOS system must accept and verify Personal Identity Verification (PIV) credentials." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_001060 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
#
#####################################################################################################

#####################################################################################################
# 
# Group ID (Vulid): V-95863
# Group Title: SRG-OS-000109-GPOS-00056
# Rule ID: SV-105001r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_001100
# Rule Title: The macOS system must require individuals to be authenticated with an individual authenticator prior to using a group authenticator.
# 
# Vulnerability Discussion: Administrator users must never log in directly as root. To assure individual accountability and prevent unauthorized access, logging
# in as root over a remote connection must be disabled. Administrators should only run commands as root after first authenticating with their individual user
# names and passwords.
# 
# Check Content: 
# To check if SSH has root logins enabled, run the following command:
# 
# /usr/bin/sudo /usr/bin/grep ^PermitRootLogin /etc/ssh/sshd_config
# 
# If there is no result, or the result is set to "yes", this is a finding.
# 
# Fix Text: To ensure that "PermitRootLogin" is disabled by sshd, run the following command:
# 
# /usr/bin/sudo /usr/bin/sed -i.bak 's/^[\#]*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config  
# 
# CCI: CCI-000770
#
# Verify organizational score
AOSX_14_001100="$(/usr/bin/defaults read "$plistlocation" AOSX_14_001100)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_001100" = "1" ]; then
	AOSX_14_001100_Audit="$(/usr/bin/grep ^PermitRootLogin /etc/ssh/sshd_config)"
	# If client fails, then note category in audit file
	if [[ "$AOSX_14_001100_Audit" = "PermitRootLogin no" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_001100 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_001100 -bool false; else
		/bin/echo "* AOSX_14_001100 The macOS system must require individuals to be authenticated with an individual authenticator prior to using a group authenticator." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_001100 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
# 
# Group ID (Vulid): V-95865
# Group Title: SRG-OS-000095-GPOS-00049
# Rule ID: SV-105003r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_002001
# Rule Title: The macOS system must be configured to disable SMB File Sharing unless it is required.
# 
# Vulnerability Discussion: File Sharing is usually non-essential and must be disabled if not required. Enabling any service increases the attack surface for an
# intruder. By disabling unnecessary services, the attack surface is minimized.
# 
# Check Content: 
# If SMB File Sharing is required, this is Not Applicable.
# 
# To check if the SMB File Sharing service is disabled, use the following command:
# 
# /usr/bin/sudo /bin/launchctl print-disabled system | /usr/bin/grep com.apple.smbd
# 
# If the results do not show the following, this is a finding:
# 
# "com.apple.smbd" => true
# 
# Fix Text: To disable the SMB File Sharing service, run the following command:
# 
# /usr/bin/sudo /bin/launchctl disable system/com.apple.smbd
# 
# The system may need to be restarted for the update to take effect.  
# 
# CCI: CCI-000381
# 
# Verify organizational score
AOSX_14_002001="$(/usr/bin/defaults read "$plistlocation" AOSX_14_002001)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_002001" = "1" ]; then
	AOSX_14_002001_Audit="$(/bin/launchctl print-disabled system | /usr/bin/grep com.apple.smbd)"
	# If client fails, then note category in audit file
	if [[ $AOSX_14_002001_Audit = *"true"* ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_002001 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_002001 -bool false; else
		/bin/echo "* AOSX_14_002001 The macOS system must be configured to disable SMB File Sharing unless it is required." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_002001 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
#
#####################################################################################################

#####################################################################################################
# 
# Group ID (Vulid): V-95867
# Group Title: SRG-OS-000095-GPOS-00049
# Rule ID: SV-105005r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_002002
# Rule Title: The macOS system must be configured to disable Apple File (AFP) Sharing.
# 
# Vulnerability Discussion: File Sharing is non-essential and must be disabled. Enabling any service increases the attack surface for an intruder. By disabling
# unnecessary services, the attack surface is minimized.
# 
# Check Content: 
# To check if the Apple File (AFP) Sharing service is disabled, use the following command:
# 
# /usr/bin/sudo /bin/launchctl print-disabled system | /usr/bin/grep com.apple.AppleFileServer
# 
# If the results do not show the following, this is a finding:
# 
# "com.apple.AppleFileServer" => true
# 
# Fix Text: To disable the Apple File (AFP) Sharing service, run the following command:
# 
# /usr/bin/sudo /bin/launchctl disable system/com.apple.AppleFileServer
# 
# The system may need to be restarted for the update to take effect.  
# 
# CCI: CCI-000381
#
# Verify organizational score
AOSX_14_002002="$(/usr/bin/defaults read "$plistlocation" AOSX_14_002002)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_002002" = "1" ]; then
	AOSX_14_002002_Audit="$(/bin/launchctl print-disabled system | /usr/bin/grep com.apple.AppleFileServer)"
	# If client fails, then note category in audit file
	if [[ $AOSX_14_002002_Audit = *"true"* ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_002002 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_002002 -bool false; else
		/bin/echo "* AOSX_14_002002 The macOS system must be configured to disable Apple File (AFP) Sharing." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_002002 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
#
#####################################################################################################

#####################################################################################################
# 
# Group ID (Vulid): V-95869
# Group Title: SRG-OS-000095-GPOS-00049
# Rule ID: SV-105007r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_002003
# Rule Title: The macOS system must be configured to disable the Network File System (NFS) daemon unless it is required.
# 
# Vulnerability Discussion: If the system does not require access to NFS file shares or is not acting as an NFS server, support for NFS is non-essential and NFS
# services must be disabled. NFS is a network file system protocol supported by UNIX-like operating systems. Enabling any service increases the attack surface
# for an intruder. By disabling unnecessary services, the attack surface is minimized.
# 
# Check Content: 
# If the NFS daemon is required, this is Not Applicable.
# 
# To check if the NFS daemon is disabled, use the following command:
# 
# /usr/bin/sudo /bin/launchctl print-disabled system | /usr/bin/grep com.apple.nfsd
# 
# If the results do not show the following, this is a finding:
# 
# "com.apple.nfsd" => true
# 
# Fix Text: To disable the NFS daemon, run the following command:
# 
# /usr/bin/sudo /bin/launchctl disable system/com.apple.nfsd
# 
# The system may need to be restarted for the update to take effect.  
# 
# CCI: CCI-000381
#
# Verify organizational score
AOSX_14_002003="$(/usr/bin/defaults read "$plistlocation" AOSX_14_002003)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_002003" = "1" ]; then
	AOSX_14_002003_Audit="$(/bin/launchctl print-disabled system | /usr/bin/grep com.apple.nfsd)"
	# If client fails, then note category in audit file
	if [[ $AOSX_14_002003_Audit = *"true"* ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_002003 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_002003 -bool false; else
		/bin/echo "* AOSX_14_002003 The macOS system must be configured to disable the Network File System (NFS) daemon unless it is required." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_002003 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
#
#####################################################################################################

#####################################################################################################
# Check this test works on T2 systems
# sudo -u _locationd /usr/bin/defaults -currentHost read com.apple.locationd LocationServicesEnabled
# This appears to work to check the status in 10.14 and 10.15 (Check T2 systems)
# 
# Group ID (Vulid): V-95871
# Group Title: SRG-OS-000095-GPOS-00049
# Rule ID: SV-105009r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_002004
# Rule Title: The macOS system must be configured to disable Location Services.
# 
# Vulnerability Discussion: To prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of
# data types within data types), organizations must disable or restrict unused or unnecessary physical and logical ports/protocols on information systems.
# 
# Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be
# necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services from a single component (e.g.,
# VPN and IPS); however, doing so increases risk over limiting the services provided by any one component.
# 
# To support the requirements and principles of least functionality, the operating system must support the organizational requirements, providing only essential
# capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, and approved to conduct official business or to
# address authorized quality-of-life issues.
# 
# Location Services must be disabled.
# 
# Check Content: 
# If Location Services are authorized by the Authorizing Official, this is Not Applicable.
# 
# Verify that Location Services are disabled:
# 
# The setting is found in System Preferences >> Security & Privacy >> Privacy >> Location Services.
# 
# If the box that says "Enable Location Services" is checked, this is a finding.
# 
# Fix Text: Disable the Location Services:
# 
# The setting is found in System Preferences >> Security & Privacy >> Privacy >> Location Services.
# 
# Uncheck the box labeled "Enable Location Services".  
# 
# CCI: CCI-000381
#
# Verify organizational score
AOSX_14_002004="$(/usr/bin/defaults read "$plistlocation" AOSX_14_002004)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_002004" = "1" ]; then
	AOSX_14_002004_Audit="$(/usr/bin/sudo -u _locationd /usr/bin/defaults -currentHost read com.apple.locationd LocationServicesEnabled)"
	# If client fails, then note category in audit file
	if [[ $AOSX_14_002004_Audit = "0" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_002004 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_002004 -bool false; else
		/bin/echo "* AOSX_14_002004 The macOS system must be configured to disable Location Services. The setting is found in System Preferences >> Security & Privacy >> Privacy >> Location Services. Uncheck the box labeled Enable Location Services" >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_002004 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
# 
# Group ID (Vulid): V-95873
# Group Title: SRG-OS-000095-GPOS-00049
# Rule ID: SV-105011r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_002005
# Rule Title: The macOS system must be configured to disable Bonjour multicast advertising.
# 
# Vulnerability Discussion: To prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of
# data types within data types), organizations must disable or restrict unused or unnecessary physical and logical ports/protocols on information systems.
# 
# Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be
# necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services from a single component (e.g.,
# VPN and IPS); however, doing so increases risk over limiting the services provided by any one component.
# 
# To support the requirements and principles of least functionality, the operating system must support the organizational requirements, providing only essential
# capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, and approved to conduct official business or to
# address authorized quality-of-life issues.
# 
# Bonjour multicast advertising must be disabled on the system.
# 
# Check Content: 
# To check that Bonjour broadcasts have been disabled, use the following command:
# 
# /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep NoMulticastAdvertisements
# 
# If the return is not, "NoMulticastAdvertisements = 1", this is a finding.
# 
# Fix Text: This setting is enforced using the "Custom Policy" configuration profile.  
# 
# CCI: CCI-000381
#
# Configuration Profile - Custom payload > com.apple.mDNSResponder > NoMulticastAdvertisements=true
# Verify organizational score
AOSX_14_002005="$(/usr/bin/defaults read "$plistlocation" AOSX_14_002005)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_002005" = "1" ]; then
	AOSX_14_002005_Audit="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'NoMulticastAdvertisements = 1')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_14_002005_Audit" > "0" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_002005 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_002005 -bool false; else
		/bin/echo "* AOSX_14_002005 Configuration Profile - The macOS system must be configured to disable Bonjour multicast advertising." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_002005 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
# 
# Group ID (Vulid): V-95875
# Group Title: SRG-OS-000095-GPOS-00049
# Rule ID: SV-105013r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_002006
# Rule Title: The macOS system must be configured to disable the UUCP service.
# 
# Vulnerability Discussion: It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission
# objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by
# providing additional attack vectors.
# 
# Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be
# necessary to support essential organizational operations (e.g., key missions, functions).
# 
# Examples of non-essential capabilities include but are not limited to games, software packages, tools, and demonstration software not related to requirements
# or providing a wide array of functionality not required for every mission but that cannot be disabled.
# 
# The system must not have the UUCP service active.
# 
# Check Content: 
# To check if the UUCP service is disabled, use the following command:
# 
# /usr/bin/sudo /bin/launchctl print-disabled system | /usr/bin/grep com.apple.uucp
# 
# If the results do not show the following, this is a finding:
# 
# "com.apple.uucp" => true
# 
# Fix Text: To disable the UUCP service, run the following command:
# 
# /usr/bin/sudo /bin/launchctl disable system/com.apple.uucp
# 
# The system may need to be restarted for the update to take effect.  
# 
# CCI: CCI-000381
# 
# Verify organizational score
AOSX_14_002006="$(/usr/bin/defaults read "$plistlocation" AOSX_14_002006)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_002006" = "1" ]; then
	AOSX_14_002006_Audit="$(/bin/launchctl print-disabled system | /usr/bin/grep com.apple.uucp)"
	# If client fails, then note category in audit file
	if [[ $AOSX_14_002006_Audit = *"true"* ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_002006 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_002006 -bool false; else
		/bin/echo "* AOSX_14_002006 The macOS system must be configured to disable the UUCP service." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_002006 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
#
#####################################################################################################

#####################################################################################################
# Check Content: NEW - This is now checked as a configuration profile
# 
# Group ID (Vulid): V-95877
# Group Title: SRG-OS-000095-GPOS-00049
# Rule ID: SV-105015r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_002007
# Rule Title: The macOS system must be configured to disable Internet Sharing.
# 
# Vulnerability Discussion: To prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of
# data types within data types), organizations must disable or restrict unused or unnecessary physical and logical ports/protocols on information systems.
# 
# Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be
# necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services from a single component (e.g.,
# VPN and IPS); however, doing so increases risk over limiting the services provided by any one component.
# 
# To support the requirements and principles of least functionality, the operating system must support the organizational requirements, providing only essential
# capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, and approved to conduct official business or to
# address authorized quality-of-life issues.
# 
# Internet Sharing is non-essential and must be disabled.
# 
# Check Content: 
# To check if Internet Sharing is disabled, use the following command:
# 
# /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep forceInternetSharingOff
# 
# If the return is not, "forceInternetSharingOff = 1", this is a finding.
# 
# Fix Text: This setting is enforced using the "Custom Policy" configuration profile.  
# 
# CCI: CCI-000381
#
# Configuration Profile - Custom payload > com.apple.MCX > forceInternetSharingOff=true
# Verify organizational score
AOSX_14_002007="$(/usr/bin/defaults read "$plistlocation" AOSX_14_002007)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_002007" = "1" ]; then
	AOSX_14_002007_Audit="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'forceInternetSharingOff = 1')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_14_002007_Audit" > "0" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_002007 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_002007 -bool false; else
		/bin/echo "* AOSX_14_002007 Configuration Profile - The macOS system must be configured to disable Internet Sharing." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_002007 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
# 
# Group ID (Vulid): V-95883
# Group Title: SRG-OS-000095-GPOS-00049
# Rule ID: SV-105021r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_002008
# Rule Title: The macOS system must be configured to disable Web Sharing.
# 
# Vulnerability Discussion: To prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of
# data types within data types), organizations must disable or restrict unused or unnecessary physical and logical ports/protocols on information systems.
# 
# Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be
# necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services from a single component (e.g.,
# VPN and IPS); however, doing so increases risk over limiting the services provided by any one component.
# 
# To support the requirements and principles of least functionality, the operating system must support the organizational requirements, providing only essential
# capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, and approved to conduct official business or to
# address authorized quality-of-life issues.
# 
# Web Sharing is non-essential and must be disabled.
# 
# Check Content: 
# To check if Web Sharing is disabled, use the following command:
# 
# /usr/bin/sudo /bin/launchctl print-disabled system | /usr/bin/grep org.apache.httpd
# 
# If the results do not show the following, this is a finding:
# 
# "org.apache.httpd" => true
# 
# Fix Text: To disable Web Sharing, run the following command:
# 
# /usr/bin/sudo /bin/launchctl disable system/org.apache.httpd
# 
# The system may need to be restarted for the update to take effect.  
# 
# CCI: CCI-000381
# 
# Verify organizational score
AOSX_14_002008="$(/usr/bin/defaults read "$plistlocation" AOSX_14_002008)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_002008" = "1" ]; then
	AOSX_14_002008_Audit="$(/bin/launchctl print-disabled system | /usr/bin/grep org.apache.httpd)"
	# If client fails, then note category in audit file
	if [[ $AOSX_14_002008_Audit = *"true"* ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_002008 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_002008 -bool false; else
		/bin/echo "* AOSX_14_002008 The macOS system must be configured to disable Web Sharing." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_002008 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
#
#####################################################################################################

#####################################################################################################
# 
# Group ID (Vulid): V-95885
# Group Title: SRG-OS-000095-GPOS-00049
# Rule ID: SV-105023r1_rule
# Severity: CAT III
# Rule Version (STIG-ID): AOSX_14_002009
# Rule Title: The macOS system must be configured to disable AirDrop.
# 
# Vulnerability Discussion: To prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of
# data types within data types), organizations must disable or restrict unused or unnecessary physical and logical ports/protocols on information systems.
# 
# Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be
# necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services from a single component (e.g.,
# VPN and IPS); however, doing so increases risk over limiting the services provided by any one component.
# 
# To support the requirements and principles of least functionality, the operating system must support the organizational requirements, providing only essential
# capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, and approved to conduct official business or to
# address authorized quality-of-life issues.
# 
# AirDrop must be disabled.
# 
# Check Content: 
# AirDrop relies on Bluetooth LE for discovery. To check if AirDrop has been disabled, run the following command:
# 
# /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep DisableBluetooth
# 
# If the return is not, "DisableBluetooth = 1", this is a finding.
# 
# Fix Text: This setting is enforced using the "Custom Policy" configuration profile.  
# 
# CCI: CCI-000381
#
# Configuration Profile - Restrictions payload > Media > Allow AirDrop (unchecked)
# Verify organizational score
AOSX_14_002009="$(/usr/bin/defaults read "$plistlocation" AOSX_14_002009)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_002009" = "1" ]; then
	AOSX_14_002009_Audit="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'DisableAirDrop = 1')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_14_002009_Audit" > "0" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_002009 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_002009 -bool false; else
		/bin/echo "* AOSX_14_002009 Configuration Profile - The macOS system must be configured to disable AirDrop." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_002009 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
# 
# Group ID (Vulid): V-95887
# Group Title: SRG-OS-000095-GPOS-00049
# Rule ID: SV-105025r1_rule
# Severity: CAT III
# Rule Version (STIG-ID): AOSX_14_002010
# Rule Title: The macOS system must be configured to disable the application FaceTime.
# 
# Vulnerability Discussion: It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission
# objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by
# providing additional attack vectors.
# 
# Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be
# necessary to support essential organizational operations (e.g., key missions, functions).
# 
# Examples of non-essential capabilities include but are not limited to games, software packages, tools, and demonstration software not related to requirements
# or providing a wide array of functionality not required for every mission but that cannot be disabled.
# 
# The application FaceTime establishes connections to Apple's iCloud, despite using security controls to disable iCloud access.
# 
# Satisfies: SRG-OS-000095-GPOS-00049, SRG-OS-000370-GPOS-00155
# 
# Check Content: 
# To check if there is a configuration policy defined for "Application Restrictions", run the following command:
# 
# /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -A 5 familyControlsEnabled | grep "FaceTime"
# 
# If the return does not contain "/Applications/FaceTime.app", this is a finding.
# 
# Fix Text: This setting is enforced using the "Restrictions Policy" configuration profile.  
# 
# CCI: CCI-000381
# CCI: CCI-001774
#
# Configuration Profile - Restrictions payload > Applications > Disallow "/Applications/FaceTime.app/"
# Verify organizational score
AOSX_14_002010="$(/usr/bin/defaults read "$plistlocation" AOSX_14_002010)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_002010" = "1" ]; then
	AOSX_14_002010_Audit="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -A 10 familyControlsEnabled | /usr/bin/grep -B 10 ');' | /usr/bin/grep 'FaceTime.app')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_14_002010_Audit" = *"/Applications/FaceTime.app"* ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_002010 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_002010 -bool false; else
		/bin/echo "* AOSX_14_002010 Configuration Profile - The macOS system must be configured to disable the application FaceTime." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_002010 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
# 
# Group ID (Vulid): V-95889
# Group Title: SRG-OS-000095-GPOS-00049
# Rule ID: SV-105027r1_rule
# Severity: CAT III
# Rule Version (STIG-ID): AOSX_14_002011
# Rule Title: The macOS system must be configured to disable the application Messages.
# 
# Vulnerability Discussion: It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission
# objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by
# providing additional attack vectors.
# 
# Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be
# necessary to support essential organizational operations (e.g., key missions, functions).
# 
# Examples of non-essential capabilities include but are not limited to games, software packages, tools, and demonstration software not related to requirements
# or providing a wide array of functionality not required for every mission but that cannot be disabled.
# 
# The application Messages establishes connections to Apple's iCloud, despite using security controls to disable iCloud access.
# 
# Satisfies: SRG-OS-000095-GPOS-00049, SRG-OS-000370-GPOS-00155
# 
# Check Content: 
# To check if there is a configuration policy defined for "Application Restrictions", run the following command:
# 
# /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -A 5 familyControlsEnabled | grep "Messages.app"
# 
# If the return does not contain "/Applications/Messages.app", this is a finding.
# 
# Fix Text: This setting is enforced using the "Restrictions Policy" configuration profile.  
# 
# CCI: CCI-000381
# CCI: CCI-001774
#
# Configuration Profile - Restrictions payload > Applications > Disallow "/Applications/Messages.app/"
# Verify organizational score
AOSX_14_002011="$(/usr/bin/defaults read "$plistlocation" AOSX_14_002011)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_002011" = "1" ]; then
	AOSX_14_002011_Audit="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -A 10 familyControlsEnabled | /usr/bin/grep -B 10 ');' | /usr/bin/grep 'Messages.app')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_14_002011_Audit" = *"/Applications/Messages.app"* ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_002011 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_002011 -bool false; else
		/bin/echo "* AOSX_14_002011 Configuration Profile - The macOS system must be configured to disable the application Messages." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_002011 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
# 
# Group ID (Vulid): V-95891
# Group Title: SRG-OS-000095-GPOS-00049
# Rule ID: SV-105029r1_rule
# Severity: CAT III
# Rule Version (STIG-ID): AOSX_14_002012
# Rule Title: The macOS system must be configured to disable the iCloud Calendar services.
# 
# Vulnerability Discussion: It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission
# objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by
# providing additional attack vectors.
# 
# Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be
# necessary to support essential organizational operations (e.g., key missions, functions).
# 
# Examples of non-essential capabilities include but are not limited to games, software packages, tools, and demonstration software not related to requirements
# or providing a wide array of functionality not required for every mission but that cannot be disabled.
# 
# The Calendar application's connections to Apple's iCloud, must be disabled.
# 
# Satisfies: SRG-OS-000095-GPOS-00049, SRG-OS-000370-GPOS-00155
# 
# Check Content: 
# To check if iCloudCalendar is disabled, run the following command:
# 
# /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep allowCloudCalendar
# 
# If the return is not “allowCloudCalendar = 0”, this is a finding.
# 
# Fix Text: This setting is enforced using the "Restrictions Policy" configuration profile.  
# 
# CCI: CCI-000381
# CCI: CCI-001774
#
# Configuration Profile - Restrictions payload > Functionality > Allow iCloud Calendar (unchecked)
# Verify organizational score
AOSX_14_002012="$(/usr/bin/defaults read "$plistlocation" AOSX_14_002012)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_002012" = "1" ]; then
	AOSX_14_002012_Audit="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'allowCloudCalendar = 0')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_14_002012_Audit" > "0" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_002012 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_002012 -bool false; else
		/bin/echo "* AOSX_14_002012 Configuration Profile - The macOS system must be configured to disable the iCloud Calendar services." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_002012 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
# 
# Group ID (Vulid): V-95893
# Group Title: SRG-OS-000095-GPOS-00049
# Rule ID: SV-105031r1_rule
# Severity: CAT III
# Rule Version (STIG-ID): AOSX_14_002013
# Rule Title: The macOS system must be configured to disable the iCloud Reminders services.
# 
# Vulnerability Discussion: It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission
# objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by
# providing additional attack vectors.
# 
# Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be
# necessary to support essential organizational operations (e.g., key missions, functions).
# 
# Examples of non-essential capabilities include but are not limited to games, software packages, tools, and demonstration software not related to requirements
# or providing a wide array of functionality not required for every mission but that cannot be disabled.
# 
# The Reminder application's connections to Apple's iCloud, must be disabled.
# 
# Satisfies: SRG-OS-000095-GPOS-00049, SRG-OS-000370-GPOS-00155
# 
# Check Content: 
# To check if iCloud Reminders is disabled, run the following command:
# 
# /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep allowCloudReminders
# 
# If the return is not “allowCloudReminders = 0”, this is a finding.
# 
# Fix Text: This setting is enforced using the "Restrictions Policy" configuration profile.  
# 
# CCI: CCI-000381
# CCI: CCI-001774
#
# Configuration Profile - Restrictions payload > Functionality > Allow iCloud Reminders (unchecked)
# Verify organizational score
AOSX_14_002013="$(/usr/bin/defaults read "$plistlocation" AOSX_14_002013)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_002013" = "1" ]; then
	AOSX_14_002013_Audit="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'allowCloudReminders = 0')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_14_002013_Audit" > "0" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_002013 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_002013 -bool false; else
		/bin/echo "* AOSX_14_002013 Configuration Profile - The macOS system must be configured to disable the iCloud Reminders services." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_002013 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
# 
# Group ID (Vulid): V-95895
# Group Title: SRG-OS-000095-GPOS-00049
# Rule ID: SV-105033r1_rule
# Severity: CAT III
# Rule Version (STIG-ID): AOSX_14_002014
# Rule Title: The macOS system must be configured to disable iCloud Address Book services.
# 
# Vulnerability Discussion: It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission
# objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by
# providing additional attack vectors.
# 
# Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be
# necessary to support essential organizational operations (e.g., key missions, functions).
# 
# Examples of non-essential capabilities include but are not limited to games, software packages, tools, and demonstration software not related to requirements
# or providing a wide array of functionality not required for every mission but that cannot be disabled.
# 
# The Address Book(Contacts) application's connections to Apple's iCloud, must be disabled.
# 
# Satisfies: SRG-OS-000095-GPOS-00049, SRG-OS-000370-GPOS-00155
# 
# Check Content: 
# /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep allowCloudAddressBook
# 
# If the result is not “allowCloudAddressBook = 0”, this is a finding.
# 
# Fix Text: This setting is enforced using the "Restrictions Policy" configuration profile.  
# 
# CCI: CCI-000381
# CCI: CCI-001774
#
# Configuration Profile - Restrictions payload > Functionality > Allow iCloud Contacts (unchecked)
# Verify organizational score
AOSX_14_002014="$(/usr/bin/defaults read "$plistlocation" AOSX_14_002014)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_002014" = "1" ]; then
	AOSX_14_002014_Audit="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'allowCloudAddressBook = 0')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_14_002014_Audit" > "0" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_002014 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_002014 -bool false; else
		/bin/echo "* AOSX_14_002014 Configuration Profile - The macOS system must be configured to disable iCloud Address Book services." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_002014 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
# 
# Group ID (Vulid): V-95897
# Group Title: SRG-OS-000095-GPOS-00049
# Rule ID: SV-105035r1_rule
# Severity: CAT III
# Rule Version (STIG-ID): AOSX_14_002015
# Rule Title: The macOS system must be configured to disable the Mail iCloud services.
# 
# Vulnerability Discussion: It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission
# objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by
# providing additional attack vectors.
# 
# Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be
# necessary to support essential organizational operations (e.g., key missions, functions).
# 
# Examples of non-essential capabilities include but are not limited to games, software packages, tools, and demonstration software not related to requirements
# or providing a wide array of functionality not required for every mission but that cannot be disabled.
# 
# The Mail application's connections to Apple's iCloud, must be disabled.
# 
# Satisfies: SRG-OS-000095-GPOS-00049, SRG-OS-000370-GPOS-00155
# 
# Check Content: 
# To check if Mail iCloud is disabled, run the following command:
# 
# /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep allowCloudMail
# 
# If the result is not “allowCloudMail = 0”, this is a finding.
# 
# Fix Text: This setting is enforced using the "Restrictions Policy" configuration profile.  
# 
# CCI: CCI-000381
# CCI: CCI-001774
#
# Configuration Profile - Restrictions payload > Functionality > Allow iCloud Mail (unchecked)
# Verify organizational score
AOSX_14_002015="$(/usr/bin/defaults read "$plistlocation" AOSX_14_002015)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_002015" = "1" ]; then
	AOSX_14_002015_Audit="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'allowCloudMail = 0')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_14_002015_Audit" > "0" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_002015 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_002015 -bool false; else
		/bin/echo "* AOSX_14_002015 Configuration Profile - The macOS system must be configured to disable the iCloud Mail services." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_002015 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
# 
# Group ID (Vulid): V-95899
# Group Title: SRG-OS-000095-GPOS-00049
# Rule ID: SV-105037r1_rule
# Severity: CAT III
# Rule Version (STIG-ID): AOSX_14_002016
# Rule Title: The macOS system must be configured to disable the iCloud Notes services.
# 
# Vulnerability Discussion: It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission
# objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by
# providing additional attack vectors.
# 
# Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be
# necessary to support essential organizational operations (e.g., key missions, functions).
# 
# Examples of non-essential capabilities include but are not limited to games, software packages, tools, and demonstration software not related to requirements
# or providing a wide array of functionality not required for every mission but that cannot be disabled.
# 
# The Notes application's connections to Apple's iCloud, must be disabled.
# 
# Satisfies: SRG-OS-000095-GPOS-00049, SRG-OS-000370-GPOS-00155
# 
# Check Content: 
# To check if iCloud Notes is disabled, run the following command:
# 
# /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep allowCloudNotes
# 
# If the return is not “allowCloudNotes = 0”, this is a finding.
# 
# Fix Text: This setting is enforced using the "Restrictions Policy" configuration profile.  
# 
# CCI: CCI-000381
# CCI: CCI-001774
#
# Configuration Profile - Restrictions payload > Functionality > Allow iCloud Notes (unchecked)
# Verify organizational score
AOSX_14_002016="$(/usr/bin/defaults read "$plistlocation" AOSX_14_002016)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_002016" = "1" ]; then
	AOSX_14_002016_Audit="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'allowCloudNotes = 0')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_14_002016_Audit" > "0" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_002016 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_002016 -bool false; else
		/bin/echo "* AOSX_14_002016 Configuration Profile - The macOS system must be configured to disable the iCloud Notes services." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_002016 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
# 
# Group ID (Vulid): V-95901
# Group Title: SRG-OS-000095-GPOS-00049
# Rule ID: SV-105039r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_002017
# Rule Title: The macOS system must be configured to disable the camera.
# 
# Vulnerability Discussion: It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission
# objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by
# providing additional attack vectors.
# 
# Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be
# necessary to support essential organizational operations (e.g., key missions, functions).
# 
# Examples of non-essential capabilities include but are not limited to games, software packages, tools, and demonstration software not related to requirements
# or providing a wide array of functionality not required for every mission but that cannot be disabled.
# 
# The camera must be disabled.
# 
# Satisfies: SRG-OS-000095-GPOS-00049, SRG-OS-000370-GPOS-00155
# 
# Check Content: 
# To check if the system has been configured to disable the camera, run the following command:
# 
# /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep allowCamera
# 
# If the result is not “allowCamera = 0”, this is a finding.
# 
# Fix Text: This setting is enforced using the "Restrictions Policy" configuration profile.  
# 
# CCI: CCI-000381
# CCI: CCI-001774
#
# Configuration Profile - Restrictions payload > Functionality > Allow use of Camera (unchecked)
# Verify organizational score
AOSX_14_002017="$(/usr/bin/defaults read "$plistlocation" AOSX_14_002017)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_002017" = "1" ]; then
	AOSX_14_002017_Audit="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'allowCamera = 0')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_14_002017_Audit" > "0" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_002017 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_002017 -bool false; else
		/bin/echo "* AOSX_14_002017 Configuration Profile - The macOS system must be configured to disable the camera." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_002017 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
# 
# Group ID (Vulid): V-95905
# Group Title: SRG-OS-000095-GPOS-00049
# Rule ID: SV-105043r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_002019
# Rule Title: The macOS system must be configured to disable the application Mail.
# 
# Vulnerability Discussion: It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission
# objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by
# providing additional attack vectors.
# 
# Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be
# necessary to support essential organizational operations (e.g., key missions, functions).
# 
# Examples of non-essential capabilities include but are not limited to games, software packages, tools, and demonstration software not related to requirements
# or providing a wide array of functionality not required for every mission but that cannot be disabled.
# 
# The application Mail establishes connections to Apple's iCloud, despite using security controls to disable iCloud access.
# 
# Check Content: 
# To check if there is a configuration policy defined for "Application Restrictions", run the following command:
# 
# /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -A 5 familyControlsEnabled | grep "Mail.app"
# 
# If the return does not contain "/Applications/Mail.app", this is a finding.
# 
# Fix Text: This setting is enforced using the "Restrictions Policy" configuration profile.  
# 
# CCI: CCI-000381
#
# Configuration Profile - Restrictions payload > Applications > Disallow "/Applications/Mail.app"
# Verify organizational score
AOSX_14_002019="$(/usr/bin/defaults read "$plistlocation" AOSX_14_002019)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_002019" = "1" ]; then
	AOSX_14_002019_Audit="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -A 10 familyControlsEnabled | /usr/bin/grep -B 10 ');' | /usr/bin/grep 'Mail.app')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_14_002019_Audit" = *"/Applications/Mail.app"* ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_002019 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_002019 -bool false; else
		/bin/echo "* AOSX_14_002019 Configuration Profile - The macOS system must be configured to disable the application Mail." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_002019 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
# 
# Group ID (Vulid): V-95907
# Group Title: SRG-OS-000095-GPOS-00049
# Rule ID: SV-105045r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_002020
# Rule Title: The macOS system must be configured to disable Siri and dictation.
# 
# Vulnerability Discussion: It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission
# objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by
# providing additional attack vectors.
# 
# Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be
# necessary to support essential organizational operations (e.g., key missions, functions).
# 
# Examples of non-essential capabilities include but are not limited to games, software packages, tools, and demonstration software not related to requirements
# or providing a wide array of functionality not required for every mission but that cannot be disabled.
# 
# Siri and dictation must be disabled.
# 
# Satisfies: SRG-OS-000095-GPOS-00049, SRG-OS-000370-GPOS-00155
# 
# Check Content: 
# To check if Siri and dictation has been disabled, run the following command:
# 
# /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -e "Assistant Allowed" -e "Ironwood Allowed"
# 
# If the output is not the following, this is a finding:
# “Assistant Allowed = 0”
# “Ironwood Allowed = 0”
# 
# Fix Text: This setting is enforced using the "Restrictions Policy" configuration profile.  
# 
# CCI: CCI-000381
# CCI: CCI-001774
#
# Configuration Profile - Custom payload > com.apple.ironwood.support > Ironwood Allowed=false
# Configuration Profile - Custom payload > com.apple.ironwood.support > Assistant Allowed=false
# Verify organizational score
AOSX_14_002020="$(/usr/bin/defaults read "$plistlocation" AOSX_14_002020)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_002020" = "1" ]; then
	AOSX_14_002020_Audit1="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c '\"Assistant Allowed\" = 0')"
	AOSX_14_002020_Audit2="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c '\"Ironwood Allowed\" = 0')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_14_002020_Audit1" > "0" ]] && [[ "$AOSX_14_002020_Audit2" > "0" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_002020 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_002020 -bool false; else
		/bin/echo "* AOSX_14_002020 Configuration Profile - The macOS system must be configured to disable Siri and dictation." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_002020 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
# 
# Group ID (Vulid): V-95909
# Group Title: SRG-OS-000096-GPOS-00050
# Rule ID: SV-105047r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_002021
# Rule Title: The macOS system must be configured to disable sending diagnostic and usage data to Apple.
# 
# Vulnerability Discussion: It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission
# objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by
# providing additional attack vectors.
# 
# Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be
# necessary to support essential organizational operations (e.g., key missions, functions).
# 
# Examples of non-essential capabilities include but are not limited to games, software packages, tools, and demonstration software not related to requirements
# or providing a wide array of functionality not required for every mission but that cannot be disabled.
# 
# The ability to submit diagnostic data to Apple must be disabled.
# 
# Check Content: 
# Sending diagnostic and usage data to Apple must be disabled.
# 
# To check if a configuration profile is configured to enforce this setting, run the following command:
# 
# /usr/bin/sudo /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep allowDiagnosticSubmission
# 
# If "allowDiagnosticSubmission" is not set to "0", this is a finding.
# 
# Alternately, the setting is found in System Preferences >> Security & Privacy >> Privacy >> Diagnostics & Usage.
# 
# If the box that says "Send diagnostic & usage data to Apple" is checked, this is a finding.
# 
# Fix Text: This setting is enforced using the "Restrictions Policy" configuration profile.
# 
# The setting "Send diagnostic & usage data to Apple" is found in System Preferences >> Security & Privacy >> Privacy >> Diagnostics & Usage.
# 
# Uncheck the box that says "Send diagnostic & usage data to Apple."
# 
# To apply the setting from the command line, run the following commands:
# 
# /usr/bin/defaults read "/Library/Application Support/CrashReporter/DiagnosticMessagesHistory.plist" AutoSubmit
# /usr/bin/sudo /usr/bin/defaults write "/Library/Application Support/CrashReporter/DiagnosticMessagesHistory.plist" AutoSubmit -bool false
# /usr/bin/sudo /bin/chmod 644 /Library/Application\ Support/CrashReporter/DiagnosticMessagesHistory.plist
# /usr/bin/sudo /usr/bin/chgrp admin /Library/Application\ Support/CrashReporter/DiagnosticMessagesHistory.plist  
# 
# CCI: CCI-000382
#
# Configuration Profile - Security & Privacy payload > Privacy > Allow sending diagnostic and usage data to Apple... (unchecked)
# Verify organizational score
AOSX_14_002021="$(/usr/bin/defaults read "$plistlocation" AOSX_14_002021)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_002021" = "1" ]; then
	AOSX_14_002021_Audit="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'AutoSubmit = 0')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_14_002021_Audit" > "0" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_002021 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_002021 -bool false; else
		/bin/echo "* AOSX_14_002021 Configuration Profile - The macOS system must be configured to disable sending diagnostic and usage data to Apple." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_002021 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
# 
# Group ID (Vulid): V-95911
# Group Title: SRG-OS-000096-GPOS-00050
# Rule ID: SV-105049r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_002022
# Rule Title: The macOS system must be configured to disable Remote Apple Events.
# 
# Vulnerability Discussion: It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission
# objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by
# providing additional attack vectors.
# 
# Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be
# necessary to support essential organizational operations (e.g., key missions, functions).
# 
# Examples of non-essential capabilities include but are not limited to games, software packages, tools, and demonstration software not related to requirements
# or providing a wide array of functionality not required for every mission but that cannot be disabled.
# 
# Remote Apple Events must be disabled.
# 
# Check Content: 
# To check if Remote Apple Events is disabled, use the following command:
# 
# /usr/bin/sudo /bin/launchctl print-disabled system | /usr/bin/grep com.apple.AEServer
# 
# If the results do not show the following, this is a finding.
# 
# "com.apple.AEServer" => true
# 
# Fix Text: To disable Remote Apple Events, run the following command:
# 
# /usr/bin/sudo /bin/launchctl disable system/com.apple.AEServer
# 
# The system may need to be restarted for the update to take effect.  
# 
# CCI: CCI-000382
# 
# Verify organizational score
AOSX_14_002022="$(/usr/bin/defaults read "$plistlocation" AOSX_14_002022)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_002022" = "1" ]; then
	AOSX_14_002022_Audit="$(/bin/launchctl print-disabled system | /usr/bin/grep com.apple.AEServer)"
	# If client fails, then note category in audit file
	if [[ $AOSX_14_002022_Audit = *"true"* ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_002022 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_002022 -bool false; else
		/bin/echo "* AOSX_14_002022 The macOS system must be configured to disable Remote Apple Events." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_002022 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
#
#####################################################################################################

#####################################################################################################
# 
# Group ID (Vulid): V-95913
# Group Title: SRG-OS-000095-GPOS-00049
# Rule ID: SV-105051r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_002023
# Rule Title: The macOS system must be configured to disable the application Calendar.
# 
# Vulnerability Discussion: It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission
# objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by
# providing additional attack vectors.
# 
# Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be
# necessary to support essential organizational operations (e.g., key missions, functions).
# 
# Examples of non-essential capabilities include but are not limited to games, software packages, tools, and demonstration software not related to requirements
# or providing a wide array of functionality not required for every mission but that cannot be disabled.
# 
# The application Calendar establishes connections to Apple's iCloud, despite using security controls to disable iCloud access.
# 
# Check Content: 
# To check if there is a configuration policy defined for "Application Restrictions", run the following command:
# 
# /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -A 5 familyControlsEnabled | grep "Calendar.app"
# 
# If the return does not contain "/Applications/Calendar.app", this is a finding.
# 
# Fix Text: This setting is enforced using the "Restrictions Policy" configuration profile.  
# 
# CCI: CCI-000381
#
# Configuration Profile - Restrictions payload > Applications > Disallow "/Applications/Calendar.app/"
# Verify organizational score
AOSX_14_002023="$(/usr/bin/defaults read "$plistlocation" AOSX_14_002023)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_002023" = "1" ]; then
	AOSX_14_002023_Audit="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -A 10 familyControlsEnabled | /usr/bin/grep -B 10 ');' | /usr/bin/grep 'Calendar.app')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_14_002023_Audit" = *"/Applications/Calendar.app"* ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_002023 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_002023 -bool false; else
		/bin/echo "* AOSX_14_002023 Configuration Profile - The macOS system must be configured to disable the application Calendar." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_002023 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
# 
# Group ID (Vulid): V-95915
# Group Title: SRG-OS-000370-GPOS-00155
# Rule ID: SV-105053r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_002031
# Rule Title: The macOS system must be configured to disable the system preference pane for iCloud.
# 
# Vulnerability Discussion: It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission
# objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by
# providing additional attack vectors.
# 
# Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be
# necessary to support essential organizational operations (e.g., key missions, functions).
# 
# Examples of non-essential capabilities include but are not limited to games, software packages, tools, and demonstration software not related to requirements
# or providing a wide array of functionality not required for every mission but that cannot be disabled.
# 
# The iCloud System Preference Pane must be disabled.
# 
# Check Content: 
# To check if the system has the correct setting in the configuration profile to disable access to the iCloud preference pane, run the following command:
# 
# /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -A 6 DisabledPreferencePanes | grep icloud
# 
# If the return is not “com.apple.preferences.icloud”, this is a finding.
# 
# Fix Text: This setting is enforced using the "Restrictions Policy" configuration profile.  
# 
# CCI: CCI-001774
#
# Configuration Profile - Restrictions payload > Preferences > disable selected items "iCloud"
# Verify organizational score
AOSX_14_002031="$(/usr/bin/defaults read "$plistlocation" AOSX_14_002031)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_002031" = "1" ]; then
	AOSX_14_002031_Audit="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -A 10 DisabledPreferencePanes | /usr/bin/grep -B 10 ');' | /usr/bin/grep 'icloud')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_14_002031_Audit" = *"com.apple.preferences.icloud"* ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_002031 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_002031 -bool false; else
		/bin/echo "* AOSX_14_002031 Configuration Profile - The macOS system must be configured to disable the system preference pane for iCloud." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_002031 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
# 
# Group ID (Vulid): V-95917
# Group Title: SRG-OS-000370-GPOS-00155
# Rule ID: SV-105055r2_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_002032
# Rule Title: The macOS system must be configured to disable the system preference pane for Internet Accounts.
# 
# Vulnerability Discussion: It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission
# objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by
# providing additional attack vectors.
# 
# Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be
# necessary to support essential organizational operations (e.g., key missions, functions). 
# 
# Examples of non-essential capabilities include but are not limited to games, software packages, tools, and demonstration software not related to requirements
# or providing a wide array of functionality not required for every mission but that cannot be disabled.
# 
# The Internet Accounts System preference pane must be disabled.
# 
# Satisfies: SRG-OS-000095-GPOS-00049.
# 
# Check Content:  
# To check if the system has the correct setting in the configuration profile to disable access to the Internet Accounts System preference pane, run the
# following command:
# 
# /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -A 6 DisabledPreferencePanes
# /
# If the return is not an array which contains: “com.apple.preferences.internetaccounts”, this is a finding.
# 
# Fix Text: This setting is enforced using the "Restrictions Policy" configuration profile.   
# 
# CCI: CCI-000381
# CCI: CCI-001774
#
# Configuration Profile - Restrictions payload > Preferences > disable selected items "Internet Accounts"
# Verify organizational score
AOSX_14_002032="$(/usr/bin/defaults read "$plistlocation" AOSX_14_002032)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_002032" = "1" ]; then
	AOSX_14_002032_Audit="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -A 10 DisabledPreferencePanes | /usr/bin/grep -B 10 ');' | /usr/bin/grep 'internetaccounts')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_14_002032_Audit" = *"com.apple.preferences.internetaccounts"* ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_002032 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_002032 -bool false; else
		/bin/echo "* AOSX_14_002032 Configuration Profile - The macOS system must be configured to disable the system preference pane for Internet Accounts." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_002032 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
# DUPLICATE check to AOSX_14_002039
# 
# Group ID (Vulid): V-95919
# Group Title: SRG-OS-000095-GPOS-00049
# Rule ID: SV-105057r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_002034
# Rule Title: The macOS system must be configured to disable the Siri Setup services.
# 
# Vulnerability Discussion: It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission
# objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by
# providing additional attack vectors.
# 
# Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be
# necessary to support essential organizational operations (e.g., key missions, functions).
# 
# Examples of non-essential capabilities include, but are not limited to, games, software packages, tools, and demonstration software, not related to
# requirements or providing a wide array of functionality not required for every mission, but which cannot be disabled.
# 
# Check Content: 
# To check if SiriSetup is disabled, run the following command:
# 
# /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep SkipSiriSetup
# 
# If the return is not “SkipSiriSetup = 1”, this is a finding.
# 
# Fix Text: This setting is enforced using the "Restrictions Policy" configuration profile.  
# 
# CCI: CCI-000381
#
# Configuration Profile - Login Window payload > Options > Disable Siri setup during login (checked)
# Verify organizational score
AOSX_14_002034="$(/usr/bin/defaults read "$plistlocation" AOSX_14_002034)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_002034" = "1" ]; then
	AOSX_14_002034_Audit="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'SkipSiriSetup = 1')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_14_002034_Audit" > "0" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_002034 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_002034 -bool false; else
		/bin/echo "* AOSX_14_002034 Configuration Profile - The macOS system must disable Siri pop-ups." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_002034 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
# 
# Group ID (Vulid): V-95921
# Group Title: SRG-OS-000095-GPOS-00049
# Rule ID: SV-105059r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_002035
# Rule Title: The macOS system must be configured to disable the Cloud Setup services.
# 
# Vulnerability Discussion: It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission
# objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by
# providing additional attack vectors.
# 
# Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be
# necessary to support essential organizational operations (e.g., key missions, functions).
# 
# Examples of non-essential capabilities include, but are not limited to, games, software packages, tools, and demonstration software, not related to
# requirements or providing a wide array of functionality not required for every mission, but which cannot be disabled.
# 
# Check Content: 
# To check if CloudSetup is disabled, run the following command:
# 
# /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep SkipCloudSetup
# 
# If the return is not “SkipCloudSetup = 1”, this is a finding.
# 
# Fix Text: This setting is enforced using the "Restrictions Policy" configuration profile.  
# 
# CCI: CCI-000381
#
# Configuration Profile - Login Window payload > Options > Disable Apple ID setup during login (checked)
# Verify organizational score
AOSX_14_002035="$(/usr/bin/defaults read "$plistlocation" AOSX_14_002035)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_002035" = "1" ]; then
	AOSX_14_002035_Audit="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'SkipCloudSetup = 1')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_14_002035_Audit" > "0" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_002035 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_002035 -bool false; else
		/bin/echo "* AOSX_14_002035 Configuration Profile - The macOS system must be configured to disable the Cloud Setup services." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_002035 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
# 
# Group ID (Vulid): V-95923
# Group Title: SRG-OS-000095-GPOS-00049
# Rule ID: SV-105061r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_002036
# Rule Title: The macOS system must be configured to disable the Privacy Setup services.
# 
# Vulnerability Discussion: It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission
# objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by
# providing additional attack vectors.
# 
# Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be
# necessary to support essential organizational operations (e.g., key missions, functions).
# 
# Examples of non-essential capabilities include, but are not limited to, games, software packages, tools, and demonstration software, not related to
# requirements or providing a wide array of functionality not required for every mission, but which cannot be disabled.
# 
# Check Content: 
# To check if PrivacySetup is disabled, run the following command:
# 
# /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep SkipPrivacySetup
# 
# If the return is not “SkipPrivacySetup = 1”, this is a finding.
# 
# Fix Text: This setting is enforced using the "Restrictions Policy" configuration profile.  
# 
# CCI: CCI-000381
#
# Configuration Profile - Login Window payload > Options > Disable Privacy setup during login (checked)
# or
# Configuration Profile - Custom payload > com.apple.SetupAssistant.managed > SkipPrivacySetup=true
# Verify organizational score
AOSX_14_002036="$(/usr/bin/defaults read "$plistlocation" AOSX_14_002036)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_002036" = "1" ]; then
	AOSX_14_002036_Audit="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'SkipPrivacySetup = 1')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_14_002036_Audit" > "0" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_002036 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_002036 -bool false; else
		/bin/echo "* AOSX_14_002036 Configuration Profile - The macOS system must be configured to disable the Privacy Setup services." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_002036 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
# 
# Group ID (Vulid): V-95925
# Group Title: SRG-OS-000095-GPOS-00049
# Rule ID: SV-105063r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_002037
# Rule Title: The macOS system must be configured to disable the Cloud Storage Setup services.
# 
# Vulnerability Discussion: It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission
# objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by
# providing additional attack vectors.
# 
# Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be
# necessary to support essential organizational operations (e.g., key missions, functions).
# 
# Examples of non-essential capabilities include, but are not limited to, games, software packages, tools, and demonstration software, not related to
# requirements or providing a wide array of functionality not required for every mission, but which cannot be disabled.
# 
# Check Content: 
# To check if CloudStorage Setup is disabled, run the following command:
# 
# /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep SkipiCloudStorageSetup
# 
# If the return is not “SkipiCloudStorageSetup = 1”, this is a finding.
# 
# Fix Text: This setting is enforced using the "Restrictions Policy" configuration profile.  
# 
# CCI: CCI-000381
#
# Configuration Profile - Login Window payload > Options > Disable iCloud Storage setup during login (checked)
# or
# Configuration Profile - Custom payload > com.apple.SetupAssistant.managed > SkipiCloudStorageSetup=true
# Verify organizational score
AOSX_14_002037="$(/usr/bin/defaults read "$plistlocation" AOSX_14_002037)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_002037" = "1" ]; then
	AOSX_14_002037_Audit="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'SkipiCloudStorageSetup = 1')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_14_002037_Audit" > "0" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_002037 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_002037 -bool false; else
		/bin/echo "* AOSX_14_002037 Configuration Profile - The macOS system must be configured to disable the Cloud Storage Setup services." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_002037 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
# 
# Group ID (Vulid): V-95927
# Group Title: SRG-OS-000074-GPOS-00042
# Rule ID: SV-105065r2_rule
# Severity: CAT I
# Rule Version (STIG-ID): AOSX_14_002038
# Rule Title: The macOS system must be configured to disable the tftpd service.
# 
# Vulnerability Discussion: The "tftpd" service service must be disabled as it sends all data in a clear-text form that can be easily intercepted and read. The
# data needs to be protected at all times during transmission, and encryption is the standard method for protecting data in transit. 
# 
# If the data is not encrypted during transmission, it can be plainly read (i.e., clear text) and easily compromised. Disabling ftp is one way to mitigate this
# risk. Administrators should be instructed to use an alternate service for data transmission that uses encryption, such as SFTP.
# 
# Additionally, the "tftpd" service uses UDP which is not secure.
# 
# Check Content:  
# To check if the tftpd service is disabled, run the following command:
# 
# sudo launchctl print-disabled system | grep tftpd
# 
# If the results do not show the following, this is a finding:
# "com.apple.tftpd" => true
# 
# Fix Text: To disable the tftpd service, run the following command:
# 
# /usr/bin/sudo /bin/launchctl disable system/com.apple.tftpd   
# 
# CCI: CCI-000197
# 
# Verify organizational score
AOSX_14_002038="$(/usr/bin/defaults read "$plistlocation" AOSX_14_002038)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_002038" = "1" ]; then
	AOSX_14_002038_Audit="$(/bin/launchctl print-disabled system | /usr/bin/grep com.apple.tftpd)"
	# If client fails, then note category in audit file
	if [[ $AOSX_14_002038_Audit = *"true"* ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_002038 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_002038 -bool false; else
		/bin/echo "* AOSX_14_002038 The macOS system must unload tftpd." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_002038 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
#
#####################################################################################################

#####################################################################################################
# DUPLICATE check to AOSX_14_002034
# 
# Group ID (Vulid): V-95929
# Group Title: SRG-OS-000095-GPOS-00049
# Rule ID: SV-105067r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_002039
# Rule Title: The macOS system must disable Siri pop-ups.
# 
# Vulnerability Discussion: It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission
# objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by
# providing additional attack vectors.
# 
# Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be
# necessary to support essential organizational operations (e.g., key missions, functions).
# 
# Examples of non-essential capabilities include but are not limited to games, software packages, tools, and demonstration software not related to requirements
# or providing a wide array of functionality not required for every mission but that cannot be disabled.
# 
# The Siri setup pop-up must be disabled.
# 
# Satisfies: SRG-OS-000095-GPOS-00049, SRG-OS-000370-GPOS-00155
# 
# Check Content: 
# To check if the Skip Siri Setup prompt is enabled, run the following command:
# 
# /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep SkipSiriSetup
# 
# If the output is null or "SkipSiriSetup" is not set to "1", this is a finding.
# 
# Fix Text: This setting is enforced using the "Restrictions Policy" configuration profile.  
# 
# CCI: CCI-000381
# CCI: CCI-001774
#
# Configuration Profile - Login Window payload > Options > Disable Siri setup during login (checked)
# Verify organizational score
AOSX_14_002039="$(/usr/bin/defaults read "$plistlocation" AOSX_14_002039)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_002039" = "1" ]; then
	AOSX_14_002039_Audit="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'SkipSiriSetup = 1')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_14_002039_Audit" > "0" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_002039 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_002039 -bool false; else
		/bin/echo "* AOSX_14_002039 Configuration Profile - The macOS system must disable Siri pop-ups." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_002039 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
# 
# Group ID (Vulid): V-95931
# Group Title: SRG-OS-000095-GPOS-00049
# Rule ID: SV-105069r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_002040
# Rule Title: The macOS system must disable iCloud Keychain synchronization.
# 
# Vulnerability Discussion: It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission
# objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by
# providing additional attack vectors.
# 
# Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be
# necessary to support essential organizational operations (e.g., key missions, functions).
# 
# Examples of non-essential capabilities include but are not limited to games, software packages, tools, and demonstration software not related to requirements
# or providing a wide array of functionality not required for every mission but that cannot be disabled.
# 
# Keychain synchronization must be disabled.
# 
# Satisfies: SRG-OS-000095-GPOS-00049, SRG-OS-000370-GPOS-00155
# 
# Check Content: 
# To view the setting for the iCloud Keychain Synchronization configuration, run the following command:
# 
# /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep allowCloudKeychainSync
# 
# If the output is null or not "allowCloudKeychainSync = 0", this is a finding.
# 
# Fix Text: This setting is enforced using the "Restrictions Policy" configuration profile.  
# 
# CCI: CCI-000381
# CCI: CCI-001774
#
# Configuration Profile - Restrictions payload > Functionality > Allow iCloud Keychain (unchecked)
# Verify organizational score
AOSX_14_002040="$(/usr/bin/defaults read "$plistlocation" AOSX_14_002040)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_002040" = "1" ]; then
	AOSX_14_002040_Audit="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'allowCloudKeychainSync = 0')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_14_002040_Audit" > "0" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_002040 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_002040 -bool false; else
		/bin/echo "* AOSX_14_002040 Configuration Profile - The macOS system must disable iCloud Keychain synchronization." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_002040 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
# DUPLICATE check to AOSX_14_002049
# 
# Group ID (Vulid): V-95933
# Group Title: SRG-OS-000095-GPOS-00049
# Rule ID: SV-105071r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_002041
# Rule Title: The macOS system must disable iCloud document synchronization.
# 
# Vulnerability Discussion: It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission
# objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by
# providing additional attack vectors.
# 
# Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be
# necessary to support essential organizational operations (e.g., key missions, functions).
# 
# Examples of non-essential capabilities include but are not limited to games, software packages, tools, and demonstration software not related to requirements
# or providing a wide array of functionality not required for every mission but that cannot be disabled.
# 
# iCloud document synchronization must be disabled.
# 
# Satisfies: SRG-OS-000095-GPOS-00049, SRG-OS-000370-GPOS-00155
# 
# Check Content: 
# To view the setting for the iCloud Document Synchronization configuration, run the following command:
# 
# /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep allowCloudDocumentSync
# 
# If the output is null or not "allowCloudDocumentSync = 0", this is a finding.
# 
# Fix Text: This setting is enforced using the "Restrictions Policy" configuration profile.  
# 
# CCI: CCI-000381
# CCI: CCI-001774
#
# Configuration Profile - Restrictions payload > Functionality > Allow iCloud Drive (unchecked)
# Verify organizational score
AOSX_14_002041="$(/usr/bin/defaults read "$plistlocation" AOSX_14_002041)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_002041" = "1" ]; then
	AOSX_14_002041_Audit="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'allowCloudDocumentSync = 0')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_14_002041_Audit" > "0" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_002041 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_002041 -bool false; else
		/bin/echo "* AOSX_14_002041 Configuration Profile - The macOS system must disable iCloud document synchronization." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_002041 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
# 
# Group ID (Vulid): V-95935
# Group Title: SRG-OS-000095-GPOS-00049
# Rule ID: SV-105073r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_002042
# Rule Title: The macOS system must disable iCloud bookmark synchronization.
# 
# Vulnerability Discussion: It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission
# objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by
# providing additional attack vectors.
# 
# Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be
# necessary to support essential organizational operations (e.g., key missions, functions).
# 
# Examples of non-essential capabilities include but are not limited to games, software packages, tools, and demonstration software not related to requirements
# or providing a wide array of functionality not required for every mission but that cannot be disabled.
# 
# iCloud Bookmark syncing must be disabled.
# 
# Satisfies: SRG-OS-000095-GPOS-00049, SRG-OS-000370-GPOS-00155
# 
# Check Content: 
# To view the setting for the iCloud Bookmark Synchronization configuration, run the following command:
# 
# /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep allowCloudBookmarks
# 
# If the output is null or not "allowCloudBookmarks = 0" this is a finding.
# 
# Fix Text: This setting is enforced using the "Restrictions Policy" configuration profile.  
# 
# CCI: CCI-000381
# CCI: CCI-001774
#
# Configuration Profile - Restrictions payload > Functionality > Allow iCloud Bookmarks (unchecked)
# Verify organizational score
AOSX_14_002042="$(/usr/bin/defaults read "$plistlocation" AOSX_14_002042)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_002042" = "1" ]; then
	AOSX_14_002042_Audit="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'allowCloudBookmarks = 0')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_14_002042_Audit" > "0" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_002042 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_002042 -bool false; else
		/bin/echo "* AOSX_14_002042 Configuration Profile - The macOS system must disable iCloud bookmark synchronization." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_002042 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
# 
# Group ID (Vulid): V-95937
# Group Title: SRG-OS-000095-GPOS-00049
# Rule ID: SV-105075r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_002043
# Rule Title: The macOS system must disable iCloud photo library.
# 
# Vulnerability Discussion: It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission
# objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by
# providing additional attack vectors.
# 
# Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be
# necessary to support essential organizational operations (e.g., key missions, functions).
# 
# Examples of non-essential capabilities include but are not limited to games, software packages, tools, and demonstration software not related to requirements
# or providing a wide array of functionality not required for every mission but that cannot be disabled.
# 
# iCloud Photo Library must be disabled.
# 
# Satisfies: SRG-OS-000095-GPOS-00049, SRG-OS-000370-GPOS-00155
# 
# Check Content: 
# To view the setting for the iCloud Photo Library configuration, run the following command:
# 
# /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep allowCloudPhotoLibrary
# 
# If the output is null or not "allowCloudPhotoLibrary = 0", this is a finding.
# 
# Fix Text: This setting is enforced using the "Restrictions Policy" configuration profile.  
# 
# CCI: CCI-000381
# CCI: CCI-001774
#
# Configuration Profile - Restrictions payload > Functionality > Allow iCloud Photos (unchecked)
# or
# Configuration Profile - Custom payload > com.apple.applicationaccess > allowCloudPhotoLibrary=false
# Verify organizational score
AOSX_14_002043="$(/usr/bin/defaults read "$plistlocation" AOSX_14_002043)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_002043" = "1" ]; then
	AOSX_14_002043_Audit="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'allowCloudPhotoLibrary = 0')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_14_002043_Audit" > "0" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_002043 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_002043 -bool false; else
		/bin/echo "* AOSX_14_002043 Configuration Profile - The macOS system must disable iCloud Photo Library." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_002043 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
# DUPLICATE check to AOSX_14_002041
# 
# Group ID (Vulid): V-95939
# Group Title: SRG-OS-000370-GPOS-00155
# Rule ID: SV-105077r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_002049
# Rule Title: The macOS system must disable Cloud Document Sync.
# 
# Vulnerability Discussion: It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission
# objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by
# providing additional attack vectors.
# 
# Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be
# necessary to support essential organizational operations (e.g., key missions, functions).
# 
# Examples of non-essential capabilities include but are not limited to games, software packages, tools, and demonstration software not related to requirements
# or providing a wide array of functionality not required for every mission but that cannot be disabled.
# 
# Cloud Document Sync must be disabled.
# 
# Check Content: 
# To view the setting for the iCloud Desktop and Documents configuration, run the following command:
# 
# /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep allowCloudDocumentSync
# 
# If the output is null or not "allowCloudDocumentSync = 0", this is a finding.
# 
# Fix Text: This setting is enforced using the "Restrictions Policy" configuration profile.  
# 
# CCI: CCI-001774
#
# Configuration Profile - Restrictions payload > Functionality > Allow iCloud Drive (unchecked)
# Verify organizational score
AOSX_14_002049="$(/usr/bin/defaults read "$plistlocation" AOSX_14_002049)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_002049" = "1" ]; then
	AOSX_14_002049_Audit="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'allowCloudDocumentSync = 0')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_14_002049_Audit" > "0" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_002049 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_002049 -bool false; else
		/bin/echo "* AOSX_14_002049 Configuration Profile - The macOS system must disable Cloud document Sync." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_002049 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
# 
# Group ID (Vulid): V-95941
# Group Title: SRG-OS-000480-GPOS-00227
# Rule ID: SV-105079r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_002050
# Rule Title: The macOS system must disable the Screen Sharing feature.
# 
# Vulnerability Discussion: The Screen Sharing feature allows remote users to view or control the desktop of the current user. A malicious user can take
# advantage of screen sharing to gain full access to the system remotely, either with stolen credentials or by guessing the username and password. Disabling
# Screen Sharing mitigates this risk.
# 
# Check Content: 
# To check if the Screen Sharing service is disabled, use the following command:
# 
# /usr/bin/sudo /bin/launchctl print-disabled system | /usr/bin/grep com.apple.screensharing
# 
# If the results do not show the following, this is a finding:
# 
# "com.apple.screensharing" => true
# 
# Fix Text: To disable the Screen Sharing service, run the following command:
# 
# /usr/bin/sudo /bin/launchctl disable system/com.apple.screensharing
# 
# The system may need to be restarted for the update to take effect.  
# 
# CCI: CCI-000366
#
# Verify organizational score
AOSX_14_002050="$(/usr/bin/defaults read "$plistlocation" AOSX_14_002050)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_002050" = "1" ]; then
	AOSX_14_002050_Audit="$(/bin/launchctl print-disabled system | /usr/bin/grep com.apple.screensharing)"
	# If client fails, then note category in audit file
	if [[ $AOSX_14_002050_Audit = *"true"* ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_002050 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_002050 -bool false; else
		/bin/echo "* AOSX_14_002050 The macOS system must disable the Screen Sharing feature." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_002050 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
# 
# Group ID (Vulid): V-95943
# Group Title: SRG-OS-000480-GPOS-00227
# Rule ID: SV-105081r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_002060
# Rule Title: The macOS system must allow only applications downloaded from the App Store and identified developers to run.
# 
# Vulnerability Discussion: Gatekeeper settings must be configured correctly to only allow the system to run applications downloaded from the Mac App Store or
# applications signed with a valid Apple Developer ID code. Administrator users will still have the option to override these settings on a per-app basis.
# Gatekeeper is a security feature that ensures that applications must be digitally signed by an Apple-issued certificate in order to run. Digital signatures
# allow the macOS host to verify that the application has not been modified by a malicious third party.
# 
# Check Content: 
# To verify only applications downloaded from the App Store are allowed to run, type the following command:
# 
# /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -E '(EnableAssessment | AllowIdentifiedDevelopers)'
# 
# If the return is null, or is not the following, this is a finding:
# AllowIdentifiedDevelopers = 1;
# EnableAssessment = 1;
# 
# Fix Text: This setting is enforced using the "Restrictions Policy" configuration profile.  
# 
# CCI: CCI-000366
#
# Configuration Profile - Security & Privacy payload > General > Mac App Store and identified developers (selected)
# Verify organizational score
AOSX_14_002060="$(/usr/bin/defaults read "$plistlocation" AOSX_14_002060)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_002060" = "1" ]; then
	AOSX_14_002060_Audit1="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'AllowIdentifiedDevelopers = 1')"
	AOSX_14_002060_Audit2="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'EnableAssessment = 1')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_14_002060_Audit1" > "0" ]] && [[ "$AOSX_14_002060_Audit2" > "0" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_002060 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_002060 -bool false; else
		/bin/echo "* AOSX_14_002060 Configuration Profile - The macOS system must allow only applications downloaded from the App Store and identified developers to run." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_002060 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
# 
# Group ID (Vulid): V-95945
# Group Title: SRG-OS-000480-GPOS-00227
# Rule ID: SV-105083r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_002061
# Rule Title: The macOS system must be configured so that end users cannot override Gatekeeper settings.
# 
# Vulnerability Discussion: Gatekeeper must be configured with a configuration profile to prevent normal users from overriding its setting. If users are allowed
# to disable Gatekeeper or set it to a less restrictive setting, malware could be introduced into the system. Gatekeeper is a security feature that ensures
# applications must be digitally signed by an Apple-issued certificate in order to run. Digital signatures allow the macOS host to verify the application has
# not been modified by a malicious third party.
# 
# Check Content: 
# To verify only applications downloaded from the App Store are allowed to run, type the following command:
# 
# /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep DisableOverride
# 
# If the return is null or is not the following, this is a finding:
# DisableOverride = 1;
# 
# Fix Text: This setting is enforced using the "RestrictionsPolicy" configuration profile.  
# 
# CCI: CCI-000366
#
# Configuration Profile - Security & Privacy payload > General > Do not allow user to override Gatekeeper setting (checked)
# Verify organizational score
AOSX_14_002061="$(/usr/bin/defaults read "$plistlocation" AOSX_14_002061)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_002061" = "1" ]; then
	AOSX_14_002061_Audit="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'DisableOverride = 1')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_14_002061_Audit" > "0" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_002061 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_002061 -bool false; else
		/bin/echo "* AOSX_14_002061 Configuration Profile - The macOS system must be configured so that end users cannot override Gatekeeper settings." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_002061 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
# 
# Group ID (Vulid): V-95947
# Group Title: SRG-OS-000481-GPOS-000481
# Rule ID: SV-105085r1_rule
# Severity: CAT III
# Rule Version (STIG-ID): AOSX_14_002062
# Rule Title: The macOS system must be configured with Bluetooth turned off unless approved by the organization.
# 
# Vulnerability Discussion: Without protection of communications with wireless peripherals, confidentiality and integrity may be compromised because unprotected
# communications can be intercepted and either read, altered, or used to compromise the operating system.
# 
# This requirement applies to wireless peripheral technologies (e.g., wireless mice, keyboards, displays, etc.) used with an operating system. Wireless
# peripherals (e.g., Wi-Fi/Bluetooth/IR Keyboards, Mice, and Pointing Devices and Near Field Communications [NFC]) present a unique challenge by creating an
# open, unsecured port on a computer. Wireless peripherals must meet DoD requirements for wireless data transmission and be approved for use by the AO. Even
# though some wireless peripherals, such as mice and pointing devices, do not ordinarily carry information that need to be protected, modification of
# communications with these wireless peripherals may be used to compromise the operating system. Communication paths outside the physical protection of a
# controlled boundary are exposed to the possibility of interception and modification.
# 
# Protecting the confidentiality and integrity of communications with wireless peripherals can be accomplished by physical means (e.g., employing physical
# barriers to wireless radio frequencies) or by logical means (e.g., employing cryptographic techniques). If physical means of protection are employed, then
# logical means (cryptography) do not have to be employed, and vice versa. If the wireless peripheral is only passing telemetry data, encryption of the data may
# not be required.
# 
# Check Content: 
# If Bluetooth connectivity is required to facilitate use of approved external devices, this is Not Applicable.
# 
# To check if Bluetooth is disabled, run the following command:
# 
# /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep DisableBluetooth
# 
# If the return is null or is not "DisableBluetooth = 1", this is a finding.
# 
# Fix Text: This setting is enforced using the "Custom Policy" configuration profile.  
# 
# CCI: CCI-002418
#
# Configuration Profile - Custom payload > com.apple.MCXBluetooth > DisableBluetooth=true
# Verify organizational score
AOSX_14_002062="$(/usr/bin/defaults read "$plistlocation" AOSX_14_002062)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_002062" = "1" ]; then
	AOSX_14_002062_Audit="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'DisableBluetooth = 1')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_14_002062_Audit" > "0" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_002062 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_002062 -bool false; else
		/bin/echo "* AOSX_14_002062 Configuration Profile - The macOS system must be configured with Bluetooth turned off." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_002062 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
# 
# Group ID (Vulid): V-95949
# Group Title: SRG-OS-000364-GPOS-00151
# Rule ID: SV-105087r1_rule
# Severity: CAT I
# Rule Version (STIG-ID): AOSX_14_002063
# Rule Title: The macOS system must disable the guest account.
# 
# Vulnerability Discussion: Failure to provide logical access restrictions associated with changes to system configuration may have significant effects on the
# overall security of the system.
# 
# When dealing with access restrictions pertaining to change control, it should be noted that any changes to the hardware, software, and/or firmware components
# of the operating system can have significant effects on the overall security of the system.
# 
# Accordingly, only qualified and authorized individuals should be allowed to obtain access to operating system components for the purposes of initiating
# changes, including upgrades and modifications.
# 
# Logical access restrictions include, for example, controls that restrict access to workflow automation, media libraries, abstract layers (e.g., changes
# implemented into third-party interfaces rather than directly into information systems), and change windows (e.g., changes occur only during specified times,
# making unauthorized changes easy to discover).
# 
# Check Content: 
# To check that the system is configured to disable the guest account, run the following command:
# 
# # /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep DisableGuestAccount
# 
# If the result is null or not "DisableGuestAccount = 1", this is a finding.
# 
# Fix Text: This is managed with Login Window Policy.  
# 
# CCI: CCI-001813
#
# Configuration Profile - Login Window payload > Options > Allow Guest User (unchecked)
# Verify organizational score
AOSX_14_002063="$(/usr/bin/defaults read "$plistlocation" AOSX_14_002063)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_002063" = "1" ]; then
	AOSX_14_002063_Audit="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'DisableGuestAccount = 1')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_14_002063_Audit" > "0" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_002063 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_002063 -bool false; else
		/bin/echo "* AOSX_14_002063 Configuration Profile - The macOS system must disable the guest account." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_002063 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
# 
# Group ID (Vulid): V-95951
# Group Title: SRG-OS-000366-GPOS-00153
# Rule ID: SV-105089r1_rule
# Severity: CAT I
# Rule Version (STIG-ID): AOSX_14_002064
# Rule Title: The macOS system must have the security assessment policy subsystem enabled.
# 
# Vulnerability Discussion: Any changes to the hardware, software, and/or firmware components of the information system and/or application can potentially have
# significant effects on the overall security of the system.
# 
# Accordingly, software defined by the organization as critical must be signed with a certificate that is recognized and approved by the organization.
# 
# Check Content: 
# To check the status of the Security assessment policy subsystem, run the following command:
# 
# /usr/bin/sudo /usr/sbin/spctl --status | /usr/bin/grep enabled
# 
# If nothing is returned, this is a finding.
# 
# Fix Text: To enable the Security assessment policy subsystem, run the following command:
# 
# /usr/bin/sudo /usr/sbin/spctl --master-enable  
# 
# CCI: CCI-001749
# 
# Verify organizational score
AOSX_14_002064="$(/usr/bin/defaults read "$plistlocation" AOSX_14_002064)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_002064" = "1" ]; then
	AOSX_14_002064_Audit="$(/usr/sbin/spctl --status | /usr/bin/grep enabled)"
	# If client fails, then note category in audit file
	if [[ $AOSX_14_002064_Audit = *"enabled"* ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_002064 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_002064 -bool false; else
		/bin/echo "* AOSX_14_002064 The macOS system must have the security assessment policy subsystem enabled." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_002064 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
# REDUNDANT to AOSX_14_002068
# 
# Group ID (Vulid): V-95533
# Group Title: SRG-OS-000480-GPOS-00230
# Rule ID: SV-104721r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_002065
# Rule Title: The macOS system must limit the ability of non-privileged users to grant other users direct access to the contents of their home directories/folders.
# 
# Vulnerability Discussion: Users' home directories/folders may contain information of a sensitive nature. Non-privileged users should coordinate any sharing of
# information with an SA through shared resources.
# 
# Check Content: 
# For each listing, with the exception of "Shared", verify that the directory is owned by the username, that only the owner has "write" permissions, and the
# correct Access Control Entry is listed.
# 
# To verify permissions on users' home directories, use the following command:
# 
# # ls -le /Users
# 
# drwxr-xr-x+ 12 Guest _guest 384 Apr 2 09:40 Guest
# 
# 0: group:everyone deny delete
# 
# drwxrwxrwt 4 root wheel 128 Mar 28 05:53 Shared
# 
# drwxr-xr-x+ 13 admin staff 416 Apr 8 08:58 admin
# 
# 0: group:everyone deny delete
# 
# drwxr-xr-x+ 11 test user 352 Apr 8 09:00 test
# 
# 0: group:everyone deny delete
# 
# If the directory is not owned by the user, this is a finding.
# 
# If anyone other than the user has "write" permissions to the directory, this is a finding.
# 
# If the Access Control Entry listed is not "0: group:everyone deny delete", this is a finding.
# 
# Fix Text: To reset the permissions on a users' home directory to their defaults, run the following command, where "username" is the user's short name:
# 
# sudo diskutil resetUserPermissions / username  
# 
# CCI: CCI-000366
# 
# Verify organizational score
AOSX_14_002065="$(/usr/bin/defaults read "$plistlocation" AOSX_14_002065)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_002065" = "1" ]; then
	AOSX_14_002065_Audit=""
	IFS=$'\n'
	for userDirs in $(/bin/ls -d /Users/* 2> /dev/null | /usr/bin/cut -f3 -d'/' | /usr/bin/grep -v "Shared" | /usr/bin/grep -v "Guest"); do
		/bin/echo "working on $userDirs"
		#
		# Count directories in /Users that that are not "0: group:everyone deny delete"
		AOSX_14_002065_Audit1=""
		AOSX_14_002065_Audit1=$(/bin/ls -led /Users/"$userDirs" 2> /dev/null | /usr/bin/grep -v /Users/"$userDirs" | /usr/bin/grep -v -c "0: group:everyone deny delete")
		/bin/echo "Number of directories in /Users that that are not \"0: group:everyone deny delete\": $AOSX_14_002065_Audit1"
		#
		# Count directories in /Users that are not "drwxr-xr-x"
		AOSX_14_002065_Audit2=""
		AOSX_14_002065_Audit2=$(/bin/ls -ld  /Users/"$userDirs" 2> /dev/null | /usr/bin/grep -v -c "drwxr-xr-x")
		/bin/echo "Number of directories in /Users that are not \"drwxr-xr-x\": $AOSX_14_002065_Audit2"
		#
		# Count directories in /Users that are not owned by the user
		AOSX_14_002065_Audit3=""
		AOSX_14_002065_Audit3=$(/bin/ls -ld  /Users/"$userDirs" 2> /dev/null | /usr/bin/grep -v -c .*" $userDirs ".*" /Users/$userDirs")
		/bin/echo "Number of directories in /Users that are not owned by $userDirs: $AOSX_14_002065_Audit3"
		#
		if [[ "$AOSX_14_002065_Audit1" < "1" ]] && [[ "$AOSX_14_002065_Audit2" < "1" ]] && [[ "$AOSX_14_002065_Audit3" < "1" ]]; then
			/bin/echo "$userDirs Pass"; else
			AOSX_14_002065_Audit="Fail"
			/bin/echo "$userDirs $AOSX_14_002065_Audit"
		fi
	done
	unset IFS
	#
	if [[ "$AOSX_14_002065_Audit" != "Fail" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_002065 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_002065 -bool false; else
		/bin/echo "* AOSX_14_002065 The macOS system must limit the ability of non-privileged users to grant other users direct access to the contents of their home directories/folders." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_002065 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
# 
# Group ID (Vulid): V-95953
# Group Title: SRG-OS-000480-GPOS-00229
# Rule ID: SV-105091r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_002066
# Rule Title: The macOS system must not allow an unattended or automatic logon to the system.
# 
# Vulnerability Discussion: Failure to restrict system access to authenticated users negatively impacts operating system security.
# 
# Check Content: 
# To check if the system is configured to automatically log on, run the following command:
# 
# /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep DisableAutoLoginClient
# 
# If "com.apple.login.mcx.DisableAutoLoginClient" is not set to "1", this is a finding.
# 
# Fix Text: This setting is enforced using the "Login Window Policy" configuration profile.  
# 
# CCI: CCI-000366
#
# Configuration Profile - Login Window payload > Options > Disable automatic login (checked)
# Verify organizational score
AOSX_14_002066="$(/usr/bin/defaults read "$plistlocation" AOSX_14_002066)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_002066" = "1" ]; then
	AOSX_14_002066_Audit="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c '"com.apple.login.mcx.DisableAutoLoginClient" = 1')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_14_002066_Audit" > "0" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_002066 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_002066 -bool false; else
		/bin/echo "* AOSX_14_002066 Configuration Profile - The macOS system must not allow an unattended or automatic logon to the system." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_002066 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
# 
# Group ID (Vulid): V-95537
# Group Title: SRG-OS-000362-GPOS-00149
# Rule ID: SV-104723r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_002067
# Rule Title: The macOS system must prohibit user installation of software without explicit privileged status.
# 
# Vulnerability Discussion: Allowing regular users to install software, without explicit privileges, creates the risk that untested or potentially malicious
# software will be installed on the system. Explicit privileges (escalated or administrative privileges) provide the regular user with explicit capabilities and
# control that exceeds the rights of a regular user.
# 
# Operating system functionality will vary, and while users are not permitted to install unapproved software, there may be instances where the organization
# allows the user to install approved software packages, such as from an approved software repository.
# 
# The operating system or software configuration management utility must enforce control of software installation by users based upon what types of software
# installations are permitted (e.g., updates and security patches to existing software) and what types of installations are prohibited (e.g., software whose
# pedigree with regard to being potentially malicious is unknown or suspect) by the organization.
# 
# Check Content: 
# To check if the system is configured to prohibit user installation of software, first check to ensure the Parental Controls are enabled with the following command:
# 
# /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -A 6 familyControlsEnabled | grep “/Users"
# 
# If the result is null, or does not contain “/Users/“, this is a finding.
# 
# Fix Text: This setting is enforced using the "Restrictions Policy" configuration profile.  
# 
# CCI: CCI-001812
#
# Configuration Profile - Restrictions payload > Applications > Disallow "/Users/"
# Verify organizational score
AOSX_14_002067="$(/usr/bin/defaults read "$plistlocation" AOSX_14_002067)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_002067" = "1" ]; then
	AOSX_14_002067_Audit="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -A 10 familyControlsEnabled | /usr/bin/grep -B 10 ');' | /usr/bin/grep '/Users')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_14_002067_Audit" = *"/Users"* ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_002067 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_002067 -bool false; else
		/bin/echo "* AOSX_14_002067 Configuration Profile - The macOS system must prohibit user installation of software without explicit privileged status." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_002067 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
# AOSX_14_002065 is redundant to this
# 
# Group ID (Vulid): V-95955
# Group Title: SRG-OS-000480-GPOS-00228
# Rule ID: SV-105093r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_002068
# Rule Title: The macOS system must set permissions on user home directories to prevent users from having access to read or modify another users files.
# 
# Vulnerability Discussion: Configuring the operating system to use the most restrictive permissions possible for user home directories helps to protect against
# inadvertent disclosures.
# 
# Check Content: 
# To verify that permissions are set correctly on user home directories, use the following commands:
# 
# ls -le /Users
# 
# Should return a listing of the permissions of the root of every user account configured on the system. For each of the users, the permissions should be:
# "drwxr-xr-x+" with the user listed as the owner and the group listed as "staff". The plus (+) sign indicates an associated Access Control List, which should be:
# 0: group:everyone deny delete
# 
# For every authorized user account, also run the following command:
# /usr/bin/sudo ls -le /Users/userid, where userid is an existing user.
# 
# This command will return the permissions of all of the objects under the users' home directory. The permissions for each of the subdirectories should be:
# drwx------+
# 0: group:everyone deny delete
# 
# With the exception of the "Public" directory, whose permissions should match the following:
# drwxr-xr-x+
# 0: group:everyone deny delete
# 
# If the permissions returned by either of these checks differ from what is shown, this is a finding.
# 
# Fix Text: To ensure the appropriate permissions are set for each user on the system, run the following command:
# 
# diskutil resetUserPermissions / userid, where userid is the user name for the user whose home directory permissions need to be repaired.  
# 
# CCI: CCI-000366
# 
# Verify organizational score
AOSX_14_002068="$(/usr/bin/defaults read "$plistlocation" AOSX_14_002068)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_002068" = "1" ]; then
	AOSX_14_002068_Audit=""
	IFS=$'\n'
	for userDirs in $(/bin/ls -d /Users/* 2> /dev/null | /usr/bin/cut -f3 -d'/' | /usr/bin/grep -v "Shared" | /usr/bin/grep -v "Guest"); do
		/bin/echo "working on $userDirs"
		#
		# Count directories in /Users that that are not "0: group:everyone deny delete"
		AOSX_14_002068_Audit1=""
		AOSX_14_002068_Audit1=$(/bin/ls -led /Users/"$userDirs" 2> /dev/null | /usr/bin/grep -v /Users/"$userDirs" | /usr/bin/grep -v -c "0: group:everyone deny delete")
		/bin/echo "Number of directories in /Users that that are not \"0: group:everyone deny delete\": $AOSX_14_002068_Audit1"
		#
		# Count directories in /Users that are not "drwxr-xr-x"
		AOSX_14_002068_Audit2=""
		AOSX_14_002068_Audit2=$(/bin/ls -ld  /Users/"$userDirs" 2> /dev/null | /usr/bin/grep -v -c "drwxr-xr-x")
		/bin/echo "Number of directories in /Users that are not \"drwxr-xr-x\": $AOSX_14_002068_Audit2"
		#
		# Count directories in /Users that are not owned by the user
		AOSX_14_002068_Audit3=""
		AOSX_14_002068_Audit3=$(/bin/ls -ld  /Users/"$userDirs" 2> /dev/null | /usr/bin/grep -v -c .*" $userDirs ".*" /Users/$userDirs")
		/bin/echo "Number of directories in /Users that are not owned by $userDirs: $AOSX_14_002068_Audit3"
		#
		# Count directories in ~/ that are not "0: group:everyone deny delete"
		AOSX_14_002068_Audit4=""
		AOSX_14_002068_Audit4=$(/bin/ls -led /Users/"$userDirs"/*/ 2> /dev/null | /usr/bin/grep -v /Users/"$userDirs" | /usr/bin/grep -v -c "0: group:everyone deny delete")
		/bin/echo "Number of directories in ~/ that that are not \"0: group:everyone deny delete\": $AOSX_14_002068_Audit4"
		#
		# Count directories in ~/ that are not "drwx------+ or drwx------@"
		AOSX_14_002068_Audit5=""
		AOSX_14_002068_Audit5=$(/bin/ls -ld  /Users/"$userDirs"/*/ 2> /dev/null | /usr/bin/grep -v "Public" | /usr/bin/grep -v -c "drwx------+ \|drwx------@ ")
		/bin/echo "Number of directories in ~/ that are not \"drwx------ or drwx------@\": $AOSX_14_002068_Audit5"
		#
		# Count directories and files in ~/ that are not owned by the user
		AOSX_14_002068_Audit6=""
		AOSX_14_002068_Audit6=$(/bin/ls -ld  /Users/"$userDirs"/* 2> /dev/null | /usr/bin/grep -v -c .*" $userDirs ".*" /Users/$userDirs")
		/bin/echo "Number of directories and files in ~/ that are not owned by $userDirs: $AOSX_14_002068_Audit6"
		#
		if [[ "$AOSX_14_002068_Audit1" < "1" ]] && [[ "$AOSX_14_002068_Audit2" < "1" ]] && [[ "$AOSX_14_002068_Audit3" < "1" ]] && [[ "$AOSX_14_002068_Audit4" < "1" ]] && [[ "$AOSX_14_002068_Audit5" < "1" ]] && [[ "$AOSX_14_002068_Audit6" < "1" ]]; then
			/bin/echo "$userDirs Pass"; else
			AOSX_14_002068_Audit="Fail"
			/bin/echo "$userDirs $AOSX_14_002068_Audit"
		fi
	done
	unset IFS
	#
	if [[ "$AOSX_14_002068_Audit" != "Fail" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_002068 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_002068 -bool false; else
		/bin/echo "* AOSX_14_002068 The macOS system must limit the ability of non-privileged users to grant other users direct access to the contents of their home directories/folders." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_002068 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
# 
# Group ID (Vulid): V-95541
# Group Title: SRG-OS-000114-GPOS-00059
# Rule ID: SV-104725r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_002069
# Rule Title: The macOS system must uniquely identify peripherals before establishing a connection.
# 
# Vulnerability Discussion: Without identifying devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity.
# 
# Peripherals include, but are not limited to, such devices as flash drives, external storage, and printers.
# 
# Check Content: 
# To check that macOS is configured to require authentication to all system preference panes, use the following commands:
# 
# /usr/bin/sudo /usr/bin/security authorizationdb read system.preferences | grep -A1 shared
# 
# If what is returned does not include the following, this is a finding.
#       <key>shared</key>
#       <false/>
# 
# Fix Text: 
# To ensure that authentication is required to access all system level preference panes use the following procedure:
# 
# Copy the authorization database to a file using the following command:
# /usr/bin/sudo /usr/bin/security authorizationdb read system.preferences > ~/Desktop/authdb.txt
# edit the file to change:
# <key>shared</key>
# <true/>
# To read:
# <key>shared</key>
# <false/>
# 
# Reload the authorization database with the following command:
# /usr/bin/sudo /usr/bin/security authorizationdb write system.preferences < ~/Desktop/authdb.txt  
# 
# CCI: CCI-000778
# 
# Verify organizational score
AOSX_14_002069="$(/usr/bin/defaults read "$plistlocation" AOSX_14_002069)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_002069" = "1" ]; then
	AOSX_14_002069_Audit="$(/usr/bin/security authorizationdb read system.preferences 2> /dev/null | /usr/bin/grep -A1 shared | /usr/bin/grep -c "false")"
	# If client fails, then note category in audit file
	if [[ $AOSX_14_002069_Audit > "0" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_002069 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_002069 -bool false; else
		/bin/echo "* AOSX_14_002069 The macOS system must uniquely identify peripherals before establishing a connection." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_002069 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
# 
# Group ID (Vulid): V-95543
# Group Title: SRG-OS-000480-GPOS-00227
# Rule ID: SV-104727r1_rule
# Severity: CAT I
# Rule Version (STIG-ID): AOSX_14_002070
# Rule Title: The macOS system must use an approved antivirus program.
# 
# Vulnerability Discussion: An approved antivirus product must be installed and configured to run.
# 
# Malicious software can establish a base on individual desktops and servers. Employing an automated mechanism to detect this type of software will aid in
# elimination of the software from the operating system.
# 
# Check Content: 
# Ask the System Administrator (SA) or Information System Security Officer (ISSO) if an approved antivirus solution is loaded on the system. The antivirus
# solution may be bundled with an approved host-based security solution.
# 
# If there is no local antivirus solution installed on the system, this is a finding.
# 
# Fix Text: Install an approved antivirus solution onto the system.  
# 
# CCI: CCI-000366
#
# Verify organizational score
AOSX_14_002070="$(/usr/bin/defaults read "$plistlocation" AOSX_14_002070)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_002070" = "1" ]; then
	# If client fails, then note category in audit file
	if [[ -f "/Library/McAfee/agent/bin/cmdagent" ]]; then # Check for the McAfee cmdagent
		/bin/echo $(/bin/date -u) "AOSX_14_002070 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_002070 -bool false; else
		/bin/echo "* AOSX_14_002070 Managed by McAfee EPO Agent - The macOS system must use an approved antivirus program." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_002070 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
# 
# Group ID (Vulid): V-95957
# Group Title: SRG-OS-000066-GPOS-00034
# Rule ID: SV-105095r1_rule
# Severity: CAT I
# Rule Version (STIG-ID): AOSX_14_003001
# Rule Title: The macOS system must issue or obtain public key certificates under an appropriate certificate policy from an approved service provider.
# 
# Vulnerability Discussion: DoD-approved certificates must be installed to the System Keychain so they will be available to all users.
# 
# For user certificates, each organization obtains certificates from an approved, shared service provider, as required by OMB policy. For federal agencies
# operating a legacy public key infrastructure cross-certified with the Federal Bridge Certification Authority at medium assurance or higher, this Certification
# Authority will suffice. This control focuses on certificates with a visibility external to the information system and does not include certificates related to
# internal system operations; for example, application-specific time services. Use of weak or untested encryption algorithms undermines the purposes of
# utilizing encryption to protect data. The operating system must implement cryptographic modules adhering to the higher standards approved by the federal
# government since this provides assurance they have been tested and validated.
# 
# Satisfies: SRG-OS-000066-GPOS-00034, SRG-OS-000478-GPOS-00223
# 
# Check Content: 
# To view a list of installed certificates, run the following command:
# 
# /usr/bin/sudo /usr/bin/security dump-keychain | /usr/bin/grep labl | awk -F\" '{ print $4 }'
# 
# If this list does not contain approved certificates, this is a finding.
# 
# Fix Text: Obtain the approved DOD certificates from the appropriate authority. Use Keychain Access from "/Applications/Utilities" to add certificates to the
# System Keychain.  
# 
# CCI: CCI-000185
# CCI: CCI-002450
#
# Configuration Profile - Certificate payload
# Verify organizational score
AOSX_14_003001="$(/usr/bin/defaults read "$plistlocation" AOSX_14_003001)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_003001" = "1" ]; then
	AOSX_14_003001_Audit="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'com.apple.security.root')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_14_003001_Audit" > "0" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_003001 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_003001 -bool false; else
		/bin/echo "* AOSX_14_003001 Configuration Profile - The macOS system must issue or obtain public key certificates under an appropriate certificate policy from an approved service provider." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_003001 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
# DUPLICATE check to AOSX_14_001060
# 
# Group ID (Vulid): V-95959
# Group Title: SRG-OS-000067-GPOS-00035
# Rule ID: SV-105097r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_003002
# Rule Title: The macOS system must enable certificate for smartcards.
# 
# Vulnerability Discussion: To prevent untrusted certificates the certificates on a smartcard card must be valid in these ways: its issuer is system-trusted,
# the certificate is not expired, its "valid-after" date is in the past, and it passes CRL and OCSP checking.
# 
# Check Content: 
# To view the setting for the smartcard certification configuration, run the following command:
# 
# sudo /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep checkCertificateTrust
# 
# If the return is not "checkCertificateTrust = 1;" with the numeral equal to 1 or greater, this is a finding.
# 
# Fix Text: This setting is enforced using the "Smart Card Policy" configuration profile.
# 
# Note: Before applying the "Smart Card Policy", the supplemental guidance provided with the STIG should be consulted to ensure continued access to the
# operating system.  
# 
# CCI: CCI-000186
#
# Configuration Profile - Smart Card payload > VERIFY CERTIFICATE TRUST (Check Certificate)
# Verify organizational score
AOSX_14_003002="$(/usr/bin/defaults read "$plistlocation" AOSX_14_003002)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_003002" = "1" ]; then
	AOSX_14_003002_Audit="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'checkCertificateTrust = 1')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_14_003002_Audit" > "0" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_003002 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_003002 -bool false; else
		/bin/echo "* AOSX_14_003002 Configuration Profile - The macOS system must enable certificate for smartcards." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_003002 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
# 
# Group ID (Vulid): V-95961
# Group Title: SRG-OS-000068-GPOS-00036
# Rule ID: SV-105099r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_003005
# Rule Title: The macOS system must map the authenticated identity to the user or group account for PKI-based authentication.
# 
# Vulnerability Discussion: Without mapping the certificate used to authenticate to the user account, the ability to determine the identity of the individual
# user or group will not be available for forensic analysis.
# 
# Check Content: 
# To view the setting for the smartcard certification configuration, run the following command:
# 
# sudo /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep enforceSmartCard
# 
# If the return is not "enforceSmartCard = 1;" this is a finding.
# 
# Fix Text: For stand-alone systems, this setting is enforced using the "Smart Card Policy" configuration profile.
# 
# Note: Before applying the "Smart Card Policy", the supplemental guidance provided with the STIG should be consulted to ensure continued access to the
# operating system.  
# 
# CCI: CCI-000187
#
# Configuration Profile - Smart Card payload > Enforce Smart Card use (checked)
# Verify organizational score
AOSX_14_003005="$(/usr/bin/defaults read "$plistlocation" AOSX_14_003005)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_003005" = "1" ]; then
	AOSX_14_003005_Audit="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'enforceSmartCard = 1')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_14_003005_Audit" > "0" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_003005 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_003005 -bool false; else
		/bin/echo "* AOSX_14_003005 Configuration Profile - The macOS system must map the authenticated identity to the user or group account for PKI-based authentication." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_003005 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
# 
# Group ID (Vulid): V-95963
# Group Title: SRG-OS-000071-GPOS-00039
# Rule ID: SV-105101r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_003007
# Rule Title: The macOS system must enforce password complexity by requiring that at least one numeric character be used.
# 
# Vulnerability Discussion: Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or
# strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.
# 
# Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of
# possible combinations that need to be tested before the password is compromised.
# 
# Check Content: 
# To check the currently applied policies for passwords and accounts, use the following command:
# 
# /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep requireAlphanumeric
# 
# If the return is not “requireAlphanumeric = 1”, this is a finding.
# 
# Fix Text: This setting is enforced using the "Passcode Policy" configuration profile.  
# 
# CCI: CCI-000194
#
# Configuration Profile - Passcode payload > Require alphanumeric value (checked)
# Verify organizational score
AOSX_14_003007="$(/usr/bin/defaults read "$plistlocation" AOSX_14_003007)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_003007" = "1" ]; then
	AOSX_14_003007_Audit="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'requireAlphanumeric = 1')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_14_003007_Audit" > "0" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_003007 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_003007 -bool false; else
		/bin/echo "* AOSX_14_003007 Configuration Profile - The macOS system must enforce password complexity by requiring that at least one numeric character be used." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_003007 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
# 
# Group ID (Vulid): V-95965
# Group Title: SRG-OS-000076-GPOS-00044
# Rule ID: SV-105103r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_003008
# Rule Title: The macOS system must enforce a 60-day maximum password lifetime restriction.
# 
# Vulnerability Discussion: Any password, no matter how complex, can eventually be cracked. Therefore, passwords need to be changed periodically.
# 
# One method of minimizing this risk is to use complex passwords and periodically change them. If the operating system does not limit the lifetime of passwords
# and force users to change their passwords, there is the risk that the operating system passwords could be compromised.
# 
# Check Content: 
# To check the currently applied policies for passwords and accounts, use the following command:
# 
# /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep maxPINAgeInDays
# 
# If "maxPINAgeInDays" is set a value greater than "60", this is a finding.
# 
# Fix Text: This setting is enforced using the "Passcode Policy" configuration profile.  
# 
# CCI: CCI-000199
#
# Configuration Profile - Passcode payload > MAXIMUM PASSCODE AGE 60
# Verify organizational score
AOSX_14_003008="$(/usr/bin/defaults read "$plistlocation" AOSX_14_003008)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_003008" = "1" ]; then
	AOSX_14_003008_Audit="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'maxPINAgeInDays = 60')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_14_003008_Audit" > "0" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_003008 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_003008 -bool false; else
		/bin/echo "* AOSX_14_003008 Configuration Profile - The macOS system must enforce a 60-day maximum password lifetime restriction." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_003008 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
# 
# Group ID (Vulid): V-95967
# Group Title: SRG-OS-000077-GPOS-00045
# Rule ID: SV-105105r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_003009
# Rule Title: The macOS system must prohibit password reuse for a minimum of five generations.
# 
# Vulnerability Discussion: Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force
# attacks. If the information system or application allows the user to consecutively reuse their password when that password has exceeded its defined lifetime,
# the end result is a password that is not changed as per policy requirements.
# 
# Check Content: 
# To check the currently applied policies for passwords and accounts, use the following command:
# 
# /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep pinHistory
# 
# If the return is not “pinHistory = 5” or greater, this is a finding.
# 
# Fix Text: This setting is enforced using the "Passcode Policy" configuration profile.  
# 
# CCI: CCI-000200
#
# Configuration Profile - Passcode payload > PASSCODE HISTORY 5
# Verify organizational score
AOSX_14_003009="$(/usr/bin/defaults read "$plistlocation" AOSX_14_003009)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_003009" = "1" ]; then
	AOSX_14_003009_Audit="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'pinHistory = 5')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_14_003009_Audit" > "0" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_003009 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_003009 -bool false; else
		/bin/echo "* AOSX_14_003009 Configuration Profile - The macOS system must prohibit password reuse for a minimum of five generations." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_003009 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
# 
# Group ID (Vulid): V-95969
# Group Title: SRG-OS-000078-GPOS-00046
# Rule ID: SV-105107r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_003010
# Rule Title: The macOS system must enforce a minimum 15-character password length.
# 
# Vulnerability Discussion: The minimum password length must be set to 15 characters. Password complexity, or strength, is a measure of the effectiveness of a
# password in resisting attempts at guessing and brute-force attacks. Password length is one factor of several that helps to determine strength and how long it
# takes to crack a password. The use of more characters in a password helps to exponentially increase the time and/or resources required to compromise the
# password.
# 
# Check Content: 
# To check the currently applied policies for passwords and accounts, use the following command:
# 
# /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep minLength
# 
# If the return is null or not “minLength = 15”, this is a finding.
# 
# Fix Text: This setting is enforced using the "Passcode Policy" configuration profile.  
# 
# CCI: CCI-000205
#
# Configuration Profile - Passcode payload > MINIMUM PASSCODE LENGTH 15
# Verify organizational score
AOSX_14_003010="$(/usr/bin/defaults read "$plistlocation" AOSX_14_003010)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_003010" = "1" ]; then
	AOSX_14_003010_Audit="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep minLength | /usr/bin/awk '{print $3-0}')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_14_003010_Audit" -ge "15" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_003010 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_003010 -bool false; else
		/bin/echo "* AOSX_14_003010 Configuration Profile - The macOS system must enforce a minimum 15-character password length." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_003010 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
# 
# Group ID (Vulid): V-95971
# Group Title: SRG-OS-000266-GPOS-00101
# Rule ID: SV-105109r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_003011
# Rule Title: The macOS system must enforce password complexity by requiring that at least one special character be used.
# 
# Vulnerability Discussion: Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity or
# strength is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Password complexity is one factor in
# determining how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested
# before the password is compromised. Special characters are those characters that are not alphanumeric. Examples include: ~ ! @ # $ % ^ *.
# 
# Check Content: 
# Password policy can be set with a configuration profile or the "pwpolicy" utility. If password policy is set with a configuration profile, run the following
# command to check if the system is configured to require that passwords contain at least one special character:
# 
# /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep minComplexChars
# 
# If the return is null or not ” minComplexChars = 1”, this is a finding.
# 
# Run the following command to check if the system is configured to require that passwords not contain repeated sequential characters or characters in
# increasing and decreasing sequential order:
# 
# /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep allowSimple
# 
# If "allowSimple" is not set to "0" or is undefined, this is a finding.
# 
# Fix Text: This setting may be enforced using the "Passcode Policy" configuration profile or by a directory service.  
# 
# CCI: CCI-001619
#
# Configuration Profile - Passcode payload > MINIMUM NUMBER OF COMPLEX CHARACTERS 1
# Configuration Profile - Passcode payload > Allow simple value (unchecked)
# Verify organizational score
AOSX_14_003011="$(/usr/bin/defaults read "$plistlocation" AOSX_14_003011)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_003011" = "1" ]; then
	AOSX_14_003011_Audit1="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep minComplexChars | /usr/bin/awk '{print $3-0}')"
	AOSX_14_003011_Audit2="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'allowSimple = 0')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_14_003011_Audit1" -ge "1" ]] && [[ "$AOSX_14_003011_Audit2" > "0" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_003011 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_003011 -bool false; else
		/bin/echo "* AOSX_14_003011 Configuration Profile - The macOS system must enforce password complexity by requiring that at least one special character be used." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_003011 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
# 
# Group ID (Vulid): V-95973
# Group Title: SRG-OS-000480-GPOS-00227
# Rule ID: SV-105111r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_003012
# Rule Title: The macOS system must be configured to prevent displaying password hints.
# 
# Vulnerability Discussion: Password hints leak information about passwords in use and can lead to loss of confidentiality.
# 
# Check Content: 
# To check that password hints are disabled, run the following command:
# 
# /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep RetriesUntilHint
# 
# If the return is null or is not "RetriesUntilHint = 0", this is a finding.
# 
# Fix Text: This setting is enforce using the "Login Window" Policy.  
# 
# CCI: CCI-000366
#
# Configuration Profile - Login Window payload > Options > Show password hint when needed and available (unchecked)
# Verify organizational score
AOSX_14_003012="$(/usr/bin/defaults read "$plistlocation" AOSX_14_003012)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_003012" = "1" ]; then
	AOSX_14_003012_Audit="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'RetriesUntilHint = 0')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_14_003012_Audit" > "0" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_003012 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_003012 -bool false; else
		/bin/echo "* AOSX_14_003012 Configuration Profile - The macOS system must be configured to prevent displaying password hints." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_003012 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
# 
# Group ID (Vulid): V-95975
# Group Title: SRG-OS-000480-GPOS-00227
# Rule ID: SV-105113r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_003013
# Rule Title: macOS must be configured with a firmware password to prevent access to single user mode and booting from alternative media.
# 
# Vulnerability Discussion: Single user mode and the boot picker, as well as numerous other tools are available on macOS through booting while holding the
# "Option" key down. Setting a firmware password restricts access to these tools.
# 
# Check Content: 
# To check that password hints are disabled, run the following command:
# 
# # sudo /usr/sbin/firmwarepasswd -check
# 
# If the return is not, "Password Enabled: Yes", this is a finding.
# 
# Fix Text: To set a firmware passcode use the following command.
# 
# sudo /usr/sbin/firmwarepasswd -setpasswd
# 
# Note: If firmware password or passcode is forgotten, the only way to reset the forgotten password is through the use of a machine specific binary generated
# and provided by Apple. Schedule a support call, and provide proof of purchase before the firmware binary will be generated.  
# 
# CCI: CCI-000366
# 
# Verify organizational score
AOSX_14_003013="$(/usr/bin/defaults read "$plistlocation" AOSX_14_003013)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_003013" = "1" ]; then
	AOSX_14_003013_Audit="$(/usr/sbin/firmwarepasswd -check | /usr/bin/grep -c 'Password Enabled: Yes')"
	# If client fails, then note category in audit file
	if [[ $AOSX_14_003013_Audit > "0" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_003013 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_003013 -bool false; else
		/bin/echo "* AOSX_14_003013 Enable Firmware Password – macOS must be configured with a firmware password to prevent access to single user mode and booting from alternative media." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_003013 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
# DUPLICATE check to AOSX_14_003024
#
# Group ID (Vulid): V-95565
# Group Title: SRG-OS-000105-GPOS-00052
# Rule ID: SV-104729r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_003020
# Rule Title: The macOS system must use multifactor authentication for local and network access to privileged and non-privileged accounts.
# 
# Vulnerability Discussion: Without the use of multifactor authentication, the ease of access to privileged and non-privileged functions is greatly increased.
# 
# Multifactor authentication requires using two or more factors to achieve authentication.
# 
# Factors include:
# 1) something a user knows (e.g., password/PIN);
# 2) something a user has (e.g., cryptographic identification device, token); and
# 3) something a user is (e.g., biometric).
# 
# A privileged account is defined as an information system account with authorizations of a privileged user.
# 
# Network access is defined as access to an information system by a user (or a process acting on behalf of a user) communicating through a network (e.g., local
# area network, wide area network, or the Internet).
# 
# Local access is defined as access to an organizational information system by a user (or process acting on behalf of a user) communicating through a direct
# connection without the use of a network.
# 
# The DoD CAC with DoD-approved PKI is an example of multifactor authentication.
# 
# Satisfies: SRG-OS-000105-GPOS-00052, SRG-OS-000106-GPOS-00053, SRG-OS-000107-GPOS-00054, SRG-OS-000108-GPOS-00055
# 
# Check Content: 
# If the system is connected to a directory server, this is Not Applicable.
# 
# To verify that the system is configured to enforce multi-factor authentication, run the following commands:
# 
# /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep enforceSmartCard
# 
# If the results do not show the following, this is a finding.
# "enforceSmartCard=1.
# 
# Run the following command to disable password based authentication in SSHD.
# 
# /usr/bin/grep -e ^[\#]*PasswordAuthentication.* -e ^[\#]*ChallengeResponseAuthentication.* /etc/ssh/sshd_config
# 
# If this command returns null, or anything other than exactly this text, with no leading hash(#), this is a finding:
# 
# "PasswordAuthentication no
# ChallengeResponseAuthentication no"
# 
# Fix Text: 
# For non directory bound systems, this setting is enforced using the "Smart Card Policy" configuration profile.
# 
# Note: Before applying the "Smart Card Policy", the supplemental guidance provided with the STIG should be consulted to ensure continued access to the
# operating system.
# 
# The following commands must be run to disable passcode based authentication for SSHD:
# 
# /usr/bin/sudo /usr/bin/sed -i.bak 's/^[\#]*ChallengeResponseAuthentication.*/ChallengeResponseAuthentication no/' /etc/ssh/sshd_config
# /usr/bin/sudo /usr/bin/sed -i.bak 's/^[\#]*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config  
# 
# CCI: CCI-000765
# CCI: CCI-000766
# CCI: CCI-000767
# CCI: CCI-000768
#
# Verify organizational score
AOSX_14_003020="$(/usr/bin/defaults read "$plistlocation" AOSX_14_003020)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_003020" = "1" ]; then
	AOSX_14_003020_Audit1="$(/usr/bin/grep -e ^[\#]*PasswordAuthentication.* /etc/ssh/sshd_config | /usr/bin/grep -c -e ^'PasswordAuthentication no')"
	AOSX_14_003020_Audit2="$(/usr/bin/grep -e ^[\#]*ChallengeResponseAuthentication.* /etc/ssh/sshd_config | /usr/bin/grep -c -e ^'ChallengeResponseAuthentication no')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_14_003020_Audit1" > "0" ]] && [[ "$AOSX_14_003020_Audit2" > "0" ]] ; then
		/bin/echo $(/bin/date -u) "AOSX_14_003020 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_003020 -bool false; else
		/usr/bin/defaults write "$plistlocation" AOSX_14_003020 -bool true
		/bin/echo "* AOSX_14_003020 The macOS system must use multifactor authentication for local and network access to privileged and non-privileged accounts. Disable password based authentication in SSHD." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_003020 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
# DUPLICATE check to AOSX_14_003020
# 
# Group ID (Vulid): V-95977
# Group Title: SRG-OS-000125-GPOS-00065
# Rule ID: SV-105115r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_003024
# Rule Title: The macOS system must use multifactor authentication in the establishment of nonlocal maintenance and diagnostic sessions.
# 
# Vulnerability Discussion: If maintenance tools are used by unauthorized personnel, they may accidentally or intentionally damage or compromise the system. The
# act of managing systems and applications includes the ability to access sensitive application information, such as system configuration details, diagnostic
# information, user information, and potentially sensitive application data.
# 
# Some maintenance and test tools are either standalone devices with their own operating systems or are applications bundled with an operating system.
# 
# Nonlocal maintenance and diagnostic activities are those activities conducted by individuals communicating through a network, either an external network
# (e.g., the Internet) or an internal network. Typically, strong authentication requires authenticators that are resistant to replay attacks and employ
# multifactor authentication. Strong authenticators include, for example, PKI where certificates are stored on a token protected by a password, passphrase, or
# biometric.
# 
# Check Content: 
# If the system is connected to a directory server, this is Not Applicable.
# 
# The following command ensures that a mandatory smart card policy is enforced:
# 
# # /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep enforceSmartCard
# enforceSmartCard=1
# 
# If the command returns null, or any other value, this is a finding.
# 
# The following command ensures that passwords are disabled in the SSHD configuration file:
# 
# # grep -e ^[\#]*PasswordAuthentication.* -e ^[\#]*ChallengeResponseAuthentication.* /etc/ssh/sshd_config
# If this command returns null, or anything other than exactly this text, with no leading hash(#), this is a finding:
# 
# "PasswordAuthentication no
# ChallengeResponseAuthentication no"
# 
# Fix Text: For non-directory bound systems, this setting is enforced using the "Smart Card Policy" configuration profile.
# 
# Note: Before applying the "Smart Card Policy", the supplemental guidance provided with the STIG should be consulted to ensure continued access to the
# operating system.
# 
# To ensure that passcode based logins are disabled in sshd, run the following command:
# 
# /usr/bin/sudo /usr/bin/sed -i.bak 's/^[\#]*ChallengeResponseAuthentication.*/ChallengeResponseAuthentication no/' /etc/ssh/sshd_config
# /usr/bin/sudo /usr/bin/sed -i.bak 's/^[\#]*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config  
# 
# CCI: CCI-000877
#
# Verify organizational score
AOSX_14_003024="$(/usr/bin/defaults read "$plistlocation" AOSX_14_003024)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_003024" = "1" ]; then
	AOSX_14_003024_Audit1="$(/usr/bin/grep -e ^[\#]*PasswordAuthentication.* /etc/ssh/sshd_config | /usr/bin/grep -c -e ^'PasswordAuthentication no')"
	AOSX_14_003024_Audit2="$(/usr/bin/grep -e ^[\#]*ChallengeResponseAuthentication.* /etc/ssh/sshd_config | /usr/bin/grep -c -e ^'ChallengeResponseAuthentication no')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_14_003024_Audit1" > "0" ]] && [[ "$AOSX_14_003024_Audit2" > "0" ]] ; then
		/bin/echo $(/bin/date -u) "AOSX_14_003024 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_003024 -bool false; else
		/usr/bin/defaults write "$plistlocation" AOSX_14_003024 -bool true
		/bin/echo "* AOSX_14_003024 The macOS system must use multifactor authentication in the establishment of nonlocal maintenance and diagnostic sessions. Ensure that passcode based logins are disabled in sshd." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_003024 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
# DUPLICATE check to AOSX_14_003005
# 
# Group ID (Vulid): V-95979
# Group Title: SRG-OS-000375-GPOS-00160
# Rule ID: SV-105117r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_003025
# Rule Title: The macOS system must implement multifactor authentication for remote access to privileged accounts in such a way that one of the factors is
# provided by a device separate from the system gaining access.
# 
# Vulnerability Discussion: Using an authentication device, such as a CAC or token that is separate from the information system, ensures that even if the
# information system is compromised, that compromise will not affect credentials stored on the authentication device.
# 
# Multifactor solutions that require devices separate from information systems gaining access include, for example, hardware tokens providing time-based or
# challenge-response authenticators and smart cards such as the U.S. Government Personal Identity Verification card and the DoD Common Access Card.
# 
# A privileged account is defined as an information system account with authorizations of a privileged user.
# 
# Remote access is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external,
# non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.
# 
# This requirement only applies to components where this is specific to the function of the device or has the concept of an organizational user (e.g., VPN,
# proxy capability). This does not apply to authentication for the purpose of configuring the device itself (management).
# 
# Requires further clarification from NIST.
# 
# Check Content: 
# The following command ensures that a mandatory smart card policy is enforced:
# 
# # /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep enforceSmartCard
# 
# If the return is not "enforceSmartCard = 1;" this is a finding.
# 
# Fix Text: This setting is enforced using the "Smart Card Policy" configuration profile.
# 
# Note: Before applying the "Smart Card Policy", the supplemental guidance provided with the STIG should be consulted to ensure continued access to the
# operating system.  
# 
# CCI: CCI-001948
#
# Configuration Profile - Smart Card payload > Enforce Smart Card use (checked)
# Verify organizational score
AOSX_14_003025="$(/usr/bin/defaults read "$plistlocation" AOSX_14_003025)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_003025" = "1" ]; then
	AOSX_14_003025_Audit="$(/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -c 'enforceSmartCard = 1')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_14_003025_Audit" > "0" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_003025 passed via configuration profile" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_003025 -bool false; else
		/bin/echo "* AOSX_14_003025 Configuration Profile - The macOS system must implement multifactor authentication for remote access to privileged accounts." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_003025 fix via configuration profile" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
# 
# Group ID (Vulid): V-95981
# Group Title: SRG-OS-000480-GPOS-00227
# Rule ID: SV-105119r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_003050
# Rule Title: The macOS system must be configured so that the login command requires smart card authentication.
# 
# Vulnerability Discussion: Configuring the operating system to implement organization-wide security implementation guides and security checklists ensures
# compliance with federal standards and establishes a common security baseline across DoD that reflects the most restrictive security posture consistent with
# operational requirements.
# 
# Configuration settings are the set of parameters that can be changed in hardware, software, or firmware components of the system that affect the security
# posture and/or functionality of the system. Security-related parameters are those parameters impacting the security state of the system, including the
# parameters required to satisfy other security control requirements. Security-related parameters include, for example: registry settings; account, file,
# directory permission settings; and settings for functions, ports, protocols, services, and remote connections.
# 
# Check Content: 
# To verify that the "login" command has been configured to require smart card authentication, run the following command:
# 
# # cat /etc/pam.d/login | grep -i pam_smartcard.so
# 
# If the text that returns does not include the line, "auth sufficient pam_smartcard.so" at the TOP of the listing, this is a finding.
# 
# Fix Text: Make a backup of the PAM LOGIN settings using the following command:
# sudo cp /etc/pam.d/login /etc/pam.d/login_backup_`date "+%Y-%m-%d_%H:%M"`
# 
# Replace the contents of "/etc/pam.d/login" with the following:
# 
# # login: auth account password session
# auth sufficient pam_smartcard.so
# auth optional pam_krb5.so use_kcminit
# auth optional pam_ntlm.so try_first_pass
# auth optional pam_mount.so try_first_pass
# auth required pam_opendirectory.so try_first_pass
# auth required pam_deny.so
# account required pam_nologin.so
# account required pam_opendirectory.so
# password required pam_opendirectory.so
# session required pam_launchd.so
# session required pam_uwtmp.so
# session optional pam_mount.so  
# 
# CCI: CCI-000366
#
# Verify organizational score
AOSX_14_003050="$(/usr/bin/defaults read "$plistlocation" AOSX_14_003050)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_003050" = "1" ]; then
	AOSX_14_003050_Audit="$(/bin/cat /etc/pam.d/login | /usr/bin/grep -i -c 'auth '.*'sufficient '.*'pam_smartcard.so')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_14_003050_Audit" > "0" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_003050 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_003050 -bool false; else
		/bin/echo "* AOSX_14_003050 The macOS system must be configured so that the login command requires smart card authentication." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_003050 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
# 
# Group ID (Vulid): V-95983
# Group Title: SRG-OS-000480-GPOS-00227
# Rule ID: SV-105121r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_003051
# Rule Title: The macOS system must be configured so that the su command requires smart card authentication.
# 
# Vulnerability Discussion: Configuring the operating system to implement organization-wide security implementation guides and security checklists ensures
# compliance with federal standards and establishes a common security baseline across DoD that reflects the most restrictive security posture consistent with
# operational requirements.
# 
# Configuration settings are the set of parameters that can be changed in hardware, software, or firmware components of the system that affect the security
# posture and/or functionality of the system. Security-related parameters are those parameters impacting the security state of the system, including the
# parameters required to satisfy other security control requirements. Security-related parameters include, for example: registry settings; account, file,
# directory permission settings; and settings for functions, ports, protocols, services, and remote connections.
# 
# Check Content: 
# To verify that the "su" command has been configured to require smart card authentication, run the following command:
# 
# cat /etc/pam.d/su | grep -i pam_smartcard.so
# 
# If the text that returns does not include the line, "auth sufficient pam_smartcard.so" at the TOP of the listing, this is a finding.
# 
# Fix Text: Make a backup of the PAM SU settings using the following command:
# cp /etc/pam.d/su /etc/pam.d/su_backup_`date "+%Y-%m-%d_%H:%M"`
# 
# Replace the contents of "/etc/pam.d/su" with the following:
# 
# # su: auth account session
# auth sufficient pam_smartcard.so
# #auth required pam_opendirectory.so
# auth required pam_deny.so
# account required pam_permit.so
# password required pam_deny.so
# session required pam_permit.so  
# 
# CCI: CCI-000366
#
# Verify organizational score
AOSX_14_003051="$(/usr/bin/defaults read "$plistlocation" AOSX_14_003051)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_003051" = "1" ]; then
	AOSX_14_003051_Audit="$(/bin/cat /etc/pam.d/su | /usr/bin/grep -i -c 'auth '.*'sufficient '.*'pam_smartcard.so')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_14_003051_Audit" > "0" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_003051 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_003051 -bool false; else
		/bin/echo "* AOSX_14_003051 The macOS system must be configured so that the su command requires smart card authentication." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_003051 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
# 
# Group ID (Vulid): V-95985
# Group Title: SRG-OS-000480-GPOS-00227
# Rule ID: SV-105123r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_003052
# Rule Title: The macOS system must be configured so that the sudo command requires smart card authentication.
# 
# Vulnerability Discussion: Configuring the operating system to implement organization-wide security implementation guides and security checklists ensures
# compliance with federal standards and establishes a common security baseline across DoD that reflects the most restrictive security posture consistent with
# operational requirements.
# 
# Configuration settings are the set of parameters that can be changed in hardware, software, or firmware components of the system that affect the security
# posture and/or functionality of the system. Security-related parameters are those parameters impacting the security state of the system, including the
# parameters required to satisfy other security control requirements. Security-related parameters include, for example: registry settings; account, file,
# directory permission settings; and settings for functions, ports, protocols, services, and remote connections.
# 
# Check Content: 
# To verify that the "sudo" command has been configured to require smart card authentication, run the following command:
# 
# cat /etc/pam.d/sudo | grep -i pam_smartcard.so
# 
# If the text that returns does not include the line, "auth sufficient pam_smartcard.so" at the TOP of the listing, this is a finding.
# 
# Fix Text: Make a backup of the PAM SUDO settings using the following command:
# cp /etc/pam.d/sudo /etc/pam.d/sudo_backup_`date "+%Y-%m-%d_%H:%M"`
# 
# Replace the contents of "/etc/pam.d/sudo" with the following:
# 
# # sudo: auth account password session
# auth sufficient pam_smartcard.so
# #auth required pam_opendirectory.so
# auth required pam_deny.so
# account required pam_permit.so
# password required pam_deny.so
# session required pam_permit.so  
# 
# CCI: CCI-000366
# 
# Verify organizational score
AOSX_14_003052="$(/usr/bin/defaults read "$plistlocation" AOSX_14_003052)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_003052" = "1" ]; then
	AOSX_14_003052_Audit="$(/bin/cat /etc/pam.d/sudo | /usr/bin/grep -i -c 'auth '.*'sufficient '.*'pam_smartcard.so')"
	# If client fails, then note category in audit file
	if [[ "$AOSX_14_003052_Audit" > "0" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_003052 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_003052 -bool false; else
		/bin/echo "* AOSX_14_003052 The macOS system must be configured so that the sudo command requires smart card authentication." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_003052 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
# 
# Group ID (Vulid): V-95987
# Group Title: SRG-OS-000206-GPOS-00084
# Rule ID: SV-105125r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_004001
# Rule Title: The macOS system must be configured with system log files owned by root and group-owned by wheel or admin.
# 
# Vulnerability Discussion: System logs should only be readable by root or admin users. System logs frequently contain sensitive information that could be used
# by an attacker. Setting the correct owner mitigates this risk.
# 
# Check Content: 
# Log files are controlled by "newsyslog" and "aslmanager".
# 
# These commands check for log files that exist on the system and print out the log with corresponding ownership. Run them from inside "/var/log":
# 
# /usr/bin/sudo stat -f '%Su:%Sg:%N' $(/usr/bin/grep -v '^#' /etc/newsyslog.conf | awk '{ print $1 }') 2> /dev/null
# /usr/bin/sudo stat -f '%Su:%Sg:%N' $(/usr/bin/grep -e '^>' /etc/asl.conf /etc/asl/* | awk '{ print $2 }') 2> /dev/null
# 
# If there are any system log files that are not owned by "root" and group-owned by "wheel" or admin, this is a finding.
# 
# Service logs may be owned by the service user account or group.
# 
# Fix Text: For any log file that returns an incorrect owner or group value, run the following command:
# 
# /usr/bin/sudo chown root:wheel [log file]
# 
# [log file] is the full path to the log file in question. If the file is managed by "newsyslog", find the configuration line in the directory
# "/etc/newsyslog.d/" or the file "/etc/newsyslog.conf" and ensure that the owner:group column is set to "root:wheel" or the appropriate service user account
# and group.
# 
# If the file is managed by "aslmanager", find the configuration line in the directory "/etc/asl/" or the file "/etc/asl.conf" and ensure that "uid" and "gid"
# options are either not present or are set to a service user account and group respectively.  
# 
# CCI: CCI-001314
#
# Verify organizational score
AOSX_14_004001="$(/usr/bin/defaults read "$plistlocation" AOSX_14_004001)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_004001" = "1" ]; then
	AOSX_14_004001_Audit=""
	cd /var/log
	grep_asl=$(/usr/bin/grep -e '^>' /etc/asl.conf /etc/asl/* | awk '{ print $2 }') 2> /dev/null
	grep_newsylog=$(/usr/bin/grep -v '^#' /etc/newsyslog.conf | awk '{ print $1 }') 2> /dev/null
	for i in $grep_asl $grep_newsylog; do
		if [ -e $i ]; then
			if [[ "$(/usr/bin/stat -f '%Su:%Sg:%N' $i)" = *"root:wheel"*  ]] || [[ "$(/usr/bin/stat -f '%Su:%Sg:%N' $i)" = *"root:admin"* ]] ; then
				/bin/echo "Ownership is correct for $i"
				:
			else
				/bin/echo "* AOSX_14_004001 The macOS system must be configured with system log files owned by root and group-owned by wheel or admin. $i" >> "$auditfilelocation"
				/bin/echo $(/bin/date -u) "AOSX_14_004001 fix ownership for $i" | /usr/bin/tee -a "$logFile"
				AOSX_14_004001_Audit="Fail"
			fi
		fi
	done
	if [[ "$AOSX_14_004001_Audit" != "Fail" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_004001 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_004001 -bool false
	fi
fi
# 
#####################################################################################################

#####################################################################################################
# 
# Group ID (Vulid): V-95989
# Group Title: SRG-OS-000206-GPOS-00084
# Rule ID: SV-105127r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_004002
# Rule Title: The macOS system must be configured with system log files set to mode 640 or less permissive.
# 
# Vulnerability Discussion: System logs should only be readable by root or admin users. System logs frequently contain sensitive information that could be used
# by an attacker. Setting the correct permissions mitigates this risk.
# 
# Check Content: 
# These commands check for log files that exist on the system and print out the log with corresponding permissions. Run them from inside "/var/log":
# 
# /usr/bin/sudo stat -f '%A:%N' $(/usr/bin/grep -v '^#' /etc/newsyslog.conf | awk '{ print $1 }') 2> /dev/null
# /usr/bin/sudo stat -f '%A:%N' $(/usr/bin/grep -e '^>' /etc/asl.conf /etc/asl/* | awk '{ print $2 }') 2> /dev/null
# 
# The correct permissions on log files should be "640" or less permissive for system logs.
# 
# Any file with more permissive settings is a finding.
# 
# Fix Text: For any log file that returns an incorrect permission value, run the following command:
# 
# /usr/bin/sudo chmod 640 [log file]
# 
# [log file] is the full path to the log file in question. If the file is managed by "newsyslog", find the configuration line in the directory
# "/etc/newsyslog.d/" or the file "/etc/newsyslog.conf" and edit the mode column to be "640" or less permissive.
# 
# If the file is managed by "aslmanager", find the configuration line in the directory "/etc/asl/" or the file "/etc/asl.conf" and add or edit the mode option
# to be "mode=0640" or less permissive.  
# 
# CCI: CCI-001314
#
# Verify organizational score
AOSX_14_004002="$(/usr/bin/defaults read "$plistlocation" AOSX_14_004002)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_004002" = "1" ]; then
	AOSX_14_004002_Audit=""
	cd /var/log
	grep_asl=$(/usr/bin/grep -e '^>' /etc/asl.conf /etc/asl/* | awk '{ print $2 }') 2> /dev/null
	grep_newsylog=$(/usr/bin/grep -v '^#' /etc/newsyslog.conf | awk '{ print $1 }') 2> /dev/null
	for i in $grep_asl $grep_newsylog; do
		if [ -e $i ]; then
			if [[ "$(/usr/bin/stat -f '%A:%N' $i)" = *"640"* ]]; then
				#/bin/echo "Permission are correct for $i"
				:
			else
				/bin/echo "* AOSX_14_004002 The macOS system must be configured with system log files set to mode 640 or less permissive. $i" >> "$auditfilelocation"
				/bin/echo $(/bin/date -u) "AOSX_14_004002 fix permissions for $i" | /usr/bin/tee -a "$logFile"
				AOSX_14_004002_Audit="Fail"
			fi
		fi
	done
	if [[ "$AOSX_14_004002_Audit" != "Fail" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_004002 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_004002 -bool false
	fi
fi
# 
#####################################################################################################

#####################################################################################################
#
# DUPLICATE check to AOSX_14_000010 and AOSX_14_004011
# 
# Group ID (Vulid): V-95991
# Group Title: SRG-OS-000423-GPOS-00187
# Rule ID: SV-105129r2_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_004010
# Rule Title: The macOS system must implement DoD-approved encryption to protect the confidentiality and integrity of remote access sessions including
# transmitted data and data during preparation for transmission.
# 
# Vulnerability Discussion: Without protection of the transmitted information, confidentiality and integrity may be compromised because unprotected
# communications can be intercepted and either read or altered.
# 
# This requirement applies to both internal and external networks and all types of information system components from which information can be transmitted
# (e.g., servers, mobile devices, notebook computers, printers, copiers, scanners, and facsimile machines). Communication paths outside the physical protection
# of a controlled boundary are exposed to the possibility of interception and modification.
# 
# Protecting the confidentiality and integrity of organizational information can be accomplished by physical means (e.g., employing physical distribution
# systems) or by logical means (e.g., employing cryptographic techniques). If physical means of protection are employed, then logical means (cryptography) do
# not have to be employed, and vice versa.
# 
# Check Content: 
# For systems that allow remote access, run the following command:
# 
# /usr/bin/sudo /bin/launchctl print-disabled system | /usr/bin/grep com.openssh.sshd
# 
# If the results do not show the following, this is a finding.
# 
# "com.openssh.sshd" => false
# 
# Fix Text: To enable the SSH service, run the following command:
# 
# /usr/bin/sudo /bin/launchctl enable system/com.openssh.sshd
# 
# The system may need to be restarted for the update to take effect.  
# 
# CCI: CCI-002418
#
# Enable remote access through SSH
# Verify organizational score
AOSX_14_004010="$(/usr/bin/defaults read "$plistlocation" AOSX_14_004010)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_004010" = "1" ]; then
	AOSX_14_004010_Audit1="$(/bin/launchctl print-disabled system | /usr/bin/grep com.openssh.sshd)"
	AOSX_14_004010_Audit2="$(/usr/sbin/systemsetup -getremotelogin)"
	# If client fails, then note category in audit file
	if [[ $AOSX_14_004010_Audit1 = *"false"* ]] || [[ $AOSX_14_004010_Audit2 = *"On"* ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_004010 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_004010 -bool false; else
		/bin/echo "* AOSX_14_004010 Enable remote access through SSH." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_004010 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
#
# Disable remote access through SSH
# Verify organizational score
AOSX_14_004010off="$(/usr/bin/defaults read "$plistlocation" AOSX_14_004010off)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_004010off" = "1" ]; then
	AOSX_14_004010off_Audit1="$(/bin/launchctl print-disabled system | /usr/bin/grep com.openssh.sshd)"
	AOSX_14_004010off_Audit2="$(/usr/sbin/systemsetup -getremotelogin)"
	# If client fails, then note category in audit file
	if [[ $AOSX_14_004010off_Audit1 = *"true"* ]] || [[ $AOSX_14_004010off_Audit2 = *"Off"* ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_004010off passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_004010off -bool false; else
		/bin/echo "* AOSX_14_004010off Disable remote access through SSH." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_004010off fix" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
#
# DUPLICATE check to AOSX_14_000010 and AOSX_14_004010
# 
# Group ID (Vulid): V-95993
# Group Title: SRG-OS-000424-GPOS-00188
# Rule ID: SV-105131r2_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_004011
# Rule Title: The macOS system must implement DoD-approved encryption to protect the confidentiality and integrity of remote access sessions including
# transmitted data and data during preparation for transmission.
# 
# Vulnerability Discussion: Without confidentiality and integrity protection mechanisms, unauthorized individuals may gain access to sensitive information via a
# remote access session.
# 
# Remote access is access to DoD non-public information systems by an authorized user (or an information system) communicating through an external,
# non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.
# 
# Encryption provides a means to secure the remote connection to prevent unauthorized access to the data traversing the remote access connection (e.g., Remote
# Desktop Protocol [RDP]), thereby providing a degree of confidentiality. The encryption strength of a mechanism is selected based on the security
# categorization of the information.
# 
# Satisfies: SRG-OS-000424-GPOS-00188, SRG-OS-000425-GPOS-00189, SRG-OS-000426-GPOS-00190
# 
# Check Content: 
# For systems that allow remote access, run the following command:
# 
# /usr/bin/sudo /bin/launchctl print-disabled system | /usr/bin/grep com.openssh.sshd
# 
# If the results do not show the following, this is a finding.
# 
# "com.openssh.sshd" => false
# 
# Fix Text: To enable the SSHD service, run the following command:
# 
# /usr/bin/sudo /bin/launchctl enable system/com.openssh.sshd
# 
# The system may need to be restarted for the update to take effect.  
# 
# CCI: CCI-002420
# CCI: CCI-002421
# CCI: CCI-002422
#
# Enable remote access through SSH
# Verify organizational score
AOSX_14_004011="$(/usr/bin/defaults read "$plistlocation" AOSX_14_004011)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_004011" = "1" ]; then
	AOSX_14_004011_Audit1="$(/bin/launchctl print-disabled system | /usr/bin/grep com.openssh.sshd)"
	AOSX_14_004011_Audit2="$(/usr/sbin/systemsetup -getremotelogin)"
	# If client fails, then note category in audit file
	if [[ $AOSX_14_004011_Audit1 = *"false"* ]] || [[ $AOSX_14_004011_Audit2 = *"On"* ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_004011 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_004011 -bool false; else
		/bin/echo "* AOSX_14_004011 Enable remote access through SSH." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_004011 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
#
# Disable remote access through SSH
# Verify organizational score
AOSX_14_004011off="$(/usr/bin/defaults read "$plistlocation" AOSX_14_004011off)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_004011off" = "1" ]; then
	AOSX_14_004011off_Audit1="$(/bin/launchctl print-disabled system | /usr/bin/grep com.openssh.sshd)"
	AOSX_14_004011off_Audit2="$(/usr/sbin/systemsetup -getremotelogin)"
	# If client fails, then note category in audit file
	if [[ $AOSX_14_004011off_Audit1 = *"true"* ]] || [[ $AOSX_14_004011off_Audit2 = *"Off"* ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_004011off passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_004011off -bool false; else
		/bin/echo "* AOSX_14_004011off Disable remote access through SSH." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_004011off fix" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
# DUPLICATE check to AOSX_14_000008
# 
# Group ID (Vulid): V-95585
# Group Title: SRG-OS-000379-GPOS-00164
# Rule ID: SV-104731r2_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_004020
# Rule Title: The macOS system must authenticate all endpoint devices before establishing a local, remote, and/or network connection using bidirectional
# authentication that is cryptographically based.
# 
# Vulnerability Discussion: Without authenticating devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity.
# Bidirectional authentication provides stronger safeguards to validate the identity of other devices for connections that are of greater risk.
# 
# Bidirectional authentication solutions include, but are not limited to, IEEE 802.1x and Extensible Authentication Protocol [EAP], RADIUS server with
# EAP-Transport Layer Security [TLS] authentication, Kerberos, and SSL mutual authentication.
# 
# A local connection is any connection with a device communicating without the use of a network. A network connection is any connection with a device that
# communicates through a network (e.g., local area network, wide area network, or the Internet). A remote connection is any connection with a device
# communicating through an external network (e.g., the Internet).
# 
# Because of the challenges of applying this requirement on a large scale, organizations are encouraged to only apply this requirement to those limited number
# (and type) of devices that truly need to support this capability.
# 
# Check Content: 
# For systems where Wi-Fi is not approved for use, run the following command to disable the Wi-Fi service:
# 
# To list the network devices that are enabled on the system, run the following command:
# 
# /usr/bin/sudo /usr/sbin/networksetup -listallnetworkservices
# 
# If the Wi-Fi service name is not preceded by an asterisk(*), this is a finding.
# 
# Fix Text: To disable a network device, run the following command:
# 
# /usr/bin/sudo /usr/sbin/networksetup -setnetworkserviceenabled Wi-Fi off  
# 
# CCI: CCI-001967
# 
# Verify organizational score
AOSX_14_004020="$(/usr/bin/defaults read "$plistlocation" AOSX_14_004020)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_004020" = "1" ]; then
	AOSX_14_004020_Audit="$(/usr/sbin/networksetup -listallnetworkservices | /usr/bin/grep 'Wi-Fi')"
	# If client fails, then note category in audit file
	if [[ $AOSX_14_004020_Audit = "*"* ]] || [[ $AOSX_14_004020_Audit = "" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_004020 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_004020 -bool false; else
		/bin/echo "* AOSX_14_004020 The macOS system must authenticate all endpoint devices before establishing a local, remote, and/or network connection using bidirectional authentication that is cryptographically based." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_004020 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
#
#####################################################################################################

#####################################################################################################
# 
# Group ID (Vulid): V-95587
# Group Title: SRG-OS-000480-GPOS-00227
# Rule ID: SV-104733r1_rule
# Severity: CAT I
# Rule Version (STIG-ID): AOSX_14_004021
# Rule Title: The macOS system must be configured with the sudoers file configured to authenticate users on a per -tty basis.
# 
# Vulnerability Discussion: The "sudo" command must be configured to prompt for the administrator's password at least once in each newly opened Terminal window
# or remote logon session, as this prevents a malicious user from taking advantage of an unlocked computer or an abandoned logon session to bypass the normal
# password prompt requirement.
# 
# Without the "tty_tickets" option, all open local and remote logon sessions would be authenticated to use sudo without a password for the duration of the
# configured password timeout window.
# 
# Check Content: 
# To check if the "tty_tickets" option is set for "/usr/bin/sudo", run the following command:
# 
# /usr/bin/sudo /usr/bin/grep tty_tickets /etc/sudoers
# 
# If there is no result, this is a finding.
# 
# Fix Text: Edit the "/etc/sudoers" file to contain the line:
# 
# Defaults tty_tickets
# 
# This line can be placed in the defaults section or at the end of the file.  
# 
# CCI: CCI-000366
# 
# Verify organizational score
AOSX_14_004021="$(/usr/bin/defaults read "$plistlocation" AOSX_14_004021)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_004021" = "1" ]; then
	AOSX_14_004021_Audit="$(/usr/bin/grep tty_tickets /etc/sudoers)"
	# If client fails, then note category in audit file
	if [[ $AOSX_14_004021_Audit != "" ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_004021 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_004021 -bool false; else
		/bin/echo "* AOSX_14_004021 The macOS system must be configured with the sudoers file configured to authenticate users on a per -tty basis." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_004021 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
#
#####################################################################################################

#####################################################################################################
# 
# Group ID (Vulid): V-95995
# Group Title: SRG-OS-000051-GPOS-00024
# Rule ID: SV-105133r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_005001
# Rule Title: The macOS system must enable System Integrity Protection.
# 
# Vulnerability Discussion: System Integrity Protection (SIP) is vital to the protection of the integrity of macOS. SIP restricts what actions can be performed
# by administrative users, including root, against protected parts of the operating system. SIP protects all system binaries, including audit tools, from
# unauthorized access by preventing the modification or deletion of system binaries, or the changing of the permissions associated with those binaries. SIP
# limits the privileges to change software resident within software libraries to processes that have signed by Apple and have special entitlements to write to
# system files, such as Apple software updates and Apple installers. By protecting audit binaries, SIP ensures the presence of an audit record generation
# capability for DoD-defined auditable events for all operating system components and supports on-demand and after-the-fact reporting requirements.
# 
# Satisfies: SRG-OS-000051-GPOS-00024, SRG-OS-000054-GPOS-00025, SRG-OS-000062-GPOS-00031, SRG-OS-000122-GPOS-00063, SRG-OS-000256-GPOS-00097,
# SRG-OS-000257-GPOS-00098, SRG-OS-000258-GPOS-00099, SRG-OS-000259-GPOS-00100, SRG-OS-000348-GPOS-00136, SRG-OS-000349-GPOS-00137, SRG-OS-000350-GPOS-00138,
# SRG-OS-000351-GPOS-00139, SRG-OS-000352-GPOS-00140, SRG-OS-000353-GPOS-00141, SRG-OS-000354-GPOS-00142
# 
# Check Content: 
# System Integrity Protection is a security feature, enabled by default, that protects certain system processes and files from being modified or tampered with.
# Check the current status of "System Integrity Protection" with the following command:
# 
# /usr/bin/csrutil status
# 
# If the result does not show the following, this is a finding.
# 
# System Integrity Protection status: enabled
# 
# Fix Text: To reenable "System Integrity Protection", boot the affected system into "Recovery" mode, launch "Terminal" from the "Utilities" menu, and run the
# following command:
# 
# /usr/bin/csrutil enable  
# 
# CCI: CCI-000154
# CCI: CCI-000158
# CCI: CCI-000169
# CCI: CCI-001493
# CCI: CCI-001494
# CCI: CCI-001495
# CCI: CCI-001499
# CCI: CCI-001875
# CCI: CCI-001876
# CCI: CCI-001877
# CCI: CCI-001878
# CCI: CCI-001879
# CCI: CCI-001880
# CCI: CCI-001881
# CCI: CCI-001882
#
# Verify organizational score
AOSX_14_005001="$(/usr/bin/defaults read "$plistlocation" AOSX_14_005001)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_005001" = "1" ]; then
	AOSX_14_005001_Audit="$(/usr/bin/csrutil status)"
	# If client fails, then note category in audit file
	if [[ $AOSX_14_005001_Audit = *"enabled"* ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_005001 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_005001 -bool false; else
		/bin/echo "* AOSX_14_005001 The macOS system must enable System Integrity Protection. To reenable System Integrity Protection, boot the affected system into Recovery mode, launch Terminal from the Utilities menu, and run the following command: /usr/bin/csrutil enable. Alternatively zap the PRAM (reboot then hold down command option p r)." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_005001 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
#
#####################################################################################################

#####################################################################################################
# 
# Group ID (Vulid): V-95997
# Group Title: SRG-OS-000185-GPOS-00079
# Rule ID: SV-105135r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_005020
# Rule Title: The macOS system must implement cryptographic mechanisms to protect the confidentiality and integrity of all information at rest.
# 
# Vulnerability Discussion: Information at rest refers to the state of information when it is located on a secondary storage device (e.g., disk drive and tape
# drive) within an organizational information system. Mobile devices, laptops, desktops, and storage devices can be lost or stolen, and the contents of their
# data storage (e.g., hard drives and non-volatile memory) can be read, copied, or altered. By encrypting the system hard drive, the confidentiality and
# integrity of any data stored on the system is ensured. FileVault Disk Encryption mitigates this risk.
# 
# Satisfies: SRG-OS-000185-GPOS-00079, SRG-OS-000404-GPOS-00183, SRG-OS-000405-GPOS-00184
# 
# Check Content: 
# To check if "FileVault 2" is enabled, run the following command:
# 
# /usr/bin/sudo /usr/bin/fdesetup status
# 
# If "FileVault" is "Off" and the device is a mobile device or the organization has determined that the drive must encrypt data at rest, this is a finding.
# 
# Fix Text: Open System Preferences >> Security and Privacy and navigate to the "FileVault" tab. Use this panel to configure full-disk encryption.
# 
# Alternately, from the command line, run the following command to enable "FileVault":
# 
# /usr/bin/sudo /usr/bin/fdesetup enable
# 
# After "FileVault" is initially set up, additional users can be added.  
# 
# CCI: CCI-001199
# CCI: CCI-002475
# CCI: CCI-002476
#
# Verify organizational score
AOSX_14_005020="$(/usr/bin/defaults read "$plistlocation" AOSX_14_005020)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_005020" = "1" ]; then
	AOSX_14_005020_Audit="$(/usr/bin/fdesetup status)"
	# If client fails, then note category in audit file
	if [[ "$AOSX_14_005020_Audit" = *"FileVault is On"* ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_005020 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_005020 -bool false; else
		/bin/echo "* AOSX_14_005020 Enable FileVault – The macOS system must implement cryptographic mechanisms to protect the confidentiality and integrity of all information at rest." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_005020 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
# 
# Group ID (Vulid): V-95999
# Group Title: SRG-OS-000480-GPOS-00232
# Rule ID: SV-105137r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_005050
# Rule Title: The macOS Application Firewall must be enabled.
# 
# Vulnerability Discussion: Firewalls protect computers from network attacks by blocking or limiting access to open network ports. Application firewalls limit
# which applications are allowed to communicate over the network.
# 
# Check Content: 
# If an approved HBSS solution is installed, this is Not Applicable.
# 
# To check if the macOS firewall has been enabled, run the following command:
# 
# /usr/bin/sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate
# 
# If the result is "disabled", this is a finding.
# 
# Fix Text: To enable the firewall, run the following command:
# 
# /usr/bin/sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on  
# 
# CCI: CCI-000366
#
# Verify organizational score
AOSX_14_005050="$(/usr/bin/defaults read "$plistlocation" AOSX_14_005050)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_005050" = "1" ]; then
	AOSX_14_005050_Audit="$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate)"
	# If client fails, then note category in audit file
	if [[ "$AOSX_14_005050_Audit" = *"Firewall is enabled"* ]]; then
		/bin/echo $(/bin/date -u) "AOSX_14_005050 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_005050 -bool false; else
		/bin/echo "* AOSX_14_005050 The macOS Application Firewall must be enabled." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_005050 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
#
# Group ID (Vulid): V-96001
# Group Title: SRG-OS-000480-GPOS-00231
# Rule ID: SV-105139r1_rule
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_005051
# Rule Title: The macOS system must employ a deny-all, allow-by-exception firewall policy for allowing connections to other systems.
# 
# Vulnerability Discussion: Failure to restrict network connectivity only to authorized systems permits inbound connections from malicious systems. It also
# permits outbound connections that may facilitate exfiltration of DoD data.
# 
# Check Content: 
# Ask the System Administrator (SA) or Information System Security Officer (ISSO) if an approved firewall is loaded on the system. The recommended system is the
# McAfee HBSS.
# 
# If no firewall is installed on the system, this is a finding.
# 
# If a firewall is installed and it is not configured with a "default-deny" policy, this is a finding.
# 
# Fix Text: Install an approved HBSS or firewall solution onto the system and configure it with a "default-deny" policy.
# 
# Modify the check to verify that signed binaries cannot automatically accept connections.
# 
# Update default deny incoming and outgoing with allow for ssh store and activation.  
# 
# CCI: CCI-000366
# CCI: CCI-002080
# 
# Verify organizational score
AOSX_14_005051="$(/usr/bin/defaults read "$plistlocation" AOSX_14_005051)"
# If organizational score is 1 or true, check status of client
if [ "$AOSX_14_005051" = "1" ]; then
	# If client fails, then note category in audit file
	if [[ -f "/Library/McAfee/agent/bin/cmdagent" ]]; then # Check for the McAfee cmdagent
		/bin/echo $(/bin/date -u) "AOSX_14_005051 passed" | /usr/bin/tee -a "$logFile"
		/usr/bin/defaults write "$plistlocation" AOSX_14_005051 -bool false; else
		/bin/echo "* AOSX_14_005051 Managed by McAfee EPO Agent - The macOS system firewall must be configured with a default-deny policy." >> "$auditfilelocation"
		/bin/echo $(/bin/date -u) "AOSX_14_005051 fix" | /usr/bin/tee -a "$logFile"
	fi
fi
# 
#####################################################################################################

#####################################################################################################
/bin/echo $(/bin/date -u) "Audit complete" | /usr/bin/tee -a "$logFile"
/bin/echo "Run 3_STIG_Remediation (if it has not already run)"

exit 0