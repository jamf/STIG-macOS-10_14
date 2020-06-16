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
# Admins set organizational compliance for each listed item, which gets written to plist.
# Values default to "true," and must be commented to "false" to disregard as an organizational priority.
# Writes to /Library/Application Support/SecurityScoring/STIG_security_score.plist by default.

# Create the Scoring file destination directory if it does not already exist
LogDir="/Library/Application Support/SecurityScoring"

if [[ ! -e "$LogDir" ]]; then
    /bin/mkdir "$LogDir"
fi
plistlocation="$LogDir/STIG_security_score.plist"

###################################################################
############### ADMINS DESIGNATE STIG VALUES BELOW ################
###################################################################

### EXAMPLE ###
# Severity: CAT X
# Rule Version (STIG-ID): AOSX_14_00000X
# Rule Title: Description
# Note:
# Configuration Profile - Payload > X > Y > Z (selected)
# AOSX_14_00000X="true"
# AOSX_14_00000X="false"
### EXAMPLE ###

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_000001
# Rule Title: The macOS system must be configured to prevent Apple Watch from terminating a session lock.
## Configuration Profile - Security & Privacy Payload > General > Allow user to unlock the Mac using an Apple Watch (un-checked)
AOSX_14_000001="true"
# AOSX_14_000001="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_000002
# Rule Title: The macOS system must retain the session lock until the user reestablishes access using established identification and authentication procedures.
# Users must be prompted to enter their passwords when unlocking the screen saver.
## Configuration Profile - Security & Privacy Payload > General > Require password * after sleep or screen saver begins (checked)
AOSX_14_000002="true"
# AOSX_14_000002="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_000003
# Rule Title: The macOS system must initiate the session lock no more than five seconds after a screen saver is started.
## Configuration Profile - Security & Privacy Payload > General > Require password * after sleep or screen saver begins (select * time no more than five seconds)
AOSX_14_000003="true"
# AOSX_14_000003="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_000004
# Rule Title: The macOS system must initiate a session lock after a 15-minute period of inactivity.
# A screen saver must be enabled and set to require a password to unlock. The timeout should be set to 15 minutes of inactivity. 
## Configuration Profile - Login Window payload > Options > Start screen saver after: (checked) > 15 Minutes of Inactivity (or less) 
AOSX_14_000004="true"
# AOSX_14_000004="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_000005
# Rule Title: The macOS system must be configured to lock the user session when a smart token is removed.
# Note: Before applying the "Smart Card Policy", the supplemental guidance provided with the STIG should be consulted to ensure continued access to the operating system.
## Configuration Profile - Smart Card payload > Enable Screen Saver on Smart Card removal (checked)
AOSX_14_000005="true"
# AOSX_14_000005="false"

# Severity: CAT III
# Rule Version (STIG-ID): AOSX_14_000006
# Rule Title: The macOS system must conceal, via the session lock, information previously visible on the display with a publicly viewable image.
# A default screen saver must be configured for all users.
## Configuration Profile - Login Window payload > Options > Start screen saver after: (checked) > USE SCREEN SAVER MODULE AT PATH: (path to screensaver)
AOSX_14_000006="true"
# AOSX_14_000006="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_000007
# Rule Title: The macOS system must be configured to disable hot corners.
## Configuration Profile - Custom payload > com.apple.dock > wvous-tl-corner=0, wvous-br-corner=0, wvous-bl-corner=0, wvous-tr-corner=0
AOSX_14_000007="true"
# AOSX_14_000007="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_000008
# Rule Title: The macOS system must be configured with Wi-Fi support software disabled.
# AOSX_14_000008="true"
AOSX_14_000008="false"

# DUPLICATE check to AOSX_14_004010 and AOSX_14_004011
# Severity: CAT I
# Rule Version (STIG-ID): AOSX_14_000010
# Rule Title: The macOS system must implement DoD-approved encryption to protect the confidentiality and integrity of remote access sessions including
# transmitted data and data during preparation for transmission.
AOSX_14_000010="true"
# AOSX_14_000010="false"
#
# If AOSX_14_000010 is not enforced then SSH should be off.
if [ "$AOSX_14_000010" = "false" ]; then
	AOSX_14_000010off="true"; else
	AOSX_14_000010off="false"
fi

# DUPLICATE check to AOSX_14_000040
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_000011
# Rule Title: The macOS system must implement DoD-approved encryption to protect the confidentiality and integrity of remote access sessions including
# transmitted data and data during preparation for transmission. ssh -V must report OpenSSH_7.9p1 or greater.
# Note: This audit checks for an exact match to "OpenSSH_7.9p1".
AOSX_14_000011="true"
# AOSX_14_000011="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_000012
# Rule Title: The macOS system must automatically remove or disable temporary user accounts after 72 hours.
# Note: Managed by a directory server (AD). This audit checks if the system is bound to Active Directory.
# AOSX_14_000012="true"
AOSX_14_000012="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_000013
# Rule Title: The macOS system must automatically remove or disable emergency accounts after the crisis is resolved or within 72 hours.
# Note: Managed by a directory server (AD). This audit checks if the system is bound to Active Directory.
# AOSX_14_000013="true"
AOSX_14_000013="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_000014
# Rule Title: The macOS system must, for networked systems, compare internal information system clocks at least every 24 hours with a server that is
# synchronized to one of the redundant United States Naval Observatory (USNO) time servers or a time server designated for the appropriate DoD network
# (NIPRNet/SIPRNet) and/or the Global Positioning System (GPS).
AOSX_14_000014="true"
# AOSX_14_000014="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_000015
# Rule Title: The macOS system must utilize an HBSS solution and implement all DoD required modules.
# Note: This audit checks if the McAfee EPO is installed. If another HBSS is used the audit must be changed.
AOSX_14_000015="true"
# AOSX_14_000015="false"

# Severity: CAT I
# Rule Version (STIG-ID): AOSX_14_000016
# Rule Title: The macOS system must be integrated into a directory services infrastructure.
AOSX_14_000016="true"
# AOSX_14_000016="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_000020
# Rule Title: The macOS system must enforce the limit of three consecutive invalid logon attempts by a user.
# Note: Use caution if passwords are managed by Active Directory, Enterprise Connect, or another similar tool.
# Having multiple password policy sources (I.E. AD and config profile) may lead to unexpected results.
# Will cause unrecoverable account lockout (see AOSX_14_000021)
## Configuration Profile - Passcode payload > MAXIMUM NUMBER OF FAILED ATTEMPTS 3
# AOSX_14_000020="true"
AOSX_14_000020="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_000021
# Rule Title: The macOS system must enforce an account lockout time period of 15 minutes in which a user makes three consecutive invalid logon attempts.
# Note: Use caution if passwords are managed by Active Directory, Enterprise Connect, or another similar tool.
# Having multiple password policy sources (I.E. AD and config profile) may lead to unexpected results.
# Will cause unrecoverable account lockout (see AOSX_14_000020)
## Configuration Profile - Passcode payload > DELAY AFTER FAILED LOGIN ATTEMPTS 15 (NOT COMPATIBLE WITH MACOS V10.11 OR LATER)
# AOSX_14_000021="true"
AOSX_14_000021="false"

# NULL - REDUNDANT to AOSX_14_000020 and AOSX_14_000021
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_000022
# Rule Title: The macOS system must enforce the limit of three consecutive invalid logon attempts by a user before the user account is locked.
# Note: Use caution if passwords are managed by Active Directory, Enterprise Connect, or another similar tool.
# Having multiple password policy sources (I.E. AD and config profile) may lead to unexpected results.
## Configuration Profile - Passcode payload > MAXIMUM NUMBER OF FAILED ATTEMPTS 3
## Configuration Profile - Passcode payload > DELAY AFTER FAILED LOGIN ATTEMPTS 15 (NOT COMPATIBLE WITH MACOS V10.11 OR LATER)
# AOSX_14_000022="true"
AOSX_14_000022="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_000023
# Rule Title: The macOS system must display the Standard Mandatory DoD Notice and Consent Banner before granting remote access to the operating system.
AOSX_14_000023="true"
# AOSX_14_000023="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_000024
# Rule Title: The macOS system must display the Standard Mandatory DoD Notice and Consent Banner before granting access to the system via SSH.
AOSX_14_000024="true"
# AOSX_14_000024="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_000025
# Rule Title: The macOS system must be configured so that any connection to the system must display the Standard Mandatory DoD Notice and Consent Banner before
# granting GUI access to the system.
AOSX_14_000025="true"
# AOSX_14_000025="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_000030
# Rule Title: The macOS system must be configured so that log files must not contain access control lists (ACLs).
AOSX_14_000030="true"
# AOSX_14_000030="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_000031
# Rule Title: The macOS system must be configured so that log folders must not contain access control lists (ACLs).
AOSX_14_000031="true"
# AOSX_14_000031="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_000032
# Rule Title: The macOS system must be configured with a dedicated user account to decrypt the hard disk upon startup.
# Ensure that only one FileVault user is defined and verify that password forwarding has been disabled on the system
## Configuration Profile - Custom payload > com.apple.loginwindow > DisableFDEAutoLogin=true
AOSX_14_000032="true"
# AOSX_14_000032="false"

# DUPLICATE check to AOSX_14_000011
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_000040
# Rule Title: The macOS system must use replay-resistant authentication mechanisms and implement cryptographic mechanisms to protect the integrity of and verify
# remote disconnection at the termination of nonlocal maintenance and diagnostic communications, when used for nonlocal maintenance sessions.
# Note: This audit checks for an exact match to "OpenSSH_7.9p1".
AOSX_14_000040="true"
# AOSX_14_000040="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_000050
# Rule Title: The macOS system must limit the number of concurrent SSH sessions to 10 for all accounts and/or account types.
AOSX_14_000050="true"
# AOSX_14_000050="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_000051
# Rule Title: The macOS system must be configured with the SSH daemon ClientAliveInterval option set to 900 or less.
AOSX_14_000051="true"
# AOSX_14_000051="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_000052
# Rule Title: The macOS system must be configured with the SSH daemon ClientAliveCountMax option set to 0.
AOSX_14_000052="true"
# AOSX_14_000052="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_000053
# Rule Title: The macOS system must be configured with the SSH daemon LoginGraceTime set to 30 or less.
AOSX_14_000053="true"
# AOSX_14_000053="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_001001
# Rule Title: The macOS system must generate audit records for all account creations, modifications, disabling, and termination events; privileged activities or
# other system-level access; all kernel module load, unload, and restart actions; all program initiations; and organizationally defined events for all non-local
# maintenance and diagnostic sessions.
AOSX_14_001001="true"
# AOSX_14_001001="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_001002
# Rule Title: The macOS system must monitor remote access methods and generate audit records when successful/unsuccessful attempts to access/modify privileges occur.
AOSX_14_001002="true"
# AOSX_14_001002="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_001003
# Rule Title: The macOS system must initiate session audits at system startup.
AOSX_14_001003="true"
# AOSX_14_001003="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_001010
# Rule Title: The macOS system must shut down by default upon audit failure (unless availability is an overriding concern).
AOSX_14_001010="true"
# AOSX_14_001010="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_001012
# Rule Title: The macOS system must be configured with audit log files owned by root.
AOSX_14_001012="true"
# AOSX_14_001012="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_001013
# Rule Title: The macOS system must be configured with audit log folders owned by root.
AOSX_14_001013="true"
# AOSX_14_001013="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_001014
# Rule Title: The macOS system must be configured with audit log files group-owned by wheel.
AOSX_14_001014="true"
# AOSX_14_001014="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_001015
# Rule Title: The macOS system must be configured with audit log folders group-owned by wheel.
AOSX_14_001015="true"
# AOSX_14_001015="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_001016
# Rule Title: The macOS system must be configured with audit log files set to mode 440 or less permissive.
AOSX_14_001016="true"
# AOSX_14_001016="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_001017
# Rule Title: The macOS system must be configured with audit log folders set to mode 700 or less permissive.
AOSX_14_001017="true"
# AOSX_14_001017="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_001020
# Rule Title: The macOS system must audit the enforcement actions used to restrict access associated with changes to the system.
AOSX_14_001020="true"
# AOSX_14_001020="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_001029
# Rule Title: The macOS system must allocate audit record storage capacity to store at least one weeks worth of audit records when audit records are not
# immediately sent to a central audit record storage facility.
AOSX_14_001029="true"
# AOSX_14_001029="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_001030
# Rule Title: The macOS system must provide an immediate warning to the System Administrator (SA) and Information System Security Officer (ISSO) (at a minimum)
# when allocated audit record storage volume reaches 75 percent of repository maximum audit record storage capacity.
AOSX_14_001030="true"
# AOSX_14_001030="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_001031
# Rule Title: The macOS system must provide an immediate real-time alert to the System Administrator (SA) and Information System Security Officer (ISSO), at a
# minimum, of all audit failure events requiring real-time alerts.
AOSX_14_001031="true"
# AOSX_14_001031="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_001044
# Rule Title: The macOS system must generate audit records for DoD-defined events such as successful/unsuccessful logon attempts, successful/unsuccessful direct
# access attempts, starting and ending time for user access, and concurrent logons to the same account from different sources.
AOSX_14_001044="true"
# AOSX_14_001044="false"

# DUPLICATE check to AOSX_14_003002
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_001060
# Rule Title: The macOS system must accept and verify Personal Identity Verification (PIV) credentials, implement a local cache of revocation data to support
# path discovery and validation in case of the inability to access revocation information via the network, and only allow the use of DoD PKI-established
# certificate authorities for verification of the establishment of protected sessions.
# Note: Before applying the "Smart Card Policy", the supplemental guidance provided with the STIG should be consulted to ensure continued access to the operating system.
## Configuration Profile - Smart Card Payload > VERIFY CERTIFICATE TRUST = Check Certificate
AOSX_14_001060="true"
# AOSX_14_001060="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_001100
# Rule Title: The macOS system must require individuals to be authenticated with an individual authenticator prior to using a group authenticator.
AOSX_14_001100="true"
# AOSX_14_001100="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_002001
# Rule Title: The macOS system must be configured to disable SMB File Sharing unless it is required.
AOSX_14_002001="true"
# AOSX_14_002001="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_002002
# Rule Title: The macOS system must be configured to disable Apple File (AFP) Sharing.
AOSX_14_002002="true"
# AOSX_14_002002="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_002003
# Rule Title: The macOS system must be configured to disable the Network File System (NFS) daemon unless it is required.
AOSX_14_002003="true"
# AOSX_14_002003="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_002004
# Rule Title: The macOS system must be configured to disable Location Services.
# Note: This audit work correctly on T2 Mac systems, but the remediation is manual.
AOSX_14_002004="true"
# AOSX_14_002004="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_002005
# Rule Title: The macOS system must be configured to disable Bonjour multicast advertising.
## Configuration Profile - Custom payload > com.apple.mDNSResponder > NoMulticastAdvertisements=true
AOSX_14_002005="true"
# AOSX_14_002005="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_002006
# Rule Title: The macOS system must be configured to disable the UUCP service.
AOSX_14_002006="true"
# AOSX_14_002006="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_002007
# Rule Title: The macOS system must be configured to disable Internet Sharing.
## Configuration Profile - Custom payload > com.apple.MCX > forceInternetSharingOff=true
AOSX_14_002007="true"
# AOSX_14_002007="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_002008
# Rule Title: The macOS system must be configured to disable Web Sharing.
AOSX_14_002008="true"
# AOSX_14_002008="false"

# Severity: CAT III
# Rule Version (STIG-ID): AOSX_14_002009
# Rule Title: The macOS system must be configured to disable AirDrop.
## Configuration Profile - Restrictions payload > Media > Allow AirDrop (unchecked)
AOSX_14_002009="true"
# AOSX_14_002009="false"

# Severity: CAT III
# Rule Version (STIG-ID): AOSX_14_002010
# Rule Title: The macOS system must be configured to disable the application FaceTime.
## Configuration Profile - Restrictions payload > Applications > Disallow "/Applications/FaceTime.app"
AOSX_14_002010="true"
# AOSX_14_002010="false"

# Severity: CAT III
# Rule Version (STIG-ID): AOSX_14_002011
# Rule Title: The macOS system must be configured to disable the application Messages.
## Configuration Profile - Restrictions payload > Applications > Disallow "/Applications/Messages.app"
AOSX_14_002011="true"
# AOSX_14_002011="false"

# Severity: CAT III
# Rule Version (STIG-ID): AOSX_14_002012
# Rule Title: The macOS system must be configured to disable the iCloud Calendar services.
## Configuration Profile - Restrictions payload > Functionality > Allow iCloud Calendar (unchecked)
AOSX_14_002012="true"
# AOSX_14_002012="false"

# Severity: CAT III
# Rule Version (STIG-ID): AOSX_14_002013
# Rule Title: The macOS system must be configured to disable the iCloud Reminders services.
## Configuration Profile - Restrictions payload > Functionality > Allow iCloud Reminders (unchecked)
AOSX_14_002013="true"
# AOSX_14_002013="false"

# Severity: CAT III
# Rule Version (STIG-ID): AOSX_14_002014
# Rule Title: The macOS system must be configured to disable iCloud Address Book services.
## Configuration Profile - Restrictions payload > Functionality > Allow iCloud Contacts (unchecked)
AOSX_14_002014="true"
# AOSX_14_002014="false"

# Severity: CAT III
# Rule Version (STIG-ID): AOSX_14_002015
# Rule Title: The macOS system must be configured to disable the Mail iCloud services.
## Configuration Profile - Restrictions payload > Functionality > Allow iCloud Mail (unchecked)
AOSX_14_002015="true"
# AOSX_14_002015="false"

# Severity: CAT III
# Rule Version (STIG-ID): AOSX_14_002016
# Rule Title: The macOS system must be configured to disable the iCloud Notes services.
## Configuration Profile - Restrictions payload > Functionality > Allow iCloud Notes (unchecked)
AOSX_14_002016="true"
# AOSX_14_002016="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_002017
# Rule Title: The macOS system must be configured to disable the camera.
## Configuration Profile - Restrictions payload > Functionality > Allow use of Camera (unchecked)
AOSX_14_002017="true"
# AOSX_14_002017="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_002019
# Rule Title: The macOS system must be configured to disable the application Mail.
## Configuration Profile - Restrictions payload > Applications > Disallow "/Applications/Mail.app"
AOSX_14_002019="true"
# AOSX_14_002019="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_002020
# Rule Title: The macOS system must be configured to disable Siri and dictation.
## Configuration Profile - Custom payload > com.apple.ironwood.support > Ironwood Allowed=false
## Configuration Profile - Custom payload > com.apple.ironwood.support > Assistant Allowed=false
AOSX_14_002020="true"
# AOSX_14_002020="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_002021
# Rule Title: The macOS system must be configured to disable sending diagnostic and usage data to Apple.
## Configuration Profile - Security & Privacy payload > Privacy > Allow sending diagnostic and usage data to Apple... (unchecked)
AOSX_14_002021="true"
# AOSX_14_002021="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_002022
# Rule Title: The macOS system must be configured to disable Remote Apple Events.
AOSX_14_002022="true"
# AOSX_14_002022="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_002023
# Rule Title: The macOS system must be configured to disable the application Calendar.
## Configuration Profile - Restrictions payload > Applications > Disallow "/Applications/Calendar.app"
AOSX_14_002023="true"
# AOSX_14_002023="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_002031
# Rule Title: The macOS system must be configured to disable the system preference pane for iCloud.
## Configuration Profile - Restrictions payload > Preferences > disable selected items "iCloud"
AOSX_14_002031="true"
# AOSX_14_002031="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_002032
# Rule Title: The macOS system must be configured to disable the system preference pane for Internet Accounts.
## Configuration Profile - Restrictions payload > Preferences > disable selected items "Internet Accounts"
AOSX_14_002032="true"
# AOSX_14_002032="false"

# DUPLICATE check to AOSX_14_002039
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_002034
# Rule Title: The macOS system must be configured to disable the Siri Setup services.
## Configuration Profile - Login Window payload > Options > Disable Siri setup during login (checked)
AOSX_14_002034="true"
# AOSX_14_002034="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_002035
# Rule Title: The macOS system must be configured to disable the Cloud Setup services.
## Configuration Profile - Login Window payload > Options > Disable Apple ID setup during login (checked)
AOSX_14_002035="true"
# AOSX_14_002035="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_002036
# Rule Title: The macOS system must be configured to disable the Privacy Setup services.
# Configuration Profile - Login Window payload > Options > Disable Privacy setup during login (checked)
# or
## Configuration Profile - Custom payload > com.apple.SetupAssistant.managed > SkipPrivacySetup=true
AOSX_14_002036="true"
# AOSX_14_002036="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_002037
# Rule Title: The macOS system must be configured to disable the Cloud Storage Setup services.
# Configuration Profile - Login Window payload > Options > Disable iCloud Storage setup during login (checked)
# or
## Configuration Profile - Custom payload > com.apple.SetupAssistant.managed > SkipiCloudStorageSetup=true
AOSX_14_002037="true"
# AOSX_14_002037="false"

# Severity: CAT I
# Rule Version (STIG-ID): AOSX_14_002038
# Rule Title: macOS must be configured to disable the tftp service.
AOSX_14_002038="true"
# AOSX_14_002038="false"

# DUPLICATE check to AOSX_14_002034
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_002039
# Rule Title: The macOS system must be configured to disable the Siri Setup services.
# Configuration Profile - Login Window payload > Options > Disable Siri setup during login (checked)
AOSX_14_002039="true"
# AOSX_14_002039="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_002040
# Rule Title: The macOS system must disable iCloud Keychain synchronization.
## Configuration Profile - Restrictions payload > Functionality > Allow iCloud Keychain (unchecked)
AOSX_14_002040="true"
# AOSX_14_002040="false"

# DUPLICATE check to AOSX_14_002049
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_002041
# Rule Title: The macOS system must disable iCloud document synchronization.
## Configuration Profile - Restrictions payload > Functionality > Allow iCloud Drive (unchecked)
AOSX_14_002041="true"
# AOSX_14_002041="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_002042
# Rule Title: The macOS system must disable iCloud bookmark synchronization.
## Configuration Profile - Restrictions payload > Functionality > Allow iCloud Bookmarks (unchecked)
AOSX_14_002042="true"
# AOSX_14_002042="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_002043
# Rule Title: The macOS system must disable iCloud photo library.
# Configuration Profile - Restrictions payload > Functionality > Allow iCloud Photos (unchecked)
# or
## Configuration Profile - Custom payload > com.apple.applicationaccess > allowCloudPhotoLibrary=false
AOSX_14_002043="true"
# AOSX_14_002043="false"

# DUPLICATE check to AOSX_14_002041
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_002049
# Rule Title: The macOS system must disable Cloud Document Sync.
# Configuration Profile - Restrictions payload > Functionality > Allow iCloud Drive (unchecked)
AOSX_14_002049="true"
# AOSX_14_002049="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_002050
# Rule Title: The macOS system must disable the Screen Sharing feature.
AOSX_14_002050="true"
# AOSX_14_002050="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_002060
# Rule Title: The macOS system must allow only applications downloaded from the App Store and identified developers to run.
## Configuration Profile - Security & Privacy payload > General > Mac App Store and identified developers (selected)
AOSX_14_002060="true"
# AOSX_14_002060="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_002061
# Rule Title: The macOS system must be configured so that end users cannot override Gatekeeper settings.
## Configuration Profile - Security & Privacy payload > General > Do not allow user to override Gatekeeper setting (checked)
AOSX_14_002061="true"
# AOSX_14_002061="false"

# Severity: CAT III
# Rule Version (STIG-ID): AOSX_14_002062
# Rule Title: The macOS system must be configured with Bluetooth turned off unless approved by the organization.
## Configuration Profile - Custom payload > com.apple.MCXBluetooth > DisableBluetooth=true
AOSX_14_002062="true"
# AOSX_14_002062="false"

# Severity: CAT I
# Rule Version (STIG-ID): AOSX_14_002063
# Rule Title: The macOS system must disable the guest account.
## Configuration Profile - Login Window payload > Options > Allow Guest User (unchecked)
AOSX_14_002063="true"
# AOSX_14_002063="false"

# Severity: CAT I
# Rule Version (STIG-ID): AOSX_14_002064
# Rule Title: The macOS system must have the security assessment policy subsystem enabled.
AOSX_14_002064="true"
# AOSX_14_002064="false"

# REDUNDANT to AOSX_14_002068
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_002065
# Rule Title: The macOS system must limit the ability of non-privileged users to grant other users direct access to the contents of their home directories/folders.
# AOSX_14_002065="true"
AOSX_14_002065="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_002066
# Rule Title: The macOS system must not allow an unattended or automatic logon to the system.
# Configuration Profile - Login Window payload > Options > Disable automatic login (checked)
AOSX_14_002066="true"
# AOSX_14_002066="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_002067
# Rule Title: The macOS system must prohibit user installation of software without explicit privileged status.
## Configuration Profile - Restrictions payload > Applications > Disallow "/Users"
AOSX_14_002067="true"
# AOSX_14_002067="false"

# AOSX_14_002065 is redundant to this
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_002068
# Rule Title: The macOS system must set permissions on user home directories to prevent users from having access to read or modify another users files.
AOSX_14_002068="true"
# AOSX_14_002068="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_002069
# Rule Title: The macOS system must uniquely identify peripherals before establishing a connection.
# Check that macOS is configured to require authentication to all system preference panes.
AOSX_14_002069="true"
# AOSX_14_002069="false"

# Severity: CAT I
# Rule Version (STIG-ID): AOSX_14_002070
# Rule Title: The macOS system must use an approved antivirus program.
# Note: This audit checks if the McAfee EPO is installed. If another HBSS is used the audit must be changed.
AOSX_14_002070="true"
# AOSX_14_002070="false"

# Severity: CAT I
# Rule Version (STIG-ID): AOSX_14_003001
# Rule Title: The macOS system must issue or obtain public key certificates under an appropriate certificate policy from an approved service provider.
## Configuration Profile - Certificate payload
AOSX_14_003001="true"
# AOSX_14_003001="false"

# DUPLICATE check to AOSX_14_001060
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_003002
# Rule Title: The macOS system must enable certificate for smartcards.
# Note: Before applying the "Smart Card Policy", the supplemental guidance provided with the STIG should be consulted to ensure continued access to the operating system.
## Configuration Profile - Smart Card payload > VERIFY CERTIFICATE TRUST (Check Certificate)
AOSX_14_003002="true"
# AOSX_14_003002="false"

# DUPLICATE check to AOSX_14_003025
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_003005
# Rule Title: The macOS system must map the authenticated identity to the user or group account for PKI-based authentication.
# Note: Before applying the "Smart Card Policy", the supplemental guidance provided with the STIG should be consulted to ensure continued access to the operating system.
## Configuration Profile - Smart Card payload > Enforce Smart Card use (checked)
AOSX_14_003005="true"
# AOSX_14_003005="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_003007
# Rule Title: The macOS system must enforce password complexity by requiring that at least one numeric character be used.
# Note: Use caution if passwords are managed by Active Directory, Enterprise Connect, or another similar tool.
# Having multiple password policy sources (I.E. AD and config profile) may lead to unexpected results.
## Configuration Profile - Passcode payload > Require alphanumeric value (checked)
# AOSX_14_003007="true"
AOSX_14_003007="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_003008
# Rule Title: The macOS system must enforce a 60-day maximum password lifetime restriction.
# Note: Use caution if passwords are managed by Active Directory, Enterprise Connect, or another similar tool.
# Having multiple password policy sources (I.E. AD and config profile) may lead to unexpected results.
## Configuration Profile - Passcode payload > MAXIMUM PASSCODE AGE 60
# AOSX_14_003008="true"
AOSX_14_003008="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_003009
# Rule Title: The macOS system must prohibit password reuse for a minimum of five generations.
# Note: Use caution if passwords are managed by Active Directory, Enterprise Connect, or another similar tool.
# Having multiple password policy sources (I.E. AD and config profile) may lead to unexpected results.
## Configuration Profile - Passcode payload > PASSCODE HISTORY 5
# AOSX_14_003009="true"
AOSX_14_003009="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_003010
# Rule Title: The macOS system must enforce a minimum 15-character password length.
# Note: Use caution if passwords are managed by Active Directory, Enterprise Connect, or another similar tool.
# Having multiple password policy sources (I.E. AD and config profile) may lead to unexpected results.
## Configuration Profile - Passcode payload > MINIMUM PASSCODE LENGTH 15
# AOSX_14_003010="true"
AOSX_14_003010="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_003011
# Rule Title: The macOS system must enforce password complexity by requiring that at least one special character be used.
# Note: Use caution if passwords are managed by Active Directory, Enterprise Connect, or another similar tool.
# Having multiple password policy sources (I.E. AD and config profile) may lead to unexpected results.
## Configuration Profile - Passcode payload > MINIMUM NUMBER OF COMPLEX CHARACTERS 1
## Configuration Profile - Passcode payload > Allow simple value (unchecked)
# AOSX_14_003011="true"
AOSX_14_003011="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_003012
# Rule Title: The macOS system must be configured to prevent displaying password hints.
## Configuration Profile - Login Window payload > Options > Show password hint when needed and available (unchecked)
AOSX_14_003012="true"
# AOSX_14_003012="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_003013
# Rule Title: macOS must be configured with a firmware password to prevent access to single user mode and booting from alternative media.
AOSX_14_003013="true"
# AOSX_14_003013="false"

# DUPLICATE check to AOSX_14_003024
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_003020
# Rule Title: The macOS system must use multifactor authentication for local and network access to privileged and non-privileged accounts. 
# Disable password based authentication in SSHD.
AOSX_14_003020="true"
# AOSX_14_003020="false"

# DUPLICATE check to AOSX_14_003020
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_003024
# Rule Title: The macOS system must use multifactor authentication in the establishment of nonlocal maintenance and diagnostic sessions. 
# Ensure that passcode based logins are disabled in sshd.
AOSX_14_003024="true"
# AOSX_14_003024="false"

# DUPLICATE check to AOSX_14_003005
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_003025
# Rule Title: The macOS system must implement multifactor authentication for remote access to privileged accounts in such a way that one of the factors is
# provided by a device separate from the system gaining access.
# Note: Before applying the "Smart Card Policy", the supplemental guidance provided with the STIG should be consulted to ensure continued access to the operating system.
# Configuration Profile - Smart Card payload > Enforce Smart Card use (checked)
AOSX_14_003025="true"
# AOSX_14_003025="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_003050
# Rule Title: The macOS system must be configured so that the login command requires smart card authentication.
# Note: Before applying the "Smart Card Policy", the supplemental guidance provided with the STIG should be consulted to ensure continued access to the operating system.
AOSX_14_003050="true"
# AOSX_14_003050="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_003051
# Rule Title: The macOS system must be configured so that the su command requires smart card authentication.
# Note: Before applying the "Smart Card Policy", the supplemental guidance provided with the STIG should be consulted to ensure continued access to the operating system.
AOSX_14_003051="true"
# AOSX_14_003051="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_003052
# Rule Title: The macOS system must be configured so that the sudo command requires smart card authentication.
# Note: Before applying the "Smart Card Policy", the supplemental guidance provided with the STIG should be consulted to ensure continued access to the operating system.
AOSX_14_003052="true"
# AOSX_14_003052="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_004001
# Rule Title: The macOS system must be configured with system log files owned by root and group-owned by wheel or admin.
AOSX_14_004001="true"
# AOSX_14_004001="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_004002
# Rule Title: The macOS system must be configured with system log files set to mode 640 or less permissive.
AOSX_14_004002="true"
# AOSX_14_004002="false"

# DUPLICATE check to AOSX_14_000010 and AOSX_14_004011
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_004010
# Rule Title: The macOS system must implement DoD-approved encryption to protect the confidentiality and integrity of remote access sessions including
# transmitted data and data during preparation for transmission.
AOSX_14_004010="true"
# AOSX_14_004010="false"
#
# If AOSX_14_004010 is not enforced then SSH should be off.
if [ "$AOSX_14_004010" = "false" ]; then
	AOSX_14_004010off="true"; else
	AOSX_14_004010off="false"
fi

# DUPLICATE check to AOSX_14_000010 and AOSX_14_004010
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_004011
# Rule Title: The macOS system must implement DoD-approved encryption to protect the confidentiality and integrity of remote access sessions including
# transmitted data and data during preparation for transmission.
AOSX_14_004011="true"
# AOSX_14_004011="false"
#
# If AOSX_14_004011 is not enforced then SSH should be off.
if [ "$AOSX_14_004011" = "false" ]; then
	AOSX_14_004011off="true"; else
	AOSX_14_004011off="false"
fi

# DUPLICATE check to AOSX_14_000008
# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_004020
# Rule Title: The macOS system must authenticate all endpoint devices before establishing a local, remote, and/or network connection using bidirectional
# authentication that is cryptographically based.
# AOSX_14_004020="true"
AOSX_14_004020="false"

# Severity: CAT I
# Rule Version (STIG-ID): AOSX_14_004021
# Rule Title: The macOS system must be configured with the sudoers file configured to authenticate users on a per -tty basis.
AOSX_14_004021="true"
# AOSX_14_004021="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_005001
# Rule Title: The macOS system must enable System Integrity Protection.
AOSX_14_005001="true"
# AOSX_14_005001="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_005020
# Rule Title: The macOS system must implement cryptographic mechanisms to protect the confidentiality and integrity of all information at rest.
AOSX_14_005020="true"
# AOSX_14_005020="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_005050
# Rule Title: The macOS Application Firewall must be enabled.
AOSX_14_005050="true"
# AOSX_14_005050="false"

# Severity: CAT II
# Rule Version (STIG-ID): AOSX_14_005051
# Rule Title: The macOS system must employ a deny-all, allow-by-exception firewall policy for allowing connections to other systems.
# Note: This audit checks if the McAfee EPO is installed. If another HBSS/Firewall is used the audit must be changed.
AOSX_14_005051="true"
# AOSX_14_005051="false"



##################################################################
############# DO NOT MODIFY ANYTHING BELOW THIS LINE #############
##################################################################
# Write org_security_score values to local plist

/bin/cat << EOF > "$plistlocation"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>		
		<key>AOSX_14_000001</key>
		<${AOSX_14_000001}/>
		<key>AOSX_14_000002</key>
		<${AOSX_14_000002}/>
		<key>AOSX_14_000003</key>
		<${AOSX_14_000003}/>
		<key>AOSX_14_000004</key>
		<${AOSX_14_000004}/>
		<key>AOSX_14_000005</key>
		<${AOSX_14_000005}/>
		<key>AOSX_14_000006</key>
		<${AOSX_14_000006}/>
		<key>AOSX_14_000007</key>
		<${AOSX_14_000007}/>
		<key>AOSX_14_000008</key>
		<${AOSX_14_000008}/>
		<key>AOSX_14_000010</key>
		<${AOSX_14_000010}/>
		<key>AOSX_14_000010off</key>
		<${AOSX_14_000010off}/>
		<key>AOSX_14_000011</key>
		<${AOSX_14_000011}/>
		<key>AOSX_14_000012</key>
		<${AOSX_14_000012}/>
		<key>AOSX_14_000013</key>
		<${AOSX_14_000013}/>
		<key>AOSX_14_000014</key>
		<${AOSX_14_000014}/>
		<key>AOSX_14_000015</key>
		<${AOSX_14_000015}/>
		<key>AOSX_14_000016</key>
		<${AOSX_14_000016}/>
		<key>AOSX_14_000020</key>
		<${AOSX_14_000020}/>
		<key>AOSX_14_000021</key>
		<${AOSX_14_000021}/>
		<key>AOSX_14_000022</key>
		<${AOSX_14_000022}/>
		<key>AOSX_14_000023</key>
		<${AOSX_14_000023}/>
		<key>AOSX_14_000024</key>
		<${AOSX_14_000024}/>
		<key>AOSX_14_000025</key>
		<${AOSX_14_000025}/>
		<key>AOSX_14_000030</key>
		<${AOSX_14_000030}/>
		<key>AOSX_14_000031</key>
		<${AOSX_14_000031}/>
		<key>AOSX_14_000032</key>
		<${AOSX_14_000032}/>
		<key>AOSX_14_000040</key>
		<${AOSX_14_000040}/>
		<key>AOSX_14_000050</key>
		<${AOSX_14_000050}/>
		<key>AOSX_14_000051</key>
		<${AOSX_14_000051}/>
		<key>AOSX_14_000052</key>
		<${AOSX_14_000052}/>
		<key>AOSX_14_000053</key>
		<${AOSX_14_000053}/>
		<key>AOSX_14_001001</key>
		<${AOSX_14_001001}/>
		<key>AOSX_14_001002</key>
		<${AOSX_14_001002}/>
		<key>AOSX_14_001003</key>
		<${AOSX_14_001003}/>
		<key>AOSX_14_001010</key>
		<${AOSX_14_001010}/>
		<key>AOSX_14_001012</key>
		<${AOSX_14_001012}/>
		<key>AOSX_14_001013</key>
		<${AOSX_14_001013}/>
		<key>AOSX_14_001014</key>
		<${AOSX_14_001014}/>
		<key>AOSX_14_001015</key>
		<${AOSX_14_001015}/>
		<key>AOSX_14_001016</key>
		<${AOSX_14_001016}/>
		<key>AOSX_14_001017</key>
		<${AOSX_14_001017}/>
		<key>AOSX_14_001020</key>
		<${AOSX_14_001020}/>
		<key>AOSX_14_001029</key>
		<${AOSX_14_001029}/>
		<key>AOSX_14_001030</key>
		<${AOSX_14_001030}/>
		<key>AOSX_14_001031</key>
		<${AOSX_14_001031}/>
		<key>AOSX_14_001044</key>
		<${AOSX_14_001044}/>
		<key>AOSX_14_001060</key>
		<${AOSX_14_001060}/>
		<key>AOSX_14_001100</key>
		<${AOSX_14_001100}/>
		<key>AOSX_14_002001</key>
		<${AOSX_14_002001}/>
		<key>AOSX_14_002002</key>
		<${AOSX_14_002002}/>
		<key>AOSX_14_002003</key>
		<${AOSX_14_002003}/>
		<key>AOSX_14_002004</key>
		<${AOSX_14_002004}/>
		<key>AOSX_14_002005</key>
		<${AOSX_14_002005}/>
		<key>AOSX_14_002006</key>
		<${AOSX_14_002006}/>
		<key>AOSX_14_002007</key>
		<${AOSX_14_002007}/>
		<key>AOSX_14_002008</key>
		<${AOSX_14_002008}/>
		<key>AOSX_14_002009</key>
		<${AOSX_14_002009}/>
		<key>AOSX_14_002010</key>
		<${AOSX_14_002010}/>
		<key>AOSX_14_002011</key>
		<${AOSX_14_002011}/>
		<key>AOSX_14_002012</key>
		<${AOSX_14_002012}/>
		<key>AOSX_14_002013</key>
		<${AOSX_14_002013}/>
		<key>AOSX_14_002014</key>
		<${AOSX_14_002014}/>
		<key>AOSX_14_002015</key>
		<${AOSX_14_002015}/>
		<key>AOSX_14_002016</key>
		<${AOSX_14_002016}/>
		<key>AOSX_14_002017</key>
		<${AOSX_14_002017}/>
		<key>AOSX_14_002019</key>
		<${AOSX_14_002019}/>
		<key>AOSX_14_002020</key>
		<${AOSX_14_002020}/>
		<key>AOSX_14_002021</key>
		<${AOSX_14_002021}/>
		<key>AOSX_14_002022</key>
		<${AOSX_14_002022}/>
		<key>AOSX_14_002023</key>
		<${AOSX_14_002023}/>
		<key>AOSX_14_002031</key>
		<${AOSX_14_002031}/>
		<key>AOSX_14_002032</key>
		<${AOSX_14_002032}/>
		<key>AOSX_14_002034</key>
		<${AOSX_14_002034}/>
		<key>AOSX_14_002035</key>
		<${AOSX_14_002035}/>
		<key>AOSX_14_002036</key>
		<${AOSX_14_002036}/>
		<key>AOSX_14_002037</key>
		<${AOSX_14_002037}/>
		<key>AOSX_14_002038</key>
		<${AOSX_14_002038}/>
		<key>AOSX_14_002039</key>
		<${AOSX_14_002039}/>
		<key>AOSX_14_002040</key>
		<${AOSX_14_002040}/>
		<key>AOSX_14_002041</key>
		<${AOSX_14_002041}/>
		<key>AOSX_14_002042</key>
		<${AOSX_14_002042}/>
		<key>AOSX_14_002043</key>
		<${AOSX_14_002043}/>
		<key>AOSX_14_002049</key>
		<${AOSX_14_002049}/>
		<key>AOSX_14_002050</key>
		<${AOSX_14_002050}/>
		<key>AOSX_14_002060</key>
		<${AOSX_14_002060}/>
		<key>AOSX_14_002061</key>
		<${AOSX_14_002061}/>
		<key>AOSX_14_002062</key>
		<${AOSX_14_002062}/>
		<key>AOSX_14_002063</key>
		<${AOSX_14_002063}/>
		<key>AOSX_14_002064</key>
		<${AOSX_14_002064}/>
		<key>AOSX_14_002065</key>
		<${AOSX_14_002065}/>
		<key>AOSX_14_002066</key>
		<${AOSX_14_002066}/>
		<key>AOSX_14_002067</key>
		<${AOSX_14_002067}/>
		<key>AOSX_14_002068</key>
		<${AOSX_14_002068}/>
		<key>AOSX_14_002069</key>
		<${AOSX_14_002069}/>
		<key>AOSX_14_002070</key>
		<${AOSX_14_002070}/>
		<key>AOSX_14_003001</key>
		<${AOSX_14_003001}/>
		<key>AOSX_14_003002</key>
		<${AOSX_14_003002}/>
		<key>AOSX_14_003005</key>
		<${AOSX_14_003005}/>
		<key>AOSX_14_003007</key>
		<${AOSX_14_003007}/>
		<key>AOSX_14_003008</key>
		<${AOSX_14_003008}/>
		<key>AOSX_14_003009</key>
		<${AOSX_14_003009}/>
		<key>AOSX_14_003010</key>
		<${AOSX_14_003010}/>
		<key>AOSX_14_003011</key>
		<${AOSX_14_003011}/>
		<key>AOSX_14_003012</key>
		<${AOSX_14_003012}/>
		<key>AOSX_14_003013</key>
		<${AOSX_14_003013}/>
		<key>AOSX_14_003020</key>
		<${AOSX_14_003020}/>
		<key>AOSX_14_003024</key>
		<${AOSX_14_003024}/>
		<key>AOSX_14_003025</key>
		<${AOSX_14_003025}/>
		<key>AOSX_14_003050</key>
		<${AOSX_14_003050}/>
		<key>AOSX_14_003051</key>
		<${AOSX_14_003051}/>
		<key>AOSX_14_003052</key>
		<${AOSX_14_003052}/>
		<key>AOSX_14_004001</key>
		<${AOSX_14_004001}/>
		<key>AOSX_14_004002</key>
		<${AOSX_14_004002}/>
		<key>AOSX_14_004010</key>
		<${AOSX_14_004010}/>
		<key>AOSX_14_004010off</key>
		<${AOSX_14_004010off}/>
		<key>AOSX_14_004011</key>
		<${AOSX_14_004011}/>
		<key>AOSX_14_004011off</key>
		<${AOSX_14_004011off}/>
		<key>AOSX_14_004020</key>
		<${AOSX_14_004020}/>
		<key>AOSX_14_004021</key>
		<${AOSX_14_004021}/>
		<key>AOSX_14_005001</key>
		<${AOSX_14_005001}/>
		<key>AOSX_14_005020</key>
		<${AOSX_14_005020}/>
		<key>AOSX_14_005050</key>
		<${AOSX_14_005050}/>
		<key>AOSX_14_005051</key>
		<${AOSX_14_005051}/>
</dict>
</plist>
EOF

/bin/echo "Run 2_STIG_Audit_Compliance"
exit 0