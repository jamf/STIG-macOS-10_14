# STIG for macOS 10.14 Mojave - Script and Configuration Profile Remediation

## INFO:
The STIG is available on IASE at: https://public.cyber.mil/stigs/downloads/?_dl_facet_stigs=operating-systems,mac-os

U_Apple_OS_X_10-14_V1R2_STIG 

Version: 1, Release: 2, 24 Jan 2020

## USAGE:
### Add the following scripts to your Jamf Pro

##### 1_STIG_10_14_Set_Priorities.sh
This script will require additional configuration prior to deployment.

Sets organizational compliance for each listed item, which gets written to STIG_security_score.plist. Values default to "true".

To disregard a given item set the value to "false" by changing the associated comment: AOSX_14_00000X="true" or AOSX_14_00000X="false"

The script writes to /Library/Application Support/SecurityScoring/STIG_security_score.plist by default.

##### 2_STIG_10_14_Audit_Compliance.sh
Run this before and after 3_STIG_10_14_Remediation to audit the remediation.

Reads the plist at /Library/Application Support/SecurityScoring/STIG_security_score.plist. For items prioritized (listed as "true,") the script queries against the current computer/user environment to determine compliance against each item.

Items that pass compliance do not require further remediation and are set to "false" in the STIG_security_score.plist.

Non-compliant items are recorded at /Library/Application\ Support/SecurityScoring/STIG_audit

##### 3_STIG_10_14_Remediation.sh
Reads the plist at /Library/Application Support/SecurityScoring/org_security_score.plist.

For items still prioritized (listed as "true,") the script applies recommended remediation actions for the client/user.

### Create a single Jamf Policy using all three scripts
* 1_STIG_10_14_Set_Priorities.sh – Script Priority: Before
* 2_STIG_10_14_Audit_Compliance.sh – Script Priority: Before
* 3_STIG_10_14_Remediation.sh – Script Priority: Before
* 2_STIG_10_14_Audit_Compliance.sh – Script Priority: After

### Set the following options for the Jamf Policy
* Recurring trigger to track compliance over time (Daily, weekly, or Monthly)
* Update Inventory

### Create Extension Attributes using the following scripts
##### 2.5_STIG_Audit_List Extension Attribute
Set as Data Type "String."
Reads contents of /Library/Application\ Support/SecurityScoring/STIG_audit file and records to Jamf Pro inventory record.

##### 2.6_STIG_Audit_Count Extension Attribute
Set as Data Type "Integer." 
Reads contents of /Library/Application\ Support/SecurityScoring/STIG_audit file and records count of items to Jamf Pro inventory record. Usable with smart group logic (2.6_STIG_Audit_Count greater than 0) to immediately determine computers not in compliance.

## REMEDIATED USING CONFIGURATION PROFILES:
The following Configuration profiles are available in mobileconfig and plist form. Mobileconfigs can be uploaded to Jamf Pro as Configuration Profiles.

### 10.14_STIG-allowCloudPhotoLibrary
* AOSX_14_002043 - Custom payload > com.apple.applicationaccess > allowCloudPhotoLibrary=false

### 10.14_STIG-Certificates
* AOSX_14_003001 - Certificate payload

### 10.14_STIG-Disable Hot Corners
* AOSX_14_000007 - Custom payload > com.apple.dock > wvous-tl-corner=0, wvous-br-corner=0, wvous-bl-corner=0, wvous-tr-corner=0

### 10.14_STIG-Disable Siri and dictation
* AOSX_14_002020 - Custom payload > com.apple.ironwood.support > Ironwood Allowed=false
* AOSX_14_002020 - Custom payload > com.apple.ironwood.support > Assistant Allowed=false

### 10.14_STIG-DisableBluetooth
* AOSX_14_002062 - Custom payload > com.apple.MCXBluetooth > DisableBluetooth=true

### 10.14_STIG-DisableFDEAutologin
* AOSX_14_000032 - Custom payload > com.apple.loginwindow > DisableFDEAutoLogin=true

### 10.14_STIG-forceInternetSharingOff
* AOSX_14_002007 - Custom payload > com.apple.MCX > forceInternetSharingOff=true

### 10.14_STIG-NoMulticastAdvertisements
* AOSX_14_002005 - Custom payload > com.apple.mDNSResponder > NoMulticastAdvertisements=true

### 10.14_STIG-Passcode
* AOSX_14_000020 - Passcode payload > MAXIMUM NUMBER OF FAILED ATTEMPTS 3
* AOSX_14_000021 - Passcode payload > DELAY AFTER FAILED LOGIN ATTEMPTS
* AOSX_14_000022 - Passcode payload > MAXIMUM NUMBER OF FAILED ATTEMPTS 3
* AOSX_14_000022 - Passcode payload > DELAY AFTER FAILED LOGIN ATTEMPTS
* AOSX_14_003007 - Passcode payload > Require alphanumeric value (checked)
* AOSX_14_003008 - Passcode payload > MAXIMUM PASSCODE AGE 60
* AOSX_14_003009 - Passcode payload > PASSCODE HISTORY 5
* AOSX_14_003010 - Passcode payload > MINIMUM PASSCODE LENGTH 15
* AOSX_14_003011 - Passcode payload > MINIMUM NUMBER OF COMPLEX CHARACTERS 1
* AOSX_14_003011 - Passcode payload > Allow simple value (unchecked)

### 10.14_STIG-Restrictions
* AOSX_14_002009 - Restrictions payload > Media > Allow AirDrop (unchecked)
* AOSX_14_002010 - Restrictions payload > Applications > Disallow "/Applications/FaceTime.app"
* AOSX_14_002011 - Restrictions payload > Applications > Disallow "/Applications/Messages.app"
* AOSX_14_002012 - Restrictions payload > Functionality > Allow iCloud Calendar (unchecked)
* AOSX_14_002013 - Restrictions payload > Functionality > Allow iCloud Reminders (unchecked)
* AOSX_14_002014 - Restrictions payload > Functionality > Allow iCloud Contacts (unchecked)
* AOSX_14_002015 - Restrictions payload > Functionality > Allow iCloud Mail (unchecked)
* AOSX_14_002016 - Restrictions payload > Functionality > Allow iCloud Notes (unchecked)
* AOSX_14_002017 - Restrictions payload > Functionality > Allow use of Camera (unchecked)
* AOSX_14_002018 - Restrictions payload > Preferences > disable selected items "Internet Accounts"
* AOSX_14_002019 - Restrictions payload > Applications > Disallow "/Applications/Mail.app"
* AOSX_14_002023 - Restrictions payload > Applications > Disallow "/Applications/Calendar.app"
* AOSX_14_002031 - Restrictions payload > Preferences > disable selected items "iCloud"
* AOSX_14_002040 - Restrictions payload > Functionality > Allow iCloud Keychain (unchecked)
* AOSX_14_002041 - Restrictions payload > Functionality > Allow iCloud Drive (unchecked)
* AOSX_14_002042 - Restrictions payload > Functionality > Allow iCloud Bookmarks (unchecked)
* AOSX_14_002049 - Restrictions payload > Functionality > Allow iCloud Drive (unchecked)
* AOSX_14_002067 - Restrictions payload > Applications > Disallow "/Users"

### 10.14_STIG-Security and Privacy-LoginWindow
* AOSX_14_000001 - Security & Privacy Payload > General > Allow user to unlock the Mac using an Apple Watch (un-checked)
* AOSX_14_000002 - Security & Privacy Payload > General > Require password * after sleep or screen saver begins (checked)
* AOSX_14_000003 - Security & Privacy Payload > General > Require password * after sleep or screen saver begins (select * time no more than five seconds)
* AOSX_14_000004 - Login Window payload > Options > Start screen saver after: (checked) > 15 Minutes of Inactivity (or less) 
* AOSX_14_000006 - Login Window payload > Options > Start screen saver after: (checked) > USE SCREEN SAVER MODULE AT PATH: (path to screensaver)
* AOSX_14_002021 - Security & Privacy payload > Privacy > Allow sending diagnostic and usage data to Apple... (unchecked)
* AOSX_14_002034 - Login Window payload > Options > Disable Siri setup during login (checked)
* AOSX_14_002035 - Login Window payload > Options > Disable Apple ID setup during login (checked)
* AOSX_14_002060 - Security & Privacy payload > General > Mac App Store and identified developers (selected)
* AOSX_14_002061 - Security & Privacy payload > General > Do not allow user to override Gatekeeper setting (checked)
* AOSX_14_002063 - Login Window payload > Options > Allow Guest User (unchecked)
* AOSX_14_002066 - Login Window payload > Options > Disable automatic login (checked)
* AOSX_14_003012 - Login Window payload > Options > Show password hint when needed and available (checked)

### 10.14_STIG-SkipiCloudStorageSetup
* AOSX_14_002037 - Custom payload > com.apple.SetupAssistant.managed > SkipiCloudStorageSetup=true

### 10.14_STIG-SkipPrivacySetup
* AOSX_14_002036 - Custom payload > com.apple.SetupAssistant.managed > SkipPrivacySetup=true

### 10.14_STIG-Smart Card Enforced
* AOSX_14_000005 - Smart Card payload > Enable Screen Saver on Smart Card removal (checked)
* AOSX_14_001060 - Smart Card Payload > VERIFY CERTIFICATE TRUST = Check Certificate
* AOSX_14_003002 - Smart Card Payload > VERIFY CERTIFICATE TRUST = Check Certificate
* AOSX_14_003005 - Smart Card payload > Enforce Smart Card use (checked)
* AOSX_14_003025 - Smart Card payload > Enforce Smart Card use (checked)

##
## RECOMMENDED STIG EXCEPTIONS

* AOSX_14_000008 – Keep Wi-Fi enabled if it is approved and needed. – The macOS system must be configured with Wi-Fi support software disabled. 
* AOSX_14_004020 – Keep Wi-Fi enabled if it is approved and needed. – The macOS system must authenticate all endpoint devices before establishing a local, remote, and/or network connection using bidirectional authentication that is cryptographically based.
* AOSX_14_000012 – Managed by a directory server (AD) – The macOS system must automatically remove or disable temporary user accounts after 72 hours.
* AOSX_14_000013 – Managed by a directory server (AD) – The macOS system must automatically remove or disable emergency accounts after the crisis is resolved or within 72 hours.
* AOSX_14_000020 – This setting will cause unrecoverable account lockout (also see AOSX_14_000021) – The macOS system must enforce the limit of three consecutive invalid logon attempts by a user.
* AOSX_14_000021 – This setting will cause unrecoverable account lockout (also see AOSX_14_000020) NOT COMPATIBLE WITH MACOS V10.11 OR LATER
* AOSX_14_000022 – REDUNDANT to AOSX_14_000020 and AOSX_14_000021 - The macOS system must enforce an account lockout time period of 15 minutes in which a user makes three consecutive invalid logon attempts.
* AOSX_14_002065 – REDUNDANT to AOSX_14_002068 – The macOS system must limit the ability of non-privileged users to grant other users direct access to the contents of their home directories/folders.

## DUPLICATE AUDIT CHECKS
* AOSX_14_000010 – DUPLICATE check to AOSX_14_004010 and AOSX_14_004011
* AOSX_14_000011 – DUPLICATE check to AOSX_14_000040
* AOSX_14_000040 – DUPLICATE check to AOSX_14_000011
* AOSX_14_001060 – DUPLICATE check to AOSX_14_003002
* AOSX_14_002034 – DUPLICATE check to AOSX_14_002039
* AOSX_14_002041 – DUPLICATE check to AOSX_14_002049
* AOSX_14_002049 – DUPLICATE check to AOSX_14_002041
* AOSX_14_003002 – DUPLICATE check to AOSX_14_001060
* AOSX_14_003005 – DUPLICATE check to AOSX_14_003025
* AOSX_14_003020 – DUPLICATE check to AOSX_14_003024
* AOSX_14_003024 – DUPLICATE check to AOSX_14_003020
* AOSX_14_003025 – DUPLICATE check to AOSX_14_003005
* AOSX_14_004010 – DUPLICATE check to AOSX_14_000010 and AOSX_14_004011
* AOSX_14_004011 – DUPLICATE check to AOSX_14_000010 and AOSX_14_004010
* AOSX_14_004020 – DUPLICATE check to AOSX_14_000008

## NOTES
* AOSX_14_000005 – Smart Card - Before applying the "Smart Card Policy", the supplemental guidance provided with the STIG should be consulted to ensure continued access to the operating system.
* AOSX_14_001060 – Smart Card - Before applying the "Smart Card Policy", the supplemental guidance provided with the STIG should be consulted to ensure continued access to the operating system.
* AOSX_14_003002 – Smart Card - Before applying the "Smart Card Policy", the supplemental guidance provided with the STIG should be consulted to ensure continued access to the operating system.
* AOSX_14_003005 – Smart Card - Before applying the "Smart Card Policy", the supplemental guidance provided with the STIG should be consulted to ensure continued access to the operating system.
* AOSX_14_003025 – Smart Card - Before applying the "Smart Card Policy", the supplemental guidance provided with the STIG should be consulted to ensure continued access to the operating system.
* AOSX_14_003050 – Smart Card - Before applying the "Smart Card Policy", the supplemental guidance provided with the STIG should be consulted to ensure continued access to the operating system.
* AOSX_14_003051 – Smart Card - Before applying the "Smart Card Policy", the supplemental guidance provided with the STIG should be consulted to ensure continued access to the operating system.
* AOSX_14_003052 – Smart Card - Before applying the "Smart Card Policy", the supplemental guidance provided with the STIG should be consulted to ensure continued access to the operating system.

* AOSX_14_000020 - Passcode – Use caution if passwords are managed by Active Directory, Enterprise Connect, or another similar tool. Having multiple password policy sources (I.E. AD and config profile) may lead to unexpected results.
* AOSX_14_000021 - Passcode – Use caution if passwords are managed by Active Directory, Enterprise Connect, or another similar tool. Having multiple password policy sources (I.E. AD and config profile) may lead to unexpected results.
* AOSX_14_000022 - Passcode – Use caution if passwords are managed by Active Directory, Enterprise Connect, or another similar tool. Having multiple password policy sources (I.E. AD and config profile) may lead to unexpected results.
* AOSX_14_003007 – Passcode – Use caution if passwords are managed by Active Directory, Enterprise Connect, or another similar tool. Having multiple password policy sources (I.E. AD and config profile) may lead to unexpected results.
* AOSX_14_003008 – Passcode – Use caution if passwords are managed by Active Directory, Enterprise Connect, or another similar tool. Having multiple password policy sources (I.E. AD and config profile) may lead to unexpected results.
* AOSX_14_003009 – Passcode – Use caution if passwords are managed by Active Directory, Enterprise Connect, or another similar tool. Having multiple password policy sources (I.E. AD and config profile) may lead to unexpected results.
* AOSX_14_003010 – Passcode – Use caution if passwords are managed by Active Directory, Enterprise Connect, or another similar tool. Having multiple password policy sources (I.E. AD and config profile) may lead to unexpected results.
* AOSX_14_003011 – Passcode – Use caution if passwords are managed by Active Directory, Enterprise Connect, or another similar tool. Having multiple password policy sources (I.E. AD and config profile) may lead to unexpected results.
