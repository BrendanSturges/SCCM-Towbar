Author: github.com/brendansturges
Description: SCCM Towbar
FEATURES
Bulk - everything works on multiples


DISCOVERY
Ping - pings all systems in list
Check Reboot Status - Gets reboot status of all systems in list
Check DNS Status - Checks for DNS Contention for all systems in list
Get Assigned Site - Checks all systems in list for the SCCM assigned sites
Get FQDN - returns the FQDN of the systems in the list
Check System Uptime - returns uptime all systems in list

REMEDIATION
Trigger Software Inventory Cycle
Trigger Hardware Inventory Cycle
Evaluate Machine Policy Assignments
Refresh Location Services
Force Update Scan
Request Machine Policy
Trigger Hearbeat

PATCHING
Get Available Patches - returns all patches that are currently set to available on the target
Get Failed Patches - returns all patches that are currently set to available but failed on the target
Apply All Available Patches - applies all available patches on the target systems
Get Applied Patches for past X days - returns event log entries for all applied patches for X days
