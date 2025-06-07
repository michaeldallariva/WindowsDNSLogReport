# WindowsDNSLogReport
Windows DNS Log Parser - Very fast generation and little resources used. This PowerShell script reads and parses the content of a Windows DNS debug log file.

# Windows DNS Log Parser - Very fast generation and little resources used.
# GitHub link : https://github.com/michaeldallariva
# Version : v1.0
# Author : Michael DALLA RIVA, with the help of some AI
# Date : 7th of June 2025
#
# Purpose:
# This script reads and parses the content of a Windows DNS debug log file.
# - Please activate Windows DNS debug log before use.
# - Copy the current log file to the same location or another one.
# - It is best not to run this script on a domain controller, it runs fine, it does not use a large amount of memory or disk, but better safe than sorry. Zip your log file and move it somewhere else.
# - Specify the location of the log file in the variable at the beginning of the script.
# - After a while run this script to generate a HTML report.
# 
# - Tested a debugged on English versions of Windows Server 2016, 2019, 2022 and 2025.
#
# License :
# Feel free to use for any purpose, personal or commercial.
