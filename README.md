# ParseOneDriveAccounts
Autopsy plugin to parse and retrieve information about linked OneDrive accounts in a Windows image.

## Overview
This plugin checks each user's personal registry hive (HKCU) for entries related to OneDrive accounts.  If it finds them, it parses them out and adds them to the blackboard for review.

## Installation and Usage
Download the code as a folder, and copy the whole folder to C:\Users\%USERNAME%\AppData\Roaming\autopsy\python_modules.  Start up Autopsy, go to Tools -> Run Ingest Modules, and click on the image you want to ingest.  Check off the "Parse OneDrive Accounts" option, then click "Finish".

Under "Data Artifacts" in the left hand menu, there will now be an entry called "OneDrive Accounts".  Click on each entry and go to the "Data Artifacts" tab in the entry window to view information about each account.
