# Module developed by Jeremy Dunn in collaboration with the Massachusetts Attorney
# General's Office, Digital Evidence Lab
#
# Built on template created by Brian Carrier for Autopsy Module Development:
# https://github.com/sleuthkit/autopsy/blob/develop/pythonExamples/dataSourceIngestModule.py
#
# This is free and unencumbered software released into the public domain.
#
# Anyone is free to copy, modify, publish, use, compile, sell, or
# distribute this software, either in source code form or as a compiled
# binary, for any purpose, commercial or non-commercial, and by any
# means.
#
# In jurisdictions that recognize copyright laws, the author or authors
# of this software dedicate any and all copyright interest in the
# software to the public domain. We make this dedication for the benefit
# of the public at large and to the detriment of our heirs and
# successors. We intend this dedication to be an overt act of
# relinquishment in perpetuity of all present and future rights to this
# software under copyright law.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
# OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
# ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.


import inspect
import os
import shutil
import ntpath
from datetime import datetime

from com.williballenthin.rejistry import RegistryHiveFile
from com.williballenthin.rejistry import RegistryKey
from com.williballenthin.rejistry import RegistryParseException
from com.williballenthin.rejistry import RegistryValue
from java.io import File
from java.lang import Class
from java.lang import System
from java.sql  import DriverManager, SQLException
from java.util.logging import Level
from java.util import Arrays
from org.sleuthkit.datamodel import SleuthkitCase
from org.sleuthkit.datamodel import AbstractFile
from org.sleuthkit.datamodel import ReadContentInputStream
from org.sleuthkit.datamodel import BlackboardArtifact
from org.sleuthkit.datamodel import BlackboardAttribute
from org.sleuthkit.datamodel import Blackboard
from org.sleuthkit.datamodel import TskData
from org.sleuthkit.autopsy.ingest import IngestModule
from org.sleuthkit.autopsy.ingest.IngestModule import IngestModuleException
from org.sleuthkit.autopsy.ingest import DataSourceIngestModule
from org.sleuthkit.autopsy.ingest import IngestModuleFactoryAdapter
from org.sleuthkit.autopsy.ingest import IngestModuleIngestJobSettings
from org.sleuthkit.autopsy.ingest import IngestModuleIngestJobSettingsPanel
from org.sleuthkit.autopsy.ingest import IngestMessage
from org.sleuthkit.autopsy.ingest import IngestServices
from org.sleuthkit.autopsy.ingest import ModuleDataEvent
from org.sleuthkit.autopsy.coreutils import Logger
from org.sleuthkit.autopsy.coreutils import PlatformUtil
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.casemodule.services import Services
from org.sleuthkit.autopsy.casemodule.services import FileManager
from org.sleuthkit.autopsy.datamodel import ContentUtils
from org.sleuthkit.autopsy.modules.interestingitems import FilesSetsManager



class ParseOneDriveAccountsModuleFactory(IngestModuleFactoryAdapter):
    """
    Factory that defines the name and details of the module and allows Autopsy
    to create instances of the modules that will do the analysis.
    """

    moduleName = "Parse OneDrive Accounts"

    def getModuleDisplayName(self):
        return self.moduleName

    def getModuleDescription(self):
        return "Module that finds OneDrive accounts in a Windows image and parses them for information."

    def getModuleVersionNumber(self):
        return "1.0"

    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return ParseOneDriveAccountsModule()


class ParseOneDriveAccountsModule(DataSourceIngestModule):
    """
    Data Source-level ingest module.  One gets created per data source.

    This particular module finds OneDrive accounts in a Windows image and parses them for information.
    It checks the registry for each user account, and if it finds a config key for OneDrive, it parses
    the information from that key.
    """

    _logger = Logger.getLogger(ParseOneDriveAccountsModuleFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    def __init__(self):
        self.context = None


    def startUp(self, context):
        """
        Perform any setup and configuration that needs to be done prior to processing.

        Args:
            context: org.sleuthkit.autopsy.ingest.IngestJobContext
                     http://sleuthkit.org/autopsy/docs/api-docs/latest/classorg_1_1sleuthkit_1_1autopsy_1_1ingest_1_1_ingest_job_context.html
        """
        
        self.context = context

        # Location of OneDrive accounts in NTUSER.DAT
        self.registryOneDriveAccounts = "Software/Microsoft/OneDrive/Accounts"

        self.businessKeysToRetrieve = [('OneAuthAccountId',             'TSK_REGISTRY_ONEDRIVE_AUTHACCOUNTID',  'OneDrive Auth Account ID'          ),
                                       ('UserEmail',                    'TSK_REGISTRY_ONEDRIVE_USEREMAIL',      'OneDrive User Email'               ),
                                       ('SPOLastUpdate',                'TSK_REGISTRY_ONEDRIVE_SPOLASTUPDATE',  'OneDrive Sharepoint Last Update'   ), 
                                       ('TeamSiteSPOResourceId',        'TSK_REGISTRY_ONEDRIVE_SPORESOURCEID',  'SharePoint Team Site Resource ID'  ),
                                       ('DisplayName',                  'TSK_REGISTRY_ONEDRIVE_DISPLAYNAME',    'OneDrive Folder Display Name'      ),
                                       ('ServiceEndpointUri',           'TSK_REGISTRY_ONEDRIVE_ENDPOINTURI',    'OneDrive Service Endpoint URI'     ), 
                                       ('UserName',                     'TSK_REGISTRY_ONEDRIVE_USERNAME',       'OneDrive User Name'                ),
                                       ('LastSignInTime',               'TSK_REGISTRY_ONEDRIVE_LASTSIGNINTIME', 'OneDrive Last Sign-in Time'        ),
                                       ('ClientFirstSignInTimestamp',   'TSK_REGISTRY_ONEDRIVE_FIRSTSIGNIN',    'OneDrive Client First Sign-in Time'), 
                                       ('UserFolder',                   'TSK_REGISTRY_ONEDRIVE_USERFOLDER',     'OneDrive User Folder Mount Point'  ),
                                       ('ConfiguredTenantId',           'TSK_REGISTRY_ONEDRIVE_TENANTID',       'OneDrive Configured Tenant ID'     )]
        
        self.personalKeysToRetrieve = [('UserFolder',                   'TSK_REGISTRY_ONEDRIVE_USERFOLDER',     'OneDrive User Folder Mount Point'  ),
                                       ('FirstRunSignInOriginDateTime', 'TSK_REGISTRY_ONEDRIVE_FIRSTRUN',       'OneDrive First Run Sign-in Time'   ),
                                       ('UserEmail',                    'TSK_REGISTRY_ONEDRIVE_USEREMAIL',      'OneDrive User Email'               ),
                                       ('LastSignInTime',               'TSK_REGISTRY_ONEDRIVE_LASTSIGNINTIME', 'OneDrive Last Sign-in Time'        ),
                                       ('ClientFirstSignInTimestamp',   'TSK_REGISTRY_ONEDRIVE_FIRSTSIGNIN',    'OneDrive Client First Sign-in Time'),
                                       ('cid',                          'TSK_REGISTRY_ONEDRIVE_CID',            'OneDrive CID'                      ),
                                       ('VaultShortcutPath',            'TSK_REGISTRY_ONEDRIVE_VAULTSHORTCUT',  'OneDrive Vault Shortcut Path'      ),
                                       ('AgeGroup',                     'TSK_REGISTRY_ONEDRIVE_AGEGROUP',       'OneDrive Age Group'                )]
  
        # OneDrive accounts found
        self.accounts = []

    def process(self, dataSource, progressBar):
        """
        Where the analysis is done.

        Args:
            dataSource: org.sleuthkit.datamodel.Content
                        http://www.sleuthkit.org/sleuthkit/docs/jni-docs/latest/interfaceorg_1_1sleuthkit_1_1datamodel_1_1_content.html 

            progressBar: org.sleuthkit.autopsy.ingest.DataSourceIngestModuleProgress
                         http://sleuthkit.org/autopsy/docs/api-docs/latest/classorg_1_1sleuthkit_1_1autopsy_1_1ingest_1_1_data_source_ingest_module_progress.html

        Returns:
            Result status: org.sleuthkit.autopsy.ingest.IngestModule.ProcessResult
                           https://github.com/sleuthkit/autopsy/blob/develop/Core/src/org/sleuthkit/autopsy/ingest/IngestModule.java
        """

        # We don't know how much work there is yet
        progressBar.switchToIndeterminate()

        # Create temp directory to save the hive files to while processing
        tempDir = os.path.join(Case.getCurrentCase().getTempDirectory(), "OneDriveProcessing")
        self.log(Level.INFO, "Create temp directory: " + tempDir)
        try:
            os.mkdir(tempDir)
        except OSError:
            self.log(Level.INFO, "Temp directory already exists: " + tempDir)

        # Get the skCase, blackboard, and file manager objects
        skCase = Case.getCurrentCase().getSleuthkitCase()
        blackboard = Case.getCurrentCase().getSleuthkitCase().getBlackboard()
        fileManager = Case.getCurrentCase().getServices().getFileManager()


        # Get all user registry files
        ntuserFiles = fileManager.findFiles(dataSource, "NTUSER.DAT")

        for file in ntuserFiles:

            # Check if the user pressed cancel while we were busy
            if self.context.isJobCancelled():
                return IngestModule.ProcessResult.OK
            
            # Use only registry files in the USERS folder
            if '/USERS' not in file.getParentPath().upper():
                continue

            # Get the account name from the file path
            try:
                account = file.getParentPath().split('/')[2]
            except:
                self.log(Level.WARNING, "Error getting account name from file path: " + file.getParentPath())
                continue
            
            # Write the hive file to the temp directory
            filePath = os.path.join(tempDir, account + "-NTUSER.DAT")
            if not os.path.exists(filePath):
                try:
                    ContentUtils.writeToFile(file, File(filePath))
                except:
                    self.log(Level.INFO, "Error writing hive file to temp directory: " + filePath)
                    continue

            # Get all OneDrive accounts from the hive file.  If the hive has no OneDrive accounts, continue to the next hive file
            parentRegistryKey = self.findRegistryKey(RegistryHiveFile(File(filePath)), self.registryOneDriveAccounts)
            if parentRegistryKey is None:
                self.log(Level.INFO, "Could not find registry key: " + self.registryOneDriveAccounts + " in hive file: " + filePath)
                continue

            # Process the OneDrive accounts
            for accountKey in parentRegistryKey.getSubkeyList():
                if "Personal" in accountKey.getName():
                    self.processOneDriveAccountInfo(accountKey, self.personalKeysToRetrieve, file)
                if "Business" in accountKey.getName():
                    self.processOneDriveAccountInfo(accountKey, self.businessKeysToRetrieve, file)
            

        # Setup artifact and attributes
        artType = skCase.getArtifactType("TSK_ARTIFACT_ONEDRIVE_ACCOUNT")
        if not artType:
            try:
                artType = skCase.addBlackboardArtifactType("TSK_ARTIFACT_ONEDRIVE_ACCOUNT", "OneDrive Accounts")
            except:
                self.log(Level.WARNING, "Artifacts Creation Error, some artifacts may not exist now. ==> ")

        # art[1]: TSK Attribute Type || art[2]: Description of the attribute
        for art in (self.businessKeysToRetrieve + self.personalKeysToRetrieve):
            try:
                skCase.addArtifactAttributeType(art[1], BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, art[2])
            except:
                self.log(Level.WARNING, "Attribute Creation Error, " + art[1] + " may already exist.")

        moduleName = ParseOneDriveAccountsModuleFactory.moduleName

        # Add the accounts to the blackboard
        for account in self.accounts:
            self.log(Level.INFO, "Adding account: " + account["key"])

            values = []
            for value in account["values"]:
                # value[0][1]: TSK Attribute Type || value[1]: Value of the attribute
                values.append(BlackboardAttribute(skCase.getAttributeType(value[0][1]), moduleName, value[1]))

            art = account["file"].newDataArtifact(artType, Arrays.asList(values))

            try:
                blackboard.postArtifact(art, moduleName)
            except Exception as ex:
                self.log(Level.SEVERE, "Error posting artifact to blackboard: " + art.getDisplayName(), + " " + ex)


        # Cleanup temp directory and files
        try:
            shutil.rmtree(tempDir)
        except:
            self.log(Level.INFO, "Error deleting temp directory: " + tempDir)

        # Post a message to the ingest messages in box saying we finished.
        message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
            "Parse OneDrive Accounts", " OneDrive accounts have been parsed and analyzed" )
        IngestServices.getInstance().postMessage(message)

        # We made it to the end with no errors, so return OK
        return IngestModule.ProcessResult.OK
    

    def findRegistryKey(self, registryHiveFile, registryKey):
        """
        Find a registry key in a registry hive file. Returns the registry key if found, otherwise returns None.

        Args:
            registryHiveFile (java.io.File):         The registry hive file to search
            registryKey      (str):                  The registry key to search for

        Returns:
            RegistryKey      (rejistry.RegistryKey): The registry key if found, otherwise None
        """

        rootKey = registryHiveFile.getRoot()
        regKeyList = registryKey.split('/')
        currentKey = rootKey

        try:
            for key in regKeyList:

                children = currentKey.getSubkeyList()
                children_names = [child.getName() for child in children]

                # Subkey found, go to next level
                if key in children_names:
                    currentKey = currentKey.getSubkey(key) 
                
                # Subkey not found, return None
                else:
                    return None
                
            # All subkeys found, return the last subkey
            return currentKey
        
        except Exception as ex:
            self.log(Level.SEVERE, "Registry key parsing issue:", ex)
            return None      


    def processOneDriveAccountInfo(self, registryKey, keysToRetrieve, file):
        """
        Process the OneDrive account information from the registry key and add it to the accounts list.

        Args:
            registryKey      (rejistry.RegistryKey):                         The registry key to process
            keysToRetrieve   (list):                                         The list of keys to retrieve from the registry key
            file             (org.sleuthkit.datamodel.AbstractFile):         The hive file the registry key was found in

        Returns:
            None
        """

        # The main registry key, e.g. "Personal" or "Business"
        entry = { "key": registryKey.getName(),
                  "values": [],
                  "file": file }

        # List of all registry keys that are valid to retrieve
        keys = [key[0] for key in keysToRetrieve]

        for raw_value in registryKey.getValueList():

            # Get the value from the registry key
            try:
                if raw_value.getName() not in keys:
                    continue
                
                # If registry value is a string, get the value as a string
                if "SZ" in str(raw_value.getValueType()):
                    value = raw_value.getValue().getAsString()

                # If registry value is a word, get the value as a number
                elif "WORD" in str(raw_value.getValueType()):
                    value = raw_value.getValue().getAsNumber()
                
                # Otherwise, get the value as raw data and decode it to a string as best as possible
                else:
                    value = raw_value.getValue().getAsRawData().decode(encoding='utf-8', errors='ignore')

                
                # Find the key tuple that corresponds to the registry key
                key = self.findKey(raw_value.getName(), keysToRetrieve)

                # Attempt to decode the value as a datetime then append it.  Done this way because the datetimes in the 
                # registry entries are sometimes stored as strings and sometimes as numbers.
                entry["values"].append((key, self.tryDateTime(value)))

            except Exception as ex:
                self.log(Level.INFO, "Error getting registry value: " + raw_value.getName() + " --> " + str(ex))
                pass

        self.accounts.append(entry)


    def tryDateTime(self, time):
        """
        Try to convert a time to a datetime object.  If it fails, return the original input as a string.

        Args:
            time (any): The time to convert

        Returns:
            string: The time as a string
        """

        try:
            return str(datetime.fromtimestamp(int(time)))
        except:
            return str(time)
        

    def findKey(self, value, keysToRetrieve):
        """
        Retrieve a key tuple based on the registry value to retrieve

        Args:
            value (string): The value to look up
            keysToRetrieve (list[tuple]): List to look the value up in.  Value must be in first slot

        Returns:
            key (tuple): The tuple containing the key
        """

        for key in keysToRetrieve:
            if key[0] in value:
                return key
            
        return None