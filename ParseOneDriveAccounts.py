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


# Factory that defines the name and details of the module and allows Autopsy
# to create instances of the modules that will do the analysis.
class ParseOneDriveAccountsModuleFactory(IngestModuleFactoryAdapter):

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


# Data Source-level ingest module.  One gets created per data source.
class ParseOneDriveAccountsModule(DataSourceIngestModule):
    _logger = Logger.getLogger(ParseOneDriveAccountsModuleFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    def __init__(self):
        self.context = None

    # Where any setup and configuration is done
    def startUp(self, context):
        
        # Throw an IngestModule.IngestModuleException exception if there was a problem setting up
        # raise IngestModuleException("Oh No!")
        self.context = context

        # Location of OneDrive accounts in NTUSER.DAT
        self.registryOneDriveAccounts = "Software/Microsoft/OneDrive/Accounts"

    # Where the analysis is done.
    # The 'dataSource' object being passed in is of type org.sleuthkit.datamodel.Content.
    # See: http://www.sleuthkit.org/sleuthkit/docs/jni-docs/latest/interfaceorg_1_1sleuthkit_1_1datamodel_1_1_content.html
    # 'progressBar' is of type org.sleuthkit.autopsy.ingest.DataSourceIngestModuleProgress
    # See: http://sleuthkit.org/autopsy/docs/api-docs/latest/classorg_1_1sleuthkit_1_1autopsy_1_1ingest_1_1_data_source_ingest_module_progress.html
    # TODO: Add your analysis code in here.
    def process(self, dataSource, progressBar):

        # we don't know how much work there is yet
        progressBar.switchToIndeterminate()

        # Create temp directory to save the hive files to while processing
        tempDir = os.path.join(Case.getCurrentCase().getTempDirectory(), "OneDriveProcessing")
        self.log(Level.INFO, "Create temp directory: " + tempDir)
        try:
            os.mkdir(tempDir)
        except OSError:
            self.log(Level.INFO, "Temp directory already exists: " + tempDir)

        # Get the blackboard and file manager objects
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
            
            # Write the hive file to the temp directory
            try:
                filePath = os.path.join(tempDir, "NTUSER.DAT")
                ContentUtils.writeToFile(file, File(filePath))
            except:
                self.log(Level.INFO, "Error writing hive file to temp directory: " + filePath)
                continue

            # Get the user account name from the file path
            userAccount = file.getParentPath().split("\\")[2]

            # Get all OneDrive accounts from the hive file
            parentRegistryKey = self.findRegistryKey(RegistryHiveFile(File(filePath)), self.registryOneDriveAccounts)

            for accountKey in parentRegistryKey.getSubkeyList():

                if "Personal" in accountKey.getName():
                    continue
                if "Business" in accountKey.getName():
                    self.processBusinessAccountInfo(RegistryHiveFile(File(filePath)), accountKey)


            # # Check if the user pressed cancel while we were busy
            # if self.context.isJobCancelled():
            #     return IngestModule.ProcessResult.OK

            # self.log(Level.INFO, "Processing file: " + file.getName())
            # fileCount += 1

            # # Make an artifact on the blackboard.  TSK_INTERESTING_FILE_HIT is a generic type of
            # # artifact.  Refer to the developer docs for other examples.
            # attrs = Arrays.asList(BlackboardAttribute(BlackboardAttribute.Type.TSK_SET_NAME,
            #                                           ParseOneDriveAccountsModuleFactory.moduleName,
            #                                           "Test file"))
            # art = file.newAnalysisResult(BlackboardArtifact.Type.TSK_INTERESTING_FILE_HIT, Score.SCORE_LIKELY_NOTABLE,
            #                              None, "Test file", None, attrs).getAnalysisResult()

            # try:
            #     blackboard.postArtifact(art, ParseOneDriveAccountsModuleFactory.moduleName, context.getJobId())
            # except Blackboard.BlackboardException as e:
            #     self.log(Level.SEVERE, "Error indexing artifact " + art.getDisplayName())

            # # To further the example, this code will read the contents of the file and count the number of bytes
            # inputStream = ReadContentInputStream(file)
            # buffer = jarray.zeros(1024, "b")
            # totLen = 0
            # readLen = inputStream.read(buffer)
            # while (readLen != -1):
            #     totLen = totLen + readLen
            #     readLen = inputStream.read(buffer)


            # Update the progress bar
            # progressBar.progress(fileCount)


        #Post a message to the ingest messages in box.
        # message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
        #     "Sample Jython Data Source Ingest Module", "Found %d files" % fileCount)
        # IngestServices.getInstance().postMessage(message)

        return IngestModule.ProcessResult.OK
    

    # Taken from: https://github.com/sleuthkit/autopsy/blob/develop/pythonExamples/Registry_Example.py
    def findRegistryKey(self, registryHiveFile, registryKey):
        # Search for the registry key
        rootKey = registryHiveFile.getRoot()
        regKeyList = registryKey.split('/')
        currentKey = rootKey
        try:
            for key in regKeyList:
                currentKey = currentKey.getSubkey(key) 
            return currentKey
        except Exception as ex:
            # Key not found
            self.log(Level.SEVERE, "registry key parsing issue:", ex)
            return None      

    def processBusinessAccountInfo(self, registryHiveFile, registryKey):
        pass
            
    def processPersonalAccountInfo(self, registryHiveFile, registryKey):
        pass