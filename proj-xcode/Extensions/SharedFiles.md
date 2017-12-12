## Shared files

Our SDKs for extensions needs to share several files witch a regular PowerAuth SDK. All those files are referenced in the xcode project and therefore if you run the build from Xcode, then it suppose to be correct. For the purpose of library packaging, we're keeping a list of files which has to be copied to the final package. Each line in the file contains a relative path to a single file. For example `Classes/keychain/PA2Keychain.h`. So, if you're going to reference a new file from PowerAuth SDK, please update those files:

-  `PA2SharedFiles_IOS.csv` contains a list of shared files for IOS extension target
-  `PA2SharedFiles_WatchOS.csv` contans a list of shared files for WatchOS extension target
