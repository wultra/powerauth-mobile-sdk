To run `PA2_IntegrationTests` scheme you have to create a configuration file at first. 
To do this, please follow these simple steps:

1. Create a new file "Configuration.json" in this folder. This file is already ignored in the .gitignore, so the
   file will not be added to the git repository.

2. Create a following keys in the file:
   ```
   {
		"restApiUrl"           : "http://localhost:8080/powerauth-webflow",
		"soapApiUrl"           : "http://localhost:8080/powerauth-java-server/soap",
		"soapApiVersion"       : "0.24",
		"powerAuthAppName"     : "AutomaticTest-IOS",
		"powerAuthAppVersion"  : "default"
   }
   ```

3. Change `restApiUrl` and `soapApiUrl` URLs to desired values

4. Change `soapApiVersion` to the version of target PowerAuth Server
   - Note that the latest mobile SDK version supports only the latest PowerAuth Server. 
   - On opposite to that, the older SDK can be usually tested with the newer server. This is because we backport SOAP API changes to older SDK tests.

5. Optional: Change `powerAuthAppName` or `powerAuthAppVersion` to desired values

6. Optional: You can devifine following additional keys in the dictionary:
   - `userIdentifier` - an user's identifier. It's recommended to set your own value when another developer is running tests against the same server.
   - `userActivationName` - a name will be used for newly created activations
