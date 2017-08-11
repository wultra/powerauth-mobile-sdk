To run `PA2_IntegrationTests` scheme you have to create a configuration file at first. 
To do this, please follow these simple steps:

1. Create a new file "Configuration.json" in this folder. This file is already ignored in the .gitignore, so the
   file will not be added to the git repository.

2. Create a following keys in the file:
   ```
   {
		"restApiUrl"           : "http://paserver.local:13030/powerauth-webauth",
		"soapApiUrl"           : "http://paserver.local:20010/powerauth-java-server/soap",
		"powerAuthAppName"     : "AutomaticTest-IOS",
		"powerAuthAppVersion"  : "default"
   }
   ```

3. Change URLs to desired values

4. Optional: Change `powerAuthAppName` or `powerAuthAppVersion` to desired values

5. Optional: You can devifine following additional keys in the dictionary:
	- `userIdentifier` - an user's identifier. It's recommended to set your own value when another developer is running tests against the same server.
	- `userActivationName` - a name will be used for newly created activations
