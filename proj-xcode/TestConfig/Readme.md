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

