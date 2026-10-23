# Password Change

The typical password-change flow in a mobile application consists of the following steps:

1. **Prompt the user for their current password.**

2. **Validate the current password with the server:**
   ```swift
   powerAuthSDK.beginPasswordChange(oldPassword: "oldPassword") { changeData, error in
       if let changeData {
           // Password is valid, keep this object aside and use in the step 4.
       } else {
           // Process error.
       }
   }
   ```
   Keep the received `changeData` object aside for later. If the user cancels the process after this step, you should either release the stored `changeData` object or call `secureClear()` to ensure that all sensitive information is destroyed:
   ```swift
   changeData.secureClear()
   ```

3. **If the current password is valid, allow the user to enter and confirm a new password.**

4. **Submit the new password to the server:**
   ```swift
   powerAuthSDK.finishPasswordChange(newPassword: "newPassword", changeData: changeData) { error in
       if let error {
           // process error
       }
   }
   ```

## Read Next

- [Working with passwords securely](iOS-Working-With-Passwords-Securely.md)
