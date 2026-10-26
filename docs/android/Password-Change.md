# Password Change

<!-- SIDEBAR _Sidebar.md -->
<!-- BREADCRUMB Android href=../PowerAuth-SDK-for-Android -->

The typical password-change flow in a mobile application consists of the following steps:

1. **Prompt the user for their current password.**

2. **Validate the current password with the server:**
    ```kotlin
    powerAuthSDK.beginPasswordChange(context, "oldPassword", object: IBeginPasswordChangeListener {
        override fun onBeginPasswordChangeSucceed(changeData: PowerAuthPasswordChangeData) {
            // Password is valid, keep the PowerAuthPasswordChangeData object aside and use in the step 4.
        }

        override fun onBeginPasswordChangeFailed(t: Throwable) {
            // Error occurred.
        }
    })
    ```
    Keep the received `changeData` object aside for later. If the user cancels the process after this step, you should either release the stored `changeData` object or call `secureClear()` to ensure that all sensitive information is destroyed:
    ```kotlin
    changeData.secureClear()
    ```

3. **If the current password is valid, allow the user to enter and confirm a new password.**

4. **Submit the new password to the server:**
    ```kotlin
    powerAuthSDK.finishPasswordChange(context, "newPassword", changeData: PowerAuthPasswordChangeData, object: IFinishPasswordChangeListener {
        override fun onFinishPasswordChangeSucceed() {
            // Password was changed.
        }

        override fun onFinishPasswordChangeFailed(t: Throwable) {
            // Error occurred.
        }
    })
    ```

## Read Next

- [Working with passwords securely](Working-With-Passwords-Securely.md)
