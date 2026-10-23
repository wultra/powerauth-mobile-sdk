# End-To-End Encryption

<!-- SIDEBAR _Sidebar_Android.md -->

Currently, PowerAuth SDK supports two basic modes of end-to-end encryption:

- In an "application" scope, the encryptor can be acquired and used during the whole lifetime of the application.
- In an "activation" scope, the encryptor can be acquired only if `PowerAuthSDK` has a valid activation. The encryptor created for this mode is cryptographically bound to the parameters agreed during the activation process. You can combine this encryption with [PowerAuth Symmetric Multi-Factor Authentication Code](Android-Authentication-Codes.md#symmetric-multi-factor-authentication-code) in "sign-then-encrypt" mode.


For both scenarios, you need to acquire an `CoreEncryptor` object, which will then provide an interface for the request encryption and the response decryption. The object currently provides only low-level encryption and decryption methods, so you need to implement your own JSON (de)serialization and request and response processing.

The following steps are typically required for a full E2EE request and response processing:

1. Acquire the right encryptor from the `PowerAuthSDK` instance. For example:
   ```kotlin
   // Encryptor for "application" scope.
   val cancelable = powerAuthSDK.getEncryptorForApplicationScope(object : IGetEncryptorListener {
        override fun onGetEncryptorSuccess(encryptor: CoreEncryptor) {
            // Success
        }

        override fun onGetEncryptorFailed(t: Throwable) {
            // Failure
        }
   });
   // ...or similar, for an "activation" scope.
   val cancelable = powerAuthSDK.getEncryptorForActivationScope(context, object : IGetEncryptorListener {
        override fun onGetEncryptorSuccess(encryptor: CoreEncryptor) {
            // Success
        }

        override fun onGetEncryptorFailed(t: Throwable) {
            // Failure
        }
   });
   ```

1. Serialize your request payload, if needed, into a sequence of bytes. This step typically means that you need to serialize your model object into a JSON-formatted sequence of bytes.

1. Encrypt your payload:
   ```kotlin
   val encryptedRequest = encryptor.encryptRequest(payloadData)
   ```

1. Use request body in your networking library
   ```kotlin
   val requestBody = encryptedRequest.requestBody;
   ```

1. Use the following HTTP headers (for signed requests, see note below) in your networking library:
   ```kotlin
   for (header in encryptedRequest.requestHeaders) {
        val headerName = header.key;
        val headerValue = header.value;
        // User header in your networking library
   }
   ```
   Note, that if an "activation" scoped encryptor is combined with PowerAuth Symmetric Multi-Factor Authentication Code, then this step is not required. The authentication header already contains all the information required for proper request decryption on the server.

1. Fire your HTTP request and wait for a response
   - In case that non-200 HTTP status code is received, then the error processing is identical to a standard RESTful response defined in our protocol. So, you can expect a JSON object with `"error"` and `"message"` properties in the response.

1. Decrypt the response
   ```kotlin
   val encryptedResponse = CoreEncryptedResponse(responseBody)
   val responseData = encryptor.decryptResponse(encryptedResponse)
   ```

1. And finally, you can process your received response.

As you can see, the E2EE is quite a non-trivial task. We recommend contacting us before using an application-specific E2EE. We can provide you with more support on a per-scenario basis, especially if we first understand what you are trying to achieve with end-to-end encryption in your application.

## Read Next

- [Secure Vault](Android-Secure-Vault.md)
