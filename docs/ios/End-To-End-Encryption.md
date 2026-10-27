# End-To-End Encryption

<!-- SIDEBAR _Sidebar.md -->
<!-- BREADCRUMB iOS href=../PowerAuth-SDK-for-iOS -->

Currently, PowerAuth SDK supports two basic modes of end-to-end encryption:

- In an "application" scope, the encryptor can be acquired and used during the whole lifetime of the application.
- In an "activation" scope, the encryptor can be acquired only if `PowerAuthSDK` has a valid activation. The encryptor created for this mode is cryptographically bound to the parameters agreed during the activation process. You can combine this encryption with [PowerAuth Symmetric Multi-Factor Authentication Code](Authentication-Codes.md#symmetric-multi-factor-authentication-code) in "sign-then-encrypt" mode.

For both scenarios, you need to acquire the `PowerAuthEncryptor` object, which will then provide an interface for the request encryption and the response decryption. The object currently provides only low-level encryption and decryption methods, so you need to implement your own JSON (de)serialization and request and response processing.

The following steps are typically required for a full E2EE request and response processing:

1. Acquire the right encryptor from the `PowerAuthSDK` instance. For example:
   ```swift   
   // Encryptor for "application" scope.
   sdk.encryptorForApplicationScope { encryptor, error in
      if let encryptor {
        // success
      } else {
        // failure
      }
   }
   // ...or similar, for an "activation" scope.
   sdk.encryptorForActivationScope { encryptor, error in
      if let encryptor {
        // success
      } else {
        // failure
      }
   }
   ```

1. Serialize your request payload, if needed, into a sequence of bytes. This step typically means that you need to serialize your model object into a JSON-formatted sequence of bytes.

1. Encrypt your payload:
   ```swift
   let encryptedRequest = try encryptor.encryptRequest(payloadData)
   ```

1. Extract request body and HTTP headers:
   ```swift
   let requestBody: Data = encryptedRequest.requestBody
   let requestHeaders: [PowerAuthHttpHeader] = encryptedRequest.requestHeaders
   ```

1. Add all HTTP headers to the request (for signed requests, see note below):
   ```swift
    var httpRequest = URLRequest(url: URL(string: "https://example.org/encrypted-request")!)
    requestHeaders.forEach { header in
        httpRequest.addValue(header.value, forHTTPHeaderField: header.key)
    }
   ```
   Note that if an "activation" scoped encryptor is combined with PowerAuth Symmetric Multi-Factor Authentication Code, then this step is not required. The authentication header already contains all the information required for proper request decryption on the server.

1. Fire your HTTP request and wait for a response
   - In case that non-200 HTTP status code is received, then the error processing is identical to a standard RESTful response defined in our protocol. So, you can expect a JSON object with `"error"` and `"message"` properties in the response.

1. In case of success, decrypt the response:
   ```swift
   let encryptedResponse = try PowerAuthEncryptedResponse(responseBody: responseBody)
   let response = try encryptor.decryptResponse(encryptedResponse)
   ```

1. And finally, you can process your received response.

As you can see, implementing end-to-end encryption is a non-trivial task. We recommend reaching out to us before deploying an application-specific E2EE solution. We can provide tailored guidance based on your specific scenario, especially once we understand your goals and use case for end-to-end encryption.

## Read Next

- [Secure Vault](Secure-Vault.md)
