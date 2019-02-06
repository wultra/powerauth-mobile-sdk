# PowerAuth Mobile SDK for Android

## Table of Contents

- [SDK Installation](#installation)
- [SDK Configuration](#configuration)
- [Device Activation](#activation)
- [Requesting Device Activation Status](#requesting-activation-status)
- [Data Signing](#data-signing)
  - [Symmetric Multi-Factor Signature](#symmetric-multi-factor-signature)
  - [Asymmetric Private Key Signature](#asymmetric-private-key-signature)
  - [Symmetric Offline Multi-Factor Signature](#symmetric-offline-multi-factor-signature)
  - [Verify server signed data](#verify-server-signed-data)
- [Password Change](#password-change)
- [Fingerprint Authentication Setup](#fingerprint-authentication-setup)
- [Device Activation Removal](#activation-removal)
- [End-To-End Encryption](#end-to-end-encryption)
- [Secure Vault](#secure-vault)
- [Token Based Authentication](#token-based-authentication)
- [Common SDK Tasks](#common-sdk-tasks)
- [Additional Features](#additional-features)

## Installation

To get PowerAuth SDK for Android up and running in your app, add following dependency in your `gradle.build` file:

```gradle
repositories {
    jcenter() // if not defined elsewhere...
}

dependencies {
    compile 'io.getlime.security.powerauth:powerauth-android-sdk:1.0.0'
}
```
Note that this documentation is using version `1.0.0` as an example. You can find the latest version in our [List of Releases](https://github.com/wultra/powerauth-crypto/wiki/Releases). The Android Studio IDE can also find and offer updates for your application's dependencies.

From now on, you can use `PowerAuthSDK` class in your project.

To use development version, you need to install it in your local Maven repository and make this repository available to your Gradle script.

```sh
$ git clone --recurse-submodules https://github.com/wultra/powerauth-mobile-sdk.git
$ cd powerauth-mobile-sdk/proj-android
$ sh build-publish-local.sh
```

In your Gradle script:

```gradle
apply plugin: "maven"

repositories {
    mavenLocal()
}
```

You also need to install base Java modules in your maven repository:

```sh
$ git clone --recurse-submodules https://github.com/wultra/powerauth-restful-integration.git
$ cd powerauth-restful-integration
$ mvn clean install -DskipTests=true
```

## Configuration

In order to be able to configure your `PowerAuthSDK` instance, you need following values from the PowerAuth 2.0 Server:

- `APP_KEY` - Application key, that binds activation with specific application.
- `APP_SECRET` - Application secret, that binds activation with specific application.
- `KEY_MASTER_SERVER_PUBLIC` - Master Server Public Key, used for non-personalized encryption and server signature verification.

Also, you need to specify your instance ID (by default, this can be for example an app package name). This is because one application may use more than one custom instances of `PowerAuthSDK` and identifier is the way to distinguish these instances while working with Keychain data.

Finally, you need to know the location of your [PowerAuth 2.0 Standard RESTful API](https://github.com/wultra/powerauth-crypto/wiki/Standard-RESTful-API) endpoints. Tha path should contain everything that goes before the `/pa/**` prefix of the API endpoints.

To sum it up, in order to configure `PowerAuthSDK` default instance, add following code to your application main activity `onCreate()` method:

```java
String INSTANCE_ID = getApplicationContext().getPackageName();
String PA_APPLICATION_KEY = "sbG8gd...MTIzNA==";
String PA_APPLICATION_SECRET = "aGVsbG...MTIzNA==";
String PA_MASTER_SERVER_PUBLIC_KEY = "MTIzNDU2Nz...jc4OTAxMg==";
String API_SERVER = "https://localhost:8080/demo-server";

final PowerAuthConfiguration configuration = new PowerAuthConfiguration.Builder(
        INSTANCE_ID,
        API_SERVER,
        PA_APPLICATION_KEY,
        PA_APPLICATION_SECRET,
        PA_MASTER_SERVER_PUBLIC_KEY)
        .build();

PowerAuthSDK powerAuthSDK = new PowerAuthSDK.Builder(configuration)
        .build(getApplicationContext());
```

## Activation

After you configure the SDK instance, you are ready to make your first activation.

### Activation via Activation Code

The original activation method uses a one-time activation code generated in PowerAuth 2.0 Server. To create an activation using this method, some external application (Internet banking, ATM application, branch / kiosk application) must generate an activation code for you and display it (as a text or in a QR code).

In case you would like to use QR code scanning to enter an activation code, you can use any library of your choice, for example [Barcode Scanner](https://github.com/dm77/barcodescanner) open-source library based on ZBar lib.

Use following code to create an activation once you have an activation code:

```java
// Call reset to clear any pending activation data from previous attempts
powerAuthSDK.reset();

String deviceName = "Petr's iPhone 7"; // or UIDevice.current.name
String activationCode = "12345-67890-12345-67890"; // let user type or QR-scan this value

// Create a new activation with given device name and activation code
powerAuthSDK.createActivation(deviceName, activationCode, new ICreateActivationListener() {
    @Override
    public void onActivationCreateSucceed(CreateActivationResult result) {
        final String fingerprint = result.getActivationFingerprint();
        // No error occurred, proceed to credentials entry (PIN prompt, Enable "Fingerprint Authentication" switch, ...) and commit
        // The 'fingerprint' value represents the combination of device and server public keys - it may be used as visual confirmation
    }

    @Override
    public void onActivationCreateFailed(Throwable t) {
        // Error occurred, report it to the user
    }
});
```

### Activation via Custom Credentials

You may also create an activation using any custom login data - it can be anything that server can use to obtain user ID to associate with a new activation. Since the credentials are custom, the endpoint that handles the custom activation must be set (standard RESTful API cannot be used).

Use following code to create an activation using custom credentials:

```java
// Call reset to clear any pending activation data from previous attempts
powerAuthSDK.reset();

// Create a new activation with given device name and login credentials
String deviceName = "Petr's iPhone 7"; // or UIDevice.current.name
Map<String, String> credentials = new HashMap<>();
credentials.put("username", "john.doe@example.com");
credentials.put("password", "YBzBEM");

String url = "https://localhost:8080/demo-server/session/login";

powerAuthSDK.createActivation(deviceName, credentials, url, new ICreateActivationListener() {
    @Override
    public void onActivationCreateSucceed(String fingerprint) {
        // No error occurred, proceed to credentials entry (PIN prompt, Enable Fingerpring Authentication switch, ...) and commit
        // The 'fingerprint' value represents the device public key - it may be used as visual confirmation
    }

    @Override
    public void onActivationCreateFailed(Throwable t) {
        // Error occurred, report it to the user
    }
});
```

Note that by using weak identity attributes to create an activation, the resulting activation is confirming a "blurry identity". This may greately limit the legal weight and usability of a signature. We recommend using a strong identity verification before an activation can actually be created.

### Committing Activation Data

After you create an activation using one of the methods mentioned above, you need to commit the activation - to use provided user credentials to store the activation data on the device. Use following code to do this.

```java
// Commit activation using given PIN
int result = powerAuthSDK.commitActivationWithPassword(context, pin);
if (result != PowerAuthErrorCodes.PA2Succeed) {
    // happens only in case SDK was not configured or activation is not in state to be committed
}
```

This code has created activation with two factors: possession (key stored using a key derived from a device fingerprint) and knowledge (password, in our case a simple PIN code). If you would like to enable fingerprint authentication support at this moment, use following code instead of the one above:

```java
// Commit activation using given PIN and ad-hoc generated biometric related key
powerAuthSDK.commitActivation(context, fragmentManager, "Enable Fingerprint Authentication", "To enable fingerprint authentication, touch the fingerprint sensor on your device.", pin, new ICommitActivationWithFingerprintListener() {
    @Override
    public void onFingerprintDialogCancelled() {
        // Fingerprint enrolment cancelled by user
    }

    @Override
    public void onFingerprintDialogSuccess() {
        // success, activation has been committed
    }
});
```

Also, you can use following code to create activation with the best granularity control:

```java
PowerAuthAuthentication authentication = new PowerAuthAuthentication();
authentication.usePossession = true;
authentication.usePassword = "1234";
authentication.useBiometry = encryptedBiometryKey;

int result =  powerAuthSDK.commitActivationWithAuthentication(context, authentication);
if (result != PowerAuthErrorCodes.PA2Succeed) {
    // happens only in case SDK was not configured or activation is not in state to be committed
}
```

Note that you currently need to obtain the encrypted biometry key yourself - you have to use `FingerprintManager.CryptoObject` or integration with Android `KeyStore` to do so.

## Requesting Activation Status

To obtain a detailed activation status information, use following code:

```java
// Check if there is some activation on the device
if (powerAuthSDK.hasValidActivation()) {

    // If there is an activation on the device, check the status with server
    powerAuthSDK.fetchActivationStatusWithCallback(context, new IActivationStatusListener() {
        @Override
        public void onActivationStatusSucceed(ActivationStatus status) {
            // Activation state: State_Created, State_OTP_Used, State_Active, State_Blocked, State_Removed
            int state = status.state;

            // Failed login attempts, remaining = max - current
            int currentFailCount = status.failCount;
            int maxAllowedFailCount = status.maxFailCount;
            int remainingFailCount = maxAllowedFailCount - currentFailCount;

        }

        @Override
        public void onActivationStatusFailed(Throwable t) {
            // Network error occurred, report it to the user
        }
    });
} else {
    // No activation present on device
}
```

## Data Signing

The main feature of PowerAuth 2.0 protocol is data signing. PowerAuth 2.0 has two types of signatures:

- **Symmetric Multi-Factor Signature**: Suitable for most operations, such as login, new payment or confirming changes in settings.
- **Asymmetric Private Key Signarture**: Suitable for documents, where strong one sided signature is desired.
- **Symmetric Offline Multi-Factor Signature**: Suitable for very secure operations, where the signature is validated over the out-of-band channel.
- **Verify server signed data**: Suitable for receiving arbitrary data from the server.

### Symmetric Multi-Factor Signature

To sign request data, you need to first obtain user credentials (password, PIN code, fingerprint scan) from the user. The task of obtaining the user credentials is used in more use-cases covered by the SDK. The core class is `PowerAuthAuthentication`, that holds information about used authentication factors:

```java
// 2FA signature, uses device related key and user PIN code.
// To use biometry, you need to fetch the encrypted biometry key value using `FingerprintManager.CryptoObject`.
PowerAuthAuthentication authentication = new PowerAuthAuthentication();
authentication.usePossession = true;
authentication.usePassword = "1234";
authentication.useBiometry = null;
```

When signing `POST`, `PUT` or `DELETE` requests, use request body bytes (UTF-8) as request data and following code:

```java
// 2FA signature, uses device related key and user PIN code
PowerAuthAuthentication authentication = new PowerAuthAuthentication();
authentication.usePossession = true;
authentication.usePassword = "1234";
authentication.useBiometry = null;

// Sign POST call with provided data made to URI with custom identifier "/payment/create"
PowerAuthAuthorizationHttpHeader header = this.requestSignatureWithAuthentication(context, authentication, "POST", "/payment/create", requestBodyBytes);
if (header.isValid()) {
    String httpHeaderKey = header.getKey();
    String httpHeaderValue = header.getValue();
} else {
    // In case of invalid configuration, invalid activation state or currupted state data
}
```

When signing `GET` requests, use the same code as above with normalized request data as described in specification, or (preferrably) use the following helper method:

```java
// 2FA signature, uses device related key and user PIN code
PowerAuthAuthentication authentication = new PowerAuthAuthentication();
authentication.usePossession = true;
authentication.usePassword = "1234";
authentication.useBiometry = null;

// Sign GET call with provided query parameters made to URI with custom identifier "/payment/create"
Map<String, String> params = new HashMap<>();
params.put("param1", "value1");
params.put("param2", "value2");

PowerAuthAuthorizationHttpHeader header = this.requestGetSignatureWithAuthentication(context, authentication, "/payment/create", params);
if (header.isValid()) {
    String httpHeaderKey = header.getKey();
    String httpHeaderValue = header.getValue();
} else {
    // In case of invalid configuration, invalid activation state or currupted state data
}
```

The result of the signature is appropriate HTTP header - you are responsible for hooking up the header value in your request correctly. The process with libraries like `OkHttp` goes like this:

```java
// Prepare the request builder
final Request.Builder builder = new Request.Builder().url(endpoint);

// Compute PA2.0 signature header
PowerAuthAuthorizationHttpHeader header = powerAuthSDK.requestSignatureWithAuthentication(context, signatureUnlockKeys, "POST", "/session/login", jsonBody);
if (!header.isValid()) {
    // request signature failed, for example due to incorrect activation status - cancel the process
    return;
 }

// Add HTTP header in the request builder
builder.header(header.getKey(), header.getValue());

// Build the request, send it and process response...
// ...
```

### Asymmetric Private Key Signature

Asymmetric Private Key Signature uses a private key stored in the PowerAuth 2.0 secure vault. In order to unlock the secure vault and retrieve the private key, user has to be first authenticated using a symmetric multi-factor signature with at least two factors. This mechanism protects the private key on the device - server plays a role of a "doorkeeper" and holds the vault unlock key.

This process is completely transparent on the SDK level. To compute an asymmetric private key signature, request user credentials (password, PIN, fingerprint scan) and use following code:

```java
// Prepare the authentication object
PowerAuthAuthentication authentication = new PowerAuthAuthentication();
authentication.usePossession = true;
authentication.usePassword = "1234";
authentication.useBiometry = null;

// Get the data to be signed
byte[] data = this.getMyData();

powerAuthSDK.signDataWithDevicePrivateKey(context, authentication, data, new IDataSignatureListener() {
    @Override
    public void onDataSignedSucceed(byte[] signature) {
        // Use data signature...
    }

    @Override
    public void onDataSignedFailed(Throwable t) {
        // Report error
    }
});
```

### Symmetric Offline Multi-Factor Signature

This type of signature is very similar to [Symmetric Multi-Factor Signature](#symmetric-multi-factor-signature) but the result is provided in form of simple, human readable string (unlike the online version, where the result is HTTP header). To calculate the signature you need a typical `PowerAuthAuthentication` object to define all required factors, nonce and data to sign. The `nonce` and `data` should be also transmitted to the application over the OOB channel (for example by scanning a QR code). Then the signature calculation is straightforward:

```java
// Prepare the authentication object
PowerAuthAuthentication authentication = new PowerAuthAuthentication();
authentication.usePossession = true;
authentication.usePassword = "1234";

final String signature = powerAuthSDK.offlineSignatureWithAuthentication(context, authentication, "/confirm/offline/operation", data, nonce);
if (signature != null) {
    android.util.Log.d(TAG, "Offline signature is: " + signature);
} else {
    // failure: session is probably invalid, or some required data is missing
}
```

Now the application has to show that calculated signature to the user and user has to re-type that code into the web application for the verification.

### Verify server signed data

This task is useful when you need to receive an arbitrary data from the server and you need to be sure that you need to be sure that data has has been issued by the server. The PowerAuthSDK is providing a high level method for validating data and associated signature:  

```java
// Validate data signed with the master server key
if (powerAuthSDK.verifyServerSignedData(data, signature, true)) {
    // data is signed with server's private master key
}
// Validate data signed with the personalized server key
if (powerAuthSDK.verifyServerSignedData(data, signature, false)) {
    // data is signed with server's private key
}
```

## Password Change

Since the device does not know the password and is unable to verify the password without the help of the server side, you need to first call an endpoint that verifies a signature computed with the password. SDK offers two ways to do that.

The safe, but typically slower way is to use following code:

```java
// Change password from "oldPassword" to "newPassword".
powerAuthSDK.changePassword(context, "oldPassword", "newPassword", new IChangePasswordListener() {
    @Override
    public void onPasswordChangeSucceed() {
        // Password was changed
    }

    @Override
    public void onPasswordChangeFailed(Throwable t) {
        // Error occurred
    }
})
```

This method calls `/pa/vault/unlock` under the hood with a 2FA signature with provided original password to verify the password correctness.

However, using this method does not usually fit to the typical UI workflow of a password change. The method may be used in cases where old password and new password are on a single screen, and therefore are both available at the same time. In most mobile apps, however, user first visits a screen to enter an old password and then (if the password is OK), the user proceeds to the two-screen flow of a new password setup (select password, confirm password). In other words, the workflow works like this:

1. Show a screen to enter old password.
2. Check old password on the server.
3. If the old password is OK, then let user chose and confirm a new one.
4. Change the password by "recrypting" the activation data.

For this purpose, you can use following code:

```java
// Ask for old password
String oldPassword = "1234";

// Validate password on the server
powerAuthSDK.validatePasswordCorrect(context, oldPassword, new IValidatePasswordListener() {
    @Override
    public void onPasswordValid() {
        // Proceed to the new password setup
    }

    @Override
    public void onPasswordValidationFailed(Throwable t) {
        // Retry entering an old password
    }
});

// ...

// Ask for new password
String newPassword = "2468";

// Change the password locally
powerAuthSDK.changePasswordUnsafe(oldPassword, newPassword);
```

**Now, beware!** Since the device does not know the actual old password, you need to make sure that the old password is validated before you use it in `unsafeChangePassword`. In case you provide a wrong old password, it will be used to decrypt the original data and these data will be encrypted using a new password. As a result, the activation data will be broken and irreversibly lost.

## Fingerprint Authentication Setup

PowerAuth SDK for Android provides an abstraction on top of the base Fingerprint Authentication support. While the authentication / data signing itself is handled using `PowerAuthAuthentication` object used in [regular request signing](#data-signing), other related processes require their own API.

### Check Fingerprint Authentication Status

You have to check for Fingerprint Authentication on three levels:

- **System Availability**: If fingerprint scanner is present on the system.
- **Activation Availability**: If biometry factor data are available for given activation.
- **Application Availability**: If user decided to use fingerprint authentication for given app. _(optional)_

PowerAuth SDK for Android provides code for the first and second of these checks.

To check if you can use fingerprint authentication on the system, use Adnroid `FingerprintManager` class directly, or our helper class:

```java
// This method is equivalent to `hasFingerprintHardware && hasEnrolledFingerprints`.
// Use it to check of fingerprint authentication can be used at the moment.
boolean isFingerprintAuthAvailable = FingerprintUtilities.isFingerprintAuthAvailable(context);

// For more fine-grained control about the actual fingerprint authentication status,
// you may use these two methods separately.
boolean hasFingerprintHardware = FingerprintUtilities.hasFingerprintHardware(context);
boolean hasEnrolledFingerprints = FingerprintUtilities.hasEnrolledFingerprints(context);
```

To check if given activation has biometry factor related data available, use following code:

```java
// Does activation have biometric factor related data in place?
boolean hasBiometryFactor = powerAuthSDK.hasBiometryFactor(context);
```

The last check is fully under your control. By keeping the fingerprint settings flag, for example a `BOOL` in `SharedPreferences`, you are able to show expected user fingerprint authentication status (in disabled state, though) even in the case fingerprint authentication is not enabled or when no fingers are enrolled on the device.

### Enable Fingerprint Authentication

In case an activation does not yet have biometry related factor data and you would like to enable fingerprint authentication support, device must first retrieve the original private key from the secure vault for the purpose of key derivation. As a result, you have to use successful 2FA with password to enable fingerprint authentication support.

Use following code to enable biometric authentication using fingerprint authentication:

```java
// Establish biometric data using provided password
powerAuthSDK.addBiometryFactor(context, fragmentManager, "Enable Fingerprint Authentication", "To enable fingerprint authentication, touch the fingerprint sensor on your device.", "1234", new IAddBiometryFactorListener() {
    @Override
    public void onAddBiometryFactorSucceed() {
        // Everything went OK, fingerprint authentication is ready to be used
    }

    @Override
    public void onAddBiometryFactorFailed(Throwable t) {
        // Error occurred, report it to user
    }
});
```

### Disable fingerprint authentication

You can remove biometry related factor data used by fingerprint authentication support by simply removing the related key locally, using this one-liner:

```java
// Remove bimetric data
powerAuthSDK.removeBiometryFactor(context);
```

### Fetching the Biometry Factor Related Key for Authentication

In order to obtain an encrypted biometry factor related key for the purpose of authentication, call following code:

```java
// Authenticate user with fingerprint and obtain encrypted biometry factor related key.
powerAuthSDK.authenticateUsingFingerprint(context, fragmentManager, "Sign in", "Confirm fingerprint to continue", new IFingerprintActionHandler() {
    @Override
    public void onFingerprintDialogCancelled() {
        // User cancelled the operation
    }

    @Override
    public void onFingerprintDialogSuccess(@Nullable byte[] encryptedBiometryKey) {
        // User authenticated and biometry key was returned
    }

    @Override
    public void onFingerprintInfoDialogClosed() {
        // User closed an information dialog with some fingerprint authentication related message
    }
});
```

## Activation Removal

You can remove activation using several ways - the choice depends on a desired behavior.

### Simple Device-Only Removal

You can clear activation data anytime from `SharedPreferences`. The benefit of this method is that it does not require help from server and user does not have to be logged in. The issue with this removal method is simple: The activation still remains active on the server side. This, however, does not have to be an issue in your case.

To remove only data related to PowerAuth SDK for Android, use following code:

```java
powerAuthSDK.removeActivationLocal(context);
```

### Removal via Authenticated Session

In case your server uses an authenticated session for keeping user logged in, you can combine the previous method with calling your proprietary endpoint that removes activation for currently logged in user. The advantage of this method is that activation does not remain active on the server. The issue is that user has to be logged in (the session must be active and must have activation ID stored) and that you have to publish your own method for the purpose of this use case.

The code for this activation removal method is as follows:

```java
// Use custom call to proprietary server endpoint to remove activation.
// User must be logged in at this moment, so that session can find
// associated activation ID
this.httpClient.post(null, "/custom/activation/remove", new ICustomListener() {
    @Override
    public void onSucceed() {
        powerAuthSDK.removeActivationLocal(context);
    }

    @Override
    public void onFailed(Throwable t) {
        // Error occurred, report it to user
    }
});
```

### Removal via Signed Request

PowerAuth 2.0 Standard RESTful API has a default endpoint `/pa/activation/remove` for an activation removal. This endpoint uses a signature verification for looking up the activation to be removed. The benefit of this method is that it is already present in both PowerAuth SDK for Android and PowerAuth 2.0 Standard RESTful API - nothing has to be programmed. Also, user does not have to be logged in to use it. However, user has to authenticate using 2FA with either password or fingerprint authentication.

Use following code for an activation removal using signed request:

```java
PowerAuthAuthentication authentication = new PowerAuthAuthentication();
authentication.usePossession = true;
authentication.usePassword = "1234";
authentication.useBiometry = null;

// Remove activation using provided authentication object
powerAuthSDK.removeActivationWithAuthentication(context, authentication, new IActivationRemoveListener() {
    @Override
    public void onActivationRemoveSucceed() {
        // OK, activation was removed
    }

    @Override
    public void onActivationRemoveFailed(Throwable t) {
        // Report error to user
    }
})
```

## End-To-End Encryption

Currently, PowerAuth SDK for Android has support for non-personalized (application key specific) encryption. You can use it to send encrypted data payload to server. Server has to be able to handle encrypted payload (decrypt request, encrypt response).

Encryption is technically carried out using an `PA2Encryptor` subclasses. Encryptors for given purpose are build using an `PA2EncryptorFactory` instance. You can easily obtain an encryptor factory right from the `PowerAuthSDK` shared instance, like so:

```java
// Obtain the default encryptor factory
PA2EncryptorFactory encryptorFactory = powerAuthSDK.getEncryptorFactory();
```

### Non-Personalized E2EE

To use non-personalized (application public key specific) encryption in your request / response cycle, build an appropriate encryptor and encrypt your data using following code:

```java
// Obtain a correct encryptor
final PA2RequestResponseNonPersonalizedEncryptor encryptor = encryptorFactory.buildRequestResponseNonPersonalizedEncryptor();

// Encrypt a request object
PowerAuthApiRequest<NonPersonalizedEncryptedPayloadModel> encryptedRequest = encryptor.encryptRequestData(requestObject);

this.httpClient.post(encryptedRequest, "/custom/url/path", new ICustomListener() {
    @Override
    public void onSucceed(PowerAuthApiResponse<NonPersonalizedEncryptedPayloadModel> encryptedResponse) {
        ResponseObject response = encryptor.decryptResponse(encryptedResponse, ResponseObject.class);
        // DONE: Process the response object
    }

    @Override
    public void onFailed(Throwable t) {
        // Error occurred, report it to user
    }
});
```

Be careful here - you have to use the same instance of `PA2RequestResponseNonPersonalizedEncryptor` for both request and response. If you build one encryptor for request and another for response, encryption will not work - encryptor keeps an istance of ephemeral private key and this private key must be used for response decryption.

## Secure Vault

PowerAuth SDK for iOS has a basic support for an encrypted secure vault. At this moment, the only supported method allows application to establish an encryption / decryption key with given index. Index represents a "key number" - your identifier for given key. Different business logic purposes should have encryption keys with different index value.

On a server side, all secure vault related work is concentrated in a `/pa/vault/unlock` endpoint of PowerAuth 2.0 Standard RESTful API. In order to receive data from this response, call must be authenticated with at least 2FA (either password, or biometry).

### Obtaining Encryption Key

In order to obtain an encryption key with given index, use following code:

```java
// 2FA signature, uses device related key and user PIN code
PowerAuthAuthentication authentication = new PowerAuthAuthentication();
authentication.usePossession = true;
authentication.usePassword = "1234";
authentication.useBiometry = null;

// Select custom key index
long index = 1000L;

// Fetch encryption key with given index
powerAuthSDK.fetchEncryptionKey(context, authentication, index, new IFetchEncryptionKeyListener() {
    @Override
    public void onFetchEncryptionKeySucceed(byte[] encryptedEncryptionKey) {
        // ... use encryption key to encrypt or decrypt data
    }

    @Override
    public void onFetchEncryptionKeyFailed(Throwable t) {
        // Report error
    }
})
```

## Token Based Authentication

WARNING: Before you start using access tokens, please visit our [wiki page for powerauth-crypto](https://github.com/wultra/powerauth-crypto/wiki/MAC-Token-Based-Authentication) for more information about this feature.

The tokens are simple, locally cached objects, producing timestamp-based authorization headers. Be aware that tokens are NOT a replacement for general PowerAuth signatures, but are helpful in situations, when the signatures are too heavy or too complicated for implementation. Each token has following properties:

- It needs PowerAuth signature for its creation (e.g. you need to provide `PowerAuthAuthentication` object)
- It has unique identifier on the server. This identifier is not exposed to the public API, but you can reveal that value in the debugger.
- It has symbolic name (e.g. "MyToken") defined by the application programmer to identify already created tokens.
- It can generate timestamp based authorization HTTP headers.
- Can be used concurrently. Token's private data doesn't change in time.
- The token is associated with the `PowerAuthSDK` instance. So, you can use the same symbolic name in multiple SDK instances and each created token will be unique.
- Tokens are persisted in the `PA2Keychain` service and cached in the memory.
- Once the parent `PowerAuthSDK` instance loose its activation, then all its tokens are removed from the local database.

### Getting token

To get an access token, you can use following code:

```java
// 1FA signature, uses device related key
PowerAuthAuthentication authentication = new PowerAuthAuthentication();
authentication.usePossession = true;

final PowerAuthTokenStore tokenStore = powerAuthSDK.getTokenStore();
final AsyncTask task = tokenStore.requestAccessToken(context, "MyToken", authentication, new IGetTokenListener() {
    @Override
    public void onGetTokenSucceeded(@NonNull PowerAuthToken powerAuthToken) {
        // the token has been successfully acquired
    }

    @Override
    public void onGetTokenFailed(@NonNull Throwable throwable) {
        // an error occured
    }
});
```

The request is performed synchronously or asynchronously depending on whether the token is locally cached on the device. You can test this situation by calling `tokenStore.hasLocalToken(context, "MyToken")`. If operation is asynchronous, then `requestAccessToken()` returns cancellable task. Be aware that you should not issue multiple asynchronous operations for the same token name.

### Generating authorization header

Once you have a `PowerAuthToken` object, use following code to generate an authorization header:

```java
PowerAuthAuthorizationHttpHeader header = token.generateHeader();
if (header.isValid()) {
    // Header is valid, you can construct HTTP header...
    String httpHeaderKey = header.key;
    String httpHeaderValue = header.value;
} else {
    // handle error
}
```

### Removing token from server

To remove token from the server, you can use following code:

```java
final PowerAuthTokenStore tokenStore = powerAuthSDK.getTokenStore();
tokenStore.removeAccessToken(context, "MyToken", new IRemoveTokenListener() {
    @Override
    public void onRemoveTokenSucceeded() {
        android.util.Log.d(TAG, "Token has been removed");
    }

    @Override
    public void onRemoveTokenFailed(@NonNull Throwable t) {
        // handle HTTP error
    }
});
```

### Removing token locally

To remove token locally, you can simply use following code:

```swift
final PowerAuthTokenStore tokenStore = powerAuthSDK.getTokenStore();
// Remove just one token
tokenStore.removeLocalToken(context, "MyToken");
// Remove all local tokens
tokenStore.removeAllLocalTokens(context);
```

Note that removing tokens locally you'll loose control about tokens stored on the server.



## Common SDK Tasks

### Error Handling

//TODO: Write documentation on error handling

### Working with Invalid SSL Certificates

Sometimes, you may need to develop or test you application against a service that runs over HTTPS protocol with invalid (self-signed) SSL certificate. By default, HTTP client used in PowerAuth SDK communication validates certificate. To disable the certificate validation, use a `PowerAuthSDK` initializer with custom client configuration to initialize your PowerAuth SDK instance, like so:

```java
// Set `PA2ClientSslNoValidationStrategy as the defauld client SSL certificate validation strategy`
final PowerAuthClientConfiguration clientConfiguration = new PowerAuthClientConfiguration.Builder()
                .clientValidationStrategy(new PA2ClientSslNoValidationStrategy())
                .build();

// Prepare the configuration, see above...
// ...

// Create a PowerAuth SDK instance
PowerAuthSDK powerAuthSDK = new PowerAuthSDK();
powerAuthSDK.initializeWithConfiguration(context, configuration, clientConfiguration);
```

## Additional Features

PowerAuth SDK for Android contains multiple additional security features that are useful for mobile apps.

### Password Strength Indicator

Whenever user selects a password, you may estimate the password strength using following code:

```java
// Determine the password strength: INVALID, WEAK, NORMAL, STRONG
PasswordStrength strength = PasswordUtil.evaluateStrength("1234", PasswordType.PIN);
```

Passwords that are `INVALID` should block the progress. You should translate `WEAK` passwords to UI warnings (not blocking progress), `NORMAL` passwords to OK state, and `STRONG` passwords to rewarding UI message (so that we appreciate user selected strong password, without pushing the user to selecting strong password too hard).

Of course, you may apply any additional measures for the password validity and strength on top of the logics we provide.
