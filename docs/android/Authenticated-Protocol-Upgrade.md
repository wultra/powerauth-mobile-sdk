# Authenticated Protocol Upgrade

<!-- SIDEBAR _Sidebar.md -->
<!-- BREADCRUMB Android href=../PowerAuth-SDK-for-Android -->

The authenticated protocol upgrade procedure enables an existing activation to
migrate to a newer algorithm for communication with the PowerAuth Server.
Following conditions must be satisfied before the upgrade can proceed:

- The PowerAuth Server version must be **2.0 or later**.
- The PowerAuth SDK instance must be configured with support for at least
`EC_P384` algorithm for communication with the PowerAuth Server.

An application can check whether a protocol upgrade is available for the current
activation by invoking:

```kotlin
val upgradeAvailable = powerAuthSDK.hasProtocolUpgradeAvailable()
```

Note that the availability information is derived from the activation status
obtained from the PowerAuth Server. Consequently, an upgrade may become
available after a successful activation status fetch. This method is not
required to be called prior to starting the protocol upgrade.

A protocol upgrade is an authenticated operation, and requires valid knowledge
authentication factor (e.g. password or PIN). The `startProtocolUpgrade()`
method is available in three variants, each designed for different biometric
configuration.

If the SDK configuration has the `authenticateOnBiometricKeySetup` enabled,
biometric key cannot be upgraded automatically during the protocol upgrade
process. If `authenticateOnBiometricKeySetup` is enabled in the SDK configuration
and activation uses biometry factor, the biometry factor will be removed
during the protocol upgrade process. In case of this setup, or when biometry
factor is not used by the activation, use following call:

```kotlin
// Initiate the protocol upgrade process
powerAuthSDK.startProtocolUpgrade(context, "password", object: IProtocolUpgradeListener {
    override fun onProtocolUpgradeSucceed(result: ProtocolUpgradeResult) {
        if (result.isActivationStatusFetchRequired()) {
            // Activation status fetch is required to complete the protocol upgrade
            if (result.isBiometryFactorRemoved()) {
                // Biometry factor was removed during the protocol upgrade process.
                // It is recommended to re-enable the biometry factor after a successful
                // activation status fetch.
            }
        } else {
            // Protocol upgrade is completed
            if (result.isBiometryFactorRemoved()) {
                // Biometry factor was removed during the protocol upgrade process.
                // It is recommended to re-enable the biometry factor.
            }
        }
    }

    override fun onProtocolUpgradeFailed(t: Throwable) {
        // Error occurred
    }
})
```

The method variant with `PowerAuthBiometricPrompt` allows the biometric key to
be upgraded during the protocol upgrade, if the SDK configuration has the
`authenticateOnBiometricKeySetup` disabled or external biometric key is not
used. Following call is recommended in that case:

```kotlin
// Prepare biometric prompt.
val biometricPrompt = PowerAuthBiometricPrompt.noPromptForBiometricKeySetup(parentFragment)
// Initiate the protocol and biometry key upgrade process
powerAuthSDK.startProtocolUpgrade(context, "password", biometricPrompt, object: IProtocolUpgradeListener {
    override fun onProtocolUpgradeSucceed(result: ProtocolUpgradeResult) {
        if (result.isActivationStatusFetchRequired()) {
            // Activation status fetch is required to complete the protocol upgrade
            if (result.isBiometryFactorRemoved()) {
                // Biometry factor was removed during the protocol upgrade process.
                // It is recommended to re-enable the biometry factor after a successful
                // activation status fetch.
            }
        } else {
            // Protocol upgrade is completed
            if (result.isBiometryFactorRemoved()) {
                // Biometry factor was removed during the protocol upgrade process.
                // It is recommended to re-enable the biometry factor.
            }
        }
    }

    override fun onProtocolUpgradeFailed(t: Throwable) {
        // Error occurred
        // If SDK instance is configured with `authenticateOnBiometricKeySetup` enabled,
        // the process fails with PowerAuthErrorCodes.WRONG_PARAMETER.
    }
})
```

The method variant with `SecureData` is intended for cases where the activation
uses external biometric key. Provided `SecureData` will replace the biometric
key during the protocol upgrade. If external biometric key is not used,
this method variant has same behavior as the method variant without
`PowerAuthBiometricPrompt` or `SecureData`.

All three variants deliver a `ProtocolUpgradeResult` on success. The application
must inspect the `activationStatusFetchRequired` field of the result object. If
set to `true`, activation status fetch must be performed to complete the
protocol upgrade. Only after successful activation status fetch is the protocol
upgrade considered completed. If the `activationStatusFetchRequired` field of
the result object is set to `false`, the protocol upgrade is considered
completed without any further action and the result object also contains new
`activationFingerprint`. The application should also inspect the
`biometryFactorRemoved` field of the result object. If set to `true`, it
indicates that the biometry factor was previously enabled but was removed during
the protocol upgrade. In such case we recommend re-enabling the biometry factor
using the standard workflow to [enable biometric authentication](Biometric-Authentication-Setup.md#enable-biometric-authentication).

If an error occurs during the protocol upgrade process, the PowerAuth SDK will
revert to the previous activation state, and the upgrade can be safely retried
later.

Until the protocol upgrade is fully completed, the PowerAuth SDK restricts
certain functionality, such as PowerAuth authentication code calculation. To
verify whether the activation is still in the middle of an upgrade, call:

```kotlin
val upgradePending = powerAuthSDK.hasPendingProtocolUpgrade()
```

If this call returns true, the application must perform an activation status
fetch to complete the upgrade.

## Read Next

- [External Encryption Key](External-Encryption-Key.md)
