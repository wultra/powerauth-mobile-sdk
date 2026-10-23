# Authenticated Protocol Upgrade

<!-- SIDEBAR _Sidebar.md -->

The authenticated protocol upgrade procedure enables an existing activation to
migrate to a newer algorithm for communication with the PowerAuth Server.
Following conditions must be satisfied before the upgrade can proceed:

- The PowerAuth Server version must be **2.0 or later**.
- The PowerAuth SDK instance must be configured with support for at least
`EC_P384` algorithm for communication with the PowerAuth Server.

An application can check whether a protocol upgrade is available for the current
activation by invoking:

```swift
let upgradeAvailable = powerAuthSDK.hasProtocolUpgradeAvailable()
```

Note that the availability information is derived from the activation status
obtained from the PowerAuth Server. Consequently, an upgrade may become
available after a successful activation status fetch. This method is not
required to be called prior to starting the protocol upgrade.

A protocol upgrade is an authenticated operation. User must provide valid
knowledge authentication factor (e.g. password or PIN). To start the protocol
upgrade, call:

```swift
powerAuthSDK.startProtocolUpgrade(password: "1234") { (result, error) in
    if let result {
        if result.activationStatusFetchRequired {
            // Activation status fetch is required to complete the protocol upgrade
        } else {
            // Protocol upgrade is completed
        }
    } else {
        // Error occurred
    }
}
```

If the call succeeds, the application must inspect the
`activationStatusFetchRequired` field of the result object. If set to `true`,
activation status fetch must be performed to complete the protocol upgrade. Only
after successful activation status fetch is the protocol upgrade considered
completed. If the `activationStatusFetchRequired` field of the result object is
set to `false`, the protocol upgrade is considered completed without any further
action and the result object also contains new `activationFingerprint`. If an
error occurs, the PowerAuth SDK will revert to the previous activation state,
and the upgrade can be safely retried later.

Until the protocol upgrade is fully completed, the PowerAuth SDK restricts
certain functionality, such as PowerAuth authentication code calculation. To
verify whether the activation is still in the middle of an upgrade, call:

```swift
let upgradePending = powerAuthSDK.hasPendingProtocolUpgrade()
```

If this call returns true, the application must perform an activation status fetch to complete the upgrade.

## Read Next

- [Apple Watch Support](Apple-Watch-Support.md)
