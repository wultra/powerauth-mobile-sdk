# Working with passwords securely

<!-- SIDEBAR _Sidebar.md -->
<!-- BREADCRUMB iOS href=../PowerAuth-SDK-for-iOS -->

PowerAuth mobile SDK uses the `PowerAuthPassword` object behind the scene, to store the user's password or PIN securely. The object automatically wipes out the plaintext password on its destroy, so there are no traces of sensitive data left in the memory. You can easily enhance your application's runtime security by adopting this object in your code and this chapter explains in detail how to do it.

## Problem explanation

If you store the user's password in a simple string, there is a high probability that the content of the string will remain in the memory until the same region is reused by the underlying memory allocator. This is because the general memory allocator doesn't clean up the region of memory being freed. It just updates its linked list of free memory regions for future reuse, so the content of the allocated object typically remains intact. This has the following implications for your application:

- If your application is using a system keyboard to enter the password or PIN, then the sensitive data will remain in memory in multiple copies for a while. 

- If the device's memory is not stressed enough, then the application may remain in memory active for days.

The situation that the user's password stays in memory for days may be critical in situations when the attacker has the device in possession. For example, if the device is lost or is in a repair shop. To minimize the risks, the `PowerAuthPassword` object does the following things:

- Always keeps the user's password scrambled with random data, so it cannot be easily found by simple string search. The password in plaintext is revealed only for a short and well-defined time when it's needed for the cryptographic operation.

- Always clear the buffer with the sensitive data before the object's deinitialization.

- Doesn't provide a simple interface to reveal the password in plaintext<sup>1)</sup> and therefore it minimizes the risks of revealing the password by accident (like printing it to the log).

<!-- begin box info -->
**Note 1:** There's a `validatePasswordComplexity()` function that reveals the password in plaintext for a limited time for complexity validation purposes. The straightforward naming of the function allows you to find all its usages in your code and properly validate all code paths.
<!-- end -->

## Special password object usage

PowerAuth mobile SDK allows you to use both strings and special password objects at input, so it's up to you which way fits best for your purposes. For simplicity, this documentation uses strings for the passwords, but all code examples can be changed to utilize the `PowerAuthPassword` object as well. For example, this is the modified code for the first step of [Password Change](Password-Change.md):

```swift
let oldPass = PowerAuthPassword(string: "oldPassword")
powerAuthSDK.beginPasswordChange(oldPassword: oldPass) { changeData, error in
    if let changeData {
        // Success
    } else {
        // Process error.
    }
}
```

## Entering PIN

If your application is using a system numeric keyboard to enter the user's PIN then you can migrate to the `PowerAuthPassword` object right now. We recommend you do the following things:

- Implement your own PIN keyboard UI

- Make sure that the password object is allocated and referenced only in the PIN keyboard controller and is deallocated when the user leaves the controller.

- Use `PowerAuthMutablePassword` that allows you to manipulate the content of the PIN 

Here's the simple pseudo-controller example:

```swift
class EnterPinScene {
    let desiredPinLength = 4
    var pin: PowerAuthMutablePassword!
    
    func onEnterScene() {
        // Allocate the pin when entering the scene
        pin = PowerAuthMutablePassword()
    }
    
    func onLeaveScene() {
        // Dereference of the password object, when the user is leaving
        // the scene to safely wipe the content out of the memory
        pin = nil
    }
    
    func onDeleteButtonAction() {
        pin.removeLastCharacter()
    }

    func onPinButtonAction(pinCharacter: Character) {
        // Mutable password works with unicode scalars, this is the example
        // that works with an arbitrary character.
        pin.addCharacter(pinCharacter.unicodeScalars.first!.value)
        if pin.length() == desiredPinLength {
            onContinueAction(pin: pin)
        }
    }
    
    func onPinButtonActionSimplified(pinIndex: Int) {
        // This is a simplified version of onPinButtonAction() that use
        // simple PIN button index as input.
        guard pinIndex >= 0 && pinIndex <= 9 else { fatalError() }
        // You don't need to add 48 (code for character "0") to the index, 
        // unless your previous implementation was using number characters.
        pin.addCharacter(UInt32(pinIndex) + 48)
        if pin.length() == desiredPinLength {
            onContinueAction(pin: pin)
        }
    }
    
    func onContinueAction(pin: PowerAuthPassword) {
        // Do something with your pin...
    }
}
```

## Entering arbitrary password

Unfortunately, there's no simple solution for this scenario. It's quite difficult to re-implement the whole keyboard on your own, so we recommend you keep using the system keyboard. You can still create the `PowerAuthPassword` object from an already entered string:

```swift
let passwordString = "nbusr123"
let password = PowerAuthPassword(string: passwordString)
```

## Create a password from data

In case that passphrase is somehow created externally in the form of an array of bytes, then you can instantiate it from the `Data` object directly:

```swift
let passwordData = Data(base64Encoded: "bmJ1c3IxMjMK")!
let password = PowerAuthPassword(data: passwordData)
```

## Compare two passwords

To compare two passwords, use `isEqual(to:)` method:

```swift
let password1 = PowerAuthPassword(string: "1234")
let password2 = PowerAuthPassword(string: "Hello")
let password3 = PowerAuthMutablePassword()
password3.addCharacter(0x31)
password3.addCharacter(0x32)
password3.addCharacter(0x33)
password3.addCharacter(0x34)
print("\(password1.isEqual(to: password2))")    // false
print("\(password1.isEqual(to: password3))")    // true
```

## Validate password complexity

The `PowerAuthPassword` object doesn't provide functions that validate password complexity, but allows you to implement such functionality on your own:

```swift
enum PasswordComplexity: Int {
    case weak = 0
    case good = 1
    case strong = 2
}

// This is an actual complexity validator that also accepts a pointer at its input. You should avoid
// converting provided memory into Data or String due to the fact, that it will lead to an uncontrolled
// passphrase copy to foundation objects' buffers.
func superPasswordValidator(passwordPtr: UnsafePointer<Int8>, size: Int) -> PasswordComplexity {
    // This is just an example, please do not use such trivial validation in your
    // production application :)
    if size < 4 {
        return .weak
    } else if size < 8 {
        return .good
    }
    return .strong
}

extension PowerAuthPassword {
    // Convenient wrapper to validateComplexity() method
    func validateComplexity() -> PasswordComplexity {
        let validationResult = self.validateComplexity { ptr, size in
            return superPasswordValidator(passwordPtr: ptr, size: size).rawValue
        }
        guard let complexity = PasswordComplexity(rawValue: validationResult) else { fatalError() }
        return complexity
    }
}
```

## Read Next

- [Working with sensitive data](Working-With-Sensitive-Data.md)
