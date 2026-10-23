# Working with passwords securely

<!-- SIDEBAR _Sidebar.md -->

PowerAuth mobile SDK uses the `io.getlime.security.powerauth.core.Password` object behind the scenes, to store the user's password or PIN securely. The object automatically wipes out the plaintext password on its destroy, so there are no traces of sensitive data left in the memory. You can easily enhance your application's runtime security by adopting this object in your code and this chapter explains in detail how to do it.

## Problem explanation

If you store the user's password in a simple string, there is a high probability that the content of the string will remain in the memory until the same region is reused by the underlying memory allocator. This is because the general memory allocator doesn't clean up the region of memory being freed. It just updates its linked-list of free memory regions for future reuse, so the content of the allocated object typically remains intact. This has the following implications for your application:

- If your application is using a system keyboard to enter the password or PIN, then the sensitive data will remain in memory in multiple copies for a while. 

- If the device's memory is not stressed enough, then the application may remain in memory active for days.

The situation that the user's password stays in memory for days may be critical in situations when the attacker has the device in possession. For example, if the device is lost or is in a repair shop. To minimize the risks, the `Password` object does the following things:

- Always keeps the user's password scrambled with random data, so it cannot be easily found by simple string search. The password in plaintext is revealed only for a short and well-defined time when it's needed for the cryptographic operation.

- Always clear buffer with the sensitive data before the object's destruction.

- Doesn't provide a simple interface to reveal the password in plaintext<sup>1)</sup> and therefore it minimizes the risks of revealing the password by accident (like printing it to the log).

<!-- begin box info -->
**Note 1:** There's a `validatePasswordComplexity()` function that reveals the password in plaintext for a limited time for complexity validation purposes. The straightforward naming of the function allows you to find all its usages in your code and properly validate all code paths.
<!-- end -->

## Special password object usage

PowerAuth mobile SDK allows you to use both strings and special password objects at input, so it's up to you which way fits best for your purposes. For simplicity, this documentation uses strings for the passwords, but all code examples can be changed to utilize the `Password` object as well. For example, this is the modified code for the first step of [Password Change](Password-Change.md):

```kotlin
val oldPass = Password("oldPassword")
powerAuthSDK.beginPasswordChange(context, oldPass, object: IBeginPasswordChangeListener {
    override fun onBeginPasswordChangeSucceed(changeData: PowerAuthPasswordChangeData) {
        // success
    }

    override fun onBeginPasswordChangeFailed(t: Throwable) {
        // Error occurred.
    }
})
```

## Entering PIN

If your application is using a system numeric keyboard to enter the user's PIN then you can migrate to the `Password` object right now. We recommend you do the following things:

- Implement your own PIN keyboard UI

- Make sure that the password object is allocated and referenced only in the PIN keyboard controller and is deallocated when the user leaves the controller.

- Use the `Password()` object that allows you to manipulate the content of the PIN 

Here's the simple pseudo-controller example:

```kotlin
class EnterPinScene(val desiredPinLength: Int = 4) {

    private var pinInstance: Password? = null
    private val pin: Password get() = pinInstance ?: throw IllegalStateException()

    fun onEnterScene() {
        // Allocate password when entering to the scene.
        // Constructor with no parameters creates a mutable Password.
        pinInstance = Password()
    }

    fun onLeaveScene() {
        // Dereference and destroy the password object, when the user is leaving
        // the scene to safely wipe the content out of the memory.
        //
        // Make sure that this is done only after PowerAuth SDK finishes all operations
        // started with this object at input.
        // 
        // Note that IllegalStateException is raised if you use Password object after its destroy.
        pinInstance?.destroy()
        pinInstance = null
    }

    fun onDeleteButtonAction() {
        pin.removeLastCharacter()
    }

    fun onPinButtonAction(pinCharacter: Char) {
        // Mutable password works with Unicode scalars, this is the example
        // that works with an arbitrary character up to code point 0xFFFF.
        // To add an arbitrary Unicode character, you need to convert it to code point first.
        // See https://stackoverflow.com/questions/9834964/char-to-unicode-more-than-uffff-in-java
        pin.addCharacter(pinCharacter.code)
        if (pin.length() == desiredPinLength) {
            onContinueAction(pin)
        }
    }

    fun onPinButtonActionSimplified(pinIndex: Int) {
        // This is a simplified version of onPinButtonAction() that use
        // simple PIN button index as input.
        if (pinIndex < 0 || pinIndex > 9) {
            throw IllegalArgumentException("Wrong PIN index")
        }
        // You don't need to add 48 (code for character "0") to the index, 
        // unless your previous implementation was using number characters.
        pin.addCharacter(48 + pinIndex)
        if (pin.length() == desiredPinLength) {
            onContinueAction(pin)
        }
    }

    fun onContinueAction(pin: Password) {
        // Do something with the entered pin...
    }
}
```

## Entering arbitrary password

Unfortunately, there's no simple solution for this scenario. It's quite difficult to re-implement the whole keyboard on your own, so we recommend you keep using the system keyboard. You can still create the `Password` object from an already entered string:

```kotlin
val passwordString = "nbusr123"
val password = Password(passwordString)
```

## Create a password from the data

In case that passphrase is somehow created externally in the form of an array of bytes, then you can instantiate it from the `Data` object directly:

```kotlin
val passwordData = Base64.decode("bmJ1c3IxMjMK", Base64.NO_WRAP)
val password = Password(passwordData)
```


## Compare two passwords

To compare two passwords, use the `isEqual(to:)` method:

```kotlin
val password1 = Password("1234")
val password2 = Password("Hello")
val password3 = Password()
password3.addCharacter(0x31)
password3.addCharacter(0x32)
password3.addCharacter(0x33)
password3.addCharacter(0x34)
print("${password1.isEqualToPassword(password2)}")  // false
print("${password1 == password3}")                  // true
```

## Validate password complexity

The `Password` object doesn't provide functions that validate password complexity, but allows you to implement such functionality on your own:

```kotlin
enum class PasswordComplexity(val value: Int) {
    WEAK(0),
    GOOD(1),
    STRONG(2);

    companion object {
        fun fromInt(value: Int): PasswordComplexity = values().first { it.value == value }
    }
}

// This is an actual complexity validator that also accepts ByteArray at its input. You should avoid
// converting provided bytes into String or copy passphrase to another byte array to minimize risk
// of leaking the password in memory.
fun superPasswordValidator(password: ByteArray): PasswordComplexity {
    // This is just an example, please do not use such trivial validation in your
    // production application :)
    if (password.size < 4) {
        return PasswordComplexity.WEAK
    } else if (password.size < 8) {
        return PasswordComplexity.GOOD
    }
    return PasswordComplexity.STRONG
}

// Convenient wrapper to validatePasswordComplexity() method
fun Password.validateComplexity(): PasswordComplexity {
    val resultValue = validatePasswordComplexity { passwordBytes ->
        superPasswordValidator(passwordBytes).value
    }
    return PasswordComplexity.fromInt(resultValue)
}
```

<!-- begin box info -->
You can use our [Passphrase meter](https://github.com/wultra/passphrase-meter) library as a proper password validation solution.
<!-- end -->

## Read Next

- [Working with sensitive data](Working-With-Sensitive-Data.md)
