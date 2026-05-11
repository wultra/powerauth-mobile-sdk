/*
 * Copyright 2026 Wultra s.r.o.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#import "PowerAuthMacros.h"

/**
 The `PowerAuthPassword` is an object representing an arbitrary password. The underlying implementation
 guarantees that the sensitive information is cleared from the memory when the object is destroyed.
 
 ## Discussion
 
 Working with an user's passwords is always a very delicate task. The good implementation should
 always follow several well known rules, for example:
 
    1. Should minimize traces of the plaintext password in the memory
    2. Should not allow serialization of sensitive information to the persistent storage
    3. Should keep the plaintext password in memory as short as possible
 
 Achieving all these principles together is usually very difficult, especially in managed
 environments, like Java or Objective-C is. For example, you can find a plenty of examples
 in the past where the system keyboard leaked the password, usually into the dynamic
 dictionary used by keyboard's auto-complete feature.
 
 Moreover, all these managed environments uses immutable strings for a string concatenation.
 The result is that one simple user's password is copied in hundred versions over the
 whole process memory.
 
 Due to this quirks, this PowerAuth library implementation provides its own custom objects
 responsible for manipulation with passwords. You can use these objects in several, very
 different scenarios, and its  only up to you which one you'll choose for your application:
 
 1. Wrapping an already complete password
 
 This is the simplest scenario, where you can simply create a `PowerAuthPassword` object with a final
 password. You can use `passwordWithString()` or `passwordWithData()` methods to do this.
 In this situation, you typically leaving an entering the password on the system components,
 with all its advantages (easy to use) and disadvantages (usually not very secure).
 
 2. Using mutable PIN
 
 If only the digits are allowed, then it's very recommended to create a custom UI interface
 for a PIN keyboard and use the `PowerAuthMutablePassword` object as the backing storage for
 the password.
 
 3. Using mutable alphanumeric password
 
 This approach is achievable, but usually very difficult to implement. Handling all the events
 from the keyboard properly, is not an easy task, but the benefits are obvious.
 At the end, you can get benefits from a supporting very strong passwords and also
 you'll minimize all traces of the password in the memory.
 */
@interface PowerAuthPassword : NSObject

/**
 Constructor with no parameters is not available.
 */
- (nonnull instancetype) init NS_UNAVAILABLE;

/**
 Initialize `PowerAuthPassword` object with UTF8 data from the given string. The method is useful
 for scenarios, when you have the full password already prepared and you want to pass it to the Session
 as a parameter.
 */
- (nonnull instancetype) initWithString:(nonnull NSString*)string;

/**
 Initialize `PowerAuthPassword` object with the content copied from given data object.
 The password object will contain an immutable password, created exactly from the bytes,
 provided by the data object.
 */
- (nonnull instancetype) initWithData:(nonnull NSData*)data;

/**
 Returns a new instance of `PowerAuthPassword` object, initialized with UTF8 data
 from the given string. The method is useful for scenarios, when you have
 the full password already prepared and you want to pass it to the Session
 as a parameter.
 */
+ (nonnull instancetype) passwordWithString:(nonnull NSString*)string;
/**
 Creates a new instance of `PowerAuthPassword` object, initialized with the content
 copied from given data object. The password object will contain an immutable
 password, created exactly from the bytes, provided by the data object.
 */
+ (nonnull instancetype) passwordWithData:(nonnull NSData*)data;

/**
 Returns length of the password (in bytes).
 For mutable passwords, returns number of stored unicode characters.
 */
- (NSUInteger) length;

/**
 Returns YES if both receiver is equal to password object.
 */
- (BOOL) isEqualToPassword:(nullable PowerAuthPassword*)password;

/**
 The method allows you to validate stored password with using provided validation block.
 The raw characters and the length of the password are revealed to the block, and the validation
 block can decide whether the password's complexity is sufficient or not.
 
 The provided pointer to the password is always null terminated, so it's safe to pass it
 to functions that accept the null terminated string. On opposite to that, it's not recommended
 to use this validation function on passwords created form an arbitrary data.
 
 It's not recommended to copy the plaintext password to another memory location, to minimize traces
 of the password in the memory.
 
 @return Returns value provided by the validation block. The meaning of returned integer depends on
 validation block's implementation.
 */
- (NSInteger) validatePasswordComplexity:(NSInteger (NS_NOESCAPE ^_Nonnull)(const char * _Nonnull password, NSInteger length))validationBlock;

/**
 The method wipes out the password stored in the object from the memory. If the object is immutable,
 then it's no longer usable for the cryptographic operations. If the object is mutable, then
 the function is equal to `clear()`.
 */
- (void) secureClear;

/**
 The method creates a new `PowerAuthPassword` immutable instance that will contain the same password
 as the receiver.
 */
- (nonnull PowerAuthPassword*) copyToImmutable;

@end


/**
 The `PowerAuthMutablePassword` object is a mutable version of `PowerAuthPassword`. You can edit
 content of the password.
 
 The final password is an UTF8 representation of added characters.
 */
@interface PowerAuthMutablePassword : PowerAuthPassword

/**
 Initialize `PowerAuthMutablePassword` object with empty password.
 */
- (nonnull instancetype) init;

/**
 Mutable password cannot be created with predefined string.
 */
- (nonnull instancetype) initWithString:(nonnull NSString*)string NS_UNAVAILABLE;

/**
 Mutable password cannot be created with predefined data.
 */
- (nonnull instancetype) initWithData:(nonnull NSData*)data NS_UNAVAILABLE;

/**
 Returns a new instance of `PowerAuthMutablePassword` object.
 */
+ (nonnull instancetype) mutablePassword;

/**
 Clears current content of the password
 */
- (void) clear;

/**
 Adds one unicode code point at the end of password.
 Returns YES if operation succeeded or NO if object is not
 mutable, or code point is invalid.
 */
- (BOOL) addCharacter:(UInt32)character;

/**
 Adds unicode code point at the desired index.
 Returns YES if operation succeeded or NO if object is not
 mutable, or code point is invalid, or index is out of the range.
 */
- (BOOL) insertCharacter:(UInt32)character atIndex:(NSUInteger)index;

/**
 Removes last unicode code point from the password.
 Returns YES if operation succeeded or NO if object is not
 mutable, or password is already empty.
 */
- (BOOL) removeLastCharacter;

/**
 Removes character from desired index.
 Returns YES if operation succeeded or NO if object is not
 mutable, or index is out of the range.
 */
- (BOOL) removeCharacterAtIndex:(NSUInteger)index;

@end

// Expose deprecated types as typedefs.

PA2_DEPRECATED_TYPE(2.0.0, PowerAuthCorePassword, PowerAuthPassword)
PA2_DEPRECATED_TYPE(2.0.0, PowerAuthCoreMutablePassword, PowerAuthMutablePassword)
