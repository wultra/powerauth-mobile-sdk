/*
 * Copyright 2021 Wultra s.r.o.
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

#import <PowerAuthCore/PowerAuthCoreMacros.h>

#pragma mark Password -

/**
 The PowerAuthCorePassword is an object representing an arbitrary passphrase. The underlying implementation
 guarantees that the sensitive information is cleared from the memory when the object is destroyed.
 
 
 Discussion
 
 Working with an user's passphrases is always a very delicate task. The good implementation should
 always follow several well known rules, for example:
 
	1. Should minimize traces of the plaintext passphrase in the memory
	2. Should not allow serialization of sensitive information to the persistent storage
	3. Should keep the plaintext passphrase in memory as short as possible
 
 Achieving all these principles together is usually very difficult, especially in managed
 environments, like Java or Objective-C is. For exmaple, you can find a plenty of examples 
 in the past where the system keyboard leaked the passphrases, usually into the dynamic
 dictionary used by keyboard's auto-complete feature.
 
 Moreover, all these managed environments uses immutable strings for a string concatenation. 
 The result is that one simple user's passphrase is copied in hundred versions over the 
 whole process memory.
 
 Due to this quirks, this PowerAuth library implementation provides its own custom objects
 responsible for manipulation with passwords. You can use these objects in several, very
 different scenarios, and its  only up to you which one you'll choose for your application:
 
 
 1. Wrapping an already complete passphrase
 
 This is the simplest scenario, where you can simply create a PowerAuthCorePassword object with a final
 passphrase. You can use 'passwordWithString' or 'passwordWithData' methods to do this.
 In this situation, you typically leaving an entering the passphrase on the system components,
 with all its advantages (easy to use) and disadvantages (usually not very secure).
 
 
 2. Using mutable PIN passphrase
 
 If onyl the digits are allowed, then it's very recommended to create a custom UI interface 
 for a PIN keyboard and use the PowerAuthCoreMutablePassword object as the backing storage for 
 the passphrase.
 
 
 3. Using mutable alphanumeric passphrase
 
 This approach is achievable, but usually very difficult to implement. Handling all the events
 from the keyboard properly, is not an easy task, but the benefits are obvious. 
 At the end, you can get benefits from a supporting very strong passphrases and also 
 you'll minimize all traces of the passphrase in the memory.
 */
@interface PowerAuthCorePassword : NSObject

/**
 Returns a new instance of PowerAuthCorePassword object, initialized with UTF8 data
 from the given string. The method is useful for scenarios, when you have
 the full password already prepared and you want to pass it to the Session
 as a parameter.
 */
+ (nullable instancetype) passwordWithString:(nonnull NSString*)string;
/**
 Creates a new instance of PowerAuthCorePassword object, initialized with the content
 copied from given data object. The password object will contain an immutable 
 passphrase, created exactly from the bytes, provided by the data object.
 */
+ (nullable instancetype) passwordWithData:(nonnull NSData*)data;

/**
 Returns length of the password (in bytes).
 For mutable passwords, returns number of stored unicode characters.
 */
- (NSUInteger) length;

/**
 Returns YES if both receiver is equal to password object.
 */
- (BOOL) isEqualToPassword:(nullable PowerAuthCorePassword*)password;

/**
 The method validates stored passphrase with using provided validation block. The raw bytes of 
 the passphrase are revealed to the block, which can decide whether the passphrase's complexity 
 is sufficient or not.
 
 Returns NO if passphrase is empty, or result returned from the block.
 */
- (BOOL) validatePasswordComplexity:(BOOL (NS_NOESCAPE ^_Nullable)(const UInt8 * _Nonnull  passphrase, NSUInteger length))validationBlock;

@end


/**
 The PowerAuthCoreMutablePassword object is a mutable version of PowerAuthCorePassword. You can edit 
 content of the passphrase
 
 The final passphrase is an UTF8 representation of added characters.
 */
@interface PowerAuthCoreMutablePassword : PowerAuthCorePassword

/**
 Returns a new insntace of PowerAuthCoreMutablePassword object.
 */
+ (nullable instancetype) mutablePassword;

/**
 Clears current content of the password
 */
- (void) clear;

/**
 Adds one unicode code point at the end of passphrase.
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
 Removes last unicode code point from the passphrase.
 Returns YES if operation succeeded or NO if object is not
 mutable, or passphrase is already empty.
 */
- (BOOL) removeLastCharacter;

/**
 Removes character from desired index.
 Returns YES if operation succeeded or NO if object is not
 mutable, or index is out of the range.
 */
- (BOOL) removeCharacterAtIndex:(NSUInteger)index;

@end
