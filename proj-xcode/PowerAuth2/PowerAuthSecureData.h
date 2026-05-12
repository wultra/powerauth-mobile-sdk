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

#import <Foundation/Foundation.h>

/**
 The `PowerAuthSecureData` class encapsulates a byte array containing cryptographically sensitive data
 and ensures that the data is securely erased from memory when the object is destroyed.
 */
@interface PowerAuthSecureData : NSObject<NSCopying>

/**
 Constructor with no parameters is not available.
 */
- (nonnull instancetype) init NS_UNAVAILABLE;

/**
 Construct object with bytes copied from the provided data object.
 */
- (nonnull instancetype) initWithData:(nullable NSData*)data
                            NS_SWIFT_NAME(init(withData:));
/**
 Construct object with bytes copied from the provided data object. If the provided data object is
 also instance of `NSMutableData` then the content will be also erased.
 */
- (nonnull instancetype) initWithDataAndClearSource:(nullable NSData*)data
                            NS_SWIFT_NAME(init(withDataAndClearSource:));

/**
 Provides access to the underlying data object.
 
 Do not retain a reference to the returned `NSData` object, as its content will be cleared
 when this object is destroyed.

 If you need to preserve the captured data for longer, make a copy of the returned data
 and securely erase its content when it is no longer needed.
 */
@property (readonly, strong, nonnull) NSData * sensitiveData;

/**
 Compares two `PowerAuthSecureData` objects.
 */
- (BOOL) isEqualToSecureData:(nullable PowerAuthSecureData*)coreData;

@end

