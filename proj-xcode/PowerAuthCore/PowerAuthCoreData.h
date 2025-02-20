/*
 * Copyright 2025 Wultra s.r.o.
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

/**
 The `PowerAuthCoreData` captures sensitive data, such as encryption keys,
 in secure manner. That mneans that the sensitive content is wiped out
 from the memory once the object is destroyed.
 */
@interface PowerAuthCoreData : NSObject<NSCopying>

/**
 Constructor with no parameters is not available.
 */
- (nonnull instancetype) init NS_UNAVAILABLE;

/**
 Construct an object with the provided data. The constructor internally copies the data.
 */
- (nonnull instancetype) initWithData:(nullable NSData*)data;
/**
 Constructs an object with the provided data. The constructor internally copies the data.
If the provided data object is mutable, its content is overwritten with zero bytes.
 */
- (nonnull instancetype) initWithDataAndClearSource:(nullable NSData*)data;

/**
 Contains underlying data object. You suppose to do not keep reference to this `Data`
 object, because it's content is cleared in `PowerAuthCoreData` destructor.
 If you want to keep safely the captured data for longer, then make copy
 of the `PowerAuthCoreData`.
 */
@property (readonly, strong, nonnull) NSData * data;

/**
 Compares two `PowerAuthCoreData` objects.
 */
- (BOOL) isEqualToCoreData:(nullable PowerAuthCoreData*)coreData;

@end
