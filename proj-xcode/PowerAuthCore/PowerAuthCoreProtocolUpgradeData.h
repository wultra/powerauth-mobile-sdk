/**
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

#import <Foundation/Foundation.h>

/**
 The `PowerAuthCoreProtocolUpgradeData` protocol defines abstract interface for providing
 data for protocol upgrade.
 */
@protocol PowerAuthCoreProtocolUpgradeData <NSObject>
@end

/**
 The `PowerAuthCoreProtocolUpgradeDataV3` object contains data required for protocol upgrade
 from version 2 to version 3.
 */
@interface PowerAuthCoreProtocolUpgradeDataV3 : NSObject<PowerAuthCoreProtocolUpgradeData>

/**
 Contains initial value for hash-based counter. The Base64 string is expected
 with exact 16 bytes long encoded data.
 */
@property (nonatomic, strong) NSString * ctrData;

@end
