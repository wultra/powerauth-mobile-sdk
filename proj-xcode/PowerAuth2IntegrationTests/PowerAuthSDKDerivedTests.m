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

#import "PowerAuthSDKSharedBaseTests.h"

// MARK: - Base tests without activation data sharing

@interface BaseTests_V3 : PowerAuthSDKBaseTests
@end
@implementation BaseTests_V3
- (PowerAuthAlgorithm) powerAuthAlgorithm
{
    return PowerAuthAlgorithm_LEGACY_P256;
}
@end

@interface BaseTests_V4_EC_P384 : PowerAuthSDKBaseTests
@end
@implementation BaseTests_V4_EC_P384
- (PowerAuthAlgorithm) powerAuthAlgorithm
{
    return PowerAuthAlgorithm_EC_P384;
}
@end


@interface BaseTests_V4_EC_P384_ML_L3 : PowerAuthSDKBaseTests
@end
@implementation BaseTests_V4_EC_P384_ML_L3
- (PowerAuthAlgorithm) powerAuthAlgorithm
{
    return PowerAuthAlgorithm_EC_P384_ML_L3;
}
@end

@interface BaseTests_V4_EC_P384_ML_L5 : PowerAuthSDKBaseTests
@end
@implementation BaseTests_V4_EC_P384_ML_L5
- (PowerAuthAlgorithm) powerAuthAlgorithm
{
    return PowerAuthAlgorithm_EC_P384_ML_L5;
}
@end

// MARK: - Tests with activation data sharing

@interface SharedTests_V3 : PowerAuthSDKSharedBaseTests
@end
@implementation SharedTests_V3
- (PowerAuthAlgorithm) powerAuthAlgorithm
{
    return PowerAuthAlgorithm_LEGACY_P256;
}
@end

@interface SharedTests_V4_EC_P384 : PowerAuthSDKSharedBaseTests
@end
@implementation SharedTests_V4_EC_P384
- (PowerAuthAlgorithm) powerAuthAlgorithm
{
    return PowerAuthAlgorithm_EC_P384;
}
@end

@interface SharedTests_V4_EC_P384_ML_L3 : PowerAuthSDKSharedBaseTests
@end
@implementation SharedTests_V4_EC_P384_ML_L3
- (PowerAuthAlgorithm) powerAuthAlgorithm
{
    return PowerAuthAlgorithm_EC_P384_ML_L3;
}
@end

@interface SharedTests_V4_EC_P384_ML_L5 : PowerAuthSDKSharedBaseTests
@end
@implementation SharedTests_V4_EC_P384_ML_L5
- (PowerAuthAlgorithm) powerAuthAlgorithm
{
    return PowerAuthAlgorithm_EC_P384_ML_L5;
}
@end

