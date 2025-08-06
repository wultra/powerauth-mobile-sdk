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

#import <PowerAuthCore/PowerAuthCoreConfig.h>

#include <PowerAuth/Configuration.h>

#include "PowerAuthCorePrivateImpl.h"

@implementation PowerAuthCoreConfig
{
    powerAuth::ConfigurationPtr _config;
}

- (powerAuth::ConfigurationPtr) configurationRef
{
    return _config;
}

- (instancetype) initWithConfig:(powerAuth::ConfigurationPtr)configuration
{
    self = [self init];
    if (self) {
        _config = configuration;
    }
    return self;
}

- (NSString*) instanceId
{
    return cc7::objc::CopyToNSString(_config->instanceId());
}

- (NSData*) deviceSpecificData
{
    return cc7::objc::CopyToNSData(_config->deviceSpecificData());
}

+ (BOOL) validateConfiguration:(nonnull NSString*)configuration
{
    return powerAuth::Configuration::validateSdkConfig(cc7::objc::CopyFromNSString(configuration));
}

+ (nullable PowerAuthCoreConfig*) buildWithConfiguration:(nonnull NSString*)configuration
                                      deviceSpecificData:(nonnull NSData*)deviceSpecificData
                                              instanceId:(nonnull NSString*)instanceId
                                               algorithm:(PowerAuthCoreAlgorithm)algorithm
                                                   error:(NSError*_Nullable*_Nullable)error
{
    try {
        auto config = powerAuth::Configuration::Builder(cc7::objc::CopyFromNSString(configuration),
                                                        static_cast<powerAuth::PowerAuthSpec::Algorithm>(algorithm))
            .withInstanceId(cc7::objc::CopyFromNSString(instanceId))
            .withDeviceSpecificData(cc7::objc::CopyFromNSData(deviceSpecificData))
            .build();
        return [[PowerAuthCoreConfig alloc] initWithConfig:config];
    } catch (...) {
        if (error) {
            *error = powerAuth::BuildNSErrorFromException();
        }
        return nil;
    }
}

@end
