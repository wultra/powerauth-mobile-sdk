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


#import <PowerAuthCore/PowerAuthCoreError.h>

#include <PowerAuth/Exception.h>
#include <cc7/objc/ObjcHelper.h>

NSString * const PowerAuthCoreErrorDomain                   = @"PowerAuthCoreErrorDomain";
NSString * const PowerAuthCoreErrorInfoKey_AdditionalErrors = @"PowerAuthCoreErrorInfoKey_AdditionalErrors";

@implementation NSError (PowerAuthCoreError)

- (PowerAuthCoreError) powerAuthCoreError
{
    if ([self.domain isEqualToString:PowerAuthCoreErrorDomain]) {
        return static_cast<PowerAuthCoreError>(self.code);
    }
    return PowerAuthCoreError_NA;
}

- (NSArray*) powerAuthCoreAdditionalErrorMessages
{
    id info = self.userInfo[PowerAuthCoreErrorInfoKey_AdditionalErrors];
    if ([info isKindOfClass:[NSArray class]]) {
        return info;
    }
    return nil;
}

@end

namespace powerAuth {

NSError* BuildCoreNSError(PowerAuthCoreError error_code, NSString * message)
{
    return [NSError errorWithDomain:PowerAuthCoreErrorDomain code:error_code userInfo:@{
        NSLocalizedDescriptionKey: message
    }];
}

NSError * BuildNSErrorFromException(std::exception_ptr ptr)
{
    NSString * message = nil;
    NSMutableArray * additional = [NSMutableArray array];
    powerAuth::ErrorCode error_code = powerAuth::EC_Other;
    
    ptr = Exception::wrapException();
    
    // Iterate over exception chain and extract debug information
    while (ptr != nullptr) {
        std::string cpp_message;
        powerAuth::ErrorCode ec = powerAuth::EC_Other;
        try {
            std::rethrow_exception(ptr);
        } catch (powerAuth::Exception & e) {
            cpp_message = e.exceptionClass() + ": " + e.message();
            ptr = e.cause();
            ec = e.error();
        } catch (cc7::BaseException & e) {
            cpp_message = e.exceptionClass() + ": " + e.message();
            ptr = e.cause();
        } catch (std::exception & e) {
            cpp_message = e.what();
            ptr = nullptr;
        } catch (...) {
            cpp_message = "Unknown exception type";
            ptr = nullptr;
        }
        if (!message) {
            message = cc7::objc::CopyToNSString(cpp_message);
            error_code = ec;
        } else {
            [additional addObject:cc7::objc::CopyToNSString(cpp_message)];
        }
    }
    // Make sure there's some message set.
    if (!message) {
        message = @"PowerAuthCore unknown failure";
    }
    
    // Build NSError
    return [NSError errorWithDomain:PowerAuthCoreErrorDomain code:error_code userInfo:@{
        NSLocalizedDescriptionKey: message,
        PowerAuthCoreErrorInfoKey_AdditionalErrors: additional
    }];
}

} // namespace powerAuth
