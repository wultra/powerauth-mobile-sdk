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

#import <PowerAuthCore/PowerAuthCoreSession.h>
#import <PowerAuthCore/PowerAuthCoreLog.h>
#import "PowerAuthCorePrivateImpl.h"

using namespace io::getlime::powerAuth;

#if defined(DEBUG)
void PowerAuthCoreObjc_DebugDumpErrorImpl(id instance, NSString * message, ErrorCode code)
{
    if (code != EC_Ok) {
        NSString * codeStr;
        switch (code) {
            case EC_Encryption: codeStr = @"EC_Encryption"; break;
            case EC_WrongParam: codeStr = @"EC_WrongParam"; break;
            case EC_WrongState: codeStr = @"EC_WrongState"; break;
            default:
                codeStr = [@(code) stringValue];
                break;
        }
        void * instancePtr = (__bridge void*)instance;
        NSString * className = NSStringFromClass([instance class]);
        
        if ([instance isKindOfClass:[PowerAuthCoreSession class]]) {
            PowerAuthCoreSession * session = (PowerAuthCoreSession*)instance;
            unsigned int sessionId = (unsigned int)session.sessionIdentifier;
            PowerAuthCoreLog(@"%@(0x%p, ID:%d): %@: Low level operation failed with error %@.", className, instancePtr, sessionId, message, codeStr);
        } else {
            PowerAuthCoreLog(@"%@(0x%p): %@: Low level operation failed with error %@.", className, instancePtr, message, codeStr);
        }
    }
}
#endif // DEBUG

