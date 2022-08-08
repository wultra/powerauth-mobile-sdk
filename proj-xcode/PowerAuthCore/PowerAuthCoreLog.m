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

#import <PowerAuthCore/PowerAuthCoreLog.h>
#import <cc7/Platform.h>

#ifdef ENABLE_POWERAUTH_CORE_LOG

void PowerAuthCoreLogImpl(NSString * format, ...)
{
    if (!PowerAuthCoreLogIsEnabled()) {
        return;
    }
    va_list args;
    va_start(args, format);
    NSString * message = [[NSString alloc] initWithFormat:format arguments:args];
    va_end(args);
    
    NSLog(@"[PowerAuthCore] %@", message);
}

#endif // ENABLE_POWERAUTH_CORE_LOG

void PowerAuthCoreLogSetEnabled(BOOL enabled)
{
    CC7_LOG_ENABLE(enabled);
}

BOOL PowerAuthCoreLogIsEnabled(void)
{
    return CC7_LOG_IS_ENABLED();
}
