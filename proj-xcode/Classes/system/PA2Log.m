/**
 * Copyright 2018 Wultra s.r.o.
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

#import "PA2Log.h"

#ifdef ENABLE_PA2_LOG
static BOOL s_log_enabled = NO;
void PA2LogImpl(NSString * format, ...)
{
	if (!s_log_enabled) {
		return;
	}
	va_list args;
	va_start(args, format);
	NSString * message = [[NSString alloc] initWithFormat:format arguments:args];
	va_end(args);
	
	NSLog(@"[PowerAuth] %@", message);
}
#endif // ENABLE_PA2_LOG


void PA2LogSetEnabled(BOOL enabled)
{
#ifdef ENABLE_PA2_LOG
	s_log_enabled = enabled;
	// Also apply to PA2CoreLog (which internally uses CC7_LOG flag)
	PA2CoreLogSetEnabled(enabled);
#endif
}

BOOL PA2LogIsEnabled(void)
{
#ifdef ENABLE_PA2_LOG
	return s_log_enabled;
#else
	return NO;
#endif
}

void PA2CriticalWarning(NSString * format, ...)
{
	va_list args;
	va_start(args, format);
	NSString * message = [[NSString alloc] initWithFormat:format arguments:args];
	va_end(args);
	
	NSLog(@"[PowerAuth] CRITICAL WARNING: %@", message);
}
