/**
 * Copyright 2017 Lime - HighTech Solutions s.r.o.
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

#import "PA2SessionStatusDataReader.h"

const uint8_t TAG1 = 'P';
const uint8_t TAG2 = 'A';

const uint8_t PD_TAG = 'P';
const uint8_t PD_VER_MIN = '3';
const uint8_t PD_VER_MAX = '6';

static BOOL _InvestigateSerializedData(const uint8_t * bytes, NSUInteger length)
{
	if (length < 3 || !bytes) {
		return NO;	// very short...
	}
	if (bytes[0] != TAG1 || bytes[1] != TAG2) {
		return NO;	// wrong data magic
	}
	uint8_t st = bytes[2];
	if (st == 0x00) {
		return NO;	// no activation
	}
	if ((st & 0x02) == 0 || length < 192) {
		return NO;	// invalid active flag, or too short
	}
	// The new data format has another version header just after that status byte
	if (bytes[3] != PD_TAG || bytes[4] < PD_VER_MIN || bytes[4] > PD_VER_MAX) {
		return NO;	// persistent data tag & ver is wrong
	}
	// Data has a possible valid activation
	return YES;
}

// DATA_MIGRATION_TAG
//  .. extension still has to be able to investigate an old data format
const uint8_t TAG3_OLD = 'M';
static BOOL _InvestigateOldSerializedData(const uint8_t * bytes, NSUInteger length)
{
	// Empty data: 50 41 4D 32 69 FF (PAM2i + 0xFF or PAM2a.... + 0xFF)
	if (length < 6 || !bytes) {
		return NO;
	}
	if (bytes[0] != TAG1 || bytes[1] != TAG2 || bytes[2] != TAG3_OLD) {
		return NO;	// wrong data magic
	}
	uint8_t ver = bytes[3], st = bytes[4];
	if ((ver != '1' && ver != '2') || (st != 'a' && st != 'i')) {
		return NO;	// wrong version or status tag
	}
	if (bytes[length - 1] != 0xff) {
		return NO;	// Wrong terminator
	}
	if (st == 'a') {
		// tag is "active", so we don't want to read a full data, so the possible activation
		// is depending on length of data.
		return length > 192;
	}
	// Has 'i' tag, and that means no-activation
	return NO;
}

BOOL PA2SessionStatusDataReader_DataContainsActivation(NSData * data)
{
	if (!data) {
		return NO;
	}
	NSUInteger length = data.length;
	const uint8_t * bytes = (const uint8_t *)data.bytes;
	// DATA_MIGRATION_TAG
	if (_InvestigateOldSerializedData(bytes, length)) {
		return YES;
	}
	return _InvestigateSerializedData(bytes, length);
}
