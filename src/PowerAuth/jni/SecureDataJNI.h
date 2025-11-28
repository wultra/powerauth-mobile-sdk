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

 #pragma once

 #include <cc7/jni/JniHelper.h>
 #include <PowerAuth/Types.h>

/**
 Create instance of SecureData from provided byte range.
 */
extern jobject CopyToSecureData(JNIEnv * env, const cc7::ByteRange & data);
/**
 Create instance of SecureData from provided byte range. If range is empty,
 then returns null.
 */
extern jobject CopyToNullableSecureData(JNIEnv * env, const cc7::ByteRange & data);
/**
 Return byte array from bytes stored in SecureData.
 */
extern cc7::ByteArray CopyFromSecureData(JNIEnv * env, jobject object);
