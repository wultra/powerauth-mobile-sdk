/*
 * Copyright 2017 Wultra s.r.o.
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
#include <PowerAuth/ECIES.h>

/**
 Creates a new ECIESCryptogram java object from given C++ cryptogram structure.
 */
CC7_EXTERN_C jobject CreateJavaCryptogramFromCppObject(JNIEnv * env, io::getlime::powerAuth::ECIESCryptogram & cryptogram);

/**
 Loads a content from ECIESCryptogram java object into cryptogram C++ structure.
 */
CC7_EXTERN_C void LoadCppCryptogramFromJavaObject(JNIEnv * env, jobject cryptogram, io::getlime::powerAuth::ECIESCryptogram & cppCryptogram);
