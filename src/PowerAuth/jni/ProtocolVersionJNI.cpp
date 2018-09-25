/*
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

#include "ProtocolVersionJNI.h"

// Package: io.getlime.security.powerauth.core
#define CC7_JNI_CLASS_PATH	    	"io/getlime/security/powerauth/core"
#define CC7_JNI_CLASS_PACKAGE	    io_getlime_security_powerauth_core
#define CC7_JNI_JAVA_CLASS  		ProtocolVersion
#define CC7_JNI_CPP_CLASS		    NA
#include <cc7/jni/JniModule.inl>

using namespace io::getlime::powerAuth;

extern "C" {
	
jobject CreateJavaProtocolVersion(JNIEnv * env, int v)
{
	if (!env) {
		CC7_ASSERT(false, "Missing required parameter or java environment is not valid.");
		return NULL;
	}
	// Convert version to name of static field in ProtocolVersion java enum
	const char * field_name;
	switch (v) {
		case io::getlime::powerAuth::Version_V2:
			field_name = "V2"; 
			break;
		case io::getlime::powerAuth::Version_V3:
			field_name = "V3";
			 break;
		default: 
			field_name = "Unsupported"; 
			break;
	}
	// Find enum class
	jclass versionClass	= env->FindClass(CC7_JNI_MODULE_CLASS_PATH("ProtocolVersion"));
	// Find static field for required case
	jfieldID caseField 	= env->GetStaticFieldID(versionClass , field_name, CC7_JNI_MODULE_CLASS_SIGNATURE("ProtocolVersion"));
	// Get object from static field
	jobject caseObject  = env->GetStaticObjectField(versionClass, caseField);
	CC7_ASSERT(caseObject != NULL, "Cannot convert version %d to java field '%s'", v, field_name);
	return caseObject;
}

} // extern "C"
