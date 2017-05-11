/*
 * Copyright 2016-2017 Lime - HighTech Solutions s.r.o.
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

#include <PowerAuth/PublicTypes.h>
#include "protocol/Constants.h"

namespace io
{
namespace getlime
{
namespace powerAuth
{

	//
	// MARK: - HTTPRequestData -
	//
	
	HTTPRequestData::HTTPRequestData()
	{
	}
	
	HTTPRequestData::HTTPRequestData(const cc7::ByteRange & body,
									 const std::string & method,
									 const std::string & uri) :
		body(body),
		method(method),
		uri(uri)
	{
	}
	
	HTTPRequestData::HTTPRequestData(const cc7::ByteRange & body,
									 const std::string & method,
									 const std::string & uri,
									 const cc7::ByteRange & nonce) :
		body(body),
		method(method),
		uri(uri),
		offlineNonce(nonce)
	{
	}
	
	bool HTTPRequestData::hasValidData() const
	{
		if (method.empty() || uri.empty()) {
			return false;
		}
		if (!(method == "GET" || method == "POST" || method == "HEAD" || method == "PUT" || method == "DELETE")) {
			return false;
		}
		if (!offlineNonce.empty() && offlineNonce.size() != protocol::SIGNATURE_KEY_SIZE) {
			return false;
		}
		return true;
	}
	
	//
	// MARK: - HTTPRequestDataSignature -
	//
	
	std::string HTTPRequestDataSignature::buildAuthHeaderValue() const
	{
		const size_t out_size = activationId.length() + applicationKey.length() + nonce.length() + factor.length() + signature.length() +
								version.length() + protocol::PA_AUTH_FRAGMENTS_LENGTH;
		std::string out;
		out.reserve(out_size);
		
		// Build header value
		out.assign(protocol::PA_AUTH_FRAGMENT_BEGIN_VERSION);
		out.append(version);
		out.append(protocol::PA_AUTH_FRAGMENT_ACTIVATION_ID);
		out.append(activationId);
		out.append(protocol::PA_AUTH_FRAGMENT_APPLICATION_KEY);
		out.append(applicationKey);
		out.append(protocol::PA_AUTH_FRAGMENT_NONCE);
		out.append(nonce);
		out.append(protocol::PA_AUTH_FRAGMENT_SIGNATURE_TYPE);
		out.append(factor);
		out.append(protocol::PA_AUTH_FRAGMENT_SIGNATURE);
		out.append(signature);
		out.append(protocol::PA_AUTH_FRAGMENT_END);
		
		return out;
	}
	
} // io::getlime::powerAuth
} // io::getlime
} // io
