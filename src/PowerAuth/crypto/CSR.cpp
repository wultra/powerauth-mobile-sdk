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

#include "CSR.h"

#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/err.h>

// helpers for OpenSSL pointers
// Custom deleter for STACK_OF(X509_EXTENSION)
struct X509ExtStackDeleter {
    void operator()(STACK_OF(X509_EXTENSION)* p) const noexcept {
        if (p) sk_X509_EXTENSION_pop_free(p, X509_EXTENSION_free);
    }
};
using x509_req_ptr  = std::unique_ptr<X509_REQ,  decltype(&X509_REQ_free)>;
using x509_name_ptr = std::unique_ptr<X509_NAME, decltype(&X509_NAME_free)>;
using x509_ext_ptr  = std::unique_ptr<X509_EXTENSION, decltype(&X509_EXTENSION_free)>;
using sk_ext_ptr    = std::unique_ptr<STACK_OF(X509_EXTENSION), X509ExtStackDeleter>;
using evp_pkey_ptr  = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using bio_ptr       = std::unique_ptr<BIO, decltype(&BIO_free)>;

namespace io
{
namespace getlime
{
namespace powerAuth
{
namespace crypto
{

    // -------------------------------------------------------------------------------------------
    // MARK: - CSR
    //

    #define CSR_FAIL(msg) CC7_LOG("CSR_CREATE failed: %s", msg); return "";

    bool add_name_entry(X509_NAME* name, const char* field, const std::string& value) {
        if (value.empty()) {
            CC7_LOG("Skipping empty field %s", field);
            return true;
        }
        
        int addResult = X509_NAME_add_entry_by_txt(name, field, MBSTRING_UTF8,
                                                   reinterpret_cast<const unsigned char*>(value.c_str()),
                                                   -1, -1, 0);
        if (addResult != 1) {
            CC7_LOG("add_name_entry failed for field %s", field);
            return false;
        }
        
        return true;
    }

    bool add_san(X509_REQ* req, const std::vector<std::string>& sanItems) {
        if (sanItems.empty()) {
            CC7_LOG("No SAN items to add");
            return true;
        }

        std::string sanList;
        for (size_t i = 0; i < sanItems.size(); ++i) {
            sanList += sanItems[i];
            if (i + 1 < sanItems.size()) {
                sanList += ",";
            }
        }

        X509V3_CTX ctx;
        X509V3_set_ctx_nodb(&ctx);
        X509V3_set_ctx(&ctx, nullptr, nullptr, req, nullptr, 0);

        x509_ext_ptr sanExt(
            X509V3_EXT_conf_nid(nullptr, &ctx, NID_subject_alt_name, sanList.c_str()),
            X509_EXTENSION_free
        );
        if (!sanExt) {
            CC7_LOG("Failed to create SAN extension");
            return false;
        }

        sk_ext_ptr exts(sk_X509_EXTENSION_new_null());
        if (!exts) {
            CC7_LOG("Failed to create extensions stack");
            return false;
        }

        if (!sk_X509_EXTENSION_push(exts.get(), sanExt.release())) {
            CC7_LOG("Failed to push SAN extension to stack");
            return false;
        }

        if (X509_REQ_add_extensions(req, exts.get()) != 1) {
            CC7_LOG("Failed to add extensions to CSR");
            return false;
        }
        
        return true;
    }
    
    std::string CSR_CREATE(EC_KEY* ec_key, const std::map<std::string, std::string>& dn_items, const std::vector<std::string>& san_items)
    {
        EVP_PKEY* pkey = EVP_PKEY_new();
        if (!pkey) {
            CSR_FAIL("Creating EVP_PKEY failed");
        }
        
        if (EVP_PKEY_assign_EC_KEY(pkey, ec_key) != 1) {
            EVP_PKEY_free(pkey);
            CSR_FAIL("Assigning EC_KEY to EVP_PKEY failed");
        }
        
        x509_req_ptr req(X509_REQ_new(), X509_REQ_free);
        if (!req) {
            CSR_FAIL("Creating X509_REQ failed!");
        }
        
        x509_name_ptr name(X509_NAME_new(), X509_NAME_free);
        if (!name) {
            CSR_FAIL("Creating X509_NAME failed");
        }
        
        for (const auto& [key, value] : dn_items) {
            if (!add_name_entry(name.get(), key.c_str(), value)) {
                CSR_FAIL("Adding name entry failed");
            }
        }
        
        if (!add_san(req.get(), san_items)) {
            CSR_FAIL("Adding SAN extension failed");
        }
        
        X509_REQ_set_subject_name(req.get(), name.get()); // TODO: verify return value?
        
        if (X509_REQ_set_pubkey(req.get(), pkey) != 1) {
            CSR_FAIL("X509_REQ_set_pubkey failed");
        }
        
        const EVP_MD* md = EVP_sha256();
        if (X509_REQ_sign(req.get(), pkey, md) <= 0) {
            CSR_FAIL("X509_REQ_sign failed");
        }
            
        bio_ptr mem(BIO_new(BIO_s_mem()), BIO_free);
        if (!mem) {
            CSR_FAIL("BIO_new failed");
        }
        
        if (PEM_write_bio_X509_REQ(mem.get(), req.get()) != 1) {
            CSR_FAIL("PEM_write_bio_X509_REQ failed");
        }
        
        BUF_MEM* bptr = nullptr;
        BIO_get_mem_ptr(mem.get(), &bptr);
        if (!bptr) {
            CSR_FAIL("BIO_get_mem_ptr failed");
        }
        
        return std::string(bptr->data, bptr->length);
    }
    
} // io::getlime::powerAuth::crypto
} // io::getlime::powerAuth
} // io::getlime
} // io

