#ifndef PROXY_CRYPTO_AES_H_H_H
#define PROXY_CRYPTO_AES_H_H_H

#include <memory>
#include <string>
#include <utility>

#include "openssl/evp.h"

#include "core/buffer.h"

namespace proxy {
namespace crypto {

class ProxyCryptoAesKeyAndIv {
public:
    ProxyCryptoAesKeyAndIv(const std::string &key, const std::string &iv): _key(key), _iv(iv) {}
    ProxyCryptoAesKeyAndIv(std::string &&key, std::string &&iv): _key(std::move(key)),
        _iv(std::move(iv)) {}
    const std::string &key() const {
        return _key;
    }
    void key(const std::string &k) {
        _key = k;
    }
    const std::string &iv() const {
        return _iv;
    }
    void iv(const std::string &i) {
        _iv = i;
    }
private:
    std::string _key;
    std::string _iv;
};


enum class ProxyCryptoAesContextType {
    AES_CONTEXT_ENCRYPT_TYPE,
    AES_CONTEXT_DECRYPT_TYPE
};

class ProxyCryptoAesContext {

public:
    ProxyCryptoAesContext() : _ctx(nullptr) {}
    ~ProxyCryptoAesContext() {
        if(_ctx) {
            EVP_CIPHER_CTX_free(_ctx);          
        }
    }
    bool setup(ProxyCryptoAesContextType, const std::string &, const std::string &);
    EVP_CIPHER_CTX *get() const {
        return _ctx;
    }

private:
    EVP_CIPHER_CTX *_ctx;
    ProxyCryptoAesContextType _type;

};


class ProxyCryptoAes {

public:

    static std::shared_ptr<ProxyCryptoAesKeyAndIv> generate_key_and_iv();

    static bool aes_cfb_encrypt(std::shared_ptr<ProxyCryptoAesContext> &,
        std::shared_ptr<proxy::core::ProxyBuffer> &, std::shared_ptr<proxy::core::ProxyBuffer> &);

    static bool aes_cfb_decrypt(std::shared_ptr<ProxyCryptoAesContext> &,
        std::shared_ptr<proxy::core::ProxyBuffer> &, std::shared_ptr<proxy::core::ProxyBuffer> &);

    static const size_t AES_KEY_SIZE;
    static const size_t AES_IV_SIZE;

};

}
}


#endif
