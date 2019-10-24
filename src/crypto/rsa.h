#ifndef PROXY_CRYPTO_RSA_H_H_H
#define PROXY_CRYPTO_RSA_H_H_H

#include <string>
#include <memory>

#include <stdlib.h>

#include "openssl/rsa.h"
#include "openssl/bio.h"
#include "openssl/pem.h"

#include "core/buffer.h"

namespace proxy {
namespace crypto {


class ProxyCryptoRsaKeypair {
public:
    ProxyCryptoRsaKeypair(const std::string &pub, const std::string &pri) : _pub(pub), _pri(pri) {}
    const std::string &pub() const {
        return _pub;
    }
    void pub(const std::string &p) {
        _pub = p;
    }
    const std::string &pri() const {
        return _pri;
    }
    void pri(const std::string &p) {
        _pri = p;
    }
private:
    std::string _pub;
    std::string _pri;
};

class ProxyCryptoRsa {

public:
    static std::shared_ptr<ProxyCryptoRsaKeypair> generate_key_pair();

    static bool rsa_encrypt(std::shared_ptr<proxy::core::ProxyBuffer> &,
            std::shared_ptr<proxy::core::ProxyBuffer> &, const std::string &);
    static bool rsa_decrypt(std::shared_ptr<proxy::core::ProxyBuffer> &,
            std::shared_ptr<proxy::core::ProxyBuffer> &, const std::string &);

private:
    static const int RSA_KEY_SIZE;

};

}

}


#endif
