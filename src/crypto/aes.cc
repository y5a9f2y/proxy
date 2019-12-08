#include "crypto/aes.h"

#include "time.h"

#include "glog/logging.h"

using proxy::core::ProxyBuffer;

namespace proxy {
namespace crypto {

const size_t ProxyCryptoAes::AES_KEY_SIZE = 32;
const size_t ProxyCryptoAes::AES_IV_SIZE = 16;

std::shared_ptr<ProxyCryptoAesKeyAndIv> ProxyCryptoAes::generate_key_and_iv() {

    std::string key;
    std::string iv;

    for(size_t i = 0; i < ProxyCryptoAes::AES_KEY_SIZE; ++i) {
        key.push_back(static_cast<char>(random() % 26 + 'a'));
    }

    for(size_t i = 0; i < ProxyCryptoAes::AES_IV_SIZE; ++i) {
        iv.push_back(static_cast<char>(random() % 26 + 'a'));
    }

    return std::make_shared<ProxyCryptoAesKeyAndIv>(std::move(key), std::move(iv));

}

bool ProxyCryptoAesContext::setup(ProxyCryptoAesContextType ty,
    const std::string &key, const std::string &iv) {

    _type = ty;

    _ctx = EVP_CIPHER_CTX_new();
    if(!_ctx) {
        LOG(ERROR) << "create a encrypt cipher context error";
        return false;
    }

    if(ty == ProxyCryptoAesContextType::AES_CONTEXT_ENCRYPT_TYPE) {
        if(!EVP_EncryptInit_ex(_ctx, EVP_aes_128_cfb(), NULL,
            reinterpret_cast<const unsigned char *>(key.c_str()),
            reinterpret_cast<const unsigned char *>(iv.c_str()))) {
            LOG(ERROR) << "setup the encrypt cipher context with aes-128-cfb error";
            return false;
        }
    } else {
        if(!EVP_DecryptInit_ex(_ctx, EVP_aes_128_cfb(), NULL,
            reinterpret_cast<const unsigned char *>(key.c_str()),
            reinterpret_cast<const unsigned char *>(iv.c_str()))) {
            LOG(ERROR) << "setup the decrypt cipher context with aes-128-cfb error";
            return false;
        }
    }

    return true;

}

bool ProxyCryptoAes::aes_cfb_encrypt(std::shared_ptr<ProxyCryptoAesContext> &ctx,
    std::shared_ptr<ProxyBuffer> &from, std::shared_ptr<ProxyBuffer> &to) {

    if((from->cur - from->start) > (to->size - to->cur)) {
        LOG(ERROR) << "the buffer size of the encrypted data is too small";
        return false;
    }

    int encrypt_size;
    if(!EVP_EncryptUpdate(ctx->get(), reinterpret_cast<unsigned char *>(to->buffer + to->cur),
        &encrypt_size, reinterpret_cast<const unsigned char *>(from->buffer + from->start),
        static_cast<int>(from->cur - from->start))) {
        LOG(ERROR) << "aes-128-cfb encrypts error";
        return false;
    }

    if(static_cast<size_t>(encrypt_size) != from->cur - from->start) {
        LOG(ERROR) << "aes-128-cfb encrypts data size error";
        return false;
    }

    to->cur += static_cast<size_t>(encrypt_size);

    return true;

}

bool ProxyCryptoAes::aes_cfb_decrypt(std::shared_ptr<ProxyCryptoAesContext> &ctx,
    std::shared_ptr<ProxyBuffer> &from, std::shared_ptr<ProxyBuffer> &to) {

    if((from->cur - from->start) > (to->size - to->cur)) {
        LOG(ERROR) << "the buffer size of the decrypted data is too small";
        return false;
    }

    int decrypt_size;
    if(!EVP_DecryptUpdate(ctx->get(), reinterpret_cast<unsigned char *>(to->buffer + to->cur),
        &decrypt_size, reinterpret_cast<const unsigned char *>(from->buffer + from->start),
        static_cast<int>(from->cur - from->start))) {
        LOG(ERROR) << "aes-128-cfb decrypts error";
        return false;
    }

    if(static_cast<size_t>(decrypt_size) != from->cur - from->start) {
        LOG(ERROR) << "aes-128-cfb decrypts data size error";
        return false;
    }

    to->cur += static_cast<size_t>(decrypt_size);

    return true;

}

}
}
