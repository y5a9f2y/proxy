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
        key.push_back(static_cast<char>(random() % 256));
    }

    for(size_t i = 0; i < ProxyCryptoAes::AES_IV_SIZE; ++i) {
        iv.push_back(static_cast<char>(random() % 256));
    }

    return std::make_shared<ProxyCryptoAesKeyAndIv>(std::move(key), std::move(iv));

}

bool ProxyCryptoAes::aes_ctr_encrypt(std::shared_ptr<ProxyBuffer> &from,
    std::shared_ptr<ProxyBuffer> &to, const std::shared_ptr<ProxyCryptoAesKeyAndIv> &ki) {

    std::shared_ptr<EVP_CIPHER_CTX> ctx(EVP_CIPHER_CTX_new(),
        [](EVP_CIPHER_CTX *c){EVP_CIPHER_CTX_free(c);});
    if(!ctx) {
        LOG(ERROR) << "create a encrypt cipher context error";
        return false;
    }

    if(!EVP_EncryptInit_ex(ctx.get(), EVP_aes_128_ctr(), NULL,
        reinterpret_cast<const unsigned char *>(ki->key().c_str()),
        reinterpret_cast<const unsigned char *>(ki->iv().c_str()))) {
        LOG(ERROR) << "setup the encrypt cipher context with cipher type error";
        return false;
    }

    if((from->cur - from->start) > (to->size - to->cur)) {
        LOG(ERROR) << "the buffer size of the encrypted data is too small";
        return false;
    }

    int encrypt_size;
    if(!EVP_EncryptUpdate(ctx.get(), reinterpret_cast<unsigned char *>(to->buffer + to->cur),
        &encrypt_size, reinterpret_cast<const unsigned char *>(from->buffer + from->start),
        static_cast<int>(from->cur - from->start))) {
        LOG(ERROR) << "aes-128-ctr encrypts error";
        return false;
    }
    to->cur += static_cast<size_t>(encrypt_size);
    if(!EVP_EncryptFinal_ex(ctx.get(), reinterpret_cast<unsigned char *>(to->buffer + to->cur),
        &encrypt_size)) {
        LOG(ERROR) << "aes-128-ctr excrypts final data error";
        return false;
    }
    to->cur += static_cast<size_t>(encrypt_size);

    return true;

}

bool ProxyCryptoAes::aes_ctr_decrypt(std::shared_ptr<ProxyBuffer> &from,
    std::shared_ptr<ProxyBuffer> &to, const std::shared_ptr<ProxyCryptoAesKeyAndIv> &ki) {

    std::shared_ptr<EVP_CIPHER_CTX> ctx(EVP_CIPHER_CTX_new(),
        [](EVP_CIPHER_CTX *c){EVP_CIPHER_CTX_free(c);});
    if(!ctx) {
        LOG(ERROR) << "create a decrypt cipher context error";
        return false;
    }

    if(!EVP_DecryptInit_ex(ctx.get(), EVP_aes_128_ctr(), NULL,
        reinterpret_cast<const unsigned char *>(ki->key().c_str()),
        reinterpret_cast<const unsigned char *>(ki->iv().c_str()))) {
        LOG(ERROR) << "setup the decrypt cipher context with cipher type error";
        return false;
    }

    if((from->cur - from->start) > (to->size - to->cur)) {
        LOG(ERROR) << "the buffer size of the decrypted data is too small";
        return false;
    }

    int decrypt_size;
    if(!EVP_DecryptUpdate(ctx.get(), reinterpret_cast<unsigned char *>(to->buffer + to->cur),
        &decrypt_size, reinterpret_cast<const unsigned char *>(from->buffer + from->start),
        static_cast<int>(from->cur - from->start))) {
        LOG(ERROR) << "aes-128-ctr decrypts error";
        return false;
    }
    to->cur += decrypt_size;
    if(!EVP_DecryptFinal_ex(ctx.get(), reinterpret_cast<unsigned char *>(to->buffer + to->cur),
        &decrypt_size)) {
        LOG(ERROR) << "aes-128-ctr decrypts the final data error";
        return false;
    }

    return true;

}

}
}
