#include "string.h"
#include "crypto/rsa.h"

#include "glog/logging.h"

using proxy::core::ProxyBuffer;

namespace proxy {
namespace crypto {

const int ProxyCryptoRsa::RSA_KEY_SIZE = 1024;

std::shared_ptr<ProxyCryptoRsaKeypair> ProxyCryptoRsa::generate_key_pair() {

    std::shared_ptr<RSA> keypair(RSA_generate_key(ProxyCryptoRsa::RSA_KEY_SIZE, RSA_F4,
        NULL, NULL), [](RSA *rsa){RSA_free(rsa);});
    if(!keypair) {
        LOG(ERROR) << "generate a 2-prime RSA key pair error";
        return nullptr;
    }

    std::shared_ptr<BIO> pri(BIO_new(BIO_s_mem()), [](BIO *bio){BIO_free_all(bio);});
    if(!pri) {
        LOG(ERROR) << "create the bio for private key error";
        return nullptr;
    }

    std::shared_ptr<BIO> pub(BIO_new(BIO_s_mem()), [](BIO *bio){BIO_free_all(bio);});
    if(!pub) {
        LOG(ERROR) << "create the bio for public key error";
        return nullptr;
    }

    if(!PEM_write_bio_RSAPrivateKey(pri.get(), keypair.get(), NULL, NULL, 0, NULL, NULL)) {
        LOG(ERROR) << "write the rsa private key in pem format to bio error";
        return nullptr;
    }

    if(!PEM_write_bio_RSAPublicKey(pub.get(), keypair.get())) {
        LOG(ERROR) << "write the rsa public key in pem format to bio error";
        return nullptr;
    }

    int private_key_len = BIO_pending(pri.get());
    int public_key_len = BIO_pending(pub.get());
    std::shared_ptr<char> private_key(new char[private_key_len + 1], [](char *p){delete []p;});
    std::shared_ptr<char> public_key(new char[public_key_len + 1], [](char *p){delete []p;});

    if(private_key_len != BIO_read(pri.get(), reinterpret_cast<void *>(private_key.get()),
        private_key_len)) {
        LOG(ERROR) << "read the private key from bio error";
        return nullptr;
    }

    if(public_key_len != BIO_read(pub.get(), reinterpret_cast<void *>(public_key.get()),
        public_key_len)) {
        LOG(ERROR) << "read the public key from bio error";
        return nullptr;
    }

    private_key.get()[private_key_len] = '\0';
    public_key.get()[public_key_len] = '\0';

    std::string pubk = public_key.get();
    std::string prik = private_key.get();

    return std::make_shared<ProxyCryptoRsaKeypair>(std::string(public_key.get()),
        std::string(private_key.get()));

}

bool ProxyCryptoRsa::rsa_encrypt(std::shared_ptr<ProxyBuffer> &from,
    std::shared_ptr<ProxyBuffer> &to, const std::string &key) {

    std::shared_ptr<BIO> bio(BIO_new_mem_buf(reinterpret_cast<const void *>(key.c_str()), -1),
        [](BIO *b) {BIO_free_all(b);});
    if(!bio) {
        LOG(ERROR) << "create the memory bio using the public key buffer error";
        return false;
    }

    RSA *tmp = NULL;
    if(!PEM_read_bio_RSAPublicKey(bio.get(), &tmp, NULL, NULL)) {
        LOG(ERROR) << "read the public key in pem format from bio to rsa structure error";
        return false;
    }
    std::shared_ptr<RSA> rsa(tmp, [](RSA *r){RSA_free(r);});

    int rsa_size = RSA_size(rsa.get());
    if(static_cast<size_t>(rsa_size) >= to->size - to->cur) {
        LOG(ERROR) << "the buffer size of the encrypted data is too small";
        return false;
    }
    memset(to->buffer + to->cur, 0, static_cast<size_t>(rsa_size));

    int encrypted_result_length = RSA_public_encrypt(static_cast<int>(from->cur - from->start),
        reinterpret_cast<const unsigned char *>(from->buffer + from->start),
        reinterpret_cast<unsigned char *>(to->buffer + to->cur), rsa.get(), RSA_PKCS1_PADDING);
    if(encrypted_result_length < 0) {
        LOG(ERROR) << "the encrypt operation error";
        return false;
    }

    to->cur += static_cast<size_t>(encrypted_result_length);

    return true;

}

bool ProxyCryptoRsa::rsa_decrypt(std::shared_ptr<ProxyBuffer> &from,
    std::shared_ptr<ProxyBuffer> &to, const std::string &key) {

    std::shared_ptr<BIO> bio(BIO_new_mem_buf(reinterpret_cast<const void *>(key.c_str()), -1),
        [](BIO *b){BIO_free_all(b);});
    if(!bio) {
        LOG(ERROR) << "create the memory bio using the private key buffer error";
        return false;
    }

    RSA *tmp = NULL;
    if(!PEM_read_bio_RSAPrivateKey(bio.get(), &tmp, NULL, NULL)) {
        LOG(ERROR) << "read the private key in pem format from bio to rsa structure error";
        return false;
    }
    std::shared_ptr<RSA> rsa(tmp, [](RSA *r){RSA_free(r);});

    int rsa_size = RSA_size(rsa.get());
    if(static_cast<size_t>(rsa_size) >= to->size - to->cur) {
        LOG(ERROR) << "the buffer size of the decrypted data is too small";
        return false;
    }
    memset(to->buffer + to->cur, 0, static_cast<size_t>(rsa_size));

    int decrypted_result_length = RSA_private_decrypt(static_cast<int>(from->cur - from->start),
        reinterpret_cast<const unsigned char *>(from->buffer + from->start),
        reinterpret_cast<unsigned char *>(to->buffer + to->cur), rsa.get(), RSA_PKCS1_PADDING);
    if(decrypted_result_length < 0) {
        LOG(ERROR) << "the decrypt operation error";
        return false;
    }

    to->cur += static_cast<size_t>(decrypted_result_length);

    return true;

}

}
}
