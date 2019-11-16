#include <exception>

#include "protocol/intimate/trans.h"

#include "core/buffer.h"
#include "glog/logging.h"

using proxy::core::ProxyStmEvent;
using proxy::core::ProxyTunnel;
using proxy::core::ProxyBuffer;

namespace proxy {
namespace protocol {
namespace intimate {

void *ProxyProtoTransmit::on_encryption_transmit(void *args) {

    std::shared_ptr<ProxyTunnel> tunnel = *reinterpret_cast<std::shared_ptr<ProxyTunnel> *>(args);
    ProxyProtoTransmit::_on_encryption_transmit(tunnel, true);
    return nullptr;

}

void *ProxyProtoTransmit::on_encryption_transmit_reverse(void *args) {

    std::shared_ptr<ProxyTunnel> tunnel = *reinterpret_cast<std::shared_ptr<ProxyTunnel> *>(args);
    ProxyProtoTransmit::_on_encryption_transmit(tunnel, false);
    return nullptr;

}

void *ProxyProtoTransmit::on_decryption_transmit(void *args) {

    std::shared_ptr<ProxyTunnel> tunnel = *reinterpret_cast<std::shared_ptr<ProxyTunnel> *>(args);
    ProxyProtoTransmit::_on_decryption_transmit(tunnel, true);
    return nullptr;

}

void *ProxyProtoTransmit::on_decryption_transmit_reverse(void *args) {

    std::shared_ptr<ProxyTunnel> tunnel = *reinterpret_cast<std::shared_ptr<ProxyTunnel> *>(args);
    ProxyProtoTransmit::_on_decryption_transmit(tunnel, false);
    return nullptr;

}

void *ProxyProtoTransmit::on_transmit(void *args) {

    std::shared_ptr<ProxyTunnel> tunnel = *reinterpret_cast<std::shared_ptr<ProxyTunnel> *>(args);
    ProxyProtoTransmit::_on_transmit(tunnel, true);
    return nullptr;

}

void *ProxyProtoTransmit::on_transmit_reverse(void *args) {

    std::shared_ptr<ProxyTunnel> tunnel = *reinterpret_cast<std::shared_ptr<ProxyTunnel> *>(args);
    ProxyProtoTransmit::_on_transmit(tunnel, false);
    return nullptr;

}

ProxyStmEvent ProxyProtoTransmit::_on_encryption_transmit(std::shared_ptr<ProxyTunnel> &tunnel,
    bool flag) {

    std::shared_ptr<ProxyBuffer> buf0;
    std::shared_ptr<ProxyBuffer> buf1;

    try {
        buf0 = std::make_shared<ProxyBuffer>(4096);
        buf1 = std::make_shared<ProxyBuffer>(4096);
    } catch (const std::exception &ex) {
        LOG(ERROR) << "create the buffer for encryption transmission error: " << ex.what();
        return ProxyStmEvent::PROXY_STM_EVENT_TRANSMISSION_FAIL;
    }

    while(1) {

        buf0->clear();
        buf1->clear();

        if(flag) {

            ssize_t nread = tunnel->from()->read(buf0);
            if(nread < 0) {
                return ProxyStmEvent::PROXY_STM_EVENT_TRANSMISSION_FAIL;
            }

            proxy::crypto::ProxyCryptoAes::aes_cfb_encrypt(tunnel->aes_ctx(), buf0, buf1);

            ssize_t nwrite = tunnel->to()->write_eq(buf1->cur - buf1->start, buf1);
            if(nwrite < 0) {
                return ProxyStmEvent::PROXY_STM_EVENT_TRANSMISSION_FAIL;
            }

        } else {

            ssize_t nread = tunnel->to()->read(buf0);
            if(nread < 0) {
                return ProxyStmEvent::PROXY_STM_EVENT_TRANSMISSION_FAIL;
            }

            proxy::crypto::ProxyCryptoAes::aes_cfb_decrypt(tunnel->aes_ctx(), buf0, buf1);

            ssize_t nwrite = tunnel->from()->write_eq(buf1->cur - buf1->start, buf1);
            if(nwrite < 0) {
                return ProxyStmEvent::PROXY_STM_EVENT_TRANSMISSION_FAIL;
            }

        }
    
    }

    return ProxyStmEvent::PROXY_STM_EVENT_TRANSMISSION_FAIL;

}

ProxyStmEvent ProxyProtoTransmit::_on_decryption_transmit(std::shared_ptr<ProxyTunnel> &tunnel,
    bool flag) {

    std::shared_ptr<ProxyBuffer> buf0;
    std::shared_ptr<ProxyBuffer> buf1;

    try {
        buf0 = std::make_shared<ProxyBuffer>(4096);
        buf1 = std::make_shared<ProxyBuffer>(4096);
    } catch (const std::exception &ex) {
        LOG(ERROR) << "create the buffer for decryption transmission error: " << ex.what();
        return ProxyStmEvent::PROXY_STM_EVENT_TRANSMISSION_FAIL;
    }

    while(1) {

        buf0->clear();
        buf1->clear();

        if(flag) {

            ssize_t nread = tunnel->to()->read(buf0);
            if(nread < 0) {
                return ProxyStmEvent::PROXY_STM_EVENT_TRANSMISSION_FAIL;
            }

            proxy::crypto::ProxyCryptoAes::aes_cfb_encrypt(tunnel->aes_ctx(), buf0, buf1);

            ssize_t nwrite = tunnel->from()->write_eq(buf1->cur - buf1->start, buf1);
            if(nwrite < 0) {
                return ProxyStmEvent::PROXY_STM_EVENT_TRANSMISSION_FAIL;
            }

        } else {

            ssize_t nread = tunnel->from()->read(buf0);
            if(nread < 0) {
                return ProxyStmEvent::PROXY_STM_EVENT_TRANSMISSION_FAIL;
            }

            proxy::crypto::ProxyCryptoAes::aes_cfb_decrypt(tunnel->aes_ctx(), buf0, buf1);

            ssize_t nwrite = tunnel->to()->write_eq(buf1->cur - buf1->start, buf1);
            if(nwrite < 0) {
                return ProxyStmEvent::PROXY_STM_EVENT_TRANSMISSION_FAIL;
            }

        }
    
    }

    return ProxyStmEvent::PROXY_STM_EVENT_TRANSMISSION_FAIL;

}

ProxyStmEvent ProxyProtoTransmit::_on_transmit(std::shared_ptr<ProxyTunnel> &tunnel, bool flag) {

    std::shared_ptr<ProxyBuffer> buf0;

    try {
        buf0 = std::make_shared<ProxyBuffer>(4096);
    } catch (const std::exception &ex) {
        LOG(ERROR) << "create the buffer for ordinary transmission error: " << ex.what();
        return ProxyStmEvent::PROXY_STM_EVENT_TRANSMISSION_FAIL;
    }

    while(1) {

        buf0->clear();

        if(flag) {

            ssize_t nread = tunnel->from()->read(buf0);
            if(nread < 0) {
                return ProxyStmEvent::PROXY_STM_EVENT_TRANSMISSION_FAIL;
            }
            ssize_t nwrite = tunnel->to()->write_eq(buf0->cur - buf0->start, buf0);
            if(nwrite < 0) {
                return ProxyStmEvent::PROXY_STM_EVENT_TRANSMISSION_FAIL;
            }

        } else {

            ssize_t nread = tunnel->to()->read(buf0);
            if(nread < 0) {
                return ProxyStmEvent::PROXY_STM_EVENT_TRANSMISSION_FAIL;
            }

            ssize_t nwrite = tunnel->from()->write_eq(buf0->cur - buf0->start, buf0);
            if(nwrite < 0) {
                return ProxyStmEvent::PROXY_STM_EVENT_TRANSMISSION_FAIL;
            }

        }
    
    }

    return ProxyStmEvent::PROXY_STM_EVENT_TRANSMISSION_FAIL;

}

}
}
}
