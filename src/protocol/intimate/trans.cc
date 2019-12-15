#include <exception>

#include "core/server.h"
#include "protocol/intimate/trans.h"

#include "core/buffer.h"
#include "glog/logging.h"

using proxy::core::ProxyStmEvent;
using proxy::core::ProxyTunnel;
using proxy::core::ProxyBuffer;

namespace proxy {
namespace protocol {
namespace intimate {

const size_t ProxyProtoTransmit::_TRANSMIT_BUFFER_SIZE = 131072;

void *ProxyProtoTransmit::on_enc_mode_transmit_ep0_ep1(void *args) {

    ProxyProtoTransmitArgs *p = reinterpret_cast<ProxyProtoTransmitArgs *>(args);
    std::shared_ptr<ProxyTunnel> tunnel = p->tunnel;

    try {
        ProxyProtoTransmit::_on_enc_mode_transmit(tunnel, true);
    } catch (const std::exception &ex) {
        LOG(ERROR) << "unexpected exception: " << ex.what();
    }
    return nullptr;

}

void *ProxyProtoTransmit::on_enc_mode_transmit_ep1_ep0(void *args) {

    ProxyProtoTransmitArgs *p = reinterpret_cast<ProxyProtoTransmitArgs *>(args);
    std::shared_ptr<ProxyTunnel> tunnel = p->tunnel;
    try {
        ProxyProtoTransmit::_on_enc_mode_transmit(tunnel, false);
    } catch (const std::exception &ex) {
        LOG(ERROR) << "unexpected exception: " << ex.what();
    }
    return nullptr;

}

void *ProxyProtoTransmit::on_dec_mode_transmit_ep0_ep1(void *args) {

    ProxyProtoTransmitArgs *p = reinterpret_cast<ProxyProtoTransmitArgs *>(args);
    std::shared_ptr<ProxyTunnel> tunnel = p->tunnel;
    try {
        ProxyProtoTransmit::_on_dec_mode_transmit(tunnel, true);
    } catch (const std::exception &ex) {
        LOG(ERROR) << "unexpected exception: " << ex.what();
    }

    return nullptr;

}

void *ProxyProtoTransmit::on_dec_mode_transmit_ep1_ep0(void *args) {

    ProxyProtoTransmitArgs *p = reinterpret_cast<ProxyProtoTransmitArgs *>(args);
    std::shared_ptr<ProxyTunnel> tunnel = p->tunnel;
    try {
        ProxyProtoTransmit::_on_dec_mode_transmit(tunnel, false);
    } catch (const std::exception &ex) {
        LOG(ERROR) << "unexpected exception: " << ex.what();
    }
    return nullptr;

}

void *ProxyProtoTransmit::on_trans_mode_transmit_ep0_ep1(void *args) {

    ProxyProtoTransmitArgs *p = reinterpret_cast<ProxyProtoTransmitArgs *>(args);
    std::shared_ptr<ProxyTunnel> tunnel = p->tunnel;
    try {
        ProxyProtoTransmit::_on_trans_mode_transmit(tunnel, true);
    } catch (const std::exception &ex) {
        LOG(ERROR) << "unexpected exception: " << ex.what();
    }
    return nullptr;

}

void *ProxyProtoTransmit::on_trans_mode_transmit_ep1_ep0(void *args) {

    ProxyProtoTransmitArgs *p = reinterpret_cast<ProxyProtoTransmitArgs *>(args);
    std::shared_ptr<ProxyTunnel> tunnel = p->tunnel;
    try {
      ProxyProtoTransmit::_on_trans_mode_transmit(tunnel, false);
    } catch (const std::exception &ex) {
        LOG(ERROR) << "unexpected exception: " << ex.what();
    }
    return nullptr;

}

ProxyStmEvent ProxyProtoTransmit::_on_enc_mode_transmit(std::shared_ptr<ProxyTunnel> &tunnel,
    bool flag) {

    /*
     * flag:
     *   true: transmit from ep0 to ep1 with encryption
     *   false: transmit from ep1 to ep0 with decryption
     *
     */

    std::shared_ptr<ProxyBuffer> buf0;
    std::shared_ptr<ProxyBuffer> buf1;

    try {
        buf0 = std::make_shared<ProxyBuffer>(_TRANSMIT_BUFFER_SIZE);
        buf1 = std::make_shared<ProxyBuffer>(_TRANSMIT_BUFFER_SIZE);
    } catch (const std::exception &ex) {
        LOG(ERROR) << tunnel->ep0_ep1_string() << ": create the buffer for transmission error: "
            << ex.what();
        return ProxyStmEvent::PROXY_STM_EVENT_TRANSMISSION_FAIL;
    }

    while(1) {

        buf0->clear();
        buf1->clear();

        if(flag) {

            ssize_t nread = tunnel->ep0()->read(buf0);
            if(nread < 0) {
                return ProxyStmEvent::PROXY_STM_EVENT_TRANSMISSION_FAIL;
            } else if(nread == 0) {
                return ProxyStmEvent::PROXY_STM_EVENT_TRANSMISSION_OK;
            }

            proxy::crypto::ProxyCryptoAes::aes_cfb_encrypt(tunnel->aes_ctx(), buf0, buf1);

            ssize_t nwrite = tunnel->ep1()->write_eq(buf1->cur - buf1->start, buf1);
            if(nwrite < 0) {
                return ProxyStmEvent::PROXY_STM_EVENT_TRANSMISSION_FAIL;
            }

            tunnel->server()->add_ep0_ep1_data_amount(static_cast<int64_t>(nwrite));

        } else {

            ssize_t nread = tunnel->ep1()->read(buf0);
            if(nread < 0) {
                return ProxyStmEvent::PROXY_STM_EVENT_TRANSMISSION_FAIL;
            } else if(nread == 0) {
                return ProxyStmEvent::PROXY_STM_EVENT_TRANSMISSION_OK;
            }

            proxy::crypto::ProxyCryptoAes::aes_cfb_decrypt(tunnel->aes_ctx_peer(), buf0, buf1);

            ssize_t nwrite = tunnel->ep0()->write_eq(buf1->cur - buf1->start, buf1);
            if(nwrite < 0) {
                return ProxyStmEvent::PROXY_STM_EVENT_TRANSMISSION_FAIL;
            }

            tunnel->server()->add_ep1_ep0_data_amount(static_cast<int64_t>(nwrite));

        }
    
    }

    return ProxyStmEvent::PROXY_STM_EVENT_TRANSMISSION_FAIL;

}

ProxyStmEvent ProxyProtoTransmit::_on_dec_mode_transmit(std::shared_ptr<ProxyTunnel> &tunnel,
    bool flag) {

    std::shared_ptr<ProxyBuffer> buf0;
    std::shared_ptr<ProxyBuffer> buf1;

    try {
        buf0 = std::make_shared<ProxyBuffer>(_TRANSMIT_BUFFER_SIZE);
        buf1 = std::make_shared<ProxyBuffer>(_TRANSMIT_BUFFER_SIZE);
    } catch (const std::exception &ex) {
        LOG(ERROR) << tunnel->ep0_ep1_string() << ": create the buffer for transmission error: "
            << ex.what();
        return ProxyStmEvent::PROXY_STM_EVENT_TRANSMISSION_FAIL;
    }

    while(1) {

        buf0->clear();
        buf1->clear();

        if(flag) {

            ssize_t nread = tunnel->ep0()->read(buf0);
            if(nread < 0) {
                return ProxyStmEvent::PROXY_STM_EVENT_TRANSMISSION_FAIL;
            } else if(nread == 0) {
                return ProxyStmEvent::PROXY_STM_EVENT_TRANSMISSION_OK;
            }

            proxy::crypto::ProxyCryptoAes::aes_cfb_decrypt(tunnel->aes_ctx_peer(), buf0, buf1);

            ssize_t nwrite = tunnel->ep1()->write_eq(buf1->cur - buf1->start, buf1);
            if(nwrite < 0) {
                return ProxyStmEvent::PROXY_STM_EVENT_TRANSMISSION_FAIL;
            }

            tunnel->server()->add_ep0_ep1_data_amount(static_cast<int64_t>(nwrite));

        } else {

            ssize_t nread = tunnel->ep1()->read(buf0);
            if(nread < 0) {
                return ProxyStmEvent::PROXY_STM_EVENT_TRANSMISSION_FAIL;
            } else if(nread == 0) {
                return ProxyStmEvent::PROXY_STM_EVENT_TRANSMISSION_OK;
            }

            proxy::crypto::ProxyCryptoAes::aes_cfb_encrypt(tunnel->aes_ctx(), buf0, buf1);

            ssize_t nwrite = tunnel->ep0()->write_eq(buf1->cur - buf1->start, buf1);
            if(nwrite < 0) {
                return ProxyStmEvent::PROXY_STM_EVENT_TRANSMISSION_FAIL;
            }

            tunnel->server()->add_ep1_ep0_data_amount(static_cast<int64_t>(nwrite));

        }
    
    }

    return ProxyStmEvent::PROXY_STM_EVENT_TRANSMISSION_FAIL;

}

ProxyStmEvent ProxyProtoTransmit::_on_trans_mode_transmit(std::shared_ptr<ProxyTunnel> &tunnel,
    bool flag) {

    std::shared_ptr<ProxyBuffer> buf;

    try {
        buf = std::make_shared<ProxyBuffer>(_TRANSMIT_BUFFER_SIZE);
    } catch (const std::exception &ex) {
        LOG(ERROR) << tunnel->ep0_ep1_string()
            << ": create the buffer for ordinary transmission error: " << ex.what();
        return ProxyStmEvent::PROXY_STM_EVENT_TRANSMISSION_FAIL;
    }

    while(1) {

        buf->clear();

        if(flag) {

            ssize_t nread = tunnel->ep0()->read(buf);
            if(nread < 0) {
                return ProxyStmEvent::PROXY_STM_EVENT_TRANSMISSION_FAIL;
            } else if(nread == 0) {
                return ProxyStmEvent::PROXY_STM_EVENT_TRANSMISSION_OK;
            }

            ssize_t nwrite = tunnel->ep1()->write_eq(buf->cur - buf->start, buf);
            if(nwrite < 0) {
                return ProxyStmEvent::PROXY_STM_EVENT_TRANSMISSION_FAIL;
            }

            tunnel->server()->add_ep0_ep1_data_amount(static_cast<int64_t>(nwrite));

        } else {

            ssize_t nread = tunnel->ep1()->read(buf);
            if(nread < 0) {
                return ProxyStmEvent::PROXY_STM_EVENT_TRANSMISSION_FAIL;
            } else if(nread == 0) {
                return ProxyStmEvent::PROXY_STM_EVENT_TRANSMISSION_OK;
            }

            ssize_t nwrite = tunnel->ep0()->write_eq(buf->cur - buf->start, buf);
            if(nwrite < 0) {
                return ProxyStmEvent::PROXY_STM_EVENT_TRANSMISSION_FAIL;
            }

            tunnel->server()->add_ep1_ep0_data_amount(static_cast<int64_t>(nwrite));

        }
    
    }

    return ProxyStmEvent::PROXY_STM_EVENT_TRANSMISSION_FAIL;

}

}
}
}
