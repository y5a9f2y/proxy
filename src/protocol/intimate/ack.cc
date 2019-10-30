#include <exception>

#include <errno.h>
#include <string.h>

#include "protocol/intimate/ack.h"
#include "core/buffer.h"

#include "glog/logging.h"

using proxy::core::ProxyTunnel;
using proxy::core::ProxyBuffer;

namespace proxy {
namespace protocol {
namespace intimate {

bool ProxyProtoAck::on_ack_send(std::shared_ptr<ProxyTunnel> &tunnel, ProxyProtoAckDirect d) {

    /*                                                                                                 
	** send 1 ack byte
    **   +------+                                                                               
    **   | flag |                                                                               
    **   +-------                                                                               
    **   | 0xf  |                                                                               
    **   +------+                                                                               
    */

    std::shared_ptr<ProxyBuffer> buf = std::make_shared<ProxyBuffer>(1);
    buf->buffer[0] = 0xf;
    buf->cur = 1;

    ssize_t nwrite;
    switch(d) {
        case ProxyProtoAckDirect::PROXY_PROTO_ACK_FROM:
            nwrite = tunnel->write_from_eq(1, buf);
            break;
        case ProxyProtoAckDirect::PROXY_PROTO_ACK_TO:
            nwrite = tunnel->write_to_eq(1, buf);
            break;
        default:
            LOG(ERROR) << "unknown ack direction of " << tunnel->from()->to_string();
            return false;
    }

    if(nwrite != 1) {
        if(d == ProxyProtoAckDirect::PROXY_PROTO_ACK_FROM) {
            LOG(ERROR) << "send the ack byte to " << tunnel->from()->to_string() << " error: "
                << strerror(errno);
        } else if(d == ProxyProtoAckDirect::PROXY_PROTO_ACK_TO) {
            LOG(ERROR) << "send the ack byte to " << tunnel->to()->to_string() << " error: "
                << strerror(errno);
        }
        return false;
    }

    return true;

}

bool ProxyProtoAck::on_ack_receive(std::shared_ptr<ProxyTunnel> &tunnel, ProxyProtoAckDirect d) {

    /*                                                                                                 
	** receive 1 ack byte
    **   +------+                                                                               
    **   | flag |                                                                               
    **   +-------                                                                               
    **   | 0xf  |                                                                               
    **   +------+                                                                               
    */

    std::shared_ptr<ProxyBuffer> buf = std::make_shared<ProxyBuffer>(1);

    ssize_t nread;
    switch(d) {
        case ProxyProtoAckDirect::PROXY_PROTO_ACK_FROM:
            nread = tunnel->read_from_eq(1, buf);
            break;
        case ProxyProtoAckDirect::PROXY_PROTO_ACK_TO:
            nread = tunnel->read_to_eq(1, buf);
            break;
        default:
            LOG(ERROR) << "unknown ack direction of " << tunnel->from()->to_string();
            return false;
    }

    if(nread != 1) {
        if(d == ProxyProtoAckDirect::PROXY_PROTO_ACK_FROM) {
            LOG(ERROR) << "receive the ack byte from " << tunnel->from()->to_string() << " error: "
                << strerror(errno);
        } else if(d == ProxyProtoAckDirect::PROXY_PROTO_ACK_TO) {
            LOG(ERROR) << "receive the ack byte from " << tunnel->to()->to_string() << " error: "
                << strerror(errno);
        }
        return false;
    }

    if(buf->buffer[0] != 0xf) {
        if(d == ProxyProtoAckDirect::PROXY_PROTO_ACK_FROM) {
            LOG(ERROR) << "receive the ack byte from " << tunnel->from()->to_string()
				<< " error: " << buf->buffer[0];
        } else if(d == ProxyProtoAckDirect::PROXY_PROTO_ACK_TO) {
            LOG(ERROR) << "receive the ack byte from " << tunnel->to()->to_string()
                << " error: " << buf->buffer[0];
        }
        return false;
    }
    
    return true;

}

}
}
}
