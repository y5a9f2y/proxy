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
        case ProxyProtoAckDirect::PROXY_PROTO_ACK_EP0:
            nwrite = tunnel->write_ep0_eq(1, buf);
            break;
        case ProxyProtoAckDirect::PROXY_PROTO_ACK_EP1:
            nwrite = tunnel->write_ep1_eq(1, buf);
            break;
        default:
            LOG(ERROR) << "unknown ack direction of " << tunnel->ep0_ep1_string();
            return false;
    }

    if(nwrite != 1) {
        LOG(ERROR) << tunnel->ep0_ep1_string() << ": send the ack byte error: " << strerror(errno);
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
        case ProxyProtoAckDirect::PROXY_PROTO_ACK_EP0:
            nread = tunnel->read_ep0_eq(1, buf);
            break;
        case ProxyProtoAckDirect::PROXY_PROTO_ACK_EP1:
            nread = tunnel->read_ep1_eq(1, buf);
            break;
        default:
            LOG(ERROR) << "unknown ack direction of " << tunnel->ep0_ep1_string();
            return false;
    }

    if(nread != 1) {
        LOG(ERROR) << tunnel->ep0_ep1_string()
            << ": receive the ack byte error: " << strerror(errno);
        return false;
    }

    if(buf->buffer[0] != 0xf) {
        LOG(ERROR) << tunnel->ep0_ep1_string()
            << ": receive the ack byte error: unexpected " << buf->buffer[0];
        return false;
    }
    
    return true;

}

}
}
}
