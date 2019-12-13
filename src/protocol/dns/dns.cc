#include <exception>

#include <netinet/in.h>
#include <stdlib.h>
#include <sstream>

#include "core/buffer.h"
#include "core/socket.h"
#include "protocol/dns/dns.h"

#include "glog/logging.h"

using proxy::core::ProxyBuffer;
using proxy::core::ProxySocket;
using proxy::core::ProxyUdpSocket;

namespace proxy {
namespace protocol {
namespace dns {

bool ProxyProtoDnsUnblockResolver::_setup() {

    try {
        _rs = std::shared_ptr<res_state_t>(new(res_state_t), [](res_state_t *p){delete p;});
    } catch (const std::exception &ex) {
        LOG(ERROR) << "create the res_state error: " << ex.what();
        return false;
    }

    if(res_ninit(_rs.get())) {
        LOG(ERROR) << "init the res_state error";
        return false;
    }

    return true;

}

bool ProxyProtoDnsUnblockResolver::resolv(const std::string &domain, std::string &address) {

    if(!_rs) {
        if(!_setup()) {
            LOG(ERROR) << "setup the unblock resolver error";
            return false;
        }
    }

    if(!_rs->nscount) {
        LOG(ERROR) << "no nameserver is found";
        return false;
    }

    /*
     * HFIXEDSZ: bytes of fixed data in header
     * QFIXEDSZ: bytes of fixed data in query
     * MAXCDNAME: maximum compressed domain name
     */
    size_t req_size = HFIXEDSZ + QFIXEDSZ + MAXCDNAME + 1;
    size_t resp_size = 65536;
    std::shared_ptr<ProxyBuffer> req_buf;
    std::shared_ptr<ProxyBuffer> resp_buf;

    try {
        req_buf = std::make_shared<ProxyBuffer>(req_size);
        resp_buf = std::make_shared<ProxyBuffer>(resp_size);
    } catch (const std::exception &ex) {
        LOG(ERROR) << "create the buffer for the resolv request/response error: " << ex.what();
        return false;
    }

    /*
     * C_IN: Internet
     * T_A: IPv4
     */
    int n = res_nmkquery(_rs.get(), QUERY, domain.c_str(), C_IN, T_A, NULL, 0, NULL,
        reinterpret_cast<unsigned char *>(req_buf->buffer), static_cast<int>(req_size));
    if(n < 0) {
        LOG(ERROR) << "construct the resolv request error";
        return false;
    }
    req_buf->cur += static_cast<size_t>(n);

    {
        std::shared_ptr<ProxySocket> fd;
        try {
            fd = std::make_shared<ProxyUdpSocket>(AF_INET, 0);
        } catch(const std::exception &ex) {
            LOG(ERROR) << "create the udp socket for the resolv request/response error: "
                << ex.what();
            return false;
        }

        ssize_t nsend;
        ssize_t nrecv;

        HEADER *req_header;
        HEADER *resp_header;
        ns_msg msg;
        ns_rr rr;
        uint16_t msg_count;
        std::string peer;

        uint16_t rr_ty;

        for(int i = 0; i < _rs->nscount; ++i) {

            req_buf->start = 0;
            resp_buf->clear();

            std::ostringstream oss;
            oss << inet_ntoa(_rs->nsaddr_list[i].sin_addr) << ":"
                << ntohs(_rs->nsaddr_list[i].sin_port);

            peer = oss.str();

            if((nsend = fd->sendto(req_buf, 0,
                reinterpret_cast<const struct sockaddr *>(&_rs->nsaddr_list[i]),
                sizeof(_rs->nsaddr_list[i]))) < 0) {
                LOG(ERROR) << "send the resolv request of " << domain << " to " << peer << " error";
                continue;
            }

            if(req_buf->start != req_buf->cur) {
                LOG(ERROR) << "partly send the resolv request of " << domain << " to " << peer;
                continue;
            }

            if((nrecv = fd->recvfrom(resp_buf, 0, NULL, NULL)) < 0) {
                LOG(ERROR) << "receive the resolv response of " << domain
                    << " from " << peer << " error";
                continue;
            }

            // validate the response
            req_header = reinterpret_cast<HEADER *>(req_buf->buffer);
            resp_header = reinterpret_cast<HEADER *>(resp_buf->buffer);

            if(req_header->id != resp_header->id) {
                LOG(ERROR) << "the id of the request of " << domain
                    << " is not the same as the response from " << peer << ", continue";
                continue;
            }

            switch(resp_header->rcode) {
                case NOERROR:
                    break;
                default:
                    LOG(ERROR) << "the request of " << domain <<  " to " << peer
                        << " response with code " << resp_header->rcode <<", continue";
                    continue;
                    break;
            }

            if(resp_header->ancount == 0 && resp_header->aa == 0
                && resp_header->ra == 0 && resp_header->arcount == 0) {
                LOG(ERROR) << "the request of " << domain <<  " to " << peer
                    << " response with no data, continue";
                continue;
            }

            if(res_queriesmatch(
                reinterpret_cast<const u_char *>(req_buf->buffer),
                reinterpret_cast<const u_char *>(req_buf->buffer + req_buf->cur),
                reinterpret_cast<const u_char *>(resp_buf->buffer),
                reinterpret_cast<const u_char *>(resp_buf->buffer + resp_buf->cur)) <= 0) {
                LOG(ERROR) << "the response of " << domain <<  " from " << peer
                    << " validate fail(not 1:1 mapping)";
                continue;
            }

            // begin to parse the response
            if(ns_initparse(reinterpret_cast<const u_char *>(resp_buf->buffer),
                static_cast<int>(resp_buf->cur), &msg) < 0) {
                LOG(ERROR) << "init the ns_msg struct of the response of resolving " << domain
                    << " from " << peer << " error";
                continue;
            }

            // ns_s_an: Query:Answer, section
            msg_count = ns_msg_count(msg, ns_s_an);
            if(msg_count == 0) {
                LOG(ERROR) << "the response of " << domain <<  " from " << peer
                    << " has no message";
                continue;
            }

            struct in_addr u32addr;
            const unsigned char *u32addrp;

            for(uint16_t j = 0; j < msg_count; ++j) {

                if(ns_parserr(&msg, ns_s_an, j, &rr) < 0) {
                    LOG(ERROR) << "the response of " << domain << " from " << peer
                        << " parse rr fail: section " << j << " error";
                    continue;
                }
                rr_ty = ns_rr_type(rr);
                // ns_t_a: A type
                if(rr_ty != ns_t_a) {
                    continue;
                }

                if(ns_rr_rdlen(rr) < 4) {
                    LOG(ERROR) << "the response of " << domain << " from " << peer
                        << " is only " << ns_rr_rdlen(rr) << " byte(s)";
                    continue;
                }

                u32addr.s_addr = 0;
                u32addrp = ns_rr_rdata(rr);
                for(int k = 3; k >= 0; --k) {
                    u32addr.s_addr *= 256;
                    u32addr.s_addr += static_cast<uint8_t>(*(u32addrp + k));
                }
                address = inet_ntoa(u32addr);
                return true;

            }

        }
    }

    return false;

}

ProxyProtoDnsUnblockResolver::~ProxyProtoDnsUnblockResolver() {
    res_nclose(_rs.get());
}

}
}
}
