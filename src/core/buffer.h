#ifndef PROXY_CORE_BUFFER_H_H_H
#define PROXY_CORE_BUFFER_H_H_H

#include <sys/types.h>

namespace proxy {
namespace core {

const size_t PROXY_BUFFER_DEFAULT_SIZE = 4096;

class ProxyBuffer {

public:

    ProxyBuffer(): ProxyBuffer(PROXY_BUFFER_DEFAULT_SIZE) {}
    ProxyBuffer(size_t sz) : start(0), cur(0), size(sz), buffer(new char[sz]) {}
    virtual ~ProxyBuffer() {
        delete []buffer;
    }

    bool full() const {
        return cur == size;
    }
    
    bool empty() const {
        return start == cur;
    }

    void defragment() {
        start = cur = 0;
    }

    size_t start;
    size_t cur;
    size_t size;
    char *buffer;

};

}
}


#endif
