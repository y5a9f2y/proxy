#ifndef PROXY_CORE_BUFFER_H_H_H
#define PROXY_CORE_BUFFER_H_H_H

#include <sys/types.h>

namespace proxy {
namespace core {

class ProxyBuffer {

public:

    ProxyBuffer(): ProxyBuffer(ProxyBuffer::PROXY_BUFFER_DEFAULT_SIZE) {}
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

    void clear() {
        start = cur = 0;
    }

    char *get_charp_at(size_t);

    size_t start;
    size_t cur;
    size_t size;
    char *buffer;

    static size_t PROXY_BUFFER_DEFAULT_SIZE;

};

}
}


#endif
