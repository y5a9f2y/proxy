#include "core/buffer.h"

namespace proxy {
namespace core {

size_t ProxyBuffer::PROXY_BUFFER_DEFAULT_SIZE = 4096;

char *ProxyBuffer::get_charp_at(size_t n) {

    if(start + n >= cur) {
        return nullptr;
    }

    return buffer + (start + n);

}

}
}
