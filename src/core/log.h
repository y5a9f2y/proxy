#ifndef PROXY_CORE_LOG_H_H_H
#define PROXY_CORE_LOG_H_H_H

#include <string>

#include "glog/logging.h"

namespace proxy {
namespace core {

class ProxyLog final {

public:

    static void set_log_dir(const std::string &dir) {
        fLS::FLAGS_log_dir = dir;
    }

    static void set_log_max_size(int size) {
        fLI::FLAGS_max_log_size = size;
    }

    static void set_log_full_stop(bool flag) {
        fLB::FLAGS_stop_logging_if_full_disk = flag;
    }

    static void set_log_buffer(int level = -1) {
        fLI::FLAGS_logbuflevel = level;
    }

    static bool init_log(const char *, const std::string &, int, bool);

};

}
}

#endif
