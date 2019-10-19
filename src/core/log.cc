#include <iostream>
#include <exception>

#include "boost/filesystem.hpp"
#include "core/log.h"

namespace proxy {
namespace core {

bool ProxyLog::init_log(const char *name, const std::string &dir, int max_size, bool full_stop) {

    try {
        boost::filesystem::create_directories(dir);
    } catch (const boost::filesystem::filesystem_error &ex) {
        std::cerr << "create the directory " << dir << " error with " << ex.what() << std::endl;
        return false;
    } catch (const std::exception &stdex) {
        std::cerr << "create the directory " << dir << " error with std exception "
            << stdex.what() << std::endl;
        return false;
    }

    ProxyLog::set_log_dir(dir);
    ProxyLog::set_log_max_size(max_size);
    ProxyLog::set_log_full_stop(full_stop);
    ProxyLog::set_log_buffer();

    google::InitGoogleLogging(name);

    return true;

}

}
}
