#ifndef PROXY_CORE_CONFIG_H_H_H
#define PROXY_CORE_CONFIG_H_H_H

#include <string>

#include "boost/property_tree/ptree.hpp"
#include "boost/property_tree/ini_parser.hpp"
#include "boost/filesystem.hpp"


namespace proxy {
namespace core {

enum class ProxyServerType {
    Encryption,
    Decryption,
    Transmission
};

class ProxyConfig {

public:

    ProxyConfig(const std::string &path) : _config_path(path) {}

    std::string config_path() const {
        return _config_path;
    }

    std::string config_abs_path() const {
        return boost::filesystem::absolute(boost::filesystem::path(_config_path)).string();
    }

    std::string local_host() const {
        return _local_host;
    }

    std::string remote_host() const {
        return _remote_host;
    }

    short local_port() const {
        return _local_port;
    }

    short remote_port() const {
        return _remote_port;
    }

    ProxyServerType mode() const {
        return _mode;
    }

    std::string log_dir() const {
        return _log_dir;
    }

    std::string log_abs_dir() const {
        return boost::filesystem::absolute(boost::filesystem::path(_log_dir)).string();
    }

    int log_max_size() const {
        return _log_max_size;
    }

    bool log_full_stop() const {
        return _log_full_stop;
    }

    bool parse();
    std::string to_string() const;

private:

    bool _extract_and_validate(const boost::property_tree::ptree &);

    std::string _config_path;

    // the config of the proxy
    std::string _local_host;
    short _local_port;
    std::string _remote_host;
    short _remote_port;
    ProxyServerType _mode;

    // the config of the logger
    std::string _log_dir;
    int _log_max_size;
    bool _log_full_stop;


};

}
}



#endif
