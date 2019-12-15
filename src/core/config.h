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

    uint16_t local_port() const {
        return _local_port;
    }

    uint16_t remote_port() const {
        return _remote_port;
    }

    ProxyServerType mode() const {
        return _mode;
    }

    int listen_backlog() const {
        return _listen_backlog;
    }

    size_t statistic_interval() const {
        return _statistic_interval;
    }

    size_t max_idle_time() const {
        return _max_idle_time;
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

    const std::string &username() const {
        return _username;
    }

    const std::string &password() const {
        return _password;
    }

    bool parse();
    std::string to_string() const;

    static const size_t USERNAME_MAX_LENGTH;
    static const size_t PASSWORD_MAX_LENGTH;

private:

    bool _extract_and_validate(const boost::property_tree::ptree &);

    std::string _config_path;

    // the config of the proxy
    std::string _local_host;
    uint16_t _local_port;
    std::string _remote_host;
    uint16_t _remote_port;
    ProxyServerType _mode;
    int _listen_backlog;
    size_t _statistic_interval;
    size_t _max_idle_time;

    // the config of the logger
    std::string _log_dir;
    int _log_max_size;
    bool _log_full_stop;

    // the config of the authentication
    std::string _username;
    std::string _password;

};

}
}


#endif
