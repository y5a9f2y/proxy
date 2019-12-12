#include <exception>
#include <iostream>
#include <sstream>

#include "core/config.h"

namespace proxy {
namespace core {

const size_t ProxyConfig::USERNAME_MAX_LENGTH = 64;
const size_t ProxyConfig::PASSWORD_MAX_LENGTH = 64;

bool ProxyConfig::parse() {

    boost::property_tree::ptree pt;

    try {

        boost::property_tree::ini_parser::read_ini(_config_path, pt);

    } catch (const boost::property_tree::ini_parser_error &ex) {

        std::cerr << "parse the config file error: " << ex.what() << std::endl;
        return false;

    } catch (const std::exception &stdex) {

        std::cerr << "parse the config file with unknown exception: " << stdex.what() << std::endl;
        return false;

    }

    return _extract_and_validate(pt);
}

bool ProxyConfig::_extract_and_validate(const boost::property_tree::ptree &pt) {

    std::string mode;

    try {

        _local_host = pt.get<std::string>("proxy.local_host");
        _local_port = pt.get<uint16_t>("proxy.local_port");

        mode = pt.get<std::string>("proxy.mode");
        if (mode == "encryption") {
            _mode = ProxyServerType::Encryption;
        } else if (mode == "decryption") {
            _mode = ProxyServerType::Decryption;
        } else if (mode == "transmission") {
            _mode = ProxyServerType::Transmission;
        } else {
            std::cerr << "unknown proxy mode: " << mode << std::endl;
            return false;
        }

        if(_mode == ProxyServerType::Encryption || _mode == ProxyServerType::Transmission) {
            _remote_host = pt.get<std::string>("proxy.remote_host");
            _remote_port = pt.get<uint16_t>("proxy.remote_port");
        }
        _listen_backlog = pt.get<int>("proxy.listen_backlog");

        _log_dir = pt.get<std::string>("log.dir");
        _log_max_size = pt.get<int>("log.max_size", 512);
        _log_full_stop = pt.get<int>("log.full_stop", 0) ? true : false;

        if(_mode == ProxyServerType::Encryption || _mode == ProxyServerType::Decryption) {

            _username = pt.get<std::string>("auth.username");
            _password = pt.get<std::string>("auth.password");

            if(_username.size() > ProxyConfig::USERNAME_MAX_LENGTH) {
                std::cerr << "the length of auth.username greater than "
                    << ProxyConfig::USERNAME_MAX_LENGTH << std::endl;
                return false;
            }

            if(_password.size() > ProxyConfig::PASSWORD_MAX_LENGTH) {
                std::cerr << "the length of auth.password greater than"
                    << ProxyConfig::PASSWORD_MAX_LENGTH << std::endl;
                return false;
            }
        
        }

    } catch(const boost::property_tree::ptree_bad_path &bpex) {

        std::cerr << "unknown configuration item: " << bpex.what() << std::endl;
        return false;

    } catch(const boost::property_tree::ptree_bad_data &bdex) {

        std::cerr << "bad configuration value: " << bdex.what() << std::endl;
        return false;

    } catch(const std::exception &stdex) {

        std::cerr << "unknown exception when extract the configuration: "
            << stdex.what() << std::endl;
        return false;

    }

    return true;

}

std::string ProxyConfig::to_string() const {

    std::ostringstream oss;

    oss << "config.file.path:" << config_abs_path() << "\n";

    oss << "proxy.mode:";
    switch(_mode) {
        case ProxyServerType::Encryption:
            oss << "encryption";
            break;
        case ProxyServerType::Decryption:
            oss << "decryption";
            break;
        case ProxyServerType::Transmission:
            oss << "transmission";
            break;
        default:
            oss << "unknown";
            break;
    }
    oss << "\n";
    oss << "proxy.local_host:" << _local_host << "\n";
    oss << "proxy.local_port:" << _local_port << "\n";
    if(_mode == ProxyServerType::Encryption || _mode == ProxyServerType::Transmission) {
        oss << "proxy.remote_host:" << _remote_host << "\n";
        oss << "proxy.remote_port:" << _remote_port << "\n";
    }
    oss << "proxy.listen_backlog:" << _listen_backlog << "\n";

    oss << "log.dir:" << log_abs_dir() << "\n";
    oss << "log.max_size:" << _log_max_size << "\n";
    oss << "log.full_stop:" << _log_full_stop << "\n";
    if(_mode == ProxyServerType::Encryption || _mode == ProxyServerType::Decryption) {
        oss << "auth.username:" << _username << "\n";
        oss << "auth.password:" << _password;
    }

    return oss.str();

}

}
}

