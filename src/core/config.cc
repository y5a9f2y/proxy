#include <exception>
#include <iostream>
#include <sstream>

#include "core/config.h"
#include "glog/logging.h"

namespace proxy {
namespace core {

const size_t ProxyConfig::USERNAME_MAX_LENGTH = 64;
const size_t ProxyConfig::PASSWORD_MAX_LENGTH = 64;

const size_t ProxyConfig::DEFAULT_STATISTIC_INTERVAL = 2;
const size_t ProxyConfig::DEFAULT_MAX_IDLE_TIME = 120;
const int ProxyConfig::DEFAULT_LOG_MAX_SIZE = 512;
const int ProxyConfig::DEFAULT_LOG_FULL_STOP = 0;

bool ProxyConfig::_load_config(boost::property_tree::ptree &pt, bool flag) {

    /*
     * flag:
     *  - true: load the config when the server start up.
     *  - false: load the config when receiving the signal.
     */

    try {

        boost::property_tree::ini_parser::read_ini(_config_path, pt);

    } catch (const boost::property_tree::ini_parser_error &ex) {

        std::string msg("parse the config file error: ");
        msg += ex.what();
        if(flag) {
            std::cerr << msg << std::endl;
        } else {
            LOG(ERROR) << msg;
        }
        return false;

    } catch (const std::exception &stdex) {

        std::string msg("parse the config file with unknown exception: ");
        msg += stdex.what();
        if(flag) {
            std::cerr << msg << std::endl;
        } else {
            LOG(ERROR) << msg;
        }
        return false;

    }

    return true;

}

bool ProxyConfig::parse() {

    boost::property_tree::ptree pt;

    _load_config(pt, true);

    return _extract_and_validate(pt);

}

bool ProxyConfig::reload() {

    boost::property_tree::ptree pt;

    LOG(INFO) << "the server is reloading the config";

    _load_config(pt, false);

    size_t statistic_interval;
    size_t max_idle_time;
    std::string username;
    std::string password;

    try {

        statistic_interval = pt.get<size_t>("proxy.statistic_interval",
            ProxyConfig::DEFAULT_STATISTIC_INTERVAL);

        max_idle_time = pt.get<size_t>("proxy.max_idle_time",
            ProxyConfig::DEFAULT_MAX_IDLE_TIME);

        if(_mode == ProxyServerType::Encryption || _mode == ProxyServerType::Decryption) {
            username = pt.get<std::string>("auth.username");
            password = pt.get<std::string>("auth.password");
            if(username.size() > ProxyConfig::USERNAME_MAX_LENGTH) {
                LOG(ERROR) << "reload config fail: the length of auth.username greater than "
                    << ProxyConfig::USERNAME_MAX_LENGTH;
                    return false;
            }
            if(password.size() > ProxyConfig::PASSWORD_MAX_LENGTH) {
                LOG(ERROR) << "reload config fail: the length of auth.password greater than"
                    << ProxyConfig::PASSWORD_MAX_LENGTH;
                return false;
            }
        }

    } catch(const boost::property_tree::ptree_bad_path &bpex) {
        LOG(ERROR) << "reload config fail: unknown configuration item: " << bpex.what();
        return false;
    } catch(const boost::property_tree::ptree_bad_data &bdex) {
        LOG(ERROR) << "reload config fail: bad configuration value: " << bdex.what();
        return false;
    } catch(const std::exception &stdex) {
        LOG(ERROR) << "reload config fail: unknown exception when reload the configuration: "
            << stdex.what();
        return false;
    }

    _statistic_interval = statistic_interval;
    _max_idle_time = max_idle_time;
    if(_mode == ProxyServerType::Encryption || _mode == ProxyServerType::Decryption) {
        _username = username;
        _password = password;
    }

    return true;

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
        _statistic_interval = pt.get<size_t>("proxy.statistic_interval",
            ProxyConfig::DEFAULT_STATISTIC_INTERVAL);
        _max_idle_time = pt.get<size_t>("proxy.max_idle_time",
            ProxyConfig::DEFAULT_MAX_IDLE_TIME);

        _log_dir = pt.get<std::string>("log.dir");
        _log_max_size = pt.get<int>("log.max_size", ProxyConfig::DEFAULT_LOG_MAX_SIZE);
        _log_full_stop = pt.get<int>("log.full_stop",
            ProxyConfig::DEFAULT_LOG_FULL_STOP) ? true : false;

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

