#include <iostream>
#include "core/config.h"
#include "core/log.h"
#include "core/server.h"

int main(int argc, char *argv[]) {

    proxy::core::ProxyConfig config("./conf/proxy.conf");
    if(!config.parse()) {
        return -1;
    }

    if(!proxy::core::ProxyLog::init_log(argv[0], config.log_abs_dir(),
        config.log_max_size(), config.log_full_stop())) {
        return -1;
    }

    proxy::core::ProxyServer server(config);

    if(!server.setup()) {
        LOG(ERROR) << "setup the proxy server error, quiting";
        return -1;
    }

    LOG(INFO) << "the config is: \n" << config.to_string();

    server.run();

    if(!server.teardown()) {
        LOG(ERROR) << "teardown the proxy server error, quiting";
        return -1;
    }

    return 0;

}
