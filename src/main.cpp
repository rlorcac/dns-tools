#include <iostream>
#include <CLI/CLI.hpp>
#include "sign/sign_command.hpp"
#include "verify/verify_command.hpp"
#include "digest/digest_command.hpp"

int main(int argc, char* argv[]){
    CLI::App dns_tools{"Allows signing of a DNS zone using a PKCS#11 device.\n\nFor more information, visit \"https://github.com/niclabs/dns-tools\"."};
    dns_tools.fallthrough(true);
    
    CLI::App *sign_cmd = register_sign(dns_tools);
    CLI::App *verify_cmd = register_verify(dns_tools);
    CLI::App *digest_cmd = register_digest(dns_tools);
    
    CLI::Option* config_option = dns_tools.set_config("-C,--config", "dns-tools-config.json", 
        "configuration file (defaults are" 
        "\"/etc/dns-tools/dns-tools-config.json\""
        "and \"./dns-tools-config.json\")")
        ->transform(
            CLI::FileOnDefaultPath("/etc/dns-tools/", false) 
            | CLI::FileOnDefaultPath("./", false)
        );
    dns_tools.get_config_formatter_base()->valueSeparator(':');

    CLI11_PARSE(dns_tools, argc, argv);
}
