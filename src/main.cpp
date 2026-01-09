#include <iostream>
#include <CLI/CLI.hpp>
#include "cli/sign/sign_command.hpp"
#include "cli/verify/verify_command.hpp"

int main(int argc, char* argv[]){
    CLI::App dns_tools{"Allows signing of a DNS zone using a PKCS#11 device.\n\nFor more information, visit \"https://github.com/niclabs/dns-tools\"."};

    dns_tools.callback([&](){
        std::cout << dns_tools.help();
    });

    register_sign(dns_tools);
    register_verify(dns_tools);

    CLI11_PARSE(dns_tools, argc, argv);
}
