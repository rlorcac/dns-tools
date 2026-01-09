#include <iostream>
#include <CLI/CLI.hpp>


int main(int argc, char* argv[]){
    CLI::App dns_tools{"Allows signing of a DNS zone using a PKCS#11 device.\n\nFor more information, visit \"https://github.com/niclabs/dns-tools\"."};

    CLI11_PARSE(dns_tools, argc, argv);
}