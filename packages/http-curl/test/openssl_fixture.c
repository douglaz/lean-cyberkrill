/*
Copyright (c) 2026 lean-cyberkrill developers. Released under the MIT License or the
Apache License 2.0, at your option; see LICENSE-MIT and LICENSE-APACHE.
*/
#include <stdio.h>
#include <curl/curl.h>
#include <openssl/crypto.h>

int main(void) {
    puts(OpenSSL_version(0));
    puts(curl_version());
    return 0;
}
