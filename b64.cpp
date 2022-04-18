
/*
* File: b64.cpp
* Author: Russell Harvey
* 
*/

#include "b64.h"

#include <stdexcept>

static unsigned int b64_char(const unsigned char chr) {
    
    // Return the position of a character in the Base64 encoding table
    
    if (chr >= 'A' && chr <= 'Z') {
        return chr - 'A';
    }
    else if (chr >= 'a' && chr <= 'z') {
        return chr - 'a' + ('Z' - 'A') + 1;
    }
    else if (chr >= '0' && chr <= '9') {
        return chr - '0' + ('Z' - 'A') + ('z' - 'a') + 2;
    }
    else if (chr == '+' || chr == '-') {
        return 62;
    }
    else if (chr == '/' || chr == '_') {
        return 63;
    }
    else {
        throw std::runtime_error("Input is not valid base64-encoded data.");
    }
}


static std::string decode(std::string encoded_string) {

    if (encoded_string.empty()) return std::string();

    size_t str_len = encoded_string.length();
    size_t position = 0;

    // Approximate the length of the decoded string, reserve space for the length of the decoded string
    size_t approx_str_len = (str_len / 4 * 3) + 1;
    std::string result;
    result.reserve(approx_str_len);

    while (position < str_len) {
        size_t b64_char_1 = b64_char(encoded_string[position + 1]);
        // First output byte
        int s1 = (b64_char(encoded_string[position + 0])) << 2;
        int s2 = (b64_char_1 & 0x30) >> 4;
        result.push_back(static_cast<std::string::value_type>((s1 + s2)));
        if ((position + 2 < str_len) && encoded_string[position + 2] != '=') {
            unsigned int b64_char_2 = b64_char(encoded_string[position + 2]);
            // Second output byte
            int s3 = (b64_char_1 & 0x0f) << 4;
            int s4 = (b64_char_2 & 0x3c) >> 2;
            result.push_back(static_cast<std::string::value_type>((s3 + s4)));
            if ((position + 3 < str_len) && encoded_string[position + 3] != '=') {
                // Third output byte
                int s5 = (b64_char_2 & 0x03) << 6;
                int s6 = b64_char(encoded_string[position + 3]);
                result.push_back(static_cast<std::string::value_type>((s5 + s6)));
            }
        }
        position += 4;
    }
    return result;
}

std::string base64_decode(std::string s) {
    return decode(s);
}