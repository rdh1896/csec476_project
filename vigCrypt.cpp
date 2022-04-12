#include "vigCrypt.h"
#define WIN32_LEAN_AND_MEAN
#include <string>
#include <stdio.h>
#include <iostream>

using namespace::std;

string vigCrypt::encrypt(string t) {
    string output;
    for (int i = 0, j = 0; i < t.length(); ++i) {
        char c = t[i];
        bool isLower = false;
        if (c >= 'a' && c <= 'z') {
            isLower = true;
            c += 'A' - 'a';
        }
        else if (c < 'A' || c > 'Z') {
            output += c; // unable to handle unrecognized chars, will ignore
            continue;
        }
        if (isLower) {
            output += tolower((c + key[j] - 2 * 'A') % 26 + 'A');
        } else {
            output += (c + key[j] - 2 * 'A') % 26 + 'A';
        }
        j = (j + 1) % key.length();
    }
    return output;
}

string vigCrypt::decrypt(string t) {
    string output;
    for (int i = 0, j = 0; i < t.length(); ++i) {
        char c = t[i];
        bool isLower = false;
        if (c >= 'a' && c <= 'z') {
            c += 'A' - 'a';
            isLower = true;
        }
        else if (c < 'A' || c > 'Z') {
            output += c;
            continue;
        }
        if (isLower) {
            output += tolower((c - key[j] + 26) % 26 + 'A');
        }
        else {
            output += (c - key[j] + 26) % 26 + 'A';
        }
        j = (j + 1) % key.length();
    }
    return output;
}