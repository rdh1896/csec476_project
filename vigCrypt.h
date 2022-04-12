#pragma once
#include <string>

using namespace::std;

class vigCrypt
{
public:
    string key;
    vigCrypt(string key) {
        for (int i = 0; i < key.size(); ++i) {
            if (key[i] >= 'A' && key[i] <= 'Z')
                this->key += key[i];
            else if (key[i] >= 'a' && key[i] <= 'z')
                this->key += key[i] + 'A' - 'a';
        }
    };
    string encrypt(string t);
    string decrypt(string t);
};

