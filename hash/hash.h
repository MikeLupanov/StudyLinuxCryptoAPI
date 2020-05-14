#pragma once
#include <iostream>
#include <fstream>
#include <string>
#include <map>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/if_alg.h>

#define ALG_MD5 "md5"
#define ALG_MD4 "md4"
#define ALG_SHA1 "sha1"
#define ALG_SHA224 "sha224"
#define ALG_SHA256 "sha256"
#define ALG_SHA384 "sha384"
#define ALG_SHA512 "sha512"
#define ALG_HMAC_SHA1 "hmac(sha1)"
#define ALG_HMAC_SHA256 "hmac(sha256)"

class Hash
{
public:
    enum HashAlg {MD4,MD5,SHA1,SHA224,SHA256,SHA384,SHA512,HMAC_SHA1,HMAC_SHA256};
protected:
    std::map<int, const char *> AlgList{
        std::pair<int, const char *>(MD5, ALG_MD5),
        std::pair<int, const char *>(MD4, ALG_MD4),
        std::pair<int, const char *>(SHA1, ALG_SHA1),
        std::pair<int, const char *>(SHA224, ALG_SHA224),
        std::pair<int, const char *>(SHA256, ALG_SHA256),
        std::pair<int, const char *>(SHA384, ALG_SHA384),
        std::pair<int, const char *>(SHA512, ALG_SHA512),
        std::pair<int, const char *>(HMAC_SHA1, ALG_HMAC_SHA1),
        std::pair<int, const char *>(HMAC_SHA256, ALG_HMAC_SHA256)};
    static constexpr int BUF_SIZE = 1024 * 4;
    unsigned char *buf;
    int cryptosocket;
    int hashsocket;
    ssize_t len;
    virtual void calcHash(const std::string data) = 0;
//    void initHash();
    void finishHash();
    std::string toString();
    HashAlg _alg;
public:
    Hash(HashAlg alg = MD5);
    Hash(std::string password, HashAlg alg = HMAC_SHA1);
    virtual ~Hash();
    std::string operator()(const std::string& data);
    std::string name() {
        return AlgList[_alg];
    }
};

class StringHash : public Hash
{
private:
    virtual void calcHash(const std::string data);

public:
    StringHash(HashAlg alg = MD5) : Hash(alg) {}
    StringHash(std::string password, HashAlg alg = HMAC_SHA1) : Hash(password, alg) {}
    virtual ~StringHash() {}
};

class FileHash : public Hash
{
private:
    virtual void calcHash(const std::string data);

public:
    FileHash(HashAlg alg = MD5) : Hash(alg) {}
    virtual ~FileHash() {}
};
