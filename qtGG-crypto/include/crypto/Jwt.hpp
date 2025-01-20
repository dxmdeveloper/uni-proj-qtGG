#pragma once
#include <string>
#include <string_view>
#include <cstdint>

class JwtReader {
public:
    JwtReader(std::string_view token);
    bool validateHash(std::string_view secret) const;
    bool isFormatValid() const;

    std::string getPayload() const;

private:
    bool invalid = false;
    std::string header;
    std::string payload;
    std::string hash;
};

class JwtWriter {
public:
    JwtWriter(std::string_view payload, std::string_view secret);

    void addField(std::string_view key, uint64_t val);
    void addField(std::string_view key, int64_t val);
    void addField(std::string_view key, bool val);
    void addField(std::string_view key, std::string_view s);

    std::string getPayload() const;
    std::string toString() const;

private:
    template<typename T>
    void addFieldTmpl(std::string_view key, T val);

    std::string secret;
    std::string payload;
};