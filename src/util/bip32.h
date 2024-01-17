// Copyright (c) 2019-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_UTIL_BIP32_H
#define BITCOIN_UTIL_BIP32_H

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

struct HDKeyPath
{
    std::vector<uint32_t> path;
    std::optional<uint32_t> mweb_index{std::nullopt};

    friend bool operator==(const HDKeyPath& a, const HDKeyPath& b)
    {
        return a.path == b.path && a.mweb_index == b.mweb_index;
    }

    friend bool operator<(const HDKeyPath& a, const HDKeyPath& b)
    {
        // Compare the sizes of the paths, shorter is "less than"
        if (a.path.size() < b.path.size()) {
            return true;
        } else if (a.path.size() > b.path.size()) {
            return false;
        }
        // Paths same length, compare them lexicographically
        if (a.path < b.path) {
            return true;
        } else if (a.path > b.path) {
            return false;
        }

        // Compare the MWEB indices
        return a.mweb_index < b.mweb_index;
    }
};

/** Parse an HD keypaths like "m/7/0'/2000". */
[[nodiscard]] bool ParseHDKeypath(const std::string& keypath_str, HDKeyPath& kehdkeypathypath);

/** Write HD keypaths as strings */
std::string WriteHDKeypath(const HDKeyPath& hdkeypath);
std::string FormatHDKeypath(const HDKeyPath& hdkeypath);

#endif // BITCOIN_UTIL_BIP32_H
