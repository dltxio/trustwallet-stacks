// Copyright © 2017-2021 Trust Wallet.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

#pragma once

#include "../Data.h"
#include "../PublicKey.h"

#include <string>

namespace TW::Stacks {

class Address {
  private:
    static const char* BASE32_ALPHABET_CROCKFORD;
  
    // 41 character base-32 encoded string
    static const size_t size = 41;

    // Decodes to 25 bytes
    static const size_t rawSize = 25;

    // Hash size
    static const size_t hashSize = 20;

  public:
    /// Address data consisting of a prefix byte followed by the public key
    /// hash.
    std::array<byte, hashSize> bytes;

    /// Determines whether a string makes a valid  address.
    static bool isValid(const std::string& string);

    /// Initializes a Stellar address with a string representation.
    explicit Address(const std::string& string);

    /// Initializes a Stellar address with a public key.
    explicit Address(const PublicKey& publicKey);

    /// Returns a string representation of the address.
    std::string string() const;
};

inline bool operator==(const Address& lhs, const Address& rhs) {
    return lhs.bytes == rhs.bytes;
}

} // namespace TW::Stacks

/// Wrapper for C interface.
struct TWStacksAddress {
    TW::Stacks::Address impl;
};
