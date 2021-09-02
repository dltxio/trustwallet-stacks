// Copyright © 2017-2021 Trust Wallet.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

#pragma once

#include "../Data.h"
#include "../PublicKey.h"

#include <string>
#include <vector>

namespace TW::Stacks {

class Address {
  private:
    static const char* BASE32_ALPHABET_CROCKFORD;
  
    // Size of base-32 encoded address string.
    static const size_t size = 41;

    // Size of prefix plus public key hash.
    static const size_t bytesSize = 21;

    // Size of checksum.
    static const size_t checksumSize = 4;

    static TW::Data deconstruct(const std::string& string);

  public:
    /// Address data consisting of prefix plus public key hash.
    std::array<byte, bytesSize> bytes;
    
    /// Determines whether a string makes a valid address.
    static bool isValid(const std::string& string);

    /// Initializes a Stacks address with a string representation.
    explicit Address(const std::string& string);

    /// Initializes a Stacks address with a public key.
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
