// Copyright © 2017-2020 Trust Wallet.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

#include "Stacks/Address.h"
#include "Bitcoin/Address.h"
#include "HexCoding.h"
#include "PrivateKey.h"

#include <gtest/gtest.h>

using namespace std;
using namespace TW;
using namespace TW::Stacks;

TEST(StacksAddress, fromPublicKey) {
    const auto privateKey = PrivateKey(parse_hex("04f3335197813301af8e8ff65a71e613a93241790a9db25b1083943d81dafc1b"));
    const auto address = Address(privateKey.getPublicKey(TWPublicKeyTypeSECP256k1));
    ASSERT_EQ(string("ST2PP2BSNVJV56CFRQFEMC5VA2X44ZBKMZ9204TY5"), address.string());
}

TEST(StacksAddress, fromString) {
    string stacksAddress = "ST2PP2BSNVJV56CFRQFEMC5VA2X44ZBKMZ9204TY5";
    const auto address = Address(stacksAddress);
    ASSERT_EQ(address.string(), stacksAddress);
}

TEST(StacksAddress, isValid) {
    string stacksAddress = "ST2PP2BSNVJV56CFRQFEMC5VA2X44ZBKMZ9204TY5";
    ASSERT_TRUE(Address::isValid(stacksAddress));
    stacksAddress[10] = 'A'; // modify character so checksum no longer matches
    ASSERT_FALSE(Address::isValid(stacksAddress));
}
