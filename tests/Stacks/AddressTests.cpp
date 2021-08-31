// Copyright © 2017-2021 Trust Wallet.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

#include "Stacks/Address.h"

#include "HDWallet.h"
#include "HexCoding.h"
#include "PrivateKey.h"

#include <gtest/gtest.h>

#include <iostream>

using namespace TW;
using namespace TW::Stacks;
using namespace std;

// TODO: Increase test rage.
TEST(StacksAddress, Validation) {
    // Empty address is not valid.
    ASSERT_FALSE(Address::isValid(""));
}
