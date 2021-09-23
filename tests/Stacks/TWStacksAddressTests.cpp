// Copyright © 2017-2020 Trust Wallet.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

#include "../interface/TWTestUtilities.h"

#include <TrustWalletCore/TWCoinType.h>
#include <TrustWalletCore/TWHDWallet.h>
#include <TrustWalletCore/TWPrivateKey.h>
#include <TrustWalletCore/TWAnyAddress.h>

#include <gtest/gtest.h>

TEST(Stacks, DeriveAddress) {
    auto words = STRING("fever surprise slender giant unlock online trumpet oblige assume pink urban lemon boy raven initial surround aware resemble cancel breeze consider acquire balcony record");
    auto passphrase = STRING("");

    auto wallet = WRAP(TWHDWallet, TWHDWalletCreateWithMnemonic(words.get(), passphrase.get()));
    auto key = WRAP(TWPrivateKey, TWHDWalletGetKeyForCoin(wallet.get(), TWCoinTypeStacks));
    auto publicKey = WRAP(TWPublicKey, TWPrivateKeyGetPublicKeySecp256k1(key.get(), true));

    auto address = WRAP(TWAnyAddress, TWAnyAddressCreateWithPublicKey(publicKey.get(), TWCoinTypeStacks));
    auto addressString = WRAPS(TWAnyAddressDescription(address.get()));

    assertStringsEqual(addressString, "SP19TEDPGHNPAA3M4KSH9V3EZ3M7E5H89RMRZQH8A");
}
