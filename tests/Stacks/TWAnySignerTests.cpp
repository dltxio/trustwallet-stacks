// Copyright © 2017-2020 Trust Wallet.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

#include "../interface/TWTestUtilities.h"

#include "HexCoding.h"
#include "PrivateKey.h"
#include "Stacks/Address.h"
#include "Stacks/Signer.h"
#include "proto/Stacks.pb.h"
#include <TrustWalletCore/TWAnySigner.h>
#include <gtest/gtest.h>

using namespace TW;
using namespace TW::Stacks;

TEST(TWAnySignerStacks, Transfer7B99) {
    auto key = parse_hex("db31d4670856f8265c9a42b86efac24c6894672266398577291563f89dcf777f01");
    auto privKey = PrivateKey(Data(key.begin(), key.end() - 1));
    auto pubKey = privKey.getPublicKey(TWPublicKeyTypeSECP256k1);
    auto addr = Address(pubKey);
    EXPECT_EQ(addr.string(), "SP19TEDPGHNPAA3M4KSH9V3EZ3M7E5H89RMRZQH8A");

    Proto::SigningInput input;
    input.set_senderkey(key.data(), key.size());
    auto transfer = input.mutable_tokentransfer();
    transfer->set_recipient("SP287TBZNVM3STD1ZH8EXDP10732R13Y43DS0JDZJ");
    transfer->set_amount(1000);
    transfer->set_fee(190);
    transfer->set_nonce(0);
    transfer->set_anchormode(Signer::AnchorModeAny);

    Proto::SigningOutput output;
    ANY_SIGN(input, TWCoinTypeStacks);

    // curl "https://explorer.stacks.co/txid/0x7b99216b0638eb2af462265456dfc1bdb8cef869909fcd694c039462671c683c"
    auto expected = parse_hex("0000000001040053a736d08d6ca50e849e629d8ddf1d0ee2c509c5000000000000000000000000000000be000014796d439a981f356479b74b0c4b910f8a41be602db4ee01a22aaba5587d220754d2251dbfc0a0f25eab8c3c297e6e2e557306f1f816e3cac02e06028da22631030200000000000516907d2ff5dd079d343f8a1dd6d82038c5808fc41b00000000000003e800000000000000000000000000000000000000000000000000000000000000000000");
    EXPECT_EQ(output.encoded(), std::string(expected.begin(), expected.end()));
}

TEST(TWAnySignerStacks, TransferWithMemoA384) {
    auto key = parse_hex("db31d4670856f8265c9a42b86efac24c6894672266398577291563f89dcf777f01");
    auto privKey = PrivateKey(Data(key.begin(), key.end() - 1));
    auto pubKey = privKey.getPublicKey(TWPublicKeyTypeSECP256k1);
    auto addr = Address(pubKey);
    EXPECT_EQ(addr.string(), "SP19TEDPGHNPAA3M4KSH9V3EZ3M7E5H89RMRZQH8A");

    Proto::SigningInput input;
    input.set_senderkey(key.data(), key.size());
    auto transfer = input.mutable_tokentransfer();
    transfer->set_recipient("SP287TBZNVM3STD1ZH8EXDP10732R13Y43DS0JDZJ");
    transfer->set_amount(3000999);
    transfer->set_fee(190);
    transfer->set_nonce(1);
    transfer->set_anchormode(Signer::AnchorModeAny);
    transfer->set_memo("This is a test");

    Proto::SigningOutput output;
    ANY_SIGN(input, TWCoinTypeStacks);

    // curl "https://explorer.stacks.co/txid/0xa3849ca6b1c76ea43b1d13d2780b2bcc1fa75f4a8c42bba773909847b802743f"
    auto expected = parse_hex("0000000001040053a736d08d6ca50e849e629d8ddf1d0ee2c509c5000000000000000100000000000000be00011f78c58b2b211596f968dc7b37d43578b12e40ae104f03c9012b61533dab1ede7c81d85b44e00466ce4856680372497945a16020a5ccc1f5c203b717e07361eb030200000000000516907d2ff5dd079d343f8a1dd6d82038c5808fc41b00000000002dcaa754686973206973206120746573740000000000000000000000000000000000000000");
    EXPECT_EQ(output.encoded(), std::string(expected.begin(), expected.end()));
}

