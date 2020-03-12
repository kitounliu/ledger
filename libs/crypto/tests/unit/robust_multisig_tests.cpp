//------------------------------------------------------------------------------
//
//   Copyright 2018-2020 Fetch.AI Limited
//
//   Licensed under the Apache License, Version 2.0 (the "License");
//   you may not use this file except in compliance with the License.
//   You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//   See the License for the specific language governing permissions and
//   limitations under the License.
//
//------------------------------------------------------------------------------

#include "crypto/robust_multisig.hpp"

#include "gtest/gtest.h"

#include <cstdint>
#include <iostream>
#include <ostream>

using namespace fetch::crypto::rsms::mcl;
using namespace fetch::byte_array;


TEST(MclMultiSigTests, RobustSubgroupSignVerify)
{
  details::MCLInitialiser();

  GeneratorG2 generator_g2;
  SetGenerator(generator_g2);

  uint32_t                          cabinet_size = 5;
  std::vector<PublicVerifyKey>      public_verify_keys;
  std::vector<PrivateKey>           private_keys;
  GroupPublicKey                    group_public_key;

  private_keys.resize(cabinet_size);
  public_verify_keys.resize(cabinet_size);

  for (uint32_t i = 0; i < cabinet_size; ++i)
  {
    auto new_keys                         = GenerateKeyPair(generator_g2);
    private_keys[i] = new_keys.first;
    public_verify_keys[i] = new_keys.second;
  }

  //setup a group
  EXPECT_TRUE(group_public_key.GroupSet(public_verify_keys, generator_g2));

  /*
    for (uint32_t i = 0; i < cabinet_size; ++i)
    {
        std::cout<<"verify_key\n"<<public_verify_keys[i].verify_key.getStr()<<std::endl;
        std::cout<<"group verify_key\n"<<group_public_key.public_verify_key_list[i].verify_key.getStr()<<std::endl;
    }
*/

  MessagePayload                          message = "Hello";
  std::unordered_map<uint32_t, Signature> signatures;
  for (uint32_t i = 0; i < cabinet_size; ++i)
  {
      Signature signature = Sign(group_public_key.aggregate_public_key, message, private_keys[i], generator_g2);
      EXPECT_TRUE(VerifySlow(group_public_key.public_verify_key_list[i].public_key, group_public_key.aggregate_public_key, message, signature, generator_g2));
      Proof pi = Prove(group_public_key.public_verify_key_list[i], group_public_key.aggregate_public_key, message, signature, private_keys[i]);
      EXPECT_TRUE(Verify(group_public_key.public_verify_key_list[i], group_public_key.aggregate_public_key, message, signature, pi));
      signatures.insert({i, signature});
  }

  auto multi_signature = MultiSig(signatures, cabinet_size);

  EXPECT_TRUE(VerifyMulti(message, multi_signature, group_public_key, generator_g2));
}
