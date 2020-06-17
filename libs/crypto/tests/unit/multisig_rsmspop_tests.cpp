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

#include "crypto/multisig_rsmspop.hpp"

#include "gtest/gtest.h"

#include <cstdint>
#include <iostream>
#include <ostream>

using namespace fetch::crypto::rsmspop::mcl;
using namespace fetch::byte_array;


TEST(MultiSigRsmspopMclTests, RobustSubgroupSignVerify)
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
    auto new_keys                         = GenerateKeys(generator_g2);
    private_keys[i] = new_keys.first;
    public_verify_keys[i] = new_keys.second;
  }

  //setup a group
  EXPECT_TRUE(group_public_key.GroupSet(public_verify_keys, generator_g2));


  MessagePayload                          message = "Hello";
  std::unordered_map<uint32_t, Signature> signatures;
  for (uint32_t i = 0; i < cabinet_size; ++i)
  {
      Signature signature = Sign( message, private_keys[i], group_public_key.tag);
      EXPECT_TRUE(VerifySlow(message, signature, group_public_key.tag, group_public_key.public_verify_keys[i].public_key, generator_g2));

      std::pair<Signature, Proof> sigma = SignProve( message, private_keys[i], group_public_key.tag, group_public_key.public_verify_keys[i]);
      EXPECT_TRUE(Verify(message, sigma.first, sigma.second, group_public_key.tag, group_public_key.public_verify_keys[i]));

      signatures.insert({i, signature});
  }

  auto multi_signature = MultiSig(signatures, cabinet_size);

  EXPECT_TRUE(VerifyMulti(message, multi_signature, group_public_key, generator_g2));
}



TEST(MultiSigRsmspopMclTests, RobustSubgroupCompress)
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
        auto new_keys                         = GenerateKeys(generator_g2);
        private_keys[i] = new_keys.first;
        public_verify_keys[i] = new_keys.second;
    }

    //setup a group
    EXPECT_TRUE(group_public_key.GroupSet(public_verify_keys, generator_g2));


    MessagePayload                          message = "Hello";
    std::unordered_map<uint32_t, Signature> signatures1, signatures2;
    for (uint32_t i = 0; i < cabinet_size; ++i)
    {

        std::pair<Signature, Proof> sigma = SignProve( message, private_keys[i], group_public_key.tag, group_public_key.public_verify_keys[i]);
        EXPECT_TRUE(Verify(message, sigma.first, sigma.second, group_public_key.tag, group_public_key.public_verify_keys[i]));

        if (i%2==0){
            signatures1.insert({i, sigma.first});
        } else {
            signatures2.insert({i, sigma.first});
        }
    }

    auto sigma1 = MultiSig(signatures1, cabinet_size);
    auto sigma2 = MultiSig(signatures2, cabinet_size);

    auto sigma = Compress(sigma1, sigma2, cabinet_size);

    EXPECT_TRUE(VerifyMulti(message, sigma, group_public_key, generator_g2));
}



TEST(MultiSigRsmspopMclTests, Aggregate)
{
  details::MCLInitialiser();

  GeneratorG2 generator_g2;
  SetGenerator(generator_g2);

  uint32_t                          cabinet_size = 8;
  uint32_t                          block_height = 5;

  std::vector<std::vector<PrivateKey>>           SK;
  std::vector<std::vector<PublicVerifyKey>>            PVK;
  std::vector<GroupPublicKey>                   GPK;
  std::vector<MultiSignature>                   multiSigs;

  SK.resize(block_height);
  PVK.resize(block_height);
  GPK.resize(block_height);
  multiSigs.resize(block_height);
  for (uint32_t i = 0; i< block_height; i++)
  {
    SK[i].resize(cabinet_size);
    PVK[i].resize(cabinet_size);
  }

  for (uint32_t i = 0; i < block_height; i++)
  {
    for (uint32_t j = 0; j < cabinet_size; j++)
    {
      auto new_keys                         = GenerateKeys(generator_g2);
      SK[i][j] = new_keys.first;
      PVK[i][j] = new_keys.second;
    }
    EXPECT_TRUE(GPK[i].GroupSet(PVK[i], generator_g2));
  }

  std::vector<MessagePayload>                          messages;
  messages.resize(block_height);
  for (uint32_t i = 0; i < block_height; i++){
    messages[i] = "block header 000" + std::to_string(rand());
  }


  for (uint32_t i = 0; i < block_height; i++)
  {
    std::unordered_map<uint32_t, Signature> signatures;
    for (uint32_t j = 0; j < cabinet_size; j++)
    {
      Signature sig = Sign(messages[i], SK[i][j], GPK[i].tag);
      signatures.insert({j, sig});
    }
    multiSigs[i] = MultiSig(signatures, cabinet_size);
    EXPECT_TRUE(VerifyMulti(messages[i], multiSigs[i], GPK[i], generator_g2));
  }

  auto aggregate_signature = AggregateSig(multiSigs);

  //  std::string s = aggregate_signature.getStr(16);
  //  std::cout<<"ARMS signature = "<< s <<"\n size of signature = "<<s.size()<<std::endl;



  EXPECT_TRUE(VerifyAgg(messages, aggregate_signature, GPK, generator_g2));

}

