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

#include "crypto/multisig_rsmsp.hpp"

#include "gtest/gtest.h"

#include <cstdint>
#include <iostream>
#include <ostream>

using namespace fetch::crypto::rsmsp::mcl;
using namespace fetch::byte_array;


TEST(MultiSigRsmspMclTests, SignVerify)
{
  details::MCLInitialiser();

  GeneratorG1 generator_g1;
  SetGenerator(generator_g1);

  uint32_t                          cabinet_size = 5;
  std::vector<PublicKey>      public_keys;
  std::vector<PrivateKey>           private_keys;
  GroupPublicKey                    group_public_key;

  private_keys.resize(cabinet_size);
  public_keys.resize(cabinet_size);

  for (uint32_t i = 0; i < cabinet_size; ++i)
  {
    auto new_keys                         = GenerateKeys(generator_g1);
    private_keys[i] = new_keys.first;
    public_keys[i] = new_keys.second;
  }

  //setup a group
  EXPECT_TRUE(group_public_key.GroupSet(public_keys));


  MessagePayload                          message = "Hello";
  std::unordered_map<uint32_t, Signature> signatures;
  for (uint32_t i = 0; i < cabinet_size; ++i)
  {
      Signature signature = Sign(message, private_keys[i], group_public_key.tag);
      EXPECT_TRUE(VerifySlow( message, signature, group_public_key.tag, group_public_key.public_keys[i],  generator_g1));

      //  Verify(PublicKey const &public_key, GroupTag const &group_tag,  const MessagePayload &message, const Signature &sig, const Proof &pi,  GeneratorG1 const &generator_g1) {
      std::pair<Signature, Proof> sigma = SignProve(message, private_keys[i], group_public_key.tag, group_public_key.public_keys[i], generator_g1);
      EXPECT_TRUE(Verify( message, sigma.first, sigma.second, group_public_key.tag, group_public_key.public_keys[i],   generator_g1));

      signatures.insert({i, signature});
  }

  auto multi_signature = MultiSig(signatures, cabinet_size, group_public_key);

  EXPECT_TRUE(VerifyMulti(message, multi_signature, group_public_key, generator_g1));
}



TEST(MultiSigRsmspMclTests, Aggregate)
{
  details::MCLInitialiser();

  GeneratorG1 generator_g1;
  SetGenerator(generator_g1);

  uint32_t                          cabinet_size = 8;
  uint32_t                          block_height = 5;

  std::vector<std::vector<PrivateKey>>           SK;
  std::vector<std::vector<PublicKey>>            PK;
  std::vector<GroupPublicKey>                   GPK;
  std::vector<MultiSignature>                   multiSigs;

  SK.resize(block_height);
  PK.resize(block_height);
  GPK.resize(block_height);
  multiSigs.resize(block_height);
  for (uint32_t i = 0; i< block_height; i++)
  {
    SK[i].resize(cabinet_size);
    PK[i].resize(cabinet_size);
  }

  for (uint32_t i = 0; i < block_height; i++)
  {
    for (uint32_t j = 0; j < cabinet_size; j++)
    {
      auto new_keys                         = GenerateKeys(generator_g1);
      SK[i][j] = new_keys.first;
      PK[i][j] = new_keys.second;
    }
    EXPECT_TRUE(GPK[i].GroupSet(PK[i]));
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
    multiSigs[i] = MultiSig(signatures, cabinet_size, GPK[i]);
    EXPECT_TRUE(VerifyMulti(messages[i], multiSigs[i], GPK[i], generator_g1));
  }

  auto aggregate_signature = AggregateSig(multiSigs);

  //  std::string s = aggregate_signature.getStr(16);
  //  std::cout<<"ARMS signature = "<< s <<"\n size of signature = "<<s.size()<<std::endl;



  EXPECT_TRUE(VerifyAgg(messages, aggregate_signature, GPK, generator_g1));

}
