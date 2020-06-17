#pragma once
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

#include "core/byte_array/const_byte_array.hpp"
#include "core/serializers/main_serializer.hpp"
#include "crypto/fetch_mcl.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <set>
#include <sstream>
#include <unordered_map>

//namespace bn = mcl::bn256;

namespace fetch {
    namespace crypto {
        namespace rsmsp {
            namespace mcl {

                namespace details {
                    struct MCLInitialiser {
                        MCLInitialiser() {
                            bool a{true};
                            a = was_initialised.exchange(a);
                            if (!a) {
                                bn::initPairing();
                            }
                        }

                        static std::atomic<bool> was_initialised;
                    };
                }  // namespace details

/**
 * Classes for Robust Subgroup MultiSignatures
 */
            class GeneratorG1 : public bn::G1 {
            public:
              GeneratorG1();

              explicit GeneratorG1(std::string const &string_to_hash);
            };

                class GeneratorG2 : public bn::G2 {
                public:
                    GeneratorG2();

                    explicit GeneratorG2(std::string const &string_to_hash);
                };


                class PublicKey : public bn::G1 {
                public:
                    PublicKey();
                };


                class Signature : public bn::G2{
                public:
                    Signature();
                };


                class PrivateKey : public bn::Fr {
                public:
                    PrivateKey();

                    void setHash(GeneratorG1 const &generator_g1, Signature const & Hmess, PublicKey const &public_key, Signature const &sig, PublicKey const &com1, Signature const &com2);
                };


                class GroupTag : public bn::Fr {
                public:
                  GroupTag();
                };


                /// Class for ZKP
                /// @{
                class Proof : public std::pair<PrivateKey, PrivateKey> {
                public:
                    Proof() = default;

                    std::pair<std::string, std::string> toString() const;

                    bool assign(const std::pair<std::string, std::string> &s);
                };





                struct GroupPublicKey {
                    GroupTag tag;
                    std::vector<PublicKey> public_keys;

                    GroupPublicKey() = default;

                    bool GroupSet(std::vector<PublicKey> const &public_key_list);
                };


                using MessagePayload     = std::string;
                using CabinetIndex       = uint32_t;
                using SignerRecord       = std::vector<uint8_t>;
                using Coefficients       = std::unordered_map<uint32_t, PrivateKey>;
                using MultiSignature = std::pair<Signature, SignerRecord>;
                using AggSignature = std::pair<Signature, std::vector<SignerRecord>>;

/**
 * Vector initialisation for mcl data structures
 *
 * @tparam T Type in vector
 * @param data Vector to be initialised
 * @param i Number of columns
 */
                template<typename T>
                void Init(std::vector<T> &data, uint32_t i) {
                    data.resize(i);
                    for (auto &data_i : data) {
                        data_i.clear();
                    }
                }

/**
 * Matrix initialisation for mcl data structures
 *
 * @tparam T Type in matrix
 * @param data Matrix to be initialised
 * @param i Number of rows
 * @param j Number of columns
 */
                template<typename T>
                void Init(std::vector<std::vector<T>> &data, uint32_t i, uint32_t j) {
                    data.resize(i);
                    for (auto &data_i : data) {
                        data_i.resize(j);
                        for (auto &data_ij : data_i) {
                            data_ij.clear();
                        }
                    }
                }


            void SetGenerator(GeneratorG1 &generator_g1,
                              std::string const &string_to_hash = "Fetch.ai Elliptic Curve Generator G1");

               void SetGenerator(GeneratorG2 &generator_g2,
                                  std::string const &string_to_hash = "Fetch.ai Elliptic Curve Generator G2");

        std::pair<PrivateKey, PublicKey> GenerateKeys(GeneratorG1 const &generator_g1);


// For signatures
            Signature Sign(MessagePayload const &message, PrivateKey const &sk, GroupTag const &group_tag);

            std::pair<Signature, Proof> SignProve(MessagePayload const &message, PrivateKey const &sk, GroupTag const &group_tag, const PublicKey &public_key, GeneratorG1 const &generator_g1);

            bool Verify(const MessagePayload &message, const Signature &sig, const Proof &pi, GroupTag const &group_tag, PublicKey const &public_key, GeneratorG1 const &generator_g1);

            bool VerifySlow(MessagePayload const &message, Signature const &sig, GroupTag const &group_tag, PublicKey const &public_key,
                            GeneratorG1 const &generator_g1);



// For aggregate signatures

                Coefficients AggregateCoefficients(GroupPublicKey const &gpk, SignerRecord signers);

                MultiSignature MultiSig(std::unordered_map<uint32_t, Signature> const &signatures, uint32_t cabinet_size, GroupPublicKey const &gpk);

                PublicKey AggregatePublicKey(GroupPublicKey const &gpk, SignerRecord signers);

                bool VerifyMulti(MessagePayload const &message, MultiSignature const &sigma, GroupPublicKey const &gpk, GeneratorG1 const &generator_g1);

                AggSignature AggregateSig(std::vector<MultiSignature> const &multi_signatures);

                bool VerifyAgg(std::vector<MessagePayload> const & messages, AggSignature const &aggregate_signature, std::vector<GroupPublicKey> const &gpks, GeneratorG1 const &generator_g1);

            }// namespace mcl
        }  // namespace rsmsp
    }  // namespace crypto

    namespace serializers {
        template <typename D>
        struct ArraySerializer<crypto::rsmsp::mcl::Signature, D>
        {

        public:
            using Type       = crypto::rsmsp::mcl::Signature;
            using DriverType = D;

            template <typename Constructor>
            static void Serialize(Constructor &array_constructor, Type const &b)
            {
                auto array = array_constructor(1);
                array.Append(b.getStr());
            }

            template <typename ArrayDeserializer>
            static void Deserialize(ArrayDeserializer &array, Type &b)
            {
                std::string sig_str;
                array.GetNextValue(sig_str);
                bool check;
                b.setStr(&check, sig_str.data());
                if (!check)
                {
                    throw SerializableException(error::TYPE_ERROR,
                                                std::string("String does not convert to MCL type"));
                }
            }
        };

        template <typename D>
        struct ArraySerializer<crypto::rsmsp::mcl::PrivateKey, D>
        {

        public:
            using Type       = crypto::rsmsp::mcl::PrivateKey;
            using DriverType = D;

            template <typename Constructor>
            static void Serialize(Constructor &array_constructor, Type const &b)
            {
                auto array = array_constructor(1);
                array.Append(b.getStr());
            }

            template <typename ArrayDeserializer>
            static void Deserialize(ArrayDeserializer &array, Type &b)
            {
                std::string sig_str;
                array.GetNextValue(sig_str);
                bool check;
                b.setStr(&check, sig_str.data());
                if (!check)
                {
                    throw SerializableException(error::TYPE_ERROR,
                                                std::string("String does not convert to MCL type"));
                }
            }
        };

        template <typename D>
        struct ArraySerializer<crypto::rsmsp::mcl::PublicKey, D>
        {

        public:
            using Type       = crypto::rsmsp::mcl::PublicKey;
            using DriverType = D;

            template <typename Constructor>
            static void Serialize(Constructor &array_constructor, Type const &b)
            {
                auto array = array_constructor(1);
                array.Append(b.getStr());
            }

            template <typename ArrayDeserializer>
            static void Deserialize(ArrayDeserializer &array, Type &b)
            {
                std::string sig_str;
                array.GetNextValue(sig_str);
                bool check;
                b.setStr(&check, sig_str.data());
                if (!check)
                {
                    throw SerializableException(error::TYPE_ERROR,
                                                std::string("String does not convert to MCL type"));
                }
            }
        };

        template <typename V, typename D>
        struct ArraySerializer<std::pair<crypto::rsmsp::mcl::PublicKey, V>, D>
        {
        public:
            using Type       = std::pair<crypto::rsmsp::mcl::PublicKey, V>;
            using DriverType = D;

            template <typename Constructor>
            static void Serialize(Constructor &array_constructor, Type const &input)
            {
                auto array = array_constructor(2);
                array.Append(input.first.getStr());
                array.Append(input.second);
            }

            template <typename ArrayDeserializer>
            static void Deserialize(ArrayDeserializer &array, Type &output)
            {
                if (array.size() != 2)
                {
                    throw SerializableException(std::string("std::pair must have exactly 2 elements."));
                }

                std::string key_str;
                array.GetNextValue(key_str);
                output.first.clear();
                bool check;
                output.first.setStr(&check, key_str.data());
                if (!check)
                {
                    throw SerializableException(error::TYPE_ERROR,
                                                std::string("String does not convert to MCL type"));
                }
                array.GetNextValue(output.second);
            }
        };
    }  // namespace serializers
}  // namespace fetch
