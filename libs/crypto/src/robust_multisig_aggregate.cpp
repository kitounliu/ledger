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

#include "crypto/robust_multisig_aggregate.hpp"
#include "mcl/bn256.hpp"

#include <cassert>
#include <cstddef>
#include <stdexcept>
#include <unordered_map>

namespace bn = mcl::bn256;

namespace fetch {
namespace crypto {
namespace arms {
namespace mcl {

std::atomic<bool>  details::MCLInitialiser::was_initialised{false};
constexpr uint16_t PUBLIC_KEY_BYTE_SIZE = 310;

    GeneratorG1::GeneratorG1()
    {
        clear();
    }


    GeneratorG1::GeneratorG1(std::string const &string_to_hash)
    {
        clear();
        bn::hashAndMapToG1(*this, string_to_hash);
    }


    GeneratorG2::GeneratorG2()
    {
        clear();
    }


    GeneratorG2::GeneratorG2(std::string const &string_to_hash)
    {
        clear();
        bn::hashAndMapToG2(*this, string_to_hash);
    }


    PublicKey::PublicKey()
    {
        clear();
    }



    PrivateKey::PrivateKey()
    {
        clear();
    }


    void PrivateKey::setHash(GeneratorG2 const &generator_g2, Signature const &Hmess, PublicKey const &pk, Signature const &sig,
                               PublicKey const &com1, Signature const &com2)
    {
        std::ostringstream os;
        os << generator_g2 << Hmess << pk << sig << com1 << com2;
        bn::Fr::setHashOf(os.str());
    }


//    PrivateKey::PrivateKey(uint32_t value)
//    {
//        clear();
//        bn::Fr::add(*this, *this, value);
//    }

    Signature::Signature()
    {
        clear();
    }


    /* todo: implement toString and assign for all classes
    std::pair<std::string, std::string> Proof::toString() const {
        return std::make_pair(first.getStr(), second.getStr());
    }

    bool Proof::assign(const std::pair<std::string, std::string> &s) {
          return first.assign(s.first) && second.assign(s.second);
    }
*/



    /**
 * Generates a private key and the corresponding public key
 *
 * @param generator Choice of generator on the elliptic curve
 * @return Pair of private and public keys
 */
    std::pair<PrivateKey, PublicKey> GenerateKeyPair(GeneratorG2 const &generator_g2)
    {
        std::pair<PrivateKey, PublicKey> key_pair;
        key_pair.first.setRand();
        bn::G2::mul(key_pair.second, generator_g2, key_pair.first);

        return key_pair;
    }


    void SetGenerator(GeneratorG1 &generator_g1, std::string const &string_to_hash)
    {
            assert(!string_to_hash.empty());
            bn::hashAndMapToG1(generator_g1, string_to_hash);
            assert(!generator_g1.isZero());
    }



        void SetGenerator(GeneratorG2 &generator_g2, std::string const &string_to_hash)
    {
        assert(!string_to_hash.empty());
        bn::hashAndMapToG2(generator_g2, string_to_hash);
        assert(!generator_g2.isZero());
    }



/**
 * Computes a sequence of deterministic hashes to the finite prime field from a set of public keys
 *
 */
    std::vector<PrivateKey> AggregateCoefficient(std::vector<PublicKey> const &public_keys)
    {
            std::vector<PrivateKey> coefficients;

            // Reserve first 48 bytes for some fixed value as the hash function (also used in DKG) is being
            // reused here in different context
            const std::string hash_function_reuse_appender =
                    "Aggregate Robust MultiSig 00000000000000000000000000000000";

            std::string concatenated_public_keys;
            concatenated_public_keys.reserve(hash_function_reuse_appender.length() +
                                      (public_keys.size() + 1) * PUBLIC_KEY_BYTE_SIZE);

            concatenated_public_keys += hash_function_reuse_appender;


            for (auto const &key : public_keys)
            {
                concatenated_public_keys += key.getStr();
            }

            coefficients.resize(public_keys.size());
            for (uint32_t i = 0; i < public_keys.size(); i++){
                PrivateKey coefficient;
                std::string keyString = public_keys[i].getStr() + concatenated_public_keys;
                coefficient.setHashOf(keyString);
                coefficients[i] = coefficient;
            }

            return coefficients;
    }

    /**
 * Computes signature share of a message
 *
 * @param message Message to be signed
 * @param x_i Secret key share
 * @return Signature share
 */

    PublicKey AggregatePublicKey(std::vector<PublicKey> const &public_keys)
    {
        std::vector<PrivateKey> coefficients = AggregateCoefficient(public_keys);
        PublicKey aggregate_public_key;
        for (uint32_t i = 0; i < public_keys.size(); i++){
            PublicKey tpk;
            bn::G2::mul(tpk, public_keys[i], coefficients[i]);
            bn::G2::add(aggregate_public_key, aggregate_public_key, tpk);
        }

        return aggregate_public_key;
    }



    std::pair<Signature, Proof> SignProve(MessagePayload const &message, std::vector<PrivateKey> const &secret_keys, std::vector<PublicKey> const &public_keys, GeneratorG2 const &generator_g2)
    {
        assert(secret_keys.size() == public_keys.size());

        std::vector<PrivateKey> coefficients = AggregateCoefficient(public_keys);

        PrivateKey sk;
        for (uint32_t i=0; i<secret_keys.size();i++){
            PrivateKey tmp;
            bn::Fr::mul(tmp, secret_keys[i], coefficients[i]);
            bn::Fr::add(sk, sk, tmp);
        }

        PublicKey aggregate_public_key;
        bn::G2::mul(aggregate_public_key, generator_g2, sk);


        const std::string hash_function_reuse_message = "Message 00000000000000000000000000000000";
        std::string apk_mess;
        apk_mess.reserve(hash_function_reuse_message.length() + PUBLIC_KEY_BYTE_SIZE + message.size() );
        apk_mess = "Message 00000000000000000000000000000000" + aggregate_public_key.getStr() + message;

        Signature Hmess;
        bn::hashAndMapToG1(Hmess, apk_mess);



        Signature sig;
        bn::G1::mul(sig, Hmess, sk);  // sign = sk H(m)

        Proof pi = Prove(generator_g2, aggregate_public_key, Hmess, sig, sk);

        return std::make_pair(sig,pi);
    }


// create a NIZK proof
    Proof Prove(const GeneratorG2 &generator_g2, const PublicKey &aggregate_public_key, const Signature &Hmess, const Signature &sig,
                           const PrivateKey &sk) {
        PrivateKey r;
        r.setRand();

        PublicKey com1;
        bn::G2::mul(com1, generator_g2, r);

        Signature com2;
        bn::G1::mul(com2, Hmess, r);

        Proof pi;
        pi.first.setHash(generator_g2, Hmess, aggregate_public_key, sig, com1, com2);
        PrivateKey localVar;
        bn::Fr::mul(localVar, pi.first, sk);
        bn::Fr::add(pi.second, localVar, r);
        return pi;
    }

// verify a NIZK proof (sig, pi)
        bool Verify(const GeneratorG2 &generator_g2, std::vector<PublicKey> const &public_keys, MessagePayload const &message, const Signature &sig, const Proof &pi) {
            std::vector<PrivateKey> coefficients = AggregateCoefficient(public_keys);
            PublicKey aggregate_public_key;
            for (uint32_t i = 0; i < public_keys.size(); i++){
                PublicKey tpk;
                bn::G2::mul(tpk, public_keys[i], coefficients[i]);
                bn::G2::add(aggregate_public_key, aggregate_public_key, tpk);
            }

            const std::string hash_function_reuse_message = "Message 00000000000000000000000000000000";
            std::string apk_mess;
            apk_mess.reserve(hash_function_reuse_message.length() + PUBLIC_KEY_BYTE_SIZE + message.size() );
            apk_mess = "Message 00000000000000000000000000000000" + aggregate_public_key.getStr() + message;

            Signature Hmess;
            bn::hashAndMapToG1(Hmess, apk_mess);

            PublicKey  com1, tmp1;
            bn::G2::mul(tmp1, generator_g2, pi.second);
            bn::G2::mul(com1, aggregate_public_key, pi.first);
            bn::G2::sub(com1, tmp1, com1);

            Signature com2, tmp2;
            bn::G1::mul(tmp2, Hmess, pi.second);
            bn::G1::mul(com2, sig, pi.first);
            bn::G1::sub(com2, tmp2, com2);

            PrivateKey ch;
            ch.setHash(generator_g2, Hmess, aggregate_public_key, sig, com1, com2);

            return pi.first == ch;
        }


/**
 * Verifies a signature by pairing equation
 *
 * @param y The public key (can be the group public key, or public key share)
 * @param message Message that was signed
 * @param sign Signature to be verified
 * @param G Generator used in DKG
 * @return
 */
        bool VerifySlow(std::vector<PublicKey> const &public_keys,  MessagePayload const &message, Signature const &sig,
                        GeneratorG2 const &generator_g2)
        {
            PublicKey aggregate_public_key = AggregatePublicKey(public_keys);

            const std::string hash_function_reuse_message = "Message 00000000000000000000000000000000";
            std::string apk_mess;
            apk_mess.reserve(hash_function_reuse_message.length() + PUBLIC_KEY_BYTE_SIZE + message.size() );
            apk_mess = "Message 00000000000000000000000000000000" + aggregate_public_key.getStr() + message;

            Signature Hmess;
            bn::hashAndMapToG1(Hmess, apk_mess);

            bn::Fp12  e1, e2;

            bn::pairing(e1, sig, generator_g2);
            bn::pairing(e2, Hmess, aggregate_public_key);

            return e1 == e2;
        }







/**
 * Computes aggregate signature from signatures of a message
 *
 * @param signatures Map of the signer index and their signature of a message
 * @param cabinet_size Size of cabinet
 * @return Pair consisting of aggregate signature and a vector indicating who's signatures were
 * aggregated
 */
        Signature AggregateSig(std::vector<Signature> const &signatures)
        {
            Signature    aggregate_signature;

            // Add individual signatures to compute aggregate signature
            for (auto const &sig : signatures)
            {
                bn::G1::add(aggregate_signature, aggregate_signature, sig);
            }
            return aggregate_signature;
        }


        bool VerifyAggSig(std::vector<MessagePayload> const & messages, Signature const &aggregate_signature, std::vector<std::vector<PublicKey>> const &PK, GeneratorG2 const &generator_g2)
        {
            assert(messages.size() == PK.size());

            std::vector<PublicKey> apks;
            apks.resize(PK.size());
            for (uint32_t i = 0; i < PK.size(); i++){
                apks[i] = AggregatePublicKey(PK[i]);
            }

            bn::Fp12  e1, e2;

            e2.setOne();

            bn::pairing(e1, aggregate_signature, generator_g2);

            for (uint32_t i = 0; i < apks.size(); i++){
                const std::string hash_function_reuse_message = "Message 00000000000000000000000000000000";
                std::string apk_mess;
                apk_mess.reserve(hash_function_reuse_message.length() + PUBLIC_KEY_BYTE_SIZE + messages[i].size() );
                apk_mess = "Message 00000000000000000000000000000000" + apks[i].getStr() + messages[i];
                Signature Hmess;
                bn::hashAndMapToG1(Hmess, apk_mess);

                bn::Fp12  tmp;
                bn::pairing(tmp, Hmess, apks[i]);

                bn::GT::mul(e2, e2, tmp);
            }

             return e1 == e2;
        }

    }  // namespace mcl
}  // namespace arms
}  // namespace crypto
}  // namespace fetch
