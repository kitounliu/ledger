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

#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wconversion"
#pragma GCC diagnostic ignored "-Wpedantic"
#pragma GCC diagnostic ignored "-Wmacro-redefined"
#endif

#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wconversion"
#pragma clang diagnostic ignored "-Wpedantic"
#pragma clang diagnostic ignored "-Wmacro-redefined"
#pragma clang diagnostic ignored "-Wshadow"
#endif


//#define BLS12
//#define BN384
//#define BN512

#ifdef BLS12
#include <mcl/bls12_381.hpp>
namespace bn = mcl::bls12;
#endif
#ifdef BN384
#include <mcl/bn384.hpp>
namespace bn = mcl::bn384;
#endif
#ifdef BN512
#include <mcl/bn512.hpp>
namespace bn = mcl::bn512;
#endif
#if !defined(BLS12) && !defined(BN384) && !defined(BN512)

#include "mcl/bn256.hpp"
namespace bn = mcl::bn256;
#endif




#if defined(__clang__)
#pragma clang diagnostic pop
#endif

#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif
