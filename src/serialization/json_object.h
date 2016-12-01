// Copyright (c) 2016, The Monero Project
// 
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
// 
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
// 
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
// 
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#pragma once

#include "rapidjson/document.h"
#include "cryptonote_core/cryptonote_basic.h"
#include "rpc/message_data_structs.h"
#include "cryptonote_protocol/cryptonote_protocol_defs.h"
#include "common/sfinae_helpers.h"

namespace cryptonote
{

namespace json
{

struct JSON_ERROR : public std::exception
{
  protected:
    JSON_ERROR() { }
    std::string m;

  public:
    virtual ~JSON_ERROR() { }

    const char* what() const throw()
    {
      return m.c_str();
    }
};

struct MISSING_KEY : public JSON_ERROR
{
  MISSING_KEY(const char* key)
  {
    m = std::string("Key \"") + key + "\" missing from object.";
  }
};

struct WRONG_TYPE : public JSON_ERROR
{
  WRONG_TYPE(const char* type)
  {
    m = std::string("Json value has incorrect type, expected: ") + type;
  }
};

struct BAD_INPUT : public JSON_ERROR
{
  BAD_INPUT()
  {
    m = "An item failed to convert from json object to native object";
  }
};

struct PARSE_FAIL : public JSON_ERROR
{
  PARSE_FAIL()
  {
    m = "Failed to parse the json request";
  }
};

// convenience macro
#define OBJECT_HAS_MEMBER_OR_THROW(val, key) \
  if (!val.HasMember(key)) \
  { \
    throw cryptonote::json::MISSING_KEY(key); \
  }



// POD to json value
template <typename Type, typename = typename std::enable_if<sfinae::is_not_container<Type>::value, Type>::type>
rapidjson::Value toJsonValue(rapidjson::Document& doc, const Type& pod);

template <typename Type, typename = typename std::enable_if<sfinae::is_not_container<Type>::value, Type>::type>
Type fromJsonValue(const rapidjson::Value& val);

template <>
rapidjson::Value toJsonValue(rapidjson::Document& doc, const std::string& i);

template <>
std::string fromJsonValue(const rapidjson::Value& i);

rapidjson::Value toJsonValue(rapidjson::Document& doc, bool i);

bool fromJsonValue(const rapidjson::Value& i);

template <>
rapidjson::Value toJsonValue(rapidjson::Document& doc, const uint8_t& i);

template <>
uint8_t fromJsonValue(const rapidjson::Value& i);

template <>
rapidjson::Value toJsonValue(rapidjson::Document& doc, const int8_t& i);

template <>
int8_t fromJsonValue(const rapidjson::Value& i);

template <>
rapidjson::Value toJsonValue(rapidjson::Document& doc, const uint16_t& i);

template <>
uint16_t fromJsonValue(const rapidjson::Value& i);

template <>
rapidjson::Value toJsonValue(rapidjson::Document& doc, const uint32_t& i);

template <>
uint32_t fromJsonValue(const rapidjson::Value& i);

template <>
rapidjson::Value toJsonValue(rapidjson::Document& doc, const uint64_t& i);

template <>
uint64_t fromJsonValue(const rapidjson::Value& i);

template <>
rapidjson::Value toJsonValue<cryptonote::transaction>(rapidjson::Document& doc, const cryptonote::transaction& tx);

template <>
cryptonote::transaction fromJsonValue<cryptonote::transaction>(const rapidjson::Value& val);

template <>
rapidjson::Value toJsonValue<cryptonote::block>(rapidjson::Document& doc, const cryptonote::block& b);

template <>
cryptonote::block fromJsonValue<cryptonote::block>(const rapidjson::Value& val);

template <>
rapidjson::Value toJsonValue<cryptonote::txin_v>(rapidjson::Document& doc, const cryptonote::txin_v& txin);

template <>
cryptonote::txin_v fromJsonValue<cryptonote::txin_v>(const rapidjson::Value& val);

template <>
rapidjson::Value toJsonValue<cryptonote::txin_gen>(rapidjson::Document& doc, const cryptonote::txin_gen& txin);

template <>
cryptonote::txin_gen fromJsonValue<cryptonote::txin_gen>(const rapidjson::Value& val);

template <>
rapidjson::Value toJsonValue<cryptonote::txin_to_script>(rapidjson::Document& doc, const cryptonote::txin_to_script& txin);

template <>
cryptonote::txin_to_script fromJsonValue<cryptonote::txin_to_script>(const rapidjson::Value& val);

template <>
rapidjson::Value toJsonValue<cryptonote::txin_to_scripthash>(rapidjson::Document& doc, const cryptonote::txin_to_scripthash& txin);

template <>
cryptonote::txin_to_scripthash fromJsonValue<cryptonote::txin_to_scripthash>(const rapidjson::Value& val);

template <>
rapidjson::Value toJsonValue<cryptonote::txin_to_key>(rapidjson::Document& doc, const cryptonote::txin_to_key& txin);

template <>
cryptonote::txin_to_key fromJsonValue<cryptonote::txin_to_key>(const rapidjson::Value& val);

template <>
rapidjson::Value toJsonValue<cryptonote::txout_target_v>(rapidjson::Document& doc, const cryptonote::txout_target_v& txout);

template <>
cryptonote::txout_target_v fromJsonValue<cryptonote::txout_target_v>(const rapidjson::Value& val);

template <>
rapidjson::Value toJsonValue<cryptonote::txout_to_script>(rapidjson::Document& doc, const cryptonote::txout_to_script& txout);

template <>
cryptonote::txout_to_script fromJsonValue<cryptonote::txout_to_script>(const rapidjson::Value& val);

template <>
rapidjson::Value toJsonValue<cryptonote::txout_to_scripthash>(rapidjson::Document& doc, const cryptonote::txout_to_scripthash& txout);

template <>
cryptonote::txout_to_scripthash fromJsonValue<cryptonote::txout_to_scripthash>(const rapidjson::Value& val);

template <>
rapidjson::Value toJsonValue<cryptonote::txout_to_key>(rapidjson::Document& doc, const cryptonote::txout_to_key& txout);

template <>
cryptonote::txout_to_key fromJsonValue<cryptonote::txout_to_key>(const rapidjson::Value& val);

template <>
rapidjson::Value toJsonValue<cryptonote::tx_out>(rapidjson::Document& doc, const cryptonote::tx_out& txout);

template <>
cryptonote::tx_out fromJsonValue<cryptonote::tx_out>(const rapidjson::Value& val);

template <>
rapidjson::Value toJsonValue<cryptonote::connection_info>(rapidjson::Document& doc, const cryptonote::connection_info& info);

template <>
cryptonote::connection_info fromJsonValue<cryptonote::connection_info>(const rapidjson::Value& val);

template <>
rapidjson::Value toJsonValue<cryptonote::block_complete_entry>(rapidjson::Document& doc, const cryptonote::block_complete_entry& blk);

template <>
cryptonote::block_complete_entry fromJsonValue<cryptonote::block_complete_entry>(const rapidjson::Value& val);

template <>
rapidjson::Value toJsonValue<cryptonote::rpc::block_with_transactions>(rapidjson::Document& doc, const cryptonote::rpc::block_with_transactions& blk);

template <>
cryptonote::rpc::block_with_transactions fromJsonValue<cryptonote::rpc::block_with_transactions>(const rapidjson::Value& val);

template <>
rapidjson::Value toJsonValue<cryptonote::rpc::transaction_info>(rapidjson::Document& doc, const cryptonote::rpc::transaction_info& tx_info);

template <>
cryptonote::rpc::transaction_info fromJsonValue<cryptonote::rpc::transaction_info>(const rapidjson::Value& val);

template <>
rapidjson::Value toJsonValue<cryptonote::rpc::output_key_and_amount_index>(rapidjson::Document& doc, const cryptonote::rpc::output_key_and_amount_index& out);

template <>
cryptonote::rpc::output_key_and_amount_index fromJsonValue<cryptonote::rpc::output_key_and_amount_index>(const rapidjson::Value& val);

template <>
rapidjson::Value toJsonValue<cryptonote::rpc::amount_with_random_outputs>(rapidjson::Document& doc, const cryptonote::rpc::amount_with_random_outputs& out);

template <>
cryptonote::rpc::amount_with_random_outputs fromJsonValue<cryptonote::rpc::amount_with_random_outputs>(const rapidjson::Value& val);

template <>
rapidjson::Value toJsonValue<cryptonote::rpc::peer>(rapidjson::Document& doc, const cryptonote::rpc::peer& out);

template <>
cryptonote::rpc::peer fromJsonValue<cryptonote::rpc::peer>(const rapidjson::Value& val);

template <>
rapidjson::Value toJsonValue<cryptonote::rpc::tx_in_pool>(rapidjson::Document& doc, const cryptonote::rpc::tx_in_pool& out);

template <>
cryptonote::rpc::tx_in_pool fromJsonValue<cryptonote::rpc::tx_in_pool>(const rapidjson::Value& val);

template <>
cryptonote::rpc::hard_fork_info fromJsonValue<cryptonote::rpc::hard_fork_info>(const rapidjson::Value& val);

template <>
rapidjson::Value toJsonValue<cryptonote::rpc::hard_fork_info>(rapidjson::Document& doc, const cryptonote::rpc::hard_fork_info& info);

template <>
cryptonote::rpc::output_amount_count fromJsonValue<cryptonote::rpc::output_amount_count>(const rapidjson::Value& val);

template <>
rapidjson::Value toJsonValue<cryptonote::rpc::output_amount_count>(rapidjson::Document& doc, const cryptonote::rpc::output_amount_count& out);

template <>
cryptonote::rpc::output_amount_and_index fromJsonValue<cryptonote::rpc::output_amount_and_index>(const rapidjson::Value& val);

template <>
rapidjson::Value toJsonValue<cryptonote::rpc::output_amount_and_index>(rapidjson::Document& doc, const cryptonote::rpc::output_amount_and_index& out);

template <>
cryptonote::rpc::output_key_mask_unlocked fromJsonValue<cryptonote::rpc::output_key_mask_unlocked>(const rapidjson::Value& val);

template <>
rapidjson::Value toJsonValue<cryptonote::rpc::output_key_mask_unlocked>(rapidjson::Document& doc, const cryptonote::rpc::output_key_mask_unlocked& out);

template <>
cryptonote::rpc::error fromJsonValue<cryptonote::rpc::error>(const rapidjson::Value& val);

template <>
rapidjson::Value toJsonValue<cryptonote::rpc::error>(rapidjson::Document& doc, const cryptonote::rpc::error& err);

template <>
cryptonote::rpc::BlockHeaderResponse fromJsonValue<cryptonote::rpc::BlockHeaderResponse>(const rapidjson::Value& val);

template <>
rapidjson::Value toJsonValue<cryptonote::rpc::BlockHeaderResponse>(rapidjson::Document& doc, const cryptonote::rpc::BlockHeaderResponse& response);


template <typename Map>
rapidjson::Value toJsonValue(rapidjson::Document& doc, const typename std::enable_if<sfinae::is_map_like<Map>::value, Map >::type &val);

template <typename Map>
typename std::enable_if<sfinae::is_map_like<Map>::value, Map>::type fromJsonValue(const rapidjson::Value& val);

template <typename Vec>
rapidjson::Value toJsonValue(rapidjson::Document& doc, const typename std::enable_if<sfinae::is_vector_like<Vec>::value, Vec>::type &vec);

template <typename Vec>
typename std::enable_if<sfinae::is_vector_like<Vec>::value, Vec>::type fromJsonValue(const rapidjson::Value& val);


// ideally would like to have the below functions in the .cpp file, but
// unfortunately because of how templates work they have to be here.

template <typename Map>
rapidjson::Value toJsonValue(rapidjson::Document& doc, const typename std::enable_if<sfinae::is_map_like<Map>::value, Map >::type &val)
{
  rapidjson::Value obj(rapidjson::kObjectType);

  auto& al = doc.GetAllocator();

  for (auto& i : val)
  {
    obj.AddMember(toJsonValue<typename Map::key_type>(doc, i.first), toJsonValue<typename Map::mapped_type>(doc, i.second), al);
  }

  return obj;
}

template <typename Map>
typename std::enable_if<sfinae::is_map_like<Map>::value, Map>::type fromJsonValue(const rapidjson::Value& val)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  Map retmap;

  auto itr = val.MemberBegin();

  while (itr != val.MemberEnd())
  {
    retmap.emplace(fromJsonValue<typename Map::key_type>(itr->name), fromJsonValue<typename Map::mapped_type>(itr->value));
    ++itr;
  }

  return retmap;
}

template <typename Vec>
rapidjson::Value toJsonValue(rapidjson::Document& doc, const typename std::enable_if<sfinae::is_vector_like<Vec>::value, Vec>::type &vec)
{
  rapidjson::Value arr(rapidjson::kArrayType);

  for (const typename Vec::value_type& t : vec)
  {
    arr.PushBack(toJsonValue<typename Vec::value_type>(doc, t), doc.GetAllocator());
  }

  return arr;
}

template <typename Vec>
typename std::enable_if<sfinae::is_vector_like<Vec>::value, Vec>::type fromJsonValue(const rapidjson::Value& val)
{
  if (!val.IsArray())
  {
    throw WRONG_TYPE("json array");
  }

  Vec vec;

  for (rapidjson::SizeType i=0; i < val.Size(); i++)
  {
    vec.push_back(fromJsonValue<typename Vec::value_type>(val[i]));
  }

  return vec;
}






}  // namespace json

}  // namespace cryptonote