// Copyright (c) 2016-2017, The Monero Project
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

#include "json_object.h"

#include "string_tools.h"

namespace cryptonote
{

namespace json
{

void toJsonValue(rapidjson::Document& doc, const std::string& i, rapidjson::Value& val)
{
  val = rapidjson::Value(i.c_str(), doc.GetAllocator());
}

void fromJsonValue(const rapidjson::Value& val, std::string& str)
{
  if (!val.IsString())
  {
    throw WRONG_TYPE("string");
  }

  str = val.GetString();
}

void toJsonValue(rapidjson::Document& doc, bool i, rapidjson::Value& val)
{
  val.SetBool(i);
}

void fromJsonValue(const rapidjson::Value& val, bool& b)
{
  if (!val.IsBool())
  {
    throw WRONG_TYPE("boolean");
  }
  b = val.GetBool();
}

void toJsonValue(rapidjson::Document& doc, const uint8_t& i, rapidjson::Value& val)
{
  val = rapidjson::Value(i);
}


void fromJsonValue(const rapidjson::Value& val, uint8_t& i)
{
  if (!val.IsUint())
  {
    throw WRONG_TYPE("unsigned integer");
  }

  i = (uint8_t)( val.GetUint() & 0xFF);
}

void toJsonValue(rapidjson::Document& doc, const int8_t& i, rapidjson::Value& val)
{
  val = rapidjson::Value(i);
}


void fromJsonValue(const rapidjson::Value& val, int8_t& i)
{
  if (!val.IsInt())
  {
    throw WRONG_TYPE("integer");
  }

  i = (int8_t) ( val.GetInt() & 0xFF);
}

void toJsonValue(rapidjson::Document& doc, const uint16_t& i, rapidjson::Value& val)
{
  val = rapidjson::Value(i);
}


void fromJsonValue(const rapidjson::Value& val, uint16_t& i)
{
  if (!val.IsUint())
  {
    throw WRONG_TYPE("unsigned integer");
  }

  i = (uint16_t) ( val.GetUint() & 0xFFFF);
}

void toJsonValue(rapidjson::Document& doc, const int32_t& i, rapidjson::Value& val)
{
  val = rapidjson::Value(i);
}


void fromJsonValue(const rapidjson::Value& val, int32_t& i)
{
  if (!val.IsInt())
  {
    throw WRONG_TYPE("signed integer");
  }

  i = val.GetInt();
}

void toJsonValue(rapidjson::Document& doc, const uint32_t& i, rapidjson::Value& val)
{
  val = rapidjson::Value(i);
}


void fromJsonValue(const rapidjson::Value& val, uint32_t& i)
{
  if (!val.IsUint())
  {
    throw WRONG_TYPE("unsigned integer");
  }

  i = val.GetUint();
}

void toJsonValue(rapidjson::Document& doc, const uint64_t& i, rapidjson::Value& val)
{
  val = rapidjson::Value(i);
}


void fromJsonValue(const rapidjson::Value& val, uint64_t& i)
{
  if (!val.IsUint64())
  {
    throw WRONG_TYPE("unsigned integer");
  }

  i = val.GetUint64();
}

void toJsonValue(rapidjson::Document& doc, const cryptonote::transaction& tx, rapidjson::Value& val)
{
  val.SetObject();

  INSERT_INTO_JSON_OBJECT(val, doc, version, tx.version);
  INSERT_INTO_JSON_OBJECT(val, doc, unlock_time, tx.unlock_time);
  INSERT_INTO_JSON_OBJECT(val, doc, vin, tx.vin);
  INSERT_INTO_JSON_OBJECT(val, doc, vout, tx.vout);
  INSERT_INTO_JSON_OBJECT(val, doc, extra, tx.extra);
  INSERT_INTO_JSON_OBJECT(val, doc, signatures, tx.signatures);
  INSERT_INTO_JSON_OBJECT(val, doc, rct_signatures, tx.rct_signatures);
}


void fromJsonValue(const rapidjson::Value& val, cryptonote::transaction& tx)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  GET_FROM_JSON_OBJECT(val, tx.version, version);
  GET_FROM_JSON_OBJECT(val, tx.unlock_time, unlock_time);
  GET_FROM_JSON_OBJECT(val, tx.vin, vin);
  GET_FROM_JSON_OBJECT(val, tx.vout, vout);
  GET_FROM_JSON_OBJECT(val, tx.extra, extra);
  GET_FROM_JSON_OBJECT(val, tx.signatures, signatures);
  GET_FROM_JSON_OBJECT(val, tx.rct_signatures, rct_signatures);
}

void toJsonValue(rapidjson::Document& doc, const cryptonote::block& b, rapidjson::Value& val)
{
  val.SetObject();

  INSERT_INTO_JSON_OBJECT(val, doc, major_version, b.major_version);
  INSERT_INTO_JSON_OBJECT(val, doc, minor_version, b.minor_version);
  INSERT_INTO_JSON_OBJECT(val, doc, timestamp, b.timestamp);
  INSERT_INTO_JSON_OBJECT(val, doc, prev_id, b.prev_id);
  INSERT_INTO_JSON_OBJECT(val, doc, nonce, b.nonce);
  INSERT_INTO_JSON_OBJECT(val, doc, miner_tx, b.miner_tx);
  INSERT_INTO_JSON_OBJECT(val, doc, tx_hashes, b.tx_hashes);
}


void fromJsonValue(const rapidjson::Value& val, cryptonote::block& b)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  GET_FROM_JSON_OBJECT(val, b.major_version, major_version);
  GET_FROM_JSON_OBJECT(val, b.minor_version, minor_version);
  GET_FROM_JSON_OBJECT(val, b.timestamp, timestamp);
  GET_FROM_JSON_OBJECT(val, b.prev_id, prev_id);
  GET_FROM_JSON_OBJECT(val, b.nonce, nonce);
  GET_FROM_JSON_OBJECT(val, b.miner_tx, miner_tx);
  GET_FROM_JSON_OBJECT(val, b.tx_hashes, tx_hashes);
}

void toJsonValue(rapidjson::Document& doc, const cryptonote::txin_v& txin, rapidjson::Value& val)
{
  val.SetObject();

  if (txin.type() == typeid(cryptonote::txin_gen))
  {
    val.AddMember("type", "txin_gen", doc.GetAllocator());
    INSERT_INTO_JSON_OBJECT(val, doc, value, boost::get<cryptonote::txin_gen>(txin));
  }
  else if (txin.type() == typeid(cryptonote::txin_to_script))
  {
    val.AddMember("type", "txin_to_script", doc.GetAllocator());
    INSERT_INTO_JSON_OBJECT(val, doc, value, boost::get<cryptonote::txin_to_script>(txin));
  }
  else if (txin.type() == typeid(cryptonote::txin_to_scripthash))
  {
    val.AddMember("type", "txin_to_scripthash", doc.GetAllocator());
    INSERT_INTO_JSON_OBJECT(val, doc, value, boost::get<cryptonote::txin_to_scripthash>(txin));
  }
  else if (txin.type() == typeid(cryptonote::txin_to_key))
  {
    val.AddMember("type", "txin_to_key", doc.GetAllocator());
    INSERT_INTO_JSON_OBJECT(val, doc, value, boost::get<cryptonote::txin_to_key>(txin));
  }
}


void fromJsonValue(const rapidjson::Value& val, cryptonote::txin_v& txin)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  OBJECT_HAS_MEMBER_OR_THROW(val, "type")
  OBJECT_HAS_MEMBER_OR_THROW(val, "value")
  if (val["type"]== "txin_gen")
  {
    cryptonote::txin_gen tmpVal;
    fromJsonValue(val["value"], tmpVal);
    txin = tmpVal;
  }
  else if (val["type"]== "txin_to_script")
  {
    cryptonote::txin_to_script tmpVal;
    fromJsonValue(val["value"], tmpVal);
    txin = tmpVal;
  }
  else if (val["type"] == "txin_to_scripthash")
  {
    cryptonote::txin_to_scripthash tmpVal;
    fromJsonValue(val["value"], tmpVal);
    txin = tmpVal;
  }
  else if (val["type"] == "txin_to_key")
  {
    cryptonote::txin_to_key tmpVal;
    fromJsonValue(val["value"], tmpVal);
    txin = tmpVal;
  }
}

void toJsonValue(rapidjson::Document& doc, const cryptonote::txin_gen& txin, rapidjson::Value& val)
{
  val.SetObject();

  INSERT_INTO_JSON_OBJECT(val, doc, height, txin.height);
}


void fromJsonValue(const rapidjson::Value& val, cryptonote::txin_gen& txin)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  GET_FROM_JSON_OBJECT(val, txin.height, height);
}

void toJsonValue(rapidjson::Document& doc, const cryptonote::txin_to_script& txin, rapidjson::Value& val)
{
  val.SetObject();

  INSERT_INTO_JSON_OBJECT(val, doc, prev, txin.prev);
  INSERT_INTO_JSON_OBJECT(val, doc, prevout, txin.prevout);
  INSERT_INTO_JSON_OBJECT(val, doc, sigset, txin.sigset);
}


void fromJsonValue(const rapidjson::Value& val, cryptonote::txin_to_script& txin)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  GET_FROM_JSON_OBJECT(val, txin.prev, prev);
  GET_FROM_JSON_OBJECT(val, txin.prevout, prevout);
  GET_FROM_JSON_OBJECT(val, txin.sigset, sigset);
}

void toJsonValue(rapidjson::Document& doc, const cryptonote::txin_to_scripthash& txin, rapidjson::Value& val)
{
  val.SetObject();

  INSERT_INTO_JSON_OBJECT(val, doc, prev, txin.prev);
  INSERT_INTO_JSON_OBJECT(val, doc, prevout, txin.prevout);
  INSERT_INTO_JSON_OBJECT(val, doc, script, txin.script);
  INSERT_INTO_JSON_OBJECT(val, doc, sigset, txin.sigset);
}


void fromJsonValue(const rapidjson::Value& val, cryptonote::txin_to_scripthash& txin)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  GET_FROM_JSON_OBJECT(val, txin.prev, prev);
  GET_FROM_JSON_OBJECT(val, txin.prevout, prevout);
  GET_FROM_JSON_OBJECT(val, txin.script, script);
  GET_FROM_JSON_OBJECT(val, txin.sigset, sigset);
}

void toJsonValue(rapidjson::Document& doc, const cryptonote::txin_to_key& txin, rapidjson::Value& val)
{
  val.SetObject();

  INSERT_INTO_JSON_OBJECT(val, doc, amount, txin.amount);
  INSERT_INTO_JSON_OBJECT(val, doc, key_offsets, txin.key_offsets);
  INSERT_INTO_JSON_OBJECT(val, doc, k_image, txin.k_image);
}


void fromJsonValue(const rapidjson::Value& val, cryptonote::txin_to_key& txin)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  GET_FROM_JSON_OBJECT(val, txin.amount, amount);
  GET_FROM_JSON_OBJECT(val, txin.key_offsets, key_offsets);
  GET_FROM_JSON_OBJECT(val, txin.k_image, k_image);
}

void toJsonValue(rapidjson::Document& doc, const cryptonote::txout_target_v& txout, rapidjson::Value& val)
{
  val.SetObject();

  if (txout.type() == typeid(cryptonote::txout_to_script))
  {
    val.AddMember("type", "txout_to_script", doc.GetAllocator());
    INSERT_INTO_JSON_OBJECT(val, doc, value, boost::get<cryptonote::txout_to_script>(txout));
  }
  else if (txout.type() == typeid(cryptonote::txout_to_scripthash))
  {
    val.AddMember("type", "txout_to_scripthash", doc.GetAllocator());
    INSERT_INTO_JSON_OBJECT(val, doc, value, boost::get<cryptonote::txout_to_scripthash>(txout));
  }
  else if (txout.type() == typeid(cryptonote::txout_to_key))
  {
    val.AddMember("type", "txout_to_key", doc.GetAllocator());
    INSERT_INTO_JSON_OBJECT(val, doc, value, boost::get<cryptonote::txout_to_key>(txout));
  }
}


void fromJsonValue(const rapidjson::Value& val, cryptonote::txout_target_v& txout)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  OBJECT_HAS_MEMBER_OR_THROW(val, "type")
  OBJECT_HAS_MEMBER_OR_THROW(val, "value")
  if (val["type"]== "txout_to_script")
  {
    cryptonote::txout_to_script tmpVal;
    fromJsonValue(val["value"], tmpVal);
    txout = tmpVal;
  }
  else if (val["type"] == "txout_to_scripthash")
  {
    cryptonote::txout_to_scripthash tmpVal;
    fromJsonValue(val["value"], tmpVal);
    txout = tmpVal;
  }
  else if (val["type"] == "txout_to_key")
  {
    cryptonote::txout_to_key tmpVal;
    fromJsonValue(val["value"], tmpVal);
    txout = tmpVal;
  }
}

void toJsonValue(rapidjson::Document& doc, const cryptonote::txout_to_script& txout, rapidjson::Value& val)
{
  val.SetObject();

  INSERT_INTO_JSON_OBJECT(val, doc, keys, txout.keys);
  INSERT_INTO_JSON_OBJECT(val, doc, script, txout.script);
}


void fromJsonValue(const rapidjson::Value& val, cryptonote::txout_to_script& txout)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  GET_FROM_JSON_OBJECT(val, txout.keys, keys);
  GET_FROM_JSON_OBJECT(val, txout.script, script);
}

void toJsonValue(rapidjson::Document& doc, const cryptonote::txout_to_scripthash& txout, rapidjson::Value& val)
{
  val.SetObject();

  INSERT_INTO_JSON_OBJECT(val, doc, hash, txout.hash);
}


void fromJsonValue(const rapidjson::Value& val, cryptonote::txout_to_scripthash& txout)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  GET_FROM_JSON_OBJECT(val, txout.hash, hash);
}

void toJsonValue(rapidjson::Document& doc, const cryptonote::txout_to_key& txout, rapidjson::Value& val)
{
  val.SetObject();

  INSERT_INTO_JSON_OBJECT(val, doc, key, txout.key);
}


void fromJsonValue(const rapidjson::Value& val, cryptonote::txout_to_key& txout)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  GET_FROM_JSON_OBJECT(val, txout.key, key);
}

void toJsonValue(rapidjson::Document& doc, const cryptonote::tx_out& txout, rapidjson::Value& val)
{
  val.SetObject();

  INSERT_INTO_JSON_OBJECT(val, doc, amount, txout.amount);
  INSERT_INTO_JSON_OBJECT(val, doc, target, txout.target);
}

void fromJsonValue(const rapidjson::Value& val, cryptonote::tx_out& txout)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  GET_FROM_JSON_OBJECT(val, txout.amount, amount);
  GET_FROM_JSON_OBJECT(val, txout.target, target);
}

void toJsonValue(rapidjson::Document& doc, const cryptonote::connection_info& info, rapidjson::Value& val)
{
  val.SetObject();

  auto& al = doc.GetAllocator();
  INSERT_INTO_JSON_OBJECT(val, doc, incoming, info.incoming);
  INSERT_INTO_JSON_OBJECT(val, doc, localhost, info.localhost);
  INSERT_INTO_JSON_OBJECT(val, doc, local_ip, info.local_ip);

  INSERT_INTO_JSON_OBJECT(val, doc, ip, info.ip);
  INSERT_INTO_JSON_OBJECT(val, doc, port, info.port);

  INSERT_INTO_JSON_OBJECT(val, doc, peer_id, info.peer_id);

  INSERT_INTO_JSON_OBJECT(val, doc, recv_count, info.recv_count);
  INSERT_INTO_JSON_OBJECT(val, doc, recv_idle_time, info.recv_idle_time);

  INSERT_INTO_JSON_OBJECT(val, doc, send_count, info.send_count);
  INSERT_INTO_JSON_OBJECT(val, doc, send_idle_time, info.send_idle_time);

  INSERT_INTO_JSON_OBJECT(val, doc, state, info.state);

  INSERT_INTO_JSON_OBJECT(val, doc, live_time, info.live_time);

  INSERT_INTO_JSON_OBJECT(val, doc, avg_download, info.avg_download);
  INSERT_INTO_JSON_OBJECT(val, doc, current_download, info.current_download);

  INSERT_INTO_JSON_OBJECT(val, doc, avg_upload, info.avg_upload);
  INSERT_INTO_JSON_OBJECT(val, doc, current_upload, info.current_upload);
}


void fromJsonValue(const rapidjson::Value& val, cryptonote::connection_info& info)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  GET_FROM_JSON_OBJECT(val, info.incoming, incoming);
  GET_FROM_JSON_OBJECT(val, info.localhost, localhost);
  GET_FROM_JSON_OBJECT(val, info.local_ip, local_ip);

  GET_FROM_JSON_OBJECT(val, info.ip, ip);
  GET_FROM_JSON_OBJECT(val, info.port, port);

  GET_FROM_JSON_OBJECT(val, info.peer_id, peer_id);

  GET_FROM_JSON_OBJECT(val, info.recv_count, recv_count);
  GET_FROM_JSON_OBJECT(val, info.recv_idle_time, recv_idle_time);

  GET_FROM_JSON_OBJECT(val, info.send_count, send_count);
  GET_FROM_JSON_OBJECT(val, info.send_idle_time, send_idle_time);

  GET_FROM_JSON_OBJECT(val, info.state, state);

  GET_FROM_JSON_OBJECT(val, info.live_time, live_time);

  GET_FROM_JSON_OBJECT(val, info.avg_download, avg_download);
  GET_FROM_JSON_OBJECT(val, info.current_download, current_download);

  GET_FROM_JSON_OBJECT(val, info.avg_upload, avg_upload);
  GET_FROM_JSON_OBJECT(val, info.current_upload, current_upload);
}

void toJsonValue(rapidjson::Document& doc, const cryptonote::block_complete_entry& blk, rapidjson::Value& val)
{
  val.SetObject();

  INSERT_INTO_JSON_OBJECT(val, doc, block, blk.block);
  INSERT_INTO_JSON_OBJECT(val, doc, txs, blk.txs);
}


void fromJsonValue(const rapidjson::Value& val, cryptonote::block_complete_entry& blk)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  GET_FROM_JSON_OBJECT(val, blk.block, block);
  GET_FROM_JSON_OBJECT(val, blk.txs, txs);
}

void toJsonValue(rapidjson::Document& doc, const cryptonote::rpc::block_with_transactions& blk, rapidjson::Value& val)
{
  val.SetObject();

  INSERT_INTO_JSON_OBJECT(val, doc, block, blk.block);
  INSERT_INTO_JSON_OBJECT(val, doc, transactions, blk.transactions);
}


void fromJsonValue(const rapidjson::Value& val, cryptonote::rpc::block_with_transactions& blk)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  GET_FROM_JSON_OBJECT(val, blk.block, block);
  GET_FROM_JSON_OBJECT(val, blk.transactions, transactions);
}

void toJsonValue(rapidjson::Document& doc, const cryptonote::rpc::transaction_info& tx_info, rapidjson::Value& val)
{
  val.SetObject();

  INSERT_INTO_JSON_OBJECT(val, doc, height, tx_info.height);
  INSERT_INTO_JSON_OBJECT(val, doc, in_pool, tx_info.in_pool);
  INSERT_INTO_JSON_OBJECT(val, doc, transaction, tx_info.transaction);
}


void fromJsonValue(const rapidjson::Value& val, cryptonote::rpc::transaction_info& tx_info)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  GET_FROM_JSON_OBJECT(val, tx_info.height, height);
  GET_FROM_JSON_OBJECT(val, tx_info.in_pool, in_pool);
  GET_FROM_JSON_OBJECT(val, tx_info.transaction, transaction);
}

void toJsonValue(rapidjson::Document& doc, const cryptonote::rpc::output_key_and_amount_index& out, rapidjson::Value& val)
{
  val.SetObject();

  INSERT_INTO_JSON_OBJECT(val, doc, amount_index, out.amount_index);
  INSERT_INTO_JSON_OBJECT(val, doc, key, out.key);
}


void fromJsonValue(const rapidjson::Value& val, cryptonote::rpc::output_key_and_amount_index& out)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  GET_FROM_JSON_OBJECT(val, out.amount_index, amount_index);
  GET_FROM_JSON_OBJECT(val, out.key, key);
}

void toJsonValue(rapidjson::Document& doc, const cryptonote::rpc::amount_with_random_outputs& out, rapidjson::Value& val)
{
  val.SetObject();

  INSERT_INTO_JSON_OBJECT(val, doc, amount, out.amount);
  INSERT_INTO_JSON_OBJECT(val, doc, outputs, out.outputs);
}


void fromJsonValue(const rapidjson::Value& val, cryptonote::rpc::amount_with_random_outputs& out)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  GET_FROM_JSON_OBJECT(val, out.amount, amount);
  GET_FROM_JSON_OBJECT(val, out.outputs, outputs);
}

void toJsonValue(rapidjson::Document& doc, const cryptonote::rpc::peer& peer, rapidjson::Value& val)
{
  val.SetObject();

  INSERT_INTO_JSON_OBJECT(val, doc, id, peer.id);
  INSERT_INTO_JSON_OBJECT(val, doc, ip, peer.ip);
  INSERT_INTO_JSON_OBJECT(val, doc, port, peer.port);
  INSERT_INTO_JSON_OBJECT(val, doc, last_seen, peer.last_seen);
}


void fromJsonValue(const rapidjson::Value& val, cryptonote::rpc::peer& peer)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  GET_FROM_JSON_OBJECT(val, peer.id, id);
  GET_FROM_JSON_OBJECT(val, peer.ip, ip);
  GET_FROM_JSON_OBJECT(val, peer.port, port);
  GET_FROM_JSON_OBJECT(val, peer.last_seen, last_seen);
}

void toJsonValue(rapidjson::Document& doc, const cryptonote::rpc::tx_in_pool& tx, rapidjson::Value& val)
{
  val.SetObject();

  INSERT_INTO_JSON_OBJECT(val, doc, tx, tx.tx);
  INSERT_INTO_JSON_OBJECT(val, doc, tx_hash, tx.tx_hash);
  INSERT_INTO_JSON_OBJECT(val, doc, blob_size, tx.blob_size);
  INSERT_INTO_JSON_OBJECT(val, doc, fee, tx.fee);
  INSERT_INTO_JSON_OBJECT(val, doc, max_used_block_hash, tx.max_used_block_hash);
  INSERT_INTO_JSON_OBJECT(val, doc, max_used_block_height, tx.max_used_block_height);
  INSERT_INTO_JSON_OBJECT(val, doc, kept_by_block, tx.kept_by_block);
  INSERT_INTO_JSON_OBJECT(val, doc, last_failed_block_hash, tx.last_failed_block_hash);
  INSERT_INTO_JSON_OBJECT(val, doc, last_failed_block_height, tx.last_failed_block_height);
  INSERT_INTO_JSON_OBJECT(val, doc, receive_time, tx.receive_time);
  INSERT_INTO_JSON_OBJECT(val, doc, last_relayed_time, tx.last_relayed_time);
  INSERT_INTO_JSON_OBJECT(val, doc, relayed, tx.relayed);
  INSERT_INTO_JSON_OBJECT(val, doc, do_not_relay, tx.do_not_relay);
}


void fromJsonValue(const rapidjson::Value& val, cryptonote::rpc::tx_in_pool& tx)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  GET_FROM_JSON_OBJECT(val, tx.tx, tx);
  GET_FROM_JSON_OBJECT(val, tx.blob_size, blob_size);
  GET_FROM_JSON_OBJECT(val, tx.fee, fee);
  GET_FROM_JSON_OBJECT(val, tx.max_used_block_hash, max_used_block_hash);
  GET_FROM_JSON_OBJECT(val, tx.max_used_block_height, max_used_block_height);
  GET_FROM_JSON_OBJECT(val, tx.kept_by_block, kept_by_block);
  GET_FROM_JSON_OBJECT(val, tx.last_failed_block_hash, last_failed_block_hash);
  GET_FROM_JSON_OBJECT(val, tx.last_failed_block_height, last_failed_block_height);
  GET_FROM_JSON_OBJECT(val, tx.receive_time, receive_time);
  GET_FROM_JSON_OBJECT(val, tx.last_relayed_time, last_relayed_time);
  GET_FROM_JSON_OBJECT(val, tx.relayed, relayed);
}

void toJsonValue(rapidjson::Document& doc, const cryptonote::rpc::hard_fork_info& info, rapidjson::Value& val)
{
  val.SetObject();

  INSERT_INTO_JSON_OBJECT(val, doc, version, info.version);
  INSERT_INTO_JSON_OBJECT(val, doc, enabled, info.enabled);
  INSERT_INTO_JSON_OBJECT(val, doc, window, info.window);
  INSERT_INTO_JSON_OBJECT(val, doc, votes, info.votes);
  INSERT_INTO_JSON_OBJECT(val, doc, threshold, info.threshold);
  INSERT_INTO_JSON_OBJECT(val, doc, voting, info.voting);
  INSERT_INTO_JSON_OBJECT(val, doc, state, info.state);
  INSERT_INTO_JSON_OBJECT(val, doc, earliest_height, info.earliest_height);
}


void fromJsonValue(const rapidjson::Value& val, cryptonote::rpc::hard_fork_info& info)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  GET_FROM_JSON_OBJECT(val, info.version, version);
  GET_FROM_JSON_OBJECT(val, info.enabled, enabled);
  GET_FROM_JSON_OBJECT(val, info.window, window);
  GET_FROM_JSON_OBJECT(val, info.votes, votes);
  GET_FROM_JSON_OBJECT(val, info.threshold, threshold);
  GET_FROM_JSON_OBJECT(val, info.voting, voting);
  GET_FROM_JSON_OBJECT(val, info.state, state);
  GET_FROM_JSON_OBJECT(val, info.earliest_height, earliest_height);
}

void toJsonValue(rapidjson::Document& doc, const cryptonote::rpc::output_amount_count& out, rapidjson::Value& val)
{
  val.SetObject();

  INSERT_INTO_JSON_OBJECT(val, doc, amount, out.amount);
  INSERT_INTO_JSON_OBJECT(val, doc, total_count, out.total_count);
  INSERT_INTO_JSON_OBJECT(val, doc, unlocked_count, out.unlocked_count);
  INSERT_INTO_JSON_OBJECT(val, doc, recent_count, out.recent_count);
}


void fromJsonValue(const rapidjson::Value& val, cryptonote::rpc::output_amount_count& out)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  GET_FROM_JSON_OBJECT(val, out.amount, amount);
  GET_FROM_JSON_OBJECT(val, out.total_count, total_count);
  GET_FROM_JSON_OBJECT(val, out.unlocked_count, unlocked_count);
  GET_FROM_JSON_OBJECT(val, out.recent_count, recent_count);
}

void toJsonValue(rapidjson::Document& doc, const cryptonote::rpc::output_amount_and_index& out, rapidjson::Value& val)
{
  val.SetObject();

  INSERT_INTO_JSON_OBJECT(val, doc, amount, out.amount);
  INSERT_INTO_JSON_OBJECT(val, doc, index, out.index);
}


void fromJsonValue(const rapidjson::Value& val, cryptonote::rpc::output_amount_and_index& out)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  GET_FROM_JSON_OBJECT(val, out.amount, amount);
  GET_FROM_JSON_OBJECT(val, out.index, index);
}

void toJsonValue(rapidjson::Document& doc, const cryptonote::rpc::output_key_mask_unlocked& out, rapidjson::Value& val)
{
  val.SetObject();

  INSERT_INTO_JSON_OBJECT(val, doc, key, out.key);
  INSERT_INTO_JSON_OBJECT(val, doc, mask, out.mask);
  INSERT_INTO_JSON_OBJECT(val, doc, unlocked, out.unlocked);
}

void fromJsonValue(const rapidjson::Value& val, cryptonote::rpc::output_key_mask_unlocked& out)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  GET_FROM_JSON_OBJECT(val, out.key, key);
  GET_FROM_JSON_OBJECT(val, out.mask, mask);
  GET_FROM_JSON_OBJECT(val, out.unlocked, unlocked);
}

void toJsonValue(rapidjson::Document& doc, const cryptonote::rpc::error& err, rapidjson::Value& val)
{
  val.SetObject();

  INSERT_INTO_JSON_OBJECT(val, doc, code, err.code);
  INSERT_INTO_JSON_OBJECT(val, doc, error_str, err.error_str);
  INSERT_INTO_JSON_OBJECT(val, doc, message, err.message);
}

void fromJsonValue(const rapidjson::Value& val, cryptonote::rpc::error& error)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  GET_FROM_JSON_OBJECT(val, error.code, code);
  GET_FROM_JSON_OBJECT(val, error.error_str, error_str);
  GET_FROM_JSON_OBJECT(val, error.message, message);
}

void toJsonValue(rapidjson::Document& doc, const cryptonote::rpc::BlockHeaderResponse& response, rapidjson::Value& val)
{
  val.SetObject();

  INSERT_INTO_JSON_OBJECT(val, doc, major_version, response.major_version);
  INSERT_INTO_JSON_OBJECT(val, doc, minor_version, response.minor_version);
  INSERT_INTO_JSON_OBJECT(val, doc, timestamp, response.timestamp);
  INSERT_INTO_JSON_OBJECT(val, doc, prev_id, response.prev_id);
  INSERT_INTO_JSON_OBJECT(val, doc, nonce, response.nonce);
  INSERT_INTO_JSON_OBJECT(val, doc, height, response.height);
  INSERT_INTO_JSON_OBJECT(val, doc, depth, response.depth);
  INSERT_INTO_JSON_OBJECT(val, doc, hash, response.hash);
  INSERT_INTO_JSON_OBJECT(val, doc, difficulty, response.difficulty);
  INSERT_INTO_JSON_OBJECT(val, doc, reward, response.reward);
}

void fromJsonValue(const rapidjson::Value& val, cryptonote::rpc::BlockHeaderResponse& response)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  GET_FROM_JSON_OBJECT(val, response.major_version, major_version);
  GET_FROM_JSON_OBJECT(val, response.minor_version, minor_version);
  GET_FROM_JSON_OBJECT(val, response.timestamp, timestamp);
  GET_FROM_JSON_OBJECT(val, response.prev_id, prev_id);
  GET_FROM_JSON_OBJECT(val, response.nonce, nonce);
  GET_FROM_JSON_OBJECT(val, response.height, height);
  GET_FROM_JSON_OBJECT(val, response.depth, depth);
  GET_FROM_JSON_OBJECT(val, response.hash, hash);
  GET_FROM_JSON_OBJECT(val, response.difficulty, difficulty);
  GET_FROM_JSON_OBJECT(val, response.reward, reward);
}

void toJsonValue(rapidjson::Document& doc, const rct::rctSig& sig, rapidjson::Value& val)
{
  val.SetObject();

  INSERT_INTO_JSON_OBJECT(val, doc, type, sig.type);
  INSERT_INTO_JSON_OBJECT(val, doc, message, sig.message);
  INSERT_INTO_JSON_OBJECT(val, doc, mixRing, sig.mixRing);
  INSERT_INTO_JSON_OBJECT(val, doc, pseudoOuts, sig.pseudoOuts);
  INSERT_INTO_JSON_OBJECT(val, doc, ecdhInfo, sig.ecdhInfo);
  INSERT_INTO_JSON_OBJECT(val, doc, outPk, sig.outPk);
  INSERT_INTO_JSON_OBJECT(val, doc, txnFee, sig.txnFee);
  INSERT_INTO_JSON_OBJECT(val, doc, p, sig.p);
}

void fromJsonValue(const rapidjson::Value& val, rct::rctSig& sig)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  GET_FROM_JSON_OBJECT(val, sig.type, type);
  GET_FROM_JSON_OBJECT(val, sig.message, message);
  GET_FROM_JSON_OBJECT(val, sig.mixRing, mixRing);
  GET_FROM_JSON_OBJECT(val, sig.pseudoOuts, pseudoOuts);
  GET_FROM_JSON_OBJECT(val, sig.ecdhInfo, ecdhInfo);
  GET_FROM_JSON_OBJECT(val, sig.outPk, outPk);
  GET_FROM_JSON_OBJECT(val, sig.txnFee, txnFee);
  GET_FROM_JSON_OBJECT(val, sig.p, p);
}

void toJsonValue(rapidjson::Document& doc, const rct::ctkey& key, rapidjson::Value& val)
{
  val.SetObject();

  INSERT_INTO_JSON_OBJECT(val, doc, dest, key.dest);
  INSERT_INTO_JSON_OBJECT(val, doc, mask, key.mask);
}

void fromJsonValue(const rapidjson::Value& val, rct::ctkey& key)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }
  GET_FROM_JSON_OBJECT(val, key.dest, dest);
  GET_FROM_JSON_OBJECT(val, key.mask, mask);
}

void toJsonValue(rapidjson::Document& doc, const rct::ecdhTuple& tuple, rapidjson::Value& val)
{
  val.SetObject();

  INSERT_INTO_JSON_OBJECT(val, doc, mask, tuple.mask);
  INSERT_INTO_JSON_OBJECT(val, doc, amount, tuple.amount);
}

void fromJsonValue(const rapidjson::Value& val, rct::ecdhTuple& tuple)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  GET_FROM_JSON_OBJECT(val, tuple.mask, mask);
  GET_FROM_JSON_OBJECT(val, tuple.amount, amount);
}

void toJsonValue(rapidjson::Document& doc, const rct::rctSigPrunable& sig, rapidjson::Value& val)
{
  val.SetObject();

  INSERT_INTO_JSON_OBJECT(val, doc, rangeSigs, sig.rangeSigs);
  INSERT_INTO_JSON_OBJECT(val, doc, MGs, sig.MGs);
}

void fromJsonValue(const rapidjson::Value& val, rct::rctSigPrunable& sig)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  GET_FROM_JSON_OBJECT(val, sig.rangeSigs, rangeSigs);
  GET_FROM_JSON_OBJECT(val, sig.MGs, MGs);
}

void toJsonValue(rapidjson::Document& doc, const rct::rangeSig& sig, rapidjson::Value& val)
{
  val.SetObject();

  INSERT_INTO_JSON_OBJECT(val, doc, asig, sig.asig);

  std::vector<rct::key> keyVector(sig.Ci, std::end(sig.Ci));
  INSERT_INTO_JSON_OBJECT(val, doc, Ci, keyVector);
}

void fromJsonValue(const rapidjson::Value& val, rct::rangeSig& sig)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  GET_FROM_JSON_OBJECT(val, sig.asig, asig);

  std::vector<rct::key> keyVector;
  cryptonote::json::fromJsonValue(val["Ci"], keyVector);
  if (!(keyVector.size() == 64))
  {
    throw WRONG_TYPE("key64 (rct::key[64])");
  }
  for (size_t i=0; i < 64; i++)
  {
    sig.Ci[i] = keyVector[i];
  }
}

void toJsonValue(rapidjson::Document& doc, const rct::boroSig& sig, rapidjson::Value& val)
{
  val.SetObject();

  std::vector<rct::key> keyVector(sig.s0, std::end(sig.s0));
  INSERT_INTO_JSON_OBJECT(val, doc, s0, sig.s0);

  keyVector.assign(sig.s1, std::end(sig.s1));
  INSERT_INTO_JSON_OBJECT(val, doc, s1, sig.s1);

  INSERT_INTO_JSON_OBJECT(val, doc, ee, sig.ee);
}

void fromJsonValue(const rapidjson::Value& val, rct::boroSig& sig)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  OBJECT_HAS_MEMBER_OR_THROW(val, "s0")
  std::vector<rct::key> keyVector;
  cryptonote::json::fromJsonValue(val["s0"], keyVector);
  if (!(keyVector.size() == 64))
  {
    throw WRONG_TYPE("key64 (rct::key[64])");
  }
  for (size_t i=0; i < 64; i++)
  {
    sig.s0[i] = keyVector[i];
  }

  OBJECT_HAS_MEMBER_OR_THROW(val, "s1")
  keyVector.clear();
  cryptonote::json::fromJsonValue(val["s1"], keyVector);
  if (!(keyVector.size() == 64))
  {
    throw WRONG_TYPE("key64 (rct::key[64])");
  }
  for (size_t i=0; i < 64; i++)
  {
    sig.s1[i] = keyVector[i];
  }

  GET_FROM_JSON_OBJECT(val, sig.ee, ee);
}

void toJsonValue(rapidjson::Document& doc, const rct::mgSig& sig, rapidjson::Value& val)
{
  val.SetObject();

  INSERT_INTO_JSON_OBJECT(val, doc, ss, sig.ss);
  INSERT_INTO_JSON_OBJECT(val, doc, cc, sig.cc);
}

void fromJsonValue(const rapidjson::Value& val, rct::mgSig& sig)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("key64 (rct::key[64])");
  }

  GET_FROM_JSON_OBJECT(val, sig.ss, ss);
  GET_FROM_JSON_OBJECT(val, sig.cc, cc);
}

}  // namespace json

}  // namespace cryptonote