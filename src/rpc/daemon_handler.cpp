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

#include "daemon_handler.h"

// likely included by daemon_handler.h's includes,
// but including here for clarity
#include "cryptonote_core/tx_pool.h"
#include "cryptonote_core/cryptonote_format_utils.h"

namespace cryptonote
{

namespace rpc
{

  void DaemonHandler::handle(GetHeight::Request& req, GetHeight::Response& res)
  {
    res.height = m_core.get_current_blockchain_height();
  }

  void DaemonHandler::handle(GetBlocksFast::Request& req, GetBlocksFast::Response& res)
  {
    std::list<std::pair<block, std::list<transaction> > > blocks;

    if(!m_core.find_blockchain_supplement(req.start_height, req.block_ids, blocks, res.current_height, res.start_height, COMMAND_RPC_GET_BLOCKS_FAST_MAX_COUNT))
    {
      res.status = Message::STATUS_FAILED;
      res.error_details = "core::find_blockchain_supplement() returned false";
      return;
    }

    res.blocks.resize(blocks.size());

    //TODO: really need to switch uses of std::list to std::vector unless
    //      it's a huge performance concern

    auto it = blocks.begin();

    uint64_t block_count = 0;
    while (it != blocks.end())
    {
      cryptonote::rpc::block_with_transactions& bwt = res.blocks[block_count];

      block& blk = it->first;
      bwt.block = blk;

      std::list<transaction>& txs = it->second;

      // assume each block returned is returned with all its transactions
      // in the correct order.
      auto tx_it = txs.begin();
      for (crypto::hash& h : blk.tx_hashes)
      {
        bwt.transactions.emplace(h, *tx_it);
        tx_it++;
      }

      it++;
      block_count++;
    }

    res.status = Message::STATUS_OK;
  }

  void DaemonHandler::handle(GetHashesFast::Request& req, GetHashesFast::Response& res)
  {
    res.start_height = req.start_height;

    auto& chain = m_core.get_blockchain_storage();

    if (!chain.find_blockchain_supplement(req.known_hashes, res.hashes, res.start_height, res.current_height))
    {
      res.status = Message::STATUS_FAILED;
      res.error_details = "Blockchain::find_blockchain_supplement() returned false";
      return;
    }

    res.status = Message::STATUS_OK;
  }

  void DaemonHandler::handle(GetTransactions::Request& req, GetTransactions::Response& res)
  {
    std::list<cryptonote::transaction> found_txs;
    std::list<crypto::hash> missed_hashes;

    bool r = m_core.get_transactions(req.tx_hashes, found_txs, missed_hashes);

    // TODO: handle return false (std::exception caught above)
    if (!r)
    {
    }

    uint64_t num_found = found_txs.size();

    // std::list is annoying
    std::vector<cryptonote::transaction> found_txs_vec
    {
      std::make_move_iterator(std::begin(found_txs)),
      std::make_move_iterator(std::end(found_txs))
    };

    std::vector<crypto::hash> missed_vec
    {
      std::make_move_iterator(std::begin(missed_hashes)),
      std::make_move_iterator(std::end(missed_hashes))
    };

    std::vector<uint64_t> heights(num_found);
    std::vector<bool> in_pool(num_found, false);
    std::vector<crypto::hash> found_hashes(num_found);

    for (size_t i=0; i < num_found; i++)
    {
      found_hashes[i] = get_transaction_hash(found_txs_vec[i]);
      heights[i] = m_core.get_blockchain_storage().get_db().get_tx_block_height(found_hashes[i]);
    }

    // if any missing from blockchain, check in tx pool
    if (!missed_vec.empty())
    {
      std::list<cryptonote::transaction> pool_txs;

      m_core.get_pool_transactions(pool_txs);

      for (auto& tx : pool_txs)
      {
        crypto::hash h = get_transaction_hash(tx);

        auto itr = std::find(missed_vec.begin(), missed_vec.end(), h);

        if (itr != missed_vec.begin())
        {
          found_hashes.push_back(h);
          found_txs_vec.push_back(tx);
          heights.push_back(std::numeric_limits<uint64_t>::max());
          in_pool.push_back(true);
          missed_vec.erase(itr);
        }
      }
    }

    for (size_t i=0; i < found_hashes.size(); i++)
    {
      cryptonote::rpc::transaction_info info;
      info.height = heights[i];
      info.in_pool = in_pool[i];
      info.transaction = std::move(found_txs_vec[i]);

      res.txs.emplace(found_hashes[i], std::move(info));
    }
                                      
    res.missed_hashes = std::move(missed_vec);
  }

  void DaemonHandler::handle(KeyImagesSpent::Request& req, KeyImagesSpent::Response& res)
  {
    res.spent_status.resize(req.key_images.size(), KeyImagesSpent::STATUS::UNSPENT);

    std::vector<bool> chain_spent_status;
    std::vector<bool> pool_spent_status;

    m_core.are_key_images_spent(req.key_images, chain_spent_status);
    m_core.get_pool().have_key_images_as_spent(req.key_images, pool_spent_status);

    for(uint64_t i=0; i < req.key_images.size(); i++)
    {
      if ( chain_spent_status[i] )
      {
        res.spent_status[i] = KeyImagesSpent::STATUS::SPENT_IN_BLOCKCHAIN;
      }
      else if ( pool_spent_status[i] )
      {
        res.spent_status[i] = KeyImagesSpent::STATUS::SPENT_IN_POOL;
      }
    }
  }

  void DaemonHandler::handle(GetTxGlobalOutputIndices::Request& req, GetTxGlobalOutputIndices::Response& res)
  {
    if (!m_core.get_tx_outputs_gindexs(req.tx_hash, res.output_indices))
    {
      res.status = Message::STATUS_FAILED;
      res.error_details = "core::get_tx_outputs_gindexs() returned false";
      return;
    }

    res.status = Message::STATUS_OK;

  }

  //TODO: handle "restricted" RPC
  void DaemonHandler::handle(GetRandomOutputsForAmounts::Request& req, GetRandomOutputsForAmounts::Response& res)
  {
    auto& chain = m_core.get_blockchain_storage();

    for (uint64_t& amount : req.amounts)
    {
      std::vector<uint64_t> indices = chain.get_random_outputs(amount, req.count);

      outputs_for_amount ofa;

      ofa.resize(indices.size());

      for (uint64_t i = 0; i < indices.size(); i++)
      {
        crypto::public_key key = chain.get_output_key(amount, indices[i]);
        ofa[i].amount_index = indices[i];
        ofa[i].key = key;
      }

      amount_with_random_outputs amt;
      amt.amount = amount;
      amt.outputs = ofa;

      res.amounts_with_outputs.push_back(amt);
    }

    res.status = Message::STATUS_OK;
  }

  void DaemonHandler::handle(SendRawTx::Request& req, SendRawTx::Response& res)
  {
    auto tx_blob = cryptonote::tx_to_blob(req.tx);

    cryptonote_connection_context fake_context = AUTO_VAL_INIT(fake_context);
    tx_verification_context tvc = AUTO_VAL_INIT(tvc);

    if(!m_core.handle_incoming_tx(tx_blob, tvc, false, false) || tvc.m_verifivation_failed)
    {
      if (tvc.m_verifivation_failed)
      {
        LOG_PRINT_L0("[on_send_raw_tx]: tx verification failed");
      }
      else
      {
        LOG_PRINT_L0("[on_send_raw_tx]: Failed to process tx");
      }
      res.status = Message::STATUS_FAILED;

      //TODO: these should be mutually exclusive, as encountering one
      //      cancels the verification process.  Need to confirm this.
      if (tvc.m_low_mixin)
        res.error_details = "mixin too low";
      else if (tvc.m_double_spend)
        res.error_details = "double spend";
      else if (tvc.m_invalid_input)
        res.error_details = "invalid input";
      else if (tvc.m_invalid_output)
        res.error_details = "invalid output";
      else if (tvc.m_too_big)
        res.error_details = "too big";
      else if (tvc.m_overspend)
        res.error_details = "overspend";
      else if (tvc.m_fee_too_low)
        res.error_details = "fee too low";
      else
        res.error_details = "an unknown issue was found with the transaction";

      return;
    }

    if(!tvc.m_should_be_relayed || !req.relay)
    {
      LOG_PRINT_L0("[on_send_raw_tx]: tx accepted, but not relayed");
      res.error_details = "Not relayed";
      res.relayed = false;
      res.status = Message::STATUS_OK;

      return;
    }

    NOTIFY_NEW_TRANSACTIONS::request r;
    r.txs.push_back(tx_blob);
    m_core.get_protocol()->relay_transactions(r, fake_context);

    //TODO: make sure that tx has reached other nodes here, probably wait to receive reflections from other nodes
    res.status = Message::STATUS_OK;
    res.relayed = true;

    return;
  }

  void DaemonHandler::handle(StartMining::Request& req, StartMining::Response& res)
  {
  }

  void DaemonHandler::handle(GetInfo::Request& req, GetInfo::Response& res)
  {
    res.height = m_core.get_current_blockchain_height();

    res.target_height = m_core.get_target_blockchain_height();

    auto& chain = m_core.get_blockchain_storage();

    res.difficulty = chain.get_difficulty_for_next_block();

    res.target = chain.get_difficulty_target();

    res.tx_count = chain.get_total_transactions() - res.height; //without coinbase

    res.tx_pool_size = m_core.get_pool_transactions_count();

    res.alt_blocks_count = chain.get_alternative_blocks_count();

    uint64_t total_conn = m_p2p.get_connections_count();
    res.outgoing_connections_count = m_p2p.get_outgoing_connections_count();
    res.incoming_connections_count = total_conn - res.outgoing_connections_count;

    res.white_peerlist_size = m_p2p.get_peerlist_manager().get_white_peers_count();

    res.grey_peerlist_size = m_p2p.get_peerlist_manager().get_gray_peers_count();

    res.testnet = m_core.is_testnet();
  }

  void DaemonHandler::handle(StopMining::Request& req, StopMining::Response& res)
  {
  }

  void DaemonHandler::handle(MiningStatus::Request& req, MiningStatus::Response& res)
  {
  }

  void DaemonHandler::handle(SaveBC::Request& req, SaveBC::Response& res)
  {
    if (!m_core.get_blockchain_storage().store_blockchain())
    {
      res.status = Message::STATUS_FAILED;
      res.error_details = "Error storing the blockchain";
    }
    else
    {
      res.status = Message::STATUS_OK;
    }
  }

  void DaemonHandler::handle(GetBlockHash::Request& req, GetBlockHash::Response& res)
  {
    if (m_core.get_current_blockchain_height() <= req.height)
    {
      res.hash = cryptonote::null_hash;
      res.status = Message::STATUS_FAILED;
      res.error_details = "height given is higher than current chain height";
      return;
    }

    res.hash = m_core.get_block_id_by_height(req.height);

    res.status = Message::STATUS_OK;
  }

  void DaemonHandler::handle(GetBlockTemplate::Request& req, GetBlockTemplate::Response& res)
  {
  }

  void DaemonHandler::handle(SubmitBlock::Request& req, SubmitBlock::Response& res)
  {
  }

  void DaemonHandler::handle(GetLastBlockHeader::Request& req, GetLastBlockHeader::Response& res)
  {
    res.hash = m_core.get_tail_id();

    GetBlockHeaderByHash::Request fake_req;
    fake_req.hash = res.hash;

    GetBlockHeaderByHash::Response fake_res;

    handle(fake_req, fake_res);

    if (!fake_res.error_details.empty())
    {
      res.status = fake_res.status;
      res.error_details = fake_res.error_details;
      return;
    }

    res.major_version = fake_res.major_version;
    res.minor_version = fake_res.minor_version;
    res.timestamp = fake_res.timestamp;
    res.prev_id = fake_res.prev_id;
    res.nonce = fake_res.nonce;
    res.height = fake_res.height;
    res.difficulty = fake_res.difficulty;
    res.reward = fake_res.reward;

    res.status = fake_res.status;
  }

  void DaemonHandler::handle(GetBlockHeaderByHash::Request& req, GetBlockHeaderByHash::Response& res)
  {
    block b;

    if (!m_core.get_block_by_hash(req.hash, b))
    {
      res.status = Message::STATUS_FAILED;
      res.error_details = "Requested block does not exist";
      return;
    }

    res.hash = req.hash;
    res.height = boost::get<txin_gen>(b.miner_tx.vin.front()).height;

    res.major_version = b.major_version;
    res.minor_version = b.minor_version;
    res.timestamp = b.timestamp;
    res.nonce = b.nonce;
    res.prev_id = b.prev_id;

    res.depth = m_core.get_current_blockchain_height() - res.height - 1;

    res.reward = 0;
    for (auto& out : b.miner_tx.vout)
    {
      res.reward += out.amount;
    }

    res.difficulty = m_core.get_blockchain_storage().block_difficulty(res.height);

    res.status = Message::STATUS_OK;
  }

  void DaemonHandler::handle(GetBlockHeaderByHeight::Request& req, GetBlockHeaderByHeight::Response& res)
  {
    res.hash = m_core.get_block_id_by_height(req.height);

    GetBlockHeaderByHash::Request fake_req;
    fake_req.hash = res.hash;

    GetBlockHeaderByHash::Response fake_res;

    handle(fake_req, fake_res);

    if (!fake_res.error_details.empty())
    {
      res.status = fake_res.status;
      res.error_details = fake_res.error_details;
      return;
    }

    res.major_version = fake_res.major_version;
    res.minor_version = fake_res.minor_version;
    res.timestamp = fake_res.timestamp;
    res.prev_id = fake_res.prev_id;
    res.nonce = fake_res.nonce;
    res.height = fake_res.height;
    res.depth = fake_res.depth;
    res.difficulty = fake_res.difficulty;
    res.reward = fake_res.reward;

    res.status = fake_res.status;
  }

  void DaemonHandler::handle(GetBlock::Request& req, GetBlock::Response& res)
  {
  }

  //FIXME: nodetool::peerlist_entry.adr.port is uint32_t for some reason
  void DaemonHandler::handle(GetPeerList::Request& req, GetPeerList::Response& res)
  {
    std::list<nodetool::peerlist_entry> white_list;
    std::list<nodetool::peerlist_entry> gray_list;
    m_p2p.get_peerlist_manager().get_peerlist_full(gray_list, white_list);

    for (auto & entry : white_list)
    {
      res.white_list.emplace_back(peer{entry.id, entry.adr.ip, (uint16_t)entry.adr.port, (uint64_t)entry.last_seen});
    }

    for (auto & entry : gray_list)
    {
      res.gray_list.emplace_back(peer{entry.id, entry.adr.ip, (uint16_t)entry.adr.port, (uint64_t)entry.last_seen});
    }

    res.status = Message::STATUS_OK;
  }

  void DaemonHandler::handle(SetLogHashRate::Request& req, SetLogHashRate::Response& res)
  {
  }

  void DaemonHandler::handle(SetLogLevel::Request& req, SetLogLevel::Response& res)
  {
    if (req.level < LOG_LEVEL_MIN || req.level > LOG_LEVEL_MAX)
    {
      res.status = Message::STATUS_FAILED;
      res.error_details = "Error: log level not valid";
    }
    else
    {
      epee::log_space::log_singletone::get_set_log_detalisation_level(true, req.level);
      int otshell_utils_log_level = 100 - (req.level * 20);
      gCurrentLogger.setDebugLevel(otshell_utils_log_level);
      res.status = Message::STATUS_OK;
    }
  }

  void DaemonHandler::handle(GetTransactionPool::Request& req, GetTransactionPool::Response& res)
  {
    cryptonote::tx_memory_pool::transactions_container txs;
    cryptonote::tx_memory_pool::key_images_container images;

    m_core.get_pool().get_transactions_and_key_images(txs, images);

    for (auto itr : txs)
    {
      tx_in_pool tx;

      tx.tx = itr.second.tx;
      tx.blob_size = itr.second.blob_size;
      tx.fee = itr.second.fee;

      tx.max_used_block_height = itr.second.max_used_block_height;
      tx.max_used_block_hash = itr.second.max_used_block_id;

      tx.kept_by_block = itr.second.kept_by_block;
      tx.last_failed_block_height = itr.second.last_failed_height;
      tx.last_failed_block_hash = itr.second.last_failed_id;

      tx.receive_time = itr.second.receive_time;
      tx.last_relayed_time = itr.second.last_relayed_time;
      tx.relayed = itr.second.relayed;

      res.transactions[itr.first] = tx;
    }
  }

  void DaemonHandler::handle(GetConnections::Request& req, GetConnections::Response& res)
  {
  }

  void DaemonHandler::handle(GetBlockHeadersRange::Request& req, GetBlockHeadersRange::Response& res)
  {
  }

  void DaemonHandler::handle(StopDaemon::Request& req, StopDaemon::Response& res)
  {
  }

  void DaemonHandler::handle(FastExit::Request& req, FastExit::Response& res)
  {
  }

  void DaemonHandler::handle(OutPeers::Request& req, OutPeers::Response& res)
  {
  }

  void DaemonHandler::handle(StartSaveGraph::Request& req, StartSaveGraph::Response& res)
  {
  }

  void DaemonHandler::handle(StopSaveGraph::Request& req, StopSaveGraph::Response& res)
  {
  }

  void DaemonHandler::handle(HardForkInfo::Request& req, HardForkInfo::Response& res)
  {
    const Blockchain &blockchain = m_core.get_blockchain_storage();
    uint8_t version = req.version > 0 ? req.version : blockchain.get_ideal_hard_fork_version();
    res.info.version = blockchain.get_current_hard_fork_version();
    res.info.enabled = blockchain.get_hard_fork_voting_info(version, res.info.window, res.info.votes, res.info.threshold, res.info.earliest_height, res.info.voting);
    res.info.state = blockchain.get_hard_fork_state();
    res.status = Message::STATUS_OK;
  }

  void DaemonHandler::handle(GetBans::Request& req, GetBans::Response& res)
  {
  }

  void DaemonHandler::handle(SetBans::Request& req, SetBans::Response& res)
  {
  }

  void DaemonHandler::handle(FlushTransactionPool::Request& req, FlushTransactionPool::Response& res)
  {
  }

  void DaemonHandler::handle(GetOutputHistogram::Request& req, GetOutputHistogram::Response& res)
  {
    std::map<uint64_t, uint64_t> histogram;
    try
    {
      histogram = m_core.get_blockchain_storage().get_output_histogram(req.amounts, req.unlocked);
    }
    catch (const std::exception &e)
    {
      res.status = Message::STATUS_FAILED;
      res.error_details = e.what();
      return;
    }

    res.histogram.clear();
    res.histogram.reserve(histogram.size());
    for (const auto &i: histogram)
    {
      if (i.second >= req.min_count && (i.second <= req.max_count || req.max_count == 0))
        res.histogram.emplace_back(output_amount_count{i.first, i.second});
    }

    res.status = Message::STATUS_OK;
  }

  void DaemonHandler::handle(GetOutputKeys::Request& req, GetOutputKeys::Response& res)
  {
    for (auto& i : req.outputs)
    {
      crypto::public_key key;
      bool unlocked;
      m_core.get_blockchain_storage().get_output_key_and_unlocked(i.amount, i.index, key, unlocked);
      res.keys.emplace_back(output_key_and_unlocked{key, unlocked});
    }

    res.status = Message::STATUS_OK;
  }

  void DaemonHandler::handle(GetRPCVersion::Request& req, GetRPCVersion::Response& res)
  {
    res.version = DAEMON_RPC_VERSION;
  }

  std::string DaemonHandler::handle(std::string& request)
  {
    try
    {
      FullMessage req_full(request, true);

      rapidjson::Value& req_json = req_full.getMessage();

      std::string request_type = req_full.getRequestType();

      Message* resp_message = NULL;

      // create correct Message subclass and call handle() on it
      REQ_RESP_TYPES_MACRO(request_type, GetHeight, req_json, resp_message, handle);
      REQ_RESP_TYPES_MACRO(request_type, GetBlocksFast, req_json, resp_message, handle);
      REQ_RESP_TYPES_MACRO(request_type, GetHashesFast, req_json, resp_message, handle);
      REQ_RESP_TYPES_MACRO(request_type, GetTransactions, req_json, resp_message, handle);
      REQ_RESP_TYPES_MACRO(request_type, KeyImagesSpent, req_json, resp_message, handle);
      REQ_RESP_TYPES_MACRO(request_type, GetTxGlobalOutputIndices, req_json, resp_message, handle);
      REQ_RESP_TYPES_MACRO(request_type, GetRandomOutputsForAmounts, req_json, resp_message, handle);
      REQ_RESP_TYPES_MACRO(request_type, SendRawTx, req_json, resp_message, handle);
      REQ_RESP_TYPES_MACRO(request_type, GetInfo, req_json, resp_message, handle);
      REQ_RESP_TYPES_MACRO(request_type, SaveBC, req_json, resp_message, handle);
      REQ_RESP_TYPES_MACRO(request_type, GetBlockHash, req_json, resp_message, handle);
      REQ_RESP_TYPES_MACRO(request_type, GetLastBlockHeader, req_json, resp_message, handle);
      REQ_RESP_TYPES_MACRO(request_type, GetBlockHeaderByHash, req_json, resp_message, handle);
      REQ_RESP_TYPES_MACRO(request_type, GetBlockHeaderByHeight, req_json, resp_message, handle);
      REQ_RESP_TYPES_MACRO(request_type, GetPeerList, req_json, resp_message, handle);
      REQ_RESP_TYPES_MACRO(request_type, SetLogLevel, req_json, resp_message, handle);
      REQ_RESP_TYPES_MACRO(request_type, GetTransactionPool, req_json, resp_message, handle);
      REQ_RESP_TYPES_MACRO(request_type, HardForkInfo, req_json, resp_message, handle);
      REQ_RESP_TYPES_MACRO(request_type, GetOutputHistogram, req_json, resp_message, handle);
      REQ_RESP_TYPES_MACRO(request_type, GetOutputKeys, req_json, resp_message, handle);
      REQ_RESP_TYPES_MACRO(request_type, GetRPCVersion, req_json, resp_message, handle);

      // if none of the request types matches
      if (resp_message == NULL)
      {
        return BAD_REQUEST(DAEMON_RPC_VERSION, request_type, req_full.getID());
      }

      FullMessage resp_full = FullMessage::responseMessage(req_full.getVersion(), resp_message, req_full.getID());

      std::string response = resp_full.getJson();
      delete resp_message;

      std::cout << "DaemonHandler::handle() response: " << response << std::endl;

      return response;
    }
    catch (std::exception& e)
    {
      return BAD_JSON(DAEMON_RPC_VERSION, e.what());
    }

    // if we get here, something's gone terribly wrong
    return std::string("");
  }

}  // namespace rpc

}  // namespace cryptonote
