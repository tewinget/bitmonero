// Copyright (c) 2014, The Monero Project
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
// 
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#include <algorithm>
#include <cstdio>
#include <boost/archive/binary_oarchive.hpp>
#include <boost/archive/binary_iarchive.hpp>
#include <boost/filesystem.hpp>

#include "include_base_utils.h"
#include "cryptonote_basic_impl.h"
#include "tx_pool.h"
#include "blockchain.h"
#include "cryptonote_core/blockchain_db.h"
#include "cryptonote_core/BlockchainDB_impl/db_lmdb.h"
#include "cryptonote_format_utils.h"
#include "cryptonote_boost_serialization.h"
#include "cryptonote_config.h"
#include "miner.h"
#include "misc_language.h"
#include "profile_tools.h"
#include "file_io_utils.h"
#include "common/boost_serialization_helper.h"
#include "warnings.h"
#include "crypto/hash.h"
#include "cryptonote_core/checkpoints_create.h"
//#include "serialization/json_archive.h"

/* TODO:
 *  Clean up code:
 *    Possibly change how outputs are referred to/indexed in blockchain and wallets
 *
 */

using namespace cryptonote;
using epee::string_tools::pod_to_hex;

DISABLE_VS_WARNINGS(4267)

//------------------------------------------------------------------
// TODO: initialize m_db with a concrete implementation of BlockchainDB
Blockchain::Blockchain(tx_memory_pool& tx_pool):m_db(), m_tx_pool(tx_pool), m_current_block_cumul_sz_limit(0), m_is_in_checkpoint_zone(false), m_is_blockchain_storing(false), m_testnet(false), m_enforce_dns_checkpoints(false)
{
  LOG_PRINT_L3("Blockchain::" << __func__);
}
//------------------------------------------------------------------
//TODO: is this still needed?  I don't think so - tewinget
template<class archive_t>
void Blockchain::serialize(archive_t & ar, const unsigned int version)
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  if(version < 11)
    return;
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  ar & m_blocks;
  ar & m_blocks_index;
  ar & m_transactions;
  ar & m_spent_keys;
  ar & m_alternative_chains;
  ar & m_outputs;
  ar & m_invalid_blocks;
  ar & m_current_block_cumul_sz_limit;
  /*serialization bug workaround*/
  if(version > 11)
  {
    uint64_t total_check_count = m_db->height() + m_blocks_index.size() + m_transactions.size() + m_spent_keys.size() + m_alternative_chains.size() + m_outputs.size() + m_invalid_blocks.size() + m_current_block_cumul_sz_limit;
    if(archive_t::is_saving::value)
    {        
      ar & total_check_count;
    }else
    {
      uint64_t total_check_count_loaded = 0;
      ar & total_check_count_loaded;
      if(total_check_count != total_check_count_loaded)
      {
        LOG_ERROR("Blockchain storage data corruption detected. total_count loaded from file = " << total_check_count_loaded << ", expected = " << total_check_count);

        LOG_PRINT_L0("Blockchain storage:" << std::endl << 
          "m_blocks: " << m_db->height() << std::endl  << 
          "m_blocks_index: " << m_blocks_index.size() << std::endl  << 
          "m_transactions: " << m_transactions.size() << std::endl  << 
          "m_spent_keys: " << m_spent_keys.size() << std::endl  << 
          "m_alternative_chains: " << m_alternative_chains.size() << std::endl  << 
          "m_outputs: " << m_outputs.size() << std::endl  << 
          "m_invalid_blocks: " << m_invalid_blocks.size() << std::endl  << 
          "m_current_block_cumul_sz_limit: " << m_current_block_cumul_sz_limit);

        throw std::runtime_error("Blockchain data corruption");
      }
    }
  }


  LOG_PRINT_L3("Blockchain storage:" << std::endl << 
      "m_blocks: " << m_db->height() << std::endl  << 
      "m_blocks_index: " << m_blocks_index.size() << std::endl  << 
      "m_transactions: " << m_transactions.size() << std::endl  << 
      "m_spent_keys: " << m_spent_keys.size() << std::endl  << 
      "m_alternative_chains: " << m_alternative_chains.size() << std::endl  << 
      "m_outputs: " << m_outputs.size() << std::endl  << 
      "m_invalid_blocks: " << m_invalid_blocks.size() << std::endl  << 
      "m_current_block_cumul_sz_limit: " << m_current_block_cumul_sz_limit);
}
//------------------------------------------------------------------
bool Blockchain::have_tx(const crypto::hash &id)
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  return m_db->tx_exists(id);
}
//------------------------------------------------------------------
bool Blockchain::have_tx_keyimg_as_spent(const crypto::key_image &key_im)
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  return  m_db->has_key_image(key_im);
}
//------------------------------------------------------------------
// This function makes sure that each "input" in an input (mixins) exists
// and collects the public key for each from the transaction it was included in
// via the visitor passed to it.
template<class visitor_t>
bool Blockchain::scan_outputkeys_for_indexes(const txin_to_key& tx_in_to_key, visitor_t& vis, uint64_t* pmax_related_block_height)
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);

  // verify that the input has key offsets (that it exists properly, really)
  if(!tx_in_to_key.key_offsets.size())
    return false;

  // cryptonote_format_utils uses relative offsets for indexing to the global
  // outputs list.  that is to say that absolute offset #2 is absolute offset
  // #1 plus relative offset #2.
  // TODO: Investigate if this is necessary / why this is done.
  std::vector<uint64_t> absolute_offsets = relative_output_offsets_to_absolute(tx_in_to_key.key_offsets);


  //std::vector<std::pair<crypto::hash, size_t> >& amount_outs_vec = it->second;
  size_t count = 0;
  for (const uint64_t& i : absolute_offsets)
  {
    try
    {
      // get tx hash and output index for output
      auto output_index = m_db->get_output_tx_and_index(tx_in_to_key.amount, i);

      // get tx that output is from
      auto tx = m_db->get_tx(output_index.first);

      // make sure output index is within range for the given transaction
      if (output_index.second >= tx.vout.size())
      {
        LOG_PRINT_L0("Output does not exist.  tx = " << output_index.first << ", index = " << output_index.second);
        return false;
      }

      // call to the passed boost visitor to grab the public key for the output
      if(!vis.handle_output(tx, tx.vout[output_index.second]))
      {
        LOG_PRINT_L0("Failed to handle_output for output no = " << count << ", with absolute offset " << i);
        return false;
      }

      // if on last output and pmax_related_block_height not null pointer
      if(++count == absolute_offsets.size() && pmax_related_block_height)
      {
        // set *pmax_related_block_height to tx block height for this output
        auto h = m_db->get_tx_block_height(output_index.first);
        if(*pmax_related_block_height < h)
        {
          *pmax_related_block_height = h;
        }
      }

    }
    catch (const OUTPUT_DNE& e)
    {
      LOG_PRINT_L0("Output does not exist: " << e.what());
      return false;
    }
    catch (const TX_DNE& e)
    {
      LOG_PRINT_L0("Transaction does not exist: " << e.what());
      return false;
    }

  }

  return true;
}
//------------------------------------------------------------------
uint64_t Blockchain::get_current_blockchain_height()
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  return m_db->height();
}
//------------------------------------------------------------------
//FIXME: possibly move this into the constructor, to avoid accidentally
//       dereferencing a null BlockchainDB pointer
bool Blockchain::init(const std::string& config_folder, bool testnet)
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);

  m_db = new BlockchainLMDB();

  m_config_folder = config_folder;
  m_testnet = testnet;

  boost::filesystem::path folder(m_config_folder);

  // append "testnet" directory as needed
  if (testnet)
  {
    folder /= "testnet";
  }

  LOG_PRINT_L0("Loading blockchain...");

  //FIXME: update filename for BlockchainDB
  const std::string filename = folder.string();
  try
  {
    m_db->open(filename);
  }
  catch (const DB_OPEN_FAILURE& e)
  {
    LOG_PRINT_L0("No blockchain file found, attempting to create one.");
    try
    {
      m_db->create(filename);
    }
    catch (const DB_CREATE_FAILURE& db_create_error)
    {
      LOG_PRINT_L0("Unable to create BlockchainDB!  This is not good...");
      //TODO: make sure whatever calls this handles the return value properly
      return false;
    }
  }

  // if the blockchain is new, add the genesis block
  // this feels kinda kludgy to do it this way, but can be looked at later.
  // TODO: add function to create and store genesis block,
  //       taking testnet into account
  if(!m_db->height())
  {
    LOG_PRINT_L0("Blockchain not loaded, generating genesis block.");
    block bl = boost::value_initialized<block>();
    block_verification_context bvc = boost::value_initialized<block_verification_context>();
    if (testnet)
    {
      generate_genesis_block(bl, config::testnet::GENESIS_TX, config::testnet::GENESIS_NONCE);
    }
    else
    {
      generate_genesis_block(bl, config::GENESIS_TX, config::GENESIS_NONCE);
    }
    add_new_block(bl, bvc);
    CHECK_AND_ASSERT_MES(!bvc.m_verifivation_failed, false, "Failed to add genesis block to blockchain");
  }
  // TODO: if blockchain load successful, verify blockchain against both
  //       hard-coded and runtime-loaded (and enforced) checkpoints.
  else
  {
  }

  // check how far behind we are
  uint64_t top_block_timestamp = m_db->get_top_block_timestamp();
  uint64_t timestamp_diff = time(NULL) - top_block_timestamp;

  // genesis block has no timestamp, could probably change it to have timestamp of 1341378000...
  if(!top_block_timestamp)
    timestamp_diff = time(NULL) - 1341378000;
  LOG_PRINT_GREEN("Blockchain initialized. last block: " << m_db->height() - 1 << ", " << epee::misc_utils::get_time_interval_string(timestamp_diff) << " time ago, current difficulty: " << get_difficulty_for_next_block(), LOG_LEVEL_0);

  return true;
}
//------------------------------------------------------------------
bool Blockchain::store_blockchain()
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  // TODO: make sure if this throws that it is not simply ignored higher
  // up the call stack
  try
  {
    m_db->sync();
  }
  catch (const std::exception& e)
  {
    LOG_PRINT_L0(std::string("Error syncing blockchain db: ") + e.what() + "-- shutting down now to prevent issues!");
    throw;
  }
  catch (...)
  {
    LOG_PRINT_L0("There was an issue storing the blockchain, shutting down now to prevent issues!");
    throw;
  }
  LOG_PRINT_L0("Blockchain stored OK.");
  return true;
}
//------------------------------------------------------------------
bool Blockchain::deinit()
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  // as this should be called if handling a SIGSEGV, need to check
  // if m_db is a NULL pointer (and thus may have caused the illegal
  // memory operation), otherwise we may cause a loop.
  if (m_db == NULL)
  {
    throw new DB_ERROR("The db pointer is null in Blockchain, the blockchain may be corrupt!");
  }

  try
  {
    m_db->close();
  }
  catch (const std::exception& e)
  {
    LOG_PRINT_L0(std::string("Error closing blockchain db: ") + e.what());
  }
  catch (...)
  {
    LOG_PRINT_L0("There was an issue closing/storing the blockchain, shutting down now to prevent issues!");
  }

  delete m_db;
  return true;
}
//------------------------------------------------------------------
// This function tells BlockchainDB to remove the top block from the
// blockchain and then returns all transactions (except the miner tx, of course)
// from it to the tx_pool
block Blockchain::pop_block_from_blockchain()
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);

  block popped_block;
  std::vector<transaction> popped_txs;

  try
  {
    m_db->pop_block(popped_block, popped_txs);
  }
  // anything that could cause this to throw is likely catastrophic,
  // so we re-throw
  catch (const std::exception& e)
  {
    LOG_ERROR("Error popping block from blockchain: " << e.what());
    throw;
  }
  catch (...)
  {
    LOG_ERROR("Error popping block from blockchain, throwing!");
    throw;
  }

  // return transactions from popped block to the tx_pool
  for (transaction& tx : popped_txs)
  {
    if (!is_coinbase(tx))
    {
      cryptonote::tx_verification_context tvc = AUTO_VAL_INIT(tvc);
      bool r = m_tx_pool.add_tx(tx, tvc, true);
      if (!r)
      {
        LOG_ERROR("Error returning transaction to tx_pool");
      }
    }
  }

  return popped_block;
}
//------------------------------------------------------------------
bool Blockchain::reset_and_set_genesis_block(const block& b)
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  m_transactions.clear();
  m_spent_keys.clear();
  m_blocks.clear();
  m_blocks_index.clear();
  m_alternative_chains.clear();
  m_outputs.clear();
  m_db->reset();

  block_verification_context bvc = boost::value_initialized<block_verification_context>();
  add_new_block(b, bvc);
  return bvc.m_added_to_main_chain && !bvc.m_verifivation_failed;
}
//------------------------------------------------------------------
//TODO: move to BlockchainDB subclass
bool Blockchain::purge_transaction_keyimages_from_blockchain(const transaction& tx, bool strict_check)
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
    struct purge_transaction_visitor: public boost::static_visitor<bool>
  {
    key_images_container& m_spent_keys;
    bool m_strict_check;
    purge_transaction_visitor(key_images_container& spent_keys, bool strict_check):m_spent_keys(spent_keys), m_strict_check(strict_check){}

    bool operator()(const txin_to_key& inp) const
    {
      //const crypto::key_image& ki = inp.k_image;
      auto r = m_spent_keys.find(inp.k_image);
      if(r != m_spent_keys.end())
      {
        m_spent_keys.erase(r);
      }else
      {
        CHECK_AND_ASSERT_MES(!m_strict_check, false, "purge_block_data_from_blockchain: key image in transaction not found");
      }
      return true;
    }
    bool operator()(const txin_gen& inp) const
    {
      return true;
    }
    bool operator()(const txin_to_script& tx) const
    {
      return false;
    }

    bool operator()(const txin_to_scripthash& tx) const
    {
      return false;
    }
  };

  BOOST_FOREACH(const txin_v& in, tx.vin)
  {
    bool r = boost::apply_visitor(purge_transaction_visitor(m_spent_keys, strict_check), in);
    CHECK_AND_ASSERT_MES(!strict_check || r, false, "failed to process purge_transaction_visitor");
  }
  return true;
}
//------------------------------------------------------------------
crypto::hash Blockchain::get_tail_id(uint64_t& height)
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  height = m_db->height();
  return get_tail_id();
}
//------------------------------------------------------------------
crypto::hash Blockchain::get_tail_id()
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  return m_db->top_block_hash();
}
//------------------------------------------------------------------
/*TODO: this function was...poorly written.  As such, I'm not entirely
 *      certain on what it was supposed to be doing.  Need to look into this,
 *      but it doesn't seem terribly important just yet.
 *
 * puts into list <ids> a list of hashes representing certain blocks
 * from the blockchain in reverse chronological order
 *
 * the blocks chosen, at the time of this writing, are:
 *   the most recent 11
 *   powers of 2 less recent from there, so 13, 17, 25, etc...
 *
 */
bool Blockchain::get_short_chain_history(std::list<crypto::hash>& ids)
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  uint64_t i = 0;
  uint64_t current_multiplier = 1;
  uint64_t sz = m_db->height();

  if(!sz)
    return true;

  bool genesis_included = false;
  uint64_t current_back_offset = 1;
  while(current_back_offset < sz)
  {
    ids.push_back(m_db->get_block_hash_from_height(sz - current_back_offset));

    if(sz-current_back_offset == 0)
    {
      genesis_included = true;
    }
    if(i < 10)
    {
      ++current_back_offset;
    }
    else
    {
      current_multiplier *= 2;
      current_back_offset += current_multiplier;
    }
    ++i;
  }

  if (!genesis_included)
  {
    ids.push_back(m_db->get_block_hash_from_height(0));
  }

  return true;
}
//------------------------------------------------------------------
crypto::hash Blockchain::get_block_id_by_height(uint64_t height)
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  try
  {
    return m_db->get_block_hash_from_height(height);
  }
  catch (const BLOCK_DNE& e)
  {
  }
  catch (const std::exception& e)
  {
    LOG_PRINT_L0(std::string("Something went wrong fetching block hash by height: ") + e.what());
    throw;
  }
  catch (...)
  {
    LOG_PRINT_L0(std::string("Something went wrong fetching block hash by height"));
    throw;
  }
  return null_hash;
}
//------------------------------------------------------------------
bool Blockchain::get_block_by_hash(const crypto::hash &h, block &blk)
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);

  // try to find block in main chain
  try
  {
    blk = m_db->get_block(h);
    return true;
  }
  // try to find block in alternative chain
  catch (const BLOCK_DNE& e)
  {
    blocks_ext_by_hash::const_iterator it_alt = m_alternative_chains.find(h);
    if (m_alternative_chains.end() != it_alt) {
      blk = it_alt->second.bl;
      return true;
    }
  }
  catch (const std::exception& e)
  {
    LOG_PRINT_L0(std::string("Something went wrong fetching block by hash: ") + e.what());
    throw;
  }
  catch (...)
  {
    LOG_PRINT_L0(std::string("Something went wrong fetching block hash by hash"));
    throw;
  }

  return false;
}
//------------------------------------------------------------------
//FIXME: this function does not seem to be called from anywhere, but
// if it ever is, should probably change std::list for std::vector
void Blockchain::get_all_known_block_ids(std::list<crypto::hash> &main, std::list<crypto::hash> &alt, std::list<crypto::hash> &invalid)
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);

  for (auto& a : m_db->get_hashes_range(0, m_db->height() - 1))
  {
    main.push_back(a);
  }

  BOOST_FOREACH(blocks_ext_by_hash::value_type &v, m_alternative_chains)
    alt.push_back(v.first);

  BOOST_FOREACH(blocks_ext_by_hash::value_type &v, m_invalid_blocks)
    invalid.push_back(v.first);
}
//------------------------------------------------------------------
// This function aggregates the cumulative difficulties and timestamps of the
// last DIFFICULTY_BLOCKS_COUNT blocks and passes them to next_difficulty,
// returning the result of that call.  Ignores the genesis block, and can use
// less blocks than desired if there aren't enough.
difficulty_type Blockchain::get_difficulty_for_next_block()
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  std::vector<uint64_t> timestamps;
  std::vector<difficulty_type> cumulative_difficulties;
  auto h = m_db->height();

  size_t offset = h - std::min(h, static_cast<size_t>(DIFFICULTY_BLOCKS_COUNT));

  if (offset == 0)
  {
    ++offset;
  }

  for(; offset < h; offset++)
  {
    timestamps.push_back(m_db->get_block_timestamp(offset));
    cumulative_difficulties.push_back(m_db->get_block_cumulative_difficulty(offset));
  }
  return next_difficulty(timestamps, cumulative_difficulties);
}
//------------------------------------------------------------------
// This function removes blocks from the blockchain until it gets to the
// position where the blockchain switch started and then re-adds the blocks
// that had been removed.
bool Blockchain::rollback_blockchain_switching(std::list<block>& original_chain, uint64_t rollback_height)
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);

  // remove blocks from blockchain until we get back to where we should be.
  while (m_db->height() != rollback_height)
  {
    pop_block_from_blockchain();
  }

  //return back original chain
  for (auto& bl : original_chain)
  {
    block_verification_context bvc = boost::value_initialized<block_verification_context>();
    bool r = handle_block_to_main_chain(bl, bvc);
    CHECK_AND_ASSERT_MES(r && bvc.m_added_to_main_chain, false, "PANIC!!! failed to add (again) block while chain switching during the rollback!");
  }

  LOG_PRINT_L1("Rollback to height " << rollback_height << " was successful.");
  if (original_chain.size())
  {
    LOG_PRINT_L1("Restoration to previous blockchain successful as well.");
  }
  return true;
}
//------------------------------------------------------------------
// This function attempts to switch to an alternate chain, returning
// boolean based on success therein.
bool Blockchain::switch_to_alternative_blockchain(std::list<blocks_ext_by_hash::iterator>& alt_chain, bool discard_disconnected_chain)
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);

  // if empty alt chain passed (not sure how that could happen), return false
  CHECK_AND_ASSERT_MES(alt_chain.size(), false, "switch_to_alternative_blockchain: empty chain passed");

  // verify that main chain has front of alt chain's parent block
  if (!m_db->block_exists(alt_chain.front()->second.bl.prev_id))
  {
    LOG_ERROR("Attempting to move to an alternate chain, but it doesn't appear to connect to the main chain!");
    return false;
  }

  // pop blocks from the blockchain until the top block is the parent
  // of the front block of the alt chain.
  std::list<block> disconnected_chain;
  while (m_db->top_block_hash() != alt_chain.front()->second.bl.prev_id)
  {
    block b = pop_block_from_blockchain();
    disconnected_chain.push_front(b);
  }

  auto split_height = m_db->height();

  //connecting new alternative chain
  for(auto alt_ch_iter = alt_chain.begin(); alt_ch_iter != alt_chain.end(); alt_ch_iter++)
  {
    auto ch_ent = *alt_ch_iter;
    block_verification_context bvc = boost::value_initialized<block_verification_context>();

    // add block to main chain
    bool r = handle_block_to_main_chain(ch_ent->second.bl, bvc);

    // if adding block to main chain failed, rollback to previous state and
    // return false
    if(!r || !bvc.m_added_to_main_chain)
    {
      LOG_PRINT_L0("Failed to switch to alternative blockchain");

      // rollback_blockchain_switching should be moved to two different
      // functions: rollback and apply_chain, but for now we pretend it is
      // just the latter (because the rollback was done above).
      rollback_blockchain_switching(disconnected_chain, m_db->height());

      // FIXME: Why do we keep invalid blocks around?  Possibly in case we hear
      // about them again so we can immediately dismiss them, but needs some
      // looking into.
      add_block_as_invalid(ch_ent->second, get_block_hash(ch_ent->second.bl));
      LOG_PRINT_L0("The block was inserted as invalid while connecting new alternative chain,  block_id: " << get_block_hash(ch_ent->second.bl));
      m_alternative_chains.erase(ch_ent);

      for(auto alt_ch_to_orph_iter = ++alt_ch_iter; alt_ch_to_orph_iter != alt_chain.end(); alt_ch_to_orph_iter++)
      {
        add_block_as_invalid((*alt_ch_iter)->second, (*alt_ch_iter)->first);
        m_alternative_chains.erase(*alt_ch_to_orph_iter);
      }
      return false;
    }
  }

  // if we're to keep the disconnected blocks, add them as alternates
  if(!discard_disconnected_chain)
  {
    //pushing old chain as alternative chain
    for (auto& old_ch_ent : disconnected_chain)
    {
      block_verification_context bvc = boost::value_initialized<block_verification_context>();
      bool r = handle_alternative_block(old_ch_ent, get_block_hash(old_ch_ent), bvc);
      if(!r)
      {
        LOG_ERROR("Failed to push ex-main chain blocks to alternative chain ");
        // previously this would fail the blockchain switching, but I don't
        // think this is bad enough to warrant that.
      }
    }
  }

  //removing alt_chain entries from alternative chain
  BOOST_FOREACH(auto ch_ent, alt_chain)
  {
    m_alternative_chains.erase(ch_ent);
  }

  LOG_PRINT_GREEN("REORGANIZE SUCCESS! on height: " << split_height << ", new blockchain size: " << m_db->height(), LOG_LEVEL_0);
  return true;
}
//------------------------------------------------------------------
// This function calculates the difficulty target for the block being added to
// an alternate chain.
difficulty_type Blockchain::get_next_difficulty_for_alternative_chain(const std::list<blocks_ext_by_hash::iterator>& alt_chain, block_extended_info& bei)
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  std::vector<uint64_t> timestamps;
  std::vector<difficulty_type> cumulative_difficulties;

  // if the alt chain isn't long enough to calculate the difficulty target
  // based on its blocks alone, need to get more blocks from the main chain
  if(alt_chain.size()< DIFFICULTY_BLOCKS_COUNT)
  {
    CRITICAL_REGION_LOCAL(m_blockchain_lock);

    // Figure out start and stop offsets for main chain blocks
    size_t main_chain_stop_offset = alt_chain.size() ? alt_chain.front()->second.height : bei.height;
    size_t main_chain_count = DIFFICULTY_BLOCKS_COUNT - std::min(static_cast<size_t>(DIFFICULTY_BLOCKS_COUNT), alt_chain.size());
    main_chain_count = std::min(main_chain_count, main_chain_stop_offset);
    size_t main_chain_start_offset = main_chain_stop_offset - main_chain_count;

    if(!main_chain_start_offset)
      ++main_chain_start_offset; //skip genesis block

    // get difficulties and timestamps from relevant main chain blocks
    for(; main_chain_start_offset < main_chain_stop_offset; ++main_chain_start_offset)
    {
      timestamps.push_back(m_db->get_block_timestamp(main_chain_start_offset));
      cumulative_difficulties.push_back(m_db->get_block_cumulative_difficulty(main_chain_start_offset));
    }

    // make sure we haven't accidentally grabbed too many blocks...maybe don't need this check?
    CHECK_AND_ASSERT_MES((alt_chain.size() + timestamps.size()) <= DIFFICULTY_BLOCKS_COUNT, false,
        "Internal error, alt_chain.size()[" << alt_chain.size()
                                            << "] + vtimestampsec.size()[" << timestamps.size()
                                            << "] NOT <= DIFFICULTY_WINDOW[]" << DIFFICULTY_BLOCKS_COUNT
    );

    for (auto it : alt_chain)
    {
      timestamps.push_back(it->second.bl.timestamp);
      cumulative_difficulties.push_back(it->second.cumulative_difficulty);
    }
  }
  // if the alt chain is long enough for the difficulty calc, grab difficulties
  // and timestamps from it alone
  else
  {
    timestamps.resize(static_cast<size_t>(DIFFICULTY_BLOCKS_COUNT));
    cumulative_difficulties.resize(static_cast<size_t>(DIFFICULTY_BLOCKS_COUNT));
    size_t count = 0;
    size_t max_i = timestamps.size()-1;
    // get difficulties and timestamps from most recent blocks in alt chain
    BOOST_REVERSE_FOREACH(auto it, alt_chain)
    {
      timestamps[max_i - count] = it->second.bl.timestamp;
      cumulative_difficulties[max_i - count] = it->second.cumulative_difficulty;
      count++;
      if(count >= DIFFICULTY_BLOCKS_COUNT)
        break;
    }
  }

  // calculate the difficulty target for the block and return it
  return next_difficulty(timestamps, cumulative_difficulties);
}
//------------------------------------------------------------------
// This function does a sanity check on basic things that all miner
// transactions have in common, such as:
//   one input, of type txin_gen, with height set to the block's height
//   correct miner tx unlock time
//   a non-overflowing tx amount (dubious necessity on this check)
bool Blockchain::prevalidate_miner_transaction(const block& b, uint64_t height)
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CHECK_AND_ASSERT_MES(b.miner_tx.vin.size() == 1, false, "coinbase transaction in the block has no inputs");
  CHECK_AND_ASSERT_MES(b.miner_tx.vin[0].type() == typeid(txin_gen), false, "coinbase transaction in the block has the wrong type");
  if(boost::get<txin_gen>(b.miner_tx.vin[0]).height != height)
  {
    LOG_PRINT_RED_L0("The miner transaction in block has invalid height: " << boost::get<txin_gen>(b.miner_tx.vin[0]).height << ", expected: " << height);
    return false;
  }
  CHECK_AND_ASSERT_MES(b.miner_tx.unlock_time == height + CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW,
                  false,
                  "coinbase transaction transaction have wrong unlock time=" << b.miner_tx.unlock_time << ", expected " << height + CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW);

  //check outs overflow
  //NOTE: not entirely sure this is necessary, given that this function is
  //      designed simply to make sure the total amount for a transaction
  //      does not overflow a uint64_t, and this transaction *is* a uint64_t...
  if(!check_outs_overflow(b.miner_tx))
  {
    LOG_PRINT_RED_L0("miner transaction have money overflow in block " << get_block_hash(b));
    return false;
  }

  return true;
}
//------------------------------------------------------------------
// This function validates the miner transaction reward
bool Blockchain::validate_miner_transaction(const block& b, size_t cumulative_block_size, uint64_t fee, uint64_t& base_reward, uint64_t already_generated_coins)
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  //validate reward
  uint64_t money_in_use = 0;
  BOOST_FOREACH(auto& o, b.miner_tx.vout)
    money_in_use += o.amount;

  std::vector<size_t> last_blocks_sizes;
  get_last_n_blocks_sizes(last_blocks_sizes, CRYPTONOTE_REWARD_BLOCKS_WINDOW);
  if (!get_block_reward(epee::misc_utils::median(last_blocks_sizes), cumulative_block_size, already_generated_coins, base_reward)) {
    LOG_PRINT_L0("block size " << cumulative_block_size << " is bigger than allowed for this blockchain");
    return false;
  }
  if(base_reward + fee < money_in_use)
  {
    LOG_ERROR("coinbase transaction spend too much money (" << money_in_use << "). Block reward is " << base_reward + fee << "(" << base_reward << "+" << fee << ")");
    return false;
  }
  if(base_reward + fee != money_in_use)
  {
    LOG_ERROR("coinbase transaction doesn't use full amount of block reward:  spent: "
                            << money_in_use << ",  block reward " << base_reward + fee << "(" << base_reward << "+" << fee << ")");
    return false;
  }
  return true;
}
//------------------------------------------------------------------
// get the block sizes of the last <count> blocks, starting at <from_height>
// and return by reference <sz>.
void Blockchain::get_last_n_blocks_sizes(std::vector<size_t>& sz, size_t count)
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  auto h = m_db->height();

  // this function is meaningless for an empty blockchain...granted it should never be empty
  if(h == 0)
    return;

  // add size of last <count> blocks to vector <sz> (or less, if blockchain size < count)
  size_t start_offset = h - std::min(h, count);
  for(size_t i = start_offset; i < h; i++)
  {
    sz.push_back(m_db->get_block_size(i));
  }
}
//------------------------------------------------------------------
uint64_t Blockchain::get_current_cumulative_blocksize_limit()
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  return m_current_block_cumul_sz_limit;
}
//------------------------------------------------------------------
//TODO: This function only needed minor modification to work with BlockchainDB,
//      and *works*.  As such, to reduce the number of things that might break
//      in moving to BlockchainDB, this function will remain otherwise
//      unchanged for the time being.
//
// This function makes a new block for a miner to mine the hash for
//
// FIXME: this codebase references #if defined(DEBUG_CREATE_BLOCK_TEMPLATE)
// in a lot of places.  That flag is not referenced in any of the code
// nor any of the makefiles, howeve.  Need to look into whether or not it's
// necessary at all.
bool Blockchain::create_block_template(block& b, const account_public_address& miner_address, difficulty_type& diffic, uint64_t& height, const blobdata& ex_nonce)
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  size_t median_size;
  uint64_t already_generated_coins;

  CRITICAL_REGION_BEGIN(m_blockchain_lock);
  b.major_version = CURRENT_BLOCK_MAJOR_VERSION;
  b.minor_version = CURRENT_BLOCK_MINOR_VERSION;
  b.prev_id = get_tail_id();
  b.timestamp = time(NULL);

  height = m_db->height();
  diffic = get_difficulty_for_next_block();
  CHECK_AND_ASSERT_MES(diffic, false, "difficulty owverhead.");

  median_size = m_current_block_cumul_sz_limit / 2;
  already_generated_coins = m_db->get_block_already_generated_coins(height - 1);

  CRITICAL_REGION_END();

  size_t txs_size;
  uint64_t fee;
  if (!m_tx_pool.fill_block_template(b, median_size, already_generated_coins, txs_size, fee)) {
    return false;
  }
#if defined(DEBUG_CREATE_BLOCK_TEMPLATE)
  size_t real_txs_size = 0;
  uint64_t real_fee = 0;
  CRITICAL_REGION_BEGIN(m_tx_pool.m_transactions_lock);
  BOOST_FOREACH(crypto::hash &cur_hash, b.tx_hashes) {
    auto cur_res = m_tx_pool.m_transactions.find(cur_hash);
    if (cur_res == m_tx_pool.m_transactions.end()) {
      LOG_ERROR("Creating block template: error: transaction not found");
      continue;
    }
    tx_memory_pool::tx_details &cur_tx = cur_res->second;
    real_txs_size += cur_tx.blob_size;
    real_fee += cur_tx.fee;
    if (cur_tx.blob_size != get_object_blobsize(cur_tx.tx)) {
      LOG_ERROR("Creating block template: error: invalid transaction size");
    }
    uint64_t inputs_amount;
    if (!get_inputs_money_amount(cur_tx.tx, inputs_amount)) {
      LOG_ERROR("Creating block template: error: cannot get inputs amount");
    } else if (cur_tx.fee != inputs_amount - get_outs_money_amount(cur_tx.tx)) {
      LOG_ERROR("Creating block template: error: invalid fee");
    }
  }
  if (txs_size != real_txs_size) {
    LOG_ERROR("Creating block template: error: wrongly calculated transaction size");
  }
  if (fee != real_fee) {
    LOG_ERROR("Creating block template: error: wrongly calculated fee");
  }
  CRITICAL_REGION_END();
  LOG_PRINT_L1("Creating block template: height " << height <<
    ", median size " << median_size <<
    ", already generated coins " << already_generated_coins <<
    ", transaction size " << txs_size <<
    ", fee " << fee);
#endif

  /*
     two-phase miner transaction generation: we don't know exact block size until we prepare block, but we don't know reward until we know
     block size, so first miner transaction generated with fake amount of money, and with phase we know think we know expected block size
  */
  //make blocks coin-base tx looks close to real coinbase tx to get truthful blob size
  bool r = construct_miner_tx(height, median_size, already_generated_coins, txs_size, fee, miner_address, b.miner_tx, ex_nonce, 11);
  CHECK_AND_ASSERT_MES(r, false, "Failed to construc miner tx, first chance");
  size_t cumulative_size = txs_size + get_object_blobsize(b.miner_tx);
#if defined(DEBUG_CREATE_BLOCK_TEMPLATE)
  LOG_PRINT_L1("Creating block template: miner tx size " << get_object_blobsize(b.miner_tx) <<
    ", cumulative size " << cumulative_size);
#endif
  for (size_t try_count = 0; try_count != 10; ++try_count) {
    r = construct_miner_tx(height, median_size, already_generated_coins, cumulative_size, fee, miner_address, b.miner_tx, ex_nonce, 11);

    CHECK_AND_ASSERT_MES(r, false, "Failed to construc miner tx, second chance");
    size_t coinbase_blob_size = get_object_blobsize(b.miner_tx);
    if (coinbase_blob_size > cumulative_size - txs_size) {
      cumulative_size = txs_size + coinbase_blob_size;
#if defined(DEBUG_CREATE_BLOCK_TEMPLATE)
      LOG_PRINT_L1("Creating block template: miner tx size " << coinbase_blob_size <<
        ", cumulative size " << cumulative_size << " is greater then before");
#endif
      continue;
    }

    if (coinbase_blob_size < cumulative_size - txs_size) {
      size_t delta = cumulative_size - txs_size - coinbase_blob_size;
#if defined(DEBUG_CREATE_BLOCK_TEMPLATE)
      LOG_PRINT_L1("Creating block template: miner tx size " << coinbase_blob_size <<
        ", cumulative size " << txs_size + coinbase_blob_size <<
        " is less then before, adding " << delta << " zero bytes");
#endif
      b.miner_tx.extra.insert(b.miner_tx.extra.end(), delta, 0);
      //here  could be 1 byte difference, because of extra field counter is varint, and it can become from 1-byte len to 2-bytes len.
      if (cumulative_size != txs_size + get_object_blobsize(b.miner_tx)) {
        CHECK_AND_ASSERT_MES(cumulative_size + 1 == txs_size + get_object_blobsize(b.miner_tx), false, "unexpected case: cumulative_size=" << cumulative_size << " + 1 is not equal txs_cumulative_size=" << txs_size << " + get_object_blobsize(b.miner_tx)=" << get_object_blobsize(b.miner_tx));
        b.miner_tx.extra.resize(b.miner_tx.extra.size() - 1);
        if (cumulative_size != txs_size + get_object_blobsize(b.miner_tx)) {
          //fuck, not lucky, -1 makes varint-counter size smaller, in that case we continue to grow with cumulative_size
          LOG_PRINT_RED("Miner tx creation have no luck with delta_extra size = " << delta << " and " << delta - 1 , LOG_LEVEL_2);
          cumulative_size += delta - 1;
          continue;
        }
        LOG_PRINT_GREEN("Setting extra for block: " << b.miner_tx.extra.size() << ", try_count=" << try_count, LOG_LEVEL_1);
      }
    }
    CHECK_AND_ASSERT_MES(cumulative_size == txs_size + get_object_blobsize(b.miner_tx), false, "unexpected case: cumulative_size=" << cumulative_size << " is not equal txs_cumulative_size=" << txs_size << " + get_object_blobsize(b.miner_tx)=" << get_object_blobsize(b.miner_tx));
#if defined(DEBUG_CREATE_BLOCK_TEMPLATE)
    LOG_PRINT_L1("Creating block template: miner tx size " << coinbase_blob_size <<
      ", cumulative size " << cumulative_size << " is now good");
#endif
    return true;
  }
  LOG_ERROR("Failed to create_block_template with " << 10 << " tries");
  return false;
}
//------------------------------------------------------------------
// for an alternate chain, get the timestamps from the main chain to complete
// the needed number of timestamps for the BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW.
bool Blockchain::complete_timestamps_vector(uint64_t start_top_height, std::vector<uint64_t>& timestamps)
{
  LOG_PRINT_L3("Blockchain::" << __func__);

  if(timestamps.size() >= BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW)
    return true;

  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  size_t need_elements = BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW - timestamps.size();
  CHECK_AND_ASSERT_MES(start_top_height < m_db->height(), false, "internal error: passed start_height not < " << " m_db->height() -- " << start_top_height << " >= " << m_db->height());
  size_t stop_offset = start_top_height > need_elements ? start_top_height - need_elements : 0;
  while (start_top_height != stop_offset);
  {
    timestamps.push_back(m_db->get_block_timestamp(start_top_height));
    --start_top_height;
  }
  return true;
}
//------------------------------------------------------------------
// If a block is to be added and its parent block is not the current
// main chain top block, then we need to see if we know about its parent block.
// If its parent block is part of a known forked chain, then we need to see
// if that chain is long enough to become the main chain and re-org accordingly
// if so.  If not, we need to hang on to the block in case it becomes part of
// a long forked chain eventually.
bool Blockchain::handle_alternative_block(const block& b, const crypto::hash& id, block_verification_context& bvc)
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);

  uint64_t block_height = get_block_height(b);
  if(0 == block_height)
  {
    LOG_ERROR("Block with id: " << epee::string_tools::pod_to_hex(id) << " (as alternative) have wrong miner transaction");
    bvc.m_verifivation_failed = true;
    return false;
  }
  // TODO: this basically says if the blockchain is smaller than the first
  // checkpoint then alternate blocks are allowed...this seems backwards, but
  // I'm not sure.  Needs further investigating.
  if (!m_checkpoints.is_alternative_block_allowed(get_current_blockchain_height(), block_height))
  {
    LOG_PRINT_RED_L0("Block with id: " << id
      << std::endl << " can't be accepted for alternative chain, block height: " << block_height
      << std::endl << " blockchain height: " << get_current_blockchain_height());
    bvc.m_verifivation_failed = true;
    return false;
  }

  //block is not related with head of main chain
  //first of all - look in alternative chains container
  auto it_prev = m_alternative_chains.find(b.prev_id);
  bool parent_in_main = m_db->block_exists(b.prev_id);
  if(it_prev != m_alternative_chains.end() || parent_in_main)
  {
    //we have new block in alternative chain

    //build alternative subchain, front -> mainchain, back -> alternative head
    blocks_ext_by_hash::iterator alt_it = it_prev; //m_alternative_chains.find()
    std::list<blocks_ext_by_hash::iterator> alt_chain;
    std::vector<uint64_t> timestamps;
    while(alt_it != m_alternative_chains.end())
    {
      alt_chain.push_front(alt_it);
      timestamps.push_back(alt_it->second.bl.timestamp);
      alt_it = m_alternative_chains.find(alt_it->second.bl.prev_id);
    }

    // if block to be added connects to known blocks that aren't part of the
    // main chain -- that is, if we're adding on to an alternate chain
    if(alt_chain.size())
    {
      // make sure alt chain doesn't somehow start past the end of the main chain
      CHECK_AND_ASSERT_MES(m_db->height() - 1 > alt_chain.front()->second.height, false, "main blockchain wrong height");

      // make sure that the blockchain contains the block that should connect
      // this alternate chain with it.
      if (!m_db->block_exists(alt_chain.front()->second.bl.prev_id))
      {
        LOG_PRINT_L1("alternate chain does not appear to connect to main chain...");
        return false;
      }

      // make sure block connects correctly to the main chain
      auto h = m_db->get_block_hash_from_height(alt_chain.front()->second.height - 1);
      CHECK_AND_ASSERT_MES(h == alt_chain.front()->second.bl.prev_id, false, "alternative chain have wrong connection to main chain");
      complete_timestamps_vector(m_db->get_block_height(alt_chain.front()->second.bl.prev_id), timestamps);
    }
    // if block not associated with known alternate chain
    else
    {
      // if block parent is not part of main chain or an alternate chain,
      // we ignore it
      CHECK_AND_ASSERT_MES(parent_in_main, false, "internal error: broken imperative condition it_main_prev != m_blocks_index.end()");

      complete_timestamps_vector(m_db->get_block_height(b.prev_id), timestamps);
    }

    // verify that the block's timestamp is within the acceptable range
    // (not earlier than the median of the last X blocks)
    if(!check_block_timestamp(timestamps, b))
    {
      LOG_PRINT_RED_L0("Block with id: " << id
        << std::endl << " for alternative chain, have invalid timestamp: " << b.timestamp);
      bvc.m_verifivation_failed = true;
      return false;
    }

    // FIXME: consider moving away from block_extended_info at some point
    block_extended_info bei = boost::value_initialized<block_extended_info>();
    bei.bl = b;
    bei.height = alt_chain.size() ? it_prev->second.height + 1 : m_db->get_block_height(b.prev_id) + 1;

    bool is_a_checkpoint;
    if(!m_checkpoints.check_block(bei.height, id, is_a_checkpoint))
    {
      LOG_ERROR("CHECKPOINT VALIDATION FAILED");
      bvc.m_verifivation_failed = true;
      return false;
    }

    // Check the block's hash against the difficulty target for its alt chain
    m_is_in_checkpoint_zone = false;
    difficulty_type current_diff = get_next_difficulty_for_alternative_chain(alt_chain, bei);
    CHECK_AND_ASSERT_MES(current_diff, false, "!!!!!!! DIFFICULTY OVERHEAD !!!!!!!");
    crypto::hash proof_of_work = null_hash;
    get_block_longhash(bei.bl, proof_of_work, bei.height);
    if(!check_hash(proof_of_work, current_diff))
    {
      LOG_PRINT_RED_L0("Block with id: " << id
        << std::endl << " for alternative chain, have not enough proof of work: " << proof_of_work
        << std::endl << " expected difficulty: " << current_diff);
      bvc.m_verifivation_failed = true;
      return false;
    }

    if(!prevalidate_miner_transaction(b, bei.height))
    {
      LOG_PRINT_RED_L0("Block with id: " << epee::string_tools::pod_to_hex(id)
        << " (as alternative) have wrong miner transaction.");
      bvc.m_verifivation_failed = true;
      return false;

    }

    // FIXME:
    // this brings up an interesting point: consider allowing to get block
    // difficulty both by height OR by hash, not just height.
    bei.cumulative_difficulty = alt_chain.size() ? it_prev->second.cumulative_difficulty : m_db->get_block_cumulative_difficulty(m_db->get_block_height(b.prev_id));
    bei.cumulative_difficulty += current_diff;

    // add block to alternate blocks storage,
    // as well as the current "alt chain" container
    auto i_res = m_alternative_chains.insert(blocks_ext_by_hash::value_type(id, bei));
    CHECK_AND_ASSERT_MES(i_res.second, false, "insertion of new alternative block returned as it already exist");
    alt_chain.push_back(i_res.first);

    // FIXME: is it even possible for a checkpoint to show up not on the main chain?
    if(is_a_checkpoint)
    {
      //do reorganize!
      LOG_PRINT_GREEN("###### REORGANIZE on height: " << alt_chain.front()->second.height << " of " << m_db->height() - 1 <<
        ", checkpoint is found in alternative chain on height " << bei.height, LOG_LEVEL_0);

      bool r = switch_to_alternative_blockchain(alt_chain, true);

      bvc.m_added_to_main_chain = r;
      bvc.m_verifivation_failed = !r;

      return r;
    }
    else if(m_blocks.back().cumulative_difficulty < bei.cumulative_difficulty) //check if difficulty bigger then in main chain
    {
      //do reorganize!
      LOG_PRINT_GREEN("###### REORGANIZE on height: "
          << alt_chain.front()->second.height << " of " << m_db->height()
          << " with cum_difficulty " << m_db->get_block_cumulative_difficulty(m_db->height())
          << std::endl << " alternative blockchain size: " << alt_chain.size()
          << " with cum_difficulty " << bei.cumulative_difficulty, LOG_LEVEL_0
      );

      bool r = switch_to_alternative_blockchain(alt_chain, false);
      if(r) bvc.m_added_to_main_chain = true;
      else bvc.m_verifivation_failed = true;
      return r;
    }
    else
    {
      LOG_PRINT_BLUE("----- BLOCK ADDED AS ALTERNATIVE ON HEIGHT " << bei.height
        << std::endl << "id:\t" << id
        << std::endl << "PoW:\t" << proof_of_work
        << std::endl << "difficulty:\t" << current_diff, LOG_LEVEL_0);
      return true;
    }
  }
  else
  {
    //block orphaned
    bvc.m_marked_as_orphaned = true;
    LOG_PRINT_RED_L0("Block recognized as orphaned and rejected, id = " << id);
  }

  return true;
}
//------------------------------------------------------------------
bool Blockchain::get_blocks(uint64_t start_offset, size_t count, std::list<block>& blocks, std::list<transaction>& txs)
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  if(start_offset > m_db->height())
    return false;

  if (!get_blocks(start_offset, count, blocks))
  {
    return false;
  }

  for(const block& blk : blocks)
  {
    std::list<crypto::hash> missed_ids;
    get_transactions(blk.tx_hashes, txs, missed_ids);
    CHECK_AND_ASSERT_MES(!missed_ids.size(), false, "have missed transactions in own block in main blockchain");
  }

  return true;
}
//------------------------------------------------------------------
bool Blockchain::get_blocks(uint64_t start_offset, size_t count, std::list<block>& blocks)
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  if(start_offset > m_db->height())
    return false;

  for(size_t i = start_offset; i < start_offset + count && i <= m_db->height();i++)
  {
    blocks.push_back(m_db->get_block_from_height(i));
  }
  return true;
}
//------------------------------------------------------------------
//TODO: This function *looks* like it won't need to be rewritten
//      to use BlockchainDB, as it calls other functions that were,
//      but it warrants some looking into later.
bool Blockchain::handle_get_objects(NOTIFY_REQUEST_GET_OBJECTS::request& arg, NOTIFY_RESPONSE_GET_OBJECTS::request& rsp)
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  rsp.current_blockchain_height = get_current_blockchain_height();
  std::list<block> blocks;
  get_blocks(arg.blocks, blocks, rsp.missed_ids);

  BOOST_FOREACH(const auto& bl, blocks)
  {
    std::list<crypto::hash> missed_tx_id;
    std::list<transaction> txs;
    get_transactions(bl.tx_hashes, txs, rsp.missed_ids);
    CHECK_AND_ASSERT_MES(!missed_tx_id.size(), false, "Internal error: have missed missed_tx_id.size()=" << missed_tx_id.size()
      << std::endl << "for block id = " << get_block_hash(bl));
   rsp.blocks.push_back(block_complete_entry());
   block_complete_entry& e = rsp.blocks.back();
   //pack block
   e.block = t_serializable_object_to_blob(bl);
   //pack transactions
   BOOST_FOREACH(transaction& tx, txs)
     e.txs.push_back(t_serializable_object_to_blob(tx));

  }
  //get another transactions, if need
  std::list<transaction> txs;
  get_transactions(arg.txs, txs, rsp.missed_ids);
  //pack aside transactions
  BOOST_FOREACH(const auto& tx, txs)
    rsp.txs.push_back(t_serializable_object_to_blob(tx));

  return true;
}
//------------------------------------------------------------------
bool Blockchain::get_alternative_blocks(std::list<block>& blocks)
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);

  BOOST_FOREACH(const auto& alt_bl, m_alternative_chains)
  {
    blocks.push_back(alt_bl.second.bl);
  }
  return true;
}
//------------------------------------------------------------------
size_t Blockchain::get_alternative_blocks_count()
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  return m_alternative_chains.size();
}
//------------------------------------------------------------------
// This function adds the output specified by <amount, i> to the result_outs container
// unlocked and other such checks should be done by here.
void Blockchain::add_out_to_get_random_outs(COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::outs_for_amount& result_outs, uint64_t amount, size_t i)
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);

  COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::out_entry& oen = *result_outs.outs.insert(result_outs.outs.end(), COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::out_entry());
  oen.global_amount_index = i;
  oen.out_key = m_db->get_output_key(amount, i);
}
//------------------------------------------------------------------
// This function takes an RPC request for mixins and creates an RPC response
// with the requested mixins.
// TODO: figure out why this returns boolean / if we should be returning false
// in some cases
bool Blockchain::get_random_outs_for_amounts(const COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::request& req, COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::response& res)
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  srand(static_cast<unsigned int>(time(NULL)));
  CRITICAL_REGION_LOCAL(m_blockchain_lock);

  // for each amount that we need to get mixins for, get <n> random outputs
  // from BlockchainDB where <n> is req.outs_count (number of mixins).
  for (uint64_t amount : req.amounts)
  {
    // create outs_for_amount struct and populate amount field
    COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::outs_for_amount& result_outs = *res.outs.insert(res.outs.end(), COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::outs_for_amount());
    result_outs.amount = amount;

    std::unordered_set<uint64_t> seen_indices;

    // if there aren't enough outputs to mix with (or just enough),
    // use all of them.  Eventually this should become impossible.
    if (m_db->get_num_outputs(amount) <= req.outs_count)
    {
      for (uint64_t i = 0; i < m_db->get_num_outputs(amount); i++)
      {
        // get tx_hash, tx_out_index from DB
        tx_out_index toi = m_db->get_output_tx_and_index(amount, i);

        // if tx is unlocked, add output to result_outs
        if (is_tx_spendtime_unlocked(m_db->get_tx_unlock_time(toi.first)))
        {
          add_out_to_get_random_outs(result_outs, amount, i);
        }

      }
    }
    else
    {
      // while we still need more mixins
      auto num_outs = m_db->get_num_outputs(amount);
      while (result_outs.outs.size() < req.outs_count)
      {
        // if we've gone through every possible output, we've gotten all we can
        if (seen_indices.size() == num_outs)
        {
          break;
        }

        // get a random output index from the DB.  If we've already seen it,
        // return to the top of the loop and try again, otherwise add it to the
        // list of output indices we've seen.
        uint64_t i = m_db->get_random_output(amount);
        if (seen_indices.count(i))
        {
          continue;
        }
        seen_indices.emplace(i);

        // get tx_hash, tx_out_index from DB
        tx_out_index toi = m_db->get_output_tx_and_index(amount, i);

        // if the output's transaction is unlocked, add the output's index to
        // our list.
        if (is_tx_spendtime_unlocked(m_db->get_tx_unlock_time(toi.first)))
        {
          add_out_to_get_random_outs(result_outs, amount, i);
        }
      }
    }
  }
  return true;
}
//------------------------------------------------------------------
// This function takes a list of block hashes from another node
// on the network to find where the split point is between us and them.
// This is used to see what to send another node that needs to sync.
bool Blockchain::find_blockchain_supplement(const std::list<crypto::hash>& qblock_ids, uint64_t& starter_offset)
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);

  // make sure the request includes at least the genesis block, otherwise
  // how can we expect to sync from the client that the block list came from?
  if(!qblock_ids.size() /*|| !req.m_total_height*/)
  {
    LOG_ERROR("Client sent wrong NOTIFY_REQUEST_CHAIN: m_block_ids.size()=" << qblock_ids.size() << /*", m_height=" << req.m_total_height <<*/ ", dropping connection");
    return false;
  }

  // make sure that the last block in the request's block list matches
  // the genesis block
  auto gen_hash = m_db->get_block_hash_from_height(0);
  if(qblock_ids.back() != gen_hash)
  {
    LOG_ERROR("Client sent wrong NOTIFY_REQUEST_CHAIN: genesis block missmatch: " << std::endl << "id: "
      << qblock_ids.back() << ", " << std::endl << "expected: " << gen_hash
      << "," << std::endl << " dropping connection");
    return false;
  }

  // Find the first block the foreign chain has that we also have.
  // Assume qblock_ids is in reverse-chronological order.
  auto bl_it = qblock_ids.begin();
  uint64_t split_height = 0;
  for(; bl_it != qblock_ids.end(); bl_it++)
  {
    try
    {
      split_height = m_db->get_block_height(*bl_it);
      break;
    }
    catch (const BLOCK_DNE& e)
    {
      continue;
    }
    catch (const std::exception& e)
    {
      LOG_PRINT_L1("Non-critical error trying to find block by hash in BlockchainDB, hash: " << *bl_it);
      return false;
    }
  }

  // this should be impossible, as we checked that we share the genesis block,
  // but just in case...
  if(bl_it == qblock_ids.end())
  {
    LOG_ERROR("Internal error handling connection, can't find split point");
    return false;
  }

  // if split_height remains 0, we didn't have any but the genesis block in common
  if(split_height == 0)
  {
    LOG_ERROR("Ours and foreign blockchain have only genesis block in common... o.O");
    return false;
  }

  //we start to put block ids INCLUDING last known id, just to make other side be sure
  starter_offset = split_height;
  return true;
}
//------------------------------------------------------------------
uint64_t Blockchain::block_difficulty(uint64_t i)
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  try
  {
    return m_db->get_block_difficulty(i);
  }
  catch (const BLOCK_DNE& e)
  {
    LOG_PRINT_L0("Attempted to get block difficulty for height above blockchain height");
  }
  return 0;
}
//------------------------------------------------------------------
template<class t_ids_container, class t_blocks_container, class t_missed_container>
bool Blockchain::get_blocks(const t_ids_container& block_ids, t_blocks_container& blocks, t_missed_container& missed_bs)
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);

  for (const auto& block_hash : block_ids)
  {
    try
    {
      blocks.push_back(m_db->get_block(block_hash));
    }
    catch (const BLOCK_DNE& e)
    {
      missed_bs.push_back(block_hash);
    }
    catch (const std::exception& e)
    {
      return false;
    }
  }
  return true;
}
//------------------------------------------------------------------
template<class t_ids_container, class t_tx_container, class t_missed_container>
bool Blockchain::get_transactions(const t_ids_container& txs_ids, t_tx_container& txs, t_missed_container& missed_txs)
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);

  for (const auto& tx_hash : txs_ids)
  {
    try
    {
      txs.push_back(m_db->get_tx(tx_hash));
    }
    catch (const TX_DNE& e)
    {
      missed_txs.push_back(tx_hash);
    }
    //FIXME: is this the correct way to handle this?
    catch (const std::exception& e)
    {
      return false;
    }
  }
  return true;
}
//------------------------------------------------------------------
void Blockchain::print_blockchain(uint64_t start_index, uint64_t end_index)
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  std::stringstream ss;
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  auto h = m_db->height();
  if(start_index > h)
  {
    LOG_PRINT_L0("Wrong starter index set: " << start_index << ", expected max index " << h);
    return;
  }

  for(size_t i = start_index; i <= h && i != end_index; i++)
  {
    ss << "height " << i
       << ", timestamp " << m_db->get_block_timestamp(i)
       << ", cumul_dif " << m_db->get_block_cumulative_difficulty(i)
       << ", size " << m_db->get_block_size(i)
       << "\nid\t\t" <<  m_db->get_block_hash_from_height(i)
       << "\ndifficulty\t\t" << m_db->get_block_difficulty(i)
       << ", nonce " << m_db->get_block_from_height(i).nonce
       << ", tx_count " << m_db->get_block_from_height(i).tx_hashes.size()
       << std::endl;
  }
  LOG_PRINT_L1("Current blockchain:" << std::endl << ss.str());
  LOG_PRINT_L0("Blockchain printed with log level 1");
}
//------------------------------------------------------------------
void Blockchain::print_blockchain_index()
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  std::stringstream ss;
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  auto height = m_db->height();
  if (height != 0)
  {
    for(uint64_t i = 0; i <= height; i++)
    {
      ss << "height: " << i << ", hash: " << m_db->get_block_hash_from_height(i);
    }
  }

  LOG_PRINT_L0("Current blockchain index:" << std::endl
               << ss.str()
              );
}
//------------------------------------------------------------------
//TODO: remove this function and references to it
void Blockchain::print_blockchain_outs(const std::string& file)
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  return;
}
//------------------------------------------------------------------
// Find the split point between us and foreign blockchain and return
// (by reference) the most recent common block hash along with up to
// BLOCKS_IDS_SYNCHRONIZING_DEFAULT_COUNT additional (more recent) hashes.
bool Blockchain::find_blockchain_supplement(const std::list<crypto::hash>& qblock_ids, NOTIFY_RESPONSE_CHAIN_ENTRY::request& resp)
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);

  // if we can't find the split point, return false
  if(!find_blockchain_supplement(qblock_ids, resp.start_height))
  {
    return false;
  }

  resp.total_height = get_current_blockchain_height();
  size_t count = 0;
  for(size_t i = resp.start_height; i < resp.total_height && count < BLOCKS_IDS_SYNCHRONIZING_DEFAULT_COUNT; i++, count++)
  {
    resp.m_block_ids.push_back(m_db->get_block_hash_from_height(i));
  }
  return true;
}
//------------------------------------------------------------------
//FIXME: change argument to std::vector, low priority
// find split point between ours and foreign blockchain (or start at
// blockchain height <req_start_block>), and return up to max_count FULL
// blocks by reference.
bool Blockchain::find_blockchain_supplement(const uint64_t req_start_block, const std::list<crypto::hash>& qblock_ids, std::list<std::pair<block, std::list<transaction> > >& blocks, uint64_t& total_height, uint64_t& start_height, size_t max_count)
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);

  // if a specific start height has been requested
  if(req_start_block > 0)
  {
    // if requested height is higher than our chain, return false -- we can't help
    if (req_start_block >= m_db->height())
    {
      return false;
    }
    start_height = req_start_block; 
  }
  else
  {
    if(!find_blockchain_supplement(qblock_ids, start_height))
    {
      return false;
    }
  }

  total_height = get_current_blockchain_height();
  size_t count = 0;
  for(size_t i = start_height; i < total_height && count < max_count; i++, count++)
  {
    blocks.resize(blocks.size()+1);
    blocks.back().first = m_db->get_block_from_height(i);
    std::list<crypto::hash> mis;
    get_transactions(blocks.back().first.tx_hashes, blocks.back().second, mis);
    CHECK_AND_ASSERT_MES(!mis.size(), false, "internal error, transaction from block not found");
  }
  return true;
}
//------------------------------------------------------------------
bool Blockchain::add_block_as_invalid(const block& bl, const crypto::hash& h)
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  block_extended_info bei = AUTO_VAL_INIT(bei);
  bei.bl = bl;
  return add_block_as_invalid(bei, h);
}
//------------------------------------------------------------------
bool Blockchain::add_block_as_invalid(const block_extended_info& bei, const crypto::hash& h)
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  auto i_res = m_invalid_blocks.insert(std::map<crypto::hash, block_extended_info>::value_type(h, bei));
  CHECK_AND_ASSERT_MES(i_res.second, false, "at insertion invalid by tx returned status existed");
  LOG_PRINT_L0("BLOCK ADDED AS INVALID: " << h << std::endl << ", prev_id=" << bei.bl.prev_id << ", m_invalid_blocks count=" << m_invalid_blocks.size());
  return true;
}
//------------------------------------------------------------------
bool Blockchain::have_block(const crypto::hash& id)
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);

  if(m_db->block_exists(id))
    return true;

  if(m_alternative_chains.count(id))
    return true;

  if(m_invalid_blocks.count(id))
    return true;

  return false;
}
//------------------------------------------------------------------
bool Blockchain::handle_block_to_main_chain(const block& bl, block_verification_context& bvc)
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  crypto::hash id = get_block_hash(bl);
  return handle_block_to_main_chain(bl, id, bvc);
}
//------------------------------------------------------------------
size_t Blockchain::get_total_transactions()
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  return m_db->get_tx_count();
}
//------------------------------------------------------------------
// This function checks each input in the transaction <tx> to make sure it
// has not been used already, and adds its key to the container <keys_this_block>.
//
// This container should be managed by the code that validates blocks so we don't
// have to store the used keys in a given block in the permanent storage only to
// remove them later if the block fails validation.
bool Blockchain::check_for_double_spend(const transaction& tx, key_images_container& keys_this_block)
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  struct add_transaction_input_visitor: public boost::static_visitor<bool>
  {
    key_images_container& m_spent_keys;
    BlockchainDB* m_db;
    add_transaction_input_visitor(key_images_container& spent_keys, BlockchainDB* db):m_spent_keys(spent_keys), m_db(db)
    {}
    bool operator()(const txin_to_key& in) const
    {
      const crypto::key_image& ki = in.k_image;

      // attempt to insert the newly-spent key into the container of
      // keys spent this block.  If this fails, the key was spent already
      // in this block, return false to flag that a double spend was detected.
      //
      // if the insert into the block-wide spent keys container succeeds,
      // check the blockchain-wide spent keys container and make sure the
      // key wasn't used in another block already.
      auto r = m_spent_keys.insert(ki);
      if(!r.second || m_db->has_key_image(ki))
      {
        //double spend detected
        return false;
      }

      // if no double-spend detected, return true
      return true;
    }

    bool operator()(const txin_gen& tx) const{return true;}
    bool operator()(const txin_to_script& tx) const{return false;}
    bool operator()(const txin_to_scripthash& tx) const{return false;}
  };

  for (const txin_v& in : tx.vin)
  {
    if(!boost::apply_visitor(add_transaction_input_visitor(keys_this_block, m_db), in))
    {
      LOG_ERROR("Double spend detected!");
      return false;
    }
  }

  return true;
}
//------------------------------------------------------------------
bool Blockchain::get_tx_outputs_gindexs(const crypto::hash& tx_id, std::vector<uint64_t>& indexs)
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  if (!m_db->tx_exists(tx_id))
  {
    LOG_PRINT_L0("warning: get_tx_outputs_gindexs failed to find transaction with id = " << tx_id);
    return false;
  }

  indexs = m_db->get_tx_output_indices(tx_id);
  return true;
}
//------------------------------------------------------------------
// This function overloads its sister function with
// an extra value (hash of highest block that holds an output used as input)
// as a return-by-reference.
bool Blockchain::check_tx_inputs(const transaction& tx, uint64_t& max_used_block_height, crypto::hash& max_used_block_id)
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  bool res = check_tx_inputs(tx, &max_used_block_height);
  if(!res) return false;
  CHECK_AND_ASSERT_MES(max_used_block_height < m_db->height(), false,  "internal error: max used block index=" << max_used_block_height << " is not less then blockchain size = " << m_db->height());
  max_used_block_id = m_db->get_block_hash_from_height(max_used_block_height);
  return true;
}
//------------------------------------------------------------------
bool Blockchain::have_tx_keyimges_as_spent(const transaction &tx)
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  BOOST_FOREACH(const txin_v& in, tx.vin)
  {
    CHECKED_GET_SPECIFIC_VARIANT(in, const txin_to_key, in_to_key, true);
    if(have_tx_keyimg_as_spent(in_to_key.k_image))
      return true;
  }
  return false;
}
//------------------------------------------------------------------
// This function validates transaction inputs and their keys.  Previously
// it also performed double spend checking, but that has been moved to its
// own function.
bool Blockchain::check_tx_inputs(const transaction& tx, uint64_t* pmax_used_block_height)
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  size_t sig_index = 0;
  if(pmax_used_block_height)
    *pmax_used_block_height = 0;

  crypto::hash tx_prefix_hash = get_transaction_prefix_hash(tx);

  for (const auto& txin : tx.vin)
  {
    // make sure output being spent is of type txin_to_key, rather than
    // e.g. txin_gen, which is only used for miner transactions
    CHECK_AND_ASSERT_MES(txin.type() == typeid(txin_to_key), false, "wrong type id in tx input at Blockchain::check_tx_inputs");
    const txin_to_key& in_to_key = boost::get<txin_to_key>(txin);

    // make sure tx output has key offset(s) (is signed to be used)
    CHECK_AND_ASSERT_MES(in_to_key.key_offsets.size(), false, "empty in_to_key.key_offsets in transaction with id " << get_transaction_hash(tx));

    // basically, make sure number of inputs == number of signatures
    CHECK_AND_ASSERT_MES(sig_index < tx.signatures.size(), false, "wrong transaction: not signature entry for input with index= " << sig_index);

    // make sure that output being spent matches up correctly with the
    // signature spending it.
    if(!check_tx_input(in_to_key, tx_prefix_hash, tx.signatures[sig_index], pmax_used_block_height))
    {
      LOG_PRINT_L0("Failed to check ring signature for tx " << get_transaction_hash(tx));
      return false;
    }

    sig_index++;
  }

  return true;
}
//------------------------------------------------------------------
// This function checks to see if a tx is unlocked.  unlock_time is either
// a block index or a unix time.
bool Blockchain::is_tx_spendtime_unlocked(uint64_t unlock_time)
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  if(unlock_time < CRYPTONOTE_MAX_BLOCK_NUMBER)
  {
    //interpret as block index
    if(get_current_blockchain_height() + CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_BLOCKS >= unlock_time)
      return true;
    else
      return false;
  }else
  {
    //interpret as time
    uint64_t current_time = static_cast<uint64_t>(time(NULL));
    if(current_time + CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_SECONDS >= unlock_time)
      return true;
    else
      return false;
  }
  return false;
}
//------------------------------------------------------------------
// This function locates all outputs associated with a given input (mixins)
// and validates that they exist and are usable.  It also checks the ring
// signature for each input.
bool Blockchain::check_tx_input(const txin_to_key& txin, const crypto::hash& tx_prefix_hash, const std::vector<crypto::signature>& sig, uint64_t* pmax_related_block_height)
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);

  struct outputs_visitor
  {
    std::vector<const crypto::public_key *>& m_p_output_keys;
    std::vector<crypto::public_key >& m_output_keys;
    Blockchain& m_bch;
    outputs_visitor(std::vector<crypto::public_key >& output_keys, std::vector<const crypto::public_key *>& p_output_keys, Blockchain& bch) : m_output_keys(output_keys), m_p_output_keys(p_output_keys), m_bch(bch)
    {}
    bool handle_output(const transaction& tx, const tx_out& out)
    {
      //check tx unlock time
      if(!m_bch.is_tx_spendtime_unlocked(tx.unlock_time))
      {
        LOG_PRINT_L0("One of outputs for one of inputs have wrong tx.unlock_time = " << tx.unlock_time);
        return false;
      }

      if(out.target.type() != typeid(txout_to_key))
      {
        LOG_PRINT_L0("Output have wrong type id, which=" << out.target.which());
        return false;
      }

      m_output_keys.push_back(boost::get<txout_to_key>(out.target).key);
      return true;
    }
  };

  //check ring signature
  std::vector<crypto::public_key> output_keys;
  std::vector<const crypto::public_key *> p_output_keys;
  outputs_visitor vi(output_keys, p_output_keys, *this);
  if(!scan_outputkeys_for_indexes(txin, vi, pmax_related_block_height))
  {
    LOG_PRINT_L0("Failed to get output keys for tx with amount = " << print_money(txin.amount) << " and count indexes " << txin.key_offsets.size());
    return false;
  }

  for (auto& k : output_keys)
  {
    p_output_keys.push_back(&k);
  }

  if(txin.key_offsets.size() != output_keys.size())
  {
    LOG_PRINT_L0("Output keys for tx with amount = " << txin.amount << " and count indexes " << txin.key_offsets.size() << " returned wrong keys count " << output_keys.size());
    return false;
  }
  CHECK_AND_ASSERT_MES(sig.size() == output_keys.size(), false, "internal error: tx signatures count=" << sig.size() << " mismatch with outputs keys count for inputs=" << output_keys.size());
  if(m_is_in_checkpoint_zone)
    return true;
  return crypto::check_ring_signature(tx_prefix_hash, txin.k_image, p_output_keys, sig.data());
}
//------------------------------------------------------------------
//TODO: Is this intended to do something else?  Need to look into the todo there.
uint64_t Blockchain::get_adjusted_time()
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  //TODO: add collecting median time
  return time(NULL);
}
//------------------------------------------------------------------
//TODO: revisit, has changed a bit on upstream
bool Blockchain::check_block_timestamp(std::vector<uint64_t>& timestamps, const block& b)
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  uint64_t median_ts = epee::misc_utils::median(timestamps);

  if(b.timestamp < median_ts)
  {
    LOG_PRINT_L0("Timestamp of block with id: " << get_block_hash(b) << ", " << b.timestamp << ", less than median of last " << BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW << " blocks, " << median_ts);
    return false;
  }

  return true;
}
//------------------------------------------------------------------
// This function grabs the timestamps from the most recent <n> blocks,
// where n = BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW.  If there are not those many
// blocks in the blockchain, the timestap is assumed to be valid.  If there
// are, this function returns:
//   true if the block's timestamp is not less than the timestamp of the
//       median of the selected blocks
//   false otherwise
bool Blockchain::check_block_timestamp(const block& b)
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  if(b.timestamp > get_adjusted_time() + CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT)
  {
    LOG_PRINT_L0("Timestamp of block with id: " << get_block_hash(b) << ", " << b.timestamp << ", bigger than adjusted time + 2 hours");
    return false;
  }

  // if not enough blocks, no proper median yet, return true
  if(m_db->height() < BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW + 1)
  {
    return true;
  }

  std::vector<uint64_t> timestamps;
  auto h = m_db->height();

  // need most recent 60 blocks, get index of first of those
  // using +1 because BlockchainDB::height() returns the index of the top block,
  // not the size of the blockchain (0-indexed)
  size_t offset = h - BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW - 1;
  for(;offset < h; ++offset)
  {
    timestamps.push_back(m_db->get_block_timestamp(offset));
  }

  return check_block_timestamp(timestamps, b);
}
//------------------------------------------------------------------
//      Needs to validate the block and acquire each transaction from the
//      transaction mem_pool, then pass the block and transactions to
//      m_db->add_block()
bool Blockchain::handle_block_to_main_chain(const block& bl, const crypto::hash& id, block_verification_context& bvc)
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  // if we already have the block, return false
  if (have_block(id))
  {
    LOG_PRINT_L0("Attempting to add block to main chain, but it's already either there or in an alternate chain.  hash: " << id);
    bvc.m_verifivation_failed = true;
    return false;
  }
  
  TIME_MEASURE_START(block_processing_time);
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  if(bl.prev_id != get_tail_id())
  {
    LOG_PRINT_L0("Block with id: " << id << std::endl
      << "have wrong prev_id: " << bl.prev_id << std::endl
      << "expected: " << get_tail_id());
    return false;
  }

  // make sure block timestamp is not less than the median timestamp
  // of a set number of the most recent blocks.
  if(!check_block_timestamp(bl))
  {
    LOG_PRINT_L0("Block with id: " << id << std::endl
      << "have invalid timestamp: " << bl.timestamp);
    bvc.m_verifivation_failed = true;
    return false;
  }

  //check proof of work
  TIME_MEASURE_START(target_calculating_time);

  // get the target difficulty for the block.
  // the calculation can overflow, among other failure cases,
  // so we need to check the return type.
  // FIXME: get_difficulty_for_next_block can also assert, look into
  // changing this to throwing exceptions instead so we can clean up.
  difficulty_type current_diffic = get_difficulty_for_next_block();
  CHECK_AND_ASSERT_MES(current_diffic, false, "!!!!!!!!! difficulty overhead !!!!!!!!!");

  TIME_MEASURE_FINISH(target_calculating_time);

  TIME_MEASURE_START(longhash_calculating_time);

  crypto::hash proof_of_work = null_hash;

  // Formerly the code below contained an if loop with the following condition
  // !m_checkpoints.is_in_checkpoint_zone(get_current_blockchain_height())
  // however, this caused the daemon to not bother checking PoW for blocks
  // before checkpoints, which is very dangerous behaviour. We moved the PoW
  // validation out of the next chunk of code to make sure that we correctly
  // check PoW now.
  // FIXME: height parameter is not used...should it be used or should it not
  // be a parameter?
  proof_of_work = get_block_longhash(bl, m_db->height());

  // validate proof_of_work versus difficulty target
  if(!check_hash(proof_of_work, current_diffic))
  {
    LOG_PRINT_L0("Block with id: " << id << std::endl
      << "have not enough proof of work: " << proof_of_work << std::endl
      << "nexpected difficulty: " << current_diffic );
    bvc.m_verifivation_failed = true;
    return false;
  }

  // If we're at a checkpoint, ensure that our hardcoded checkpoint hash
  // is correct.
  if(m_checkpoints.is_in_checkpoint_zone(get_current_blockchain_height()))
  {
    if(!m_checkpoints.check_block(get_current_blockchain_height(), id))
    {
      LOG_ERROR("CHECKPOINT VALIDATION FAILED");
      bvc.m_verifivation_failed = true;
      return false;
    }
  }

  TIME_MEASURE_FINISH(longhash_calculating_time);

  // sanity check basic miner tx properties
  if(!prevalidate_miner_transaction(bl, m_db->height()))
  {
    LOG_PRINT_L0("Block with id: " << id
      << " failed to pass prevalidation");
    bvc.m_verifivation_failed = true;
    return false;
  }

  size_t coinbase_blob_size = get_object_blobsize(bl.miner_tx);
  size_t cumulative_block_size = coinbase_blob_size;

  std::vector<transaction> txs;
  key_images_container keys;

  uint64_t fee_summary = 0;

  // Iterate over the block's transaction hashes, grabbing each
  // from the tx_pool and validating them.  Each is then added
  // to txs.  Keys spent in each are added to <keys> by the double spend check.
  for (const crypto::hash& tx_id : bl.tx_hashes)
  {
    transaction tx;
    size_t blob_size = 0;
    uint64_t fee = 0;

    if (m_db->tx_exists(tx_id))
    {
      LOG_PRINT_L0("Block with id: " << id << " attempting to add transaction already in blockchain with id: " << tx_id);
      bvc.m_verifivation_failed = true;
      break;
    }

    // get transaction with hash <tx_id> from tx_pool
    if(!m_tx_pool.take_tx(tx_id, tx, blob_size, fee))
    {
      LOG_PRINT_L0("Block with id: " << id  << "have at least one unknown transaction with id: " << tx_id);
      bvc.m_verifivation_failed = true;
      break;
    }

    // add the transaction to the temp list of transactions, so we can either
    // store the list of transactions all at once or return the ones we've
    // taken from the tx_pool back to it if the block fails verification.
    txs.push_back(tx);

    // validate that transaction inputs and the keys spending them are correct.
    if(!check_tx_inputs(tx))
    {
      LOG_PRINT_L0("Block with id: " << id  << "have at least one transaction (id: " << tx_id << ") with wrong inputs.");

      //TODO: why is this done?  make sure that keeping invalid blocks makes sense.
      add_block_as_invalid(bl, id);
      LOG_PRINT_L0("Block with id " << id << " added as invalid becouse of wrong inputs in transactions");
      bvc.m_verifivation_failed = true;
      break;
    }

    if (!check_for_double_spend(tx, keys))
    {
      LOG_PRINT_L0("Double spend detected in transaction (id: " << tx_id);
      bvc.m_verifivation_failed = true;
      break;
    }

    fee_summary += fee;
    cumulative_block_size += blob_size;
  }

  uint64_t base_reward = 0;
  uint64_t already_generated_coins = m_db->height() ? m_db->get_block_already_generated_coins(m_db->height() - 1) : 0;
  if(!validate_miner_transaction(bl, cumulative_block_size, fee_summary, base_reward, already_generated_coins))
  {
    LOG_PRINT_L0("Block with id: " << id
      << " have wrong miner transaction");
    bvc.m_verifivation_failed = true;
  }


  block_extended_info bei = boost::value_initialized<block_extended_info>();
  size_t block_size;
  difficulty_type cumulative_difficulty;

  // populate various metadata about the block to be stored alongside it.
  block_size = cumulative_block_size;
  cumulative_difficulty = current_diffic;
  already_generated_coins = already_generated_coins + base_reward;
  if(m_db->height())
    cumulative_difficulty += m_db->get_block_cumulative_difficulty(m_db->height() - 1);

  update_next_cumulative_size_limit();

  TIME_MEASURE_FINISH(block_processing_time);

  uint64_t new_height = 0;
  bool add_success = true;
  if (!bvc.m_verifivation_failed)
  {
    try
    {
      new_height = m_db->add_block(bl, block_size, cumulative_difficulty, already_generated_coins, txs);
    }
    catch (const std::exception& e)
    {
      //TODO: figure out the best way to deal with this failure
      LOG_ERROR("Error adding block with hash: " << id << " to blockchain, what = " << e.what());
      add_success = false;
    }
  }

  // if we failed for any reason to verify the block, return taken
  // transactions to the tx_pool.
  if (bvc.m_verifivation_failed || !add_success)
  {
    // return taken transactions to transaction pool
    for (auto& tx : txs)
    {
      cryptonote::tx_verification_context tvc = AUTO_VAL_INIT(tvc);
      if (!m_tx_pool.add_tx(tx, tvc, true))
      {
        LOG_PRINT_L0("Failed to return taken transaction with hash: " << get_transaction_hash(tx) << " to tx_pool");
      }
    }
    return false;
  }

  LOG_PRINT_L1("+++++ BLOCK SUCCESSFULLY ADDED" << std::endl << "id:\t" << id
    << std::endl << "PoW:\t" << proof_of_work
    << std::endl << "HEIGHT " << new_height << ", difficulty:\t" << current_diffic
    << std::endl << "block reward: " << print_money(fee_summary + base_reward) << "(" << print_money(base_reward) << " + " << print_money(fee_summary)
    << "), coinbase_blob_size: " << coinbase_blob_size << ", cumulative size: " << cumulative_block_size
    << ", " << block_processing_time << "("<< target_calculating_time << "/" << longhash_calculating_time << ")ms");

  bvc.m_added_to_main_chain = true;

  // appears to be a NOP *and* is called elsewhere.  wat?
  m_tx_pool.on_blockchain_inc(new_height, id);

  return true;
}
//------------------------------------------------------------------
bool Blockchain::update_next_cumulative_size_limit()
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  std::vector<size_t> sz;
  get_last_n_blocks_sizes(sz, CRYPTONOTE_REWARD_BLOCKS_WINDOW);

  uint64_t median = epee::misc_utils::median(sz);
  if(median <= CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE)
    median = CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE;

  m_current_block_cumul_sz_limit = median*2;
  return true;
}
//------------------------------------------------------------------
bool Blockchain::add_new_block(const block& bl_, block_verification_context& bvc)
{
  LOG_PRINT_L3("Blockchain::" << __func__);
  //copy block here to let modify block.target
  block bl = bl_;
  crypto::hash id = get_block_hash(bl);
  CRITICAL_REGION_LOCAL(m_tx_pool);//to avoid deadlock lets lock tx_pool for whole add/reorganize process
  CRITICAL_REGION_LOCAL1(m_blockchain_lock);
  if(have_block(id))
  {
    LOG_PRINT_L3("block with id = " << id << " already exists");
    bvc.m_already_exists = true;
    return false;
  }

  //check that block refers to chain tail
  if(!(bl.prev_id == get_tail_id()))
  {
    //chain switching or wrong block
    bvc.m_added_to_main_chain = false;
    return handle_alternative_block(bl, id, bvc);
    //never relay alternative blocks
  }

  return handle_block_to_main_chain(bl, id, bvc);
}
//------------------------------------------------------------------
void Blockchain::check_against_checkpoints(checkpoints& points, bool enforce)
{
  const auto& pts = points.get_points();

  for (const auto& pt : pts)
  {
    // if the checkpoint is for a block we don't have yet, move on
    if (pt.first >= m_db->height())
    {
      continue;
    }

    if (!points.check_block(pt.first, m_db->get_block_hash_from_height(pt.first)))
    {
      // if asked to enforce checkpoints, roll back to a couple of blocks before the checkpoint
      if (enforce)
      {
        LOG_ERROR("Local blockchain failed to pass a checkpoint, rolling back!");
        std::list<block> empty;
        rollback_blockchain_switching(empty, pt.first - 2);
      }
      else
      {
        LOG_ERROR("WARNING: local blockchain failed to pass a MoneroPulse checkpoint, and you could be on a fork. You should either sync up from scratch, OR download a fresh blockchain bootstrap, OR enable checkpoint enforcing with the --enforce-dns-checkpointing command-line option");
      }
    }
  }
}
//------------------------------------------------------------------
// returns false if any of the checkpoints loading returns false.
// That should happen only if a checkpoint is added that conflicts
// with an existing checkpoint.
bool Blockchain::update_checkpoints(const std::string& file_path, bool check_dns)
{
  if (!cryptonote::load_checkpoints_from_json(m_checkpoints, file_path))
  {
    return false;
  }

  // if we're checking both dns and json, load checkpoints from dns.
  // if we're not hard-enforcing dns checkpoints, handle accordingly
  if (m_enforce_dns_checkpoints && check_dns)
  {
    if (!cryptonote::load_checkpoints_from_dns(m_checkpoints))
    {
      return false;
    }
  }
  else if (check_dns)
  {
    checkpoints dns_points;
    cryptonote::load_checkpoints_from_dns(dns_points);
    if (m_checkpoints.check_for_conflicts(dns_points))
    {
      check_against_checkpoints(dns_points, false);
    }
    else
    {
      LOG_PRINT_L0("One or more checkpoints fetched from DNS conflicted with existing checkpoints!");
    }
  }

  check_against_checkpoints(m_checkpoints, true);

  return true;
}
//------------------------------------------------------------------
void Blockchain::set_enforce_dns_checkpoints(bool enforce_checkpoints)
{
  m_enforce_dns_checkpoints = enforce_checkpoints;
}
