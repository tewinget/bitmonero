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

#include "include_base_utils.h"
#include "cryptonote_basic_impl.h"
#include "blockchain.h"
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
//#include "serialization/json_archive.h"

/* TODO:
 *  Clean up code:
 *    Clarify where double spend check should be done, and only do it there.
 *    Combine check_tx_inputs functions into one coherent function.
 *    Possibly change how outputs are referred to/indexed in blockchain and wallets
 *
 */

using namespace cryptonote;

DISABLE_VS_WARNINGS(4267)

//------------------------------------------------------------------
// TODO: initialize m_db with a concrete implementation of BlockchainDB
Blockchain::Blockchain(tx_memory_pool& tx_pool):m_db(), m_tx_pool(tx_pool), m_current_block_cumul_sz_limit(0), m_is_in_checkpoint_zone(false), m_is_blockchain_storing(false)
{
  if (m_db == NULL)
  {
    throw new DB_ERROR("database pointer null in blockchain init");
  }
}
//------------------------------------------------------------------
//TODO: is this still needed?  I don't think so - tewinget
template<class archive_t>
void Blockchain::serialize(archive_t & ar, const unsigned int version)
{
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


  LOG_PRINT_L2("Blockchain storage:" << std::endl << 
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
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  return m_db->tx_exists(id);
}
//------------------------------------------------------------------
bool Blockchain::have_tx_keyimg_as_spent(const crypto::key_image &key_im)
{
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
      auto tx = m_db->get_transaction(output_index.first);

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
      LOG_PRINT_L0("Output with amount " << tx_in_to_key.amount << " and index " << i << " does not exist!");
      return false;
    }
    catch (const TX_DNE& e)
    {
      LOG_PRINT_L0("Transaction with hash " << output_index.first << " does not exist!");
      return false;
    }

  }

  return true;
}
//------------------------------------------------------------------
uint64_t Blockchain::get_current_blockchain_height()
{
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  return m_db->height();
}
//------------------------------------------------------------------
//FIXME: possibly move this into the constructor, to avoid accidentally
//       dereferencing a null BlockchainDB pointer
bool Blockchain::init(const std::string& config_folder)
{
  CRITICAL_REGION_LOCAL(m_blockchain_lock);

  m_config_folder = config_folder;
  LOG_PRINT_L0("Loading blockchain...");

  //FIXME: update filename for BlockchainDB
  const std::string filename = m_config_folder + "/" CRYPTONOTE_BLOCKCHAINDATA_FILENAME;
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
  if(!m_db->height())
  {
    LOG_PRINT_L0("Blockchain not loaded, generating genesis block.");
    block bl = boost::value_initialized<block>();
    block_verification_context bvc = boost::value_initialized<block_verification_context>();
    generate_genesis_block(bl);
    add_new_block(bl, bvc);
    CHECK_AND_ASSERT_MES(!bvc.m_verification_failed, false, "Failed to add genesis block to blockchain");
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
  return true;
}
//------------------------------------------------------------------
bool Blockchain::pop_block_from_blockchain()
{
  CRITICAL_REGION_LOCAL(m_blockchain_lock);

  auto h = m_db->height();
  CHECK_AND_ASSERT_MES(h > 1, false, "popping the genesis block from the blockchain doesn't make any sense");
  auto popped_block = m_db->pop_block();

  //TODO: revisit this after the function purge_block_data_from_blockchain has been modified as needed
  bool r = purge_block_data_from_blockchain(popped_block, popped_block.tx_hashes.size());
  CHECK_AND_ASSERT_MES(r, false, "Failed to purge_block_data_from_blockchain for block " << get_block_hash(popped_block) << "at height " << h);

  //TODO: this appears to be a NOP on m_tx_pool's end, verify and remove if possible
  m_tx_pool.on_blockchain_dec(h, get_tail_id());
  return true;
}
//------------------------------------------------------------------
bool Blockchain::reset_and_set_genesis_block(const block& b)
{
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
  return bvc.m_added_to_main_chain && !bvc.m_verification_failed;
}
//------------------------------------------------------------------
//TODO: move to BlockchainDB subclass
bool Blockchain::purge_transaction_keyimages_from_blockchain(const transaction& tx, bool strict_check)
{
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
//TODO: this functionality will be split between the BlockchainDB and this class.
//      The BlockchainDB class will handle the actual removal, and the function
//      in this class that removes a block from the blockchain will handle giving
//      the transactions back to the transaction pool.
bool Blockchain::purge_transaction_from_blockchain(const crypto::hash& tx_id)
{
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  auto tx_index_it = m_transactions.find(tx_id);
  CHECK_AND_ASSERT_MES(tx_index_it != m_transactions.end(), false, "purge_block_data_from_blockchain: transaction not found in blockchain index!!");
  transaction& tx = tx_index_it->second.tx;

  purge_transaction_keyimages_from_blockchain(tx, true);

  if(!is_coinbase(tx))
  {
    cryptonote::tx_verification_context tvc = AUTO_VAL_INIT(tvc);
    bool r = m_tx_pool.add_tx(tx, tvc, true);
    CHECK_AND_ASSERT_MES(r, false, "purge_block_data_from_blockchain: failed to add transaction to transaction pool");
  }

  bool res = pop_transaction_from_global_index(tx, tx_id);
  m_transactions.erase(tx_index_it);
  LOG_PRINT_L1("Removed transaction from blockchain history:" << tx_id << std::endl);
  return res;
}
//------------------------------------------------------------------
//TODO: This functionality will be done in BlockchainDB, much like
//      purge_transaction_from_blockchain above.  This function can
//      be removed once that is in place.
bool Blockchain::purge_block_data_from_blockchain(const block& bl, size_t processed_tx_count)
{
  CRITICAL_REGION_LOCAL(m_blockchain_lock);

  bool res = true;
  CHECK_AND_ASSERT_MES(processed_tx_count <= bl.tx_hashes.size(), false, "wrong processed_tx_count in purge_block_data_from_blockchain");
  for(size_t count = 0; count != processed_tx_count; count++)
  {
    res = purge_transaction_from_blockchain(bl.tx_hashes[(processed_tx_count -1)- count]) && res;
  }

  res = purge_transaction_from_blockchain(get_transaction_hash(bl.miner_tx)) && res;

  return res;
}
//------------------------------------------------------------------
crypto::hash Blockchain::get_tail_id(uint64_t& height)
{
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  height = m_db->height();
  return get_tail_id();
}
//------------------------------------------------------------------
crypto::hash Blockchain::get_tail_id()
{
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  return m_db->top_block_hash();
}
//------------------------------------------------------------------
//TODO: rewrite using BlockchainDB
bool Blockchain::get_short_chain_history(std::list<crypto::hash>& ids)
{
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  size_t i = 0;
  size_t current_multiplier = 1;
  size_t sz = m_db->height();
  if(!sz)
    return true;
  size_t current_back_offset = 1;
  bool genesis_included = false;
  while(current_back_offset < sz)
  {
    ids.push_back(get_block_hash(m_blocks[sz-current_back_offset].bl));
    if(sz-current_back_offset == 0)
      genesis_included = true;
    if(i < 10)
    {
      ++current_back_offset;
    }else
    {
      current_back_offset += current_multiplier *= 2;
    }
    ++i;
  }
  if(!genesis_included)
    ids.push_back(get_block_hash(m_blocks[0].bl));

  return true;
}
//------------------------------------------------------------------
crypto::hash Blockchain::get_block_id_by_height(uint64_t height)
{
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  try
  {
    return m_db->get_block_from_height(height);
  }
  catch (BLOCK_DNE e)
  {
  }
  catch (std::exception e)
  {
    LOG_PRINT_L0(std::string("Something went wrong fetching block hash by height: ") + e.what());
    throw;
  }
  return null_hash;
}
//------------------------------------------------------------------
bool Blockchain::get_block_by_hash(const crypto::hash &h, block &blk) {
  CRITICAL_REGION_LOCAL(m_blockchain_lock);

  // try to find block in main chain
  try
  {
    blk = m_db->get_block(hash);
    return true;
  }
  // try to find block in alternative chain
  catch (BLOCK_DNE e)
  {
    blocks_ext_by_hash::const_iterator it_alt = m_alternative_chains.find(h);
    if (m_alternative_chains.end() != it_alt) {
      blk = it_alt->second.bl;
      return true;
    }
  }
  catch (std::exception e)
  {
    LOG_PRINT_L0(std::string("Something went wrong fetching block by hash: ") + e.what());
    throw;
  }

  return false;
}
//------------------------------------------------------------------
void Blockchain::get_all_known_block_ids(std::list<crypto::hash> &main, std::list<crypto::hash> &alt, std::list<crypto::hash> &invalid) {
  CRITICAL_REGION_LOCAL(m_blockchain_lock);

  main = m_db->get_hashes_range(0, m_db->height());

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
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  std::vector<uint64_t> timestamps;
  std::vector<difficulty_type> cumulative_difficulties;
  auto h = m_db->height();

  size_t offset = h - std::min(h, static_cast<size_t>(DIFFICULTY_BLOCKS_COUNT));

  // because BlockchainDB::height() returns the index of the top block, the
  // first index we need to get needs to be one
  // higher than height() - DIFFICULTY_BLOCKS_COUNT.  This also conveniently
  // makes sure we don't use the genesis block.
  ++offset;

  for(; offset <= h; offset++)
  {
    timestamps.push_back(m_db->get_block_timestamp(offset));
    cumulative_difficulties.push_back(m_db->get_block_cumulative_difficulty(offset));
  }
  return next_difficulty(timestamps, cumulative_difficulties);
}
//------------------------------------------------------------------
//TODO: rewrite using BlockchainDB
bool Blockchain::rollback_blockchain_switching(std::list<block>& original_chain, size_t rollback_height)
{
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  //remove failed subchain
  for(size_t i = m_db->height()-1; i >=rollback_height; i--)
  {
    bool r = pop_block_from_blockchain();
    CHECK_AND_ASSERT_MES(r, false, "PANIC!!! failed to remove block while chain switching during the rollback!");
  }
  //return back original chain
  BOOST_FOREACH(auto& bl, original_chain)
  {
    block_verification_context bvc = boost::value_initialized<block_verification_context>();
    bool r = handle_block_to_main_chain(bl, bvc);
    CHECK_AND_ASSERT_MES(r && bvc.m_added_to_main_chain, false, "PANIC!!! failed to add (again) block while chain switching during the rollback!");
  }

  LOG_PRINT_L0("Rollback success.");
  return true;
}
//------------------------------------------------------------------
//TODO: rewrite using BlockchainDB
bool Blockchain::switch_to_alternative_blockchain(std::list<blocks_ext_by_hash::iterator>& alt_chain, bool discard_disconnected_chain)
{
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  CHECK_AND_ASSERT_MES(alt_chain.size(), false, "switch_to_alternative_blockchain: empty chain passed");

  size_t split_height = alt_chain.front()->second.height;
  CHECK_AND_ASSERT_MES(m_db->height() > split_height, false, "switch_to_alternative_blockchain: blockchain size is lower than split height");

  //disconnecting old chain
  std::list<block> disconnected_chain;
  for(size_t i = m_db->height()-1; i >=split_height; i--)
  {
    block b = m_blocks[i].bl;
    bool r = pop_block_from_blockchain();
    CHECK_AND_ASSERT_MES(r, false, "failed to remove block on chain switching");
    disconnected_chain.push_front(b);
  }

  //connecting new alternative chain
  for(auto alt_ch_iter = alt_chain.begin(); alt_ch_iter != alt_chain.end(); alt_ch_iter++)
  {
    auto ch_ent = *alt_ch_iter;
    block_verification_context bvc = boost::value_initialized<block_verification_context>();
    bool r = handle_block_to_main_chain(ch_ent->second.bl, bvc);
    if(!r || !bvc.m_added_to_main_chain)
    {
      LOG_PRINT_L0("Failed to switch to alternative blockchain");
      rollback_blockchain_switching(disconnected_chain, split_height);
      add_block_as_invalid(ch_ent->second, get_block_hash(ch_ent->second.bl));
      LOG_PRINT_L0("The block was inserted as invalid while connecting new alternative chain,  block_id: " << get_block_hash(ch_ent->second.bl));
      m_alternative_chains.erase(ch_ent);

      for(auto alt_ch_to_orph_iter = ++alt_ch_iter; alt_ch_to_orph_iter != alt_chain.end(); alt_ch_to_orph_iter++)
      {
        //block_verification_context bvc = boost::value_initialized<block_verification_context>();
        add_block_as_invalid((*alt_ch_iter)->second, (*alt_ch_iter)->first);
        m_alternative_chains.erase(*alt_ch_to_orph_iter);
      }
      return false;
    }
  }

  if(!discard_disconnected_chain)
  {
    //pushing old chain as alternative chain
    BOOST_FOREACH(auto& old_ch_ent, disconnected_chain)
    {
      block_verification_context bvc = boost::value_initialized<block_verification_context>();
      bool r = handle_alternative_block(old_ch_ent, get_block_hash(old_ch_ent), bvc);
      if(!r)
      {
        LOG_ERROR("Failed to push ex-main chain blocks to alternative chain ");
        rollback_blockchain_switching(disconnected_chain, split_height);
        return false;
      }
    }
  }

  //removing all_chain entries from alternative chain
  BOOST_FOREACH(auto ch_ent, alt_chain)
  {
    m_alternative_chains.erase(ch_ent);
  }

  LOG_PRINT_GREEN("REORGANIZE SUCCESS! on height: " << split_height << ", new blockchain size: " << m_db->height(), LOG_LEVEL_0);
  return true;
}
//------------------------------------------------------------------
//TODO: rewrite using BlockchainDB
difficulty_type Blockchain::get_next_difficulty_for_alternative_chain(const std::list<blocks_ext_by_hash::iterator>& alt_chain, block_extended_info& bei)
{
  std::vector<uint64_t> timestamps;
  std::vector<difficulty_type> commulative_difficulties;
  if(alt_chain.size()< DIFFICULTY_BLOCKS_COUNT)
  {
    CRITICAL_REGION_LOCAL(m_blockchain_lock);
    size_t main_chain_stop_offset = alt_chain.size() ? alt_chain.front()->second.height : bei.height;
    size_t main_chain_count = DIFFICULTY_BLOCKS_COUNT - std::min(static_cast<size_t>(DIFFICULTY_BLOCKS_COUNT), alt_chain.size());
    main_chain_count = std::min(main_chain_count, main_chain_stop_offset);
    size_t main_chain_start_offset = main_chain_stop_offset - main_chain_count;

    if(!main_chain_start_offset)
      ++main_chain_start_offset; //skip genesis block
    for(; main_chain_start_offset < main_chain_stop_offset; ++main_chain_start_offset)
    {
      timestamps.push_back(m_blocks[main_chain_start_offset].bl.timestamp);
      commulative_difficulties.push_back(m_blocks[main_chain_start_offset].cumulative_difficulty);
    }

    CHECK_AND_ASSERT_MES((alt_chain.size() + timestamps.size()) <= DIFFICULTY_BLOCKS_COUNT, false, "Internal error, alt_chain.size()["<< alt_chain.size()
                                                                                    << "] + vtimestampsec.size()[" << timestamps.size() << "] NOT <= DIFFICULTY_WINDOW[]" << DIFFICULTY_BLOCKS_COUNT );
    BOOST_FOREACH(auto it, alt_chain)
    {
      timestamps.push_back(it->second.bl.timestamp);
      commulative_difficulties.push_back(it->second.cumulative_difficulty);
    }
  }else
  {
    timestamps.resize(std::min(alt_chain.size(), static_cast<size_t>(DIFFICULTY_BLOCKS_COUNT)));
    commulative_difficulties.resize(std::min(alt_chain.size(), static_cast<size_t>(DIFFICULTY_BLOCKS_COUNT)));
    size_t count = 0;
    size_t max_i = timestamps.size()-1;
    BOOST_REVERSE_FOREACH(auto it, alt_chain)
    {
      timestamps[max_i - count] = it->second.bl.timestamp;
      commulative_difficulties[max_i - count] = it->second.cumulative_difficulty;
      count++;
      if(count >= DIFFICULTY_BLOCKS_COUNT)
        break;
    }
  }
  return next_difficulty(timestamps, commulative_difficulties);
}
//------------------------------------------------------------------
// This function does a sanity check on basic things that all miner
// transactions have in common, such as:
//   one input, of type txin_gen, with height set to the block's height
//   correct miner tx unlock time
//   a non-overflowing tx amount (dubious necessity on this check)
bool Blockchain::prevalidate_miner_transaction(const block& b, uint64_t height)
{
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
    LOG_ERROR("coinbase transaction spend too much money (" << print_money(money_in_use) << "). Block reward is " << print_money(base_reward + fee) << "(" << print_money(base_reward) << "+" << print_money(fee) << ")");
    return false;
  }
  if(base_reward + fee != money_in_use)
  {
    LOG_ERROR("coinbase transaction doesn't use full amount of block reward:  spent: "
                            << print_money(money_in_use) << ",  block reward " << print_money(base_reward + fee) << "(" << print_money(base_reward) << "+" << print_money(fee) << ")");
    return false;
  }
  return true;
}
//------------------------------------------------------------------
// get the block sizes of the last <count> blocks, starting at <from_height>
// and return by reference <sz>.
void Blockchain::get_last_n_blocks_sizes(std::vector<size_t>& sz, size_t count)
{
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  auto h = m_db->height();

  // this function is meaningless for an empty blockchain...granted it should never be empty
  if(h == 0)
    return;

  // add size of last <count> blocks to vector <sz> (or less, if blockchain size < count)
  size_t start_offset = (h+1) - std::min((h+1), count);
  for(size_t i = start_offset; i <= h; i++)
  {
    sz.push_back(m_db->get_block_size(i));
  }
}
//------------------------------------------------------------------
uint64_t Blockchain::get_current_cumulative_blocksize_limit()
{
  return m_current_block_cumul_sz_limit;
}
//------------------------------------------------------------------
//TODO: rewrite using BlockchainDB
bool Blockchain::create_block_template(block& b, const account_public_address& miner_address, difficulty_type& diffic, uint64_t& height, const blobdata& ex_nonce)
{
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
  already_generated_coins = m_blocks.back().already_generated_coins;

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
//TODO: rewrite using BlockchainDB
bool Blockchain::complete_timestamps_vector(uint64_t start_top_height, std::vector<uint64_t>& timestamps)
{

  if(timestamps.size() >= BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW)
    return true;

  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  size_t need_elements = BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW - timestamps.size();
  CHECK_AND_ASSERT_MES(start_top_height < m_db->height(), false, "internal error: passed start_height = " << start_top_height << " not less then m_db->height()=" << m_db->height());
  size_t stop_offset = start_top_height > need_elements ? start_top_height - need_elements:0;
  do
  {
    timestamps.push_back(m_blocks[start_top_height].bl.timestamp);
    if(start_top_height == 0)
      break;
    --start_top_height;
  }while(start_top_height != stop_offset);
  return true;
}
//------------------------------------------------------------------
//TODO: rewrite using BlockchainDB
bool Blockchain::handle_alternative_block(const block& b, const crypto::hash& id, block_verification_context& bvc)
{
  CRITICAL_REGION_LOCAL(m_blockchain_lock);

  uint64_t block_height = get_block_height(b);
  if(0 == block_height)
  {
    LOG_ERROR("Block with id: " << epee::string_tools::pod_to_hex(id) << " (as alternative) have wrong miner transaction");
    bvc.m_verification_failed = true;
    return false;
  }
  if (!m_checkpoints.is_alternative_block_allowed(get_current_blockchain_height(), block_height))
  {
    LOG_PRINT_RED_L0("Block with id: " << id
      << std::endl << " can't be accepted for alternative chain, block height: " << block_height
      << std::endl << " blockchain height: " << get_current_blockchain_height());
    bvc.m_verification_failed = true;
    return false;
  }

  //block is not related with head of main chain
  //first of all - look in alternative chains container
  auto it_main_prev = m_blocks_index.find(b.prev_id);
  auto it_prev = m_alternative_chains.find(b.prev_id);
  if(it_prev != m_alternative_chains.end() || it_main_prev != m_blocks_index.end())
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

    if(alt_chain.size())
    {
      //make sure that it has right connection to main chain
      CHECK_AND_ASSERT_MES(m_db->height() > alt_chain.front()->second.height, false, "main blockchain wrong height");
      crypto::hash h = null_hash;
      get_block_hash(m_blocks[alt_chain.front()->second.height - 1].bl, h);
      CHECK_AND_ASSERT_MES(h == alt_chain.front()->second.bl.prev_id, false, "alternative chain have wrong connection to main chain");
      complete_timestamps_vector(alt_chain.front()->second.height - 1, timestamps);
    }else
    {
      CHECK_AND_ASSERT_MES(it_main_prev != m_blocks_index.end(), false, "internal error: broken imperative condition it_main_prev != m_blocks_index.end()");
      complete_timestamps_vector(it_main_prev->second, timestamps);
    }
    //check timestamp correct
    if(!check_block_timestamp(timestamps, b))
    {
      LOG_PRINT_RED_L0("Block with id: " << id
        << std::endl << " for alternative chain, have invalid timestamp: " << b.timestamp);
      //add_block_as_invalid(b, id);//do not add blocks to invalid storage before proof of work check was passed
      bvc.m_verification_failed = true;
      return false;
    }

    block_extended_info bei = boost::value_initialized<block_extended_info>();
    bei.bl = b;
    bei.height = alt_chain.size() ? it_prev->second.height + 1 : it_main_prev->second + 1;

    bool is_a_checkpoint;
    if(!m_checkpoints.check_block(bei.height, id, is_a_checkpoint))
    {
      LOG_ERROR("CHECKPOINT VALIDATION FAILED");
      bvc.m_verification_failed = true;
      return false;
    }

    // Always check PoW for alternative blocks
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
      bvc.m_verification_failed = true;
      return false;
    }

    if(!prevalidate_miner_transaction(b, bei.height))
    {
      LOG_PRINT_RED_L0("Block with id: " << epee::string_tools::pod_to_hex(id)
        << " (as alternative) have wrong miner transaction.");
      bvc.m_verification_failed = true;
      return false;

    }

    bei.cumulative_difficulty = alt_chain.size() ? it_prev->second.cumulative_difficulty: m_blocks[it_main_prev->second].cumulative_difficulty;
    bei.cumulative_difficulty += current_diff;

#ifdef _DEBUG
    auto i_dres = m_alternative_chains.find(id);
    CHECK_AND_ASSERT_MES(i_dres == m_alternative_chains.end(), false, "insertion of new alternative block returned as it already exist");
#endif
    auto i_res = m_alternative_chains.insert(blocks_ext_by_hash::value_type(id, bei));
    CHECK_AND_ASSERT_MES(i_res.second, false, "insertion of new alternative block returned as it already exist");
    alt_chain.push_back(i_res.first);

    if(is_a_checkpoint)
    {
      //do reorganize!
      LOG_PRINT_GREEN("###### REORGANIZE on height: " << alt_chain.front()->second.height << " of " << m_db->height() - 1 <<
        ", checkpoint is found in alternative chain on height " << bei.height, LOG_LEVEL_0);
      bool r = switch_to_alternative_blockchain(alt_chain, true);
      if(r) bvc.m_added_to_main_chain = true;
      else bvc.m_verification_failed = true;
      return r;
    }else if(m_blocks.back().cumulative_difficulty < bei.cumulative_difficulty) //check if difficulty bigger then in main chain
    {
      //do reorganize!
      LOG_PRINT_GREEN("###### REORGANIZE on height: " << alt_chain.front()->second.height << " of " << m_db->height() - 1 << " with cum_difficulty " << m_blocks.back().cumulative_difficulty
        << std::endl << " alternative blockchain size: " << alt_chain.size() << " with cum_difficulty " << bei.cumulative_difficulty, LOG_LEVEL_0);
      bool r = switch_to_alternative_blockchain(alt_chain, false);
      if(r) bvc.m_added_to_main_chain = true;
      else bvc.m_verification_failed = true;
      return r;
    }else
    {
      LOG_PRINT_BLUE("----- BLOCK ADDED AS ALTERNATIVE ON HEIGHT " << bei.height
        << std::endl << "id:\t" << id
        << std::endl << "PoW:\t" << proof_of_work
        << std::endl << "difficulty:\t" << current_diff, LOG_LEVEL_0);
      return true;
    }
  }else
  {
    //block orphaned
    bvc.m_marked_as_orphaned = true;
    LOG_PRINT_RED_L0("Block recognized as orphaned and rejected, id = " << id);
  }

  return true;
}
//------------------------------------------------------------------
//TODO: rewrite using BlockchainDB
bool Blockchain::get_blocks(uint64_t start_offset, size_t count, std::list<block>& blocks, std::list<transaction>& txs)
{
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  if(start_offset >= m_db->height())
    return false;
  for(size_t i = start_offset; i < start_offset + count && i < m_db->height();i++)
  {
    blocks.push_back(m_blocks[i].bl);
    std::list<crypto::hash> missed_ids;
    get_transactions(m_blocks[i].bl.tx_hashes, txs, missed_ids);
    CHECK_AND_ASSERT_MES(!missed_ids.size(), false, "have missed transactions in own block in main blockchain");
  }

  return true;
}
//------------------------------------------------------------------
//TODO: rewrite using BlockchainDB
bool Blockchain::get_blocks(uint64_t start_offset, size_t count, std::list<block>& blocks)
{
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  if(start_offset >= m_db->height())
    return false;

  for(size_t i = start_offset; i < start_offset + count && i < m_db->height();i++)
    blocks.push_back(m_blocks[i].bl);
  return true;
}
//------------------------------------------------------------------
//TODO: rewrite using BlockchainDB
bool Blockchain::handle_get_objects(NOTIFY_REQUEST_GET_OBJECTS::request& arg, NOTIFY_RESPONSE_GET_OBJECTS::request& rsp)
{
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
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  return m_alternative_chains.size();
}
//------------------------------------------------------------------
//TODO: rewrite using BlockchainDB
bool Blockchain::add_out_to_get_random_outs(std::vector<std::pair<crypto::hash, size_t> >& amount_outs, COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::outs_for_amount& result_outs, uint64_t amount, size_t i)
{
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  transactions_container::iterator tx_it = m_transactions.find(amount_outs[i].first);
  CHECK_AND_ASSERT_MES(tx_it != m_transactions.end(), false, "internal error: transaction with id " << amount_outs[i].first << std::endl <<
    ", used in mounts global index for amount=" << amount << ": i=" << i << "not found in transactions index");
  CHECK_AND_ASSERT_MES(tx_it->second.tx.vout.size() > amount_outs[i].second, false, "internal error: in global outs index, transaction out index="
    << amount_outs[i].second << " more than transaction outputs = " << tx_it->second.tx.vout.size() << ", for tx id = " << amount_outs[i].first);
  transaction& tx = tx_it->second.tx;
  CHECK_AND_ASSERT_MES(tx.vout[amount_outs[i].second].target.type() == typeid(txout_to_key), false, "unknown tx out type");

  //check if transaction is unlocked
  if(!is_tx_spendtime_unlocked(tx.unlock_time))
    return false;

  COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::out_entry& oen = *result_outs.outs.insert(result_outs.outs.end(), COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::out_entry());
  oen.global_amount_index = i;
  oen.out_key = boost::get<txout_to_key>(tx.vout[amount_outs[i].second].target).key;
  return true;
}
//------------------------------------------------------------------
//TODO: rewrite using BlockchainDB
size_t Blockchain::find_end_of_allowed_index(const std::vector<std::pair<crypto::hash, size_t> >& amount_outs)
{
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  if(!amount_outs.size())
    return 0;
  size_t i = amount_outs.size();
  do
  {
    --i;
    transactions_container::iterator it = m_transactions.find(amount_outs[i].first);
    CHECK_AND_ASSERT_MES(it != m_transactions.end(), 0, "internal error: failed to find transaction from outputs index with tx_id=" << amount_outs[i].first);
    if(it->second.m_keeper_block_height + CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW <= get_current_blockchain_height() )
      return i+1;
  } while (i != 0);
  return 0;
}
//------------------------------------------------------------------
//TODO: rewrite using BlockchainDB
bool Blockchain::get_random_outs_for_amounts(const COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::request& req, COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::response& res)
{
  srand(static_cast<unsigned int>(time(NULL)));
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  BOOST_FOREACH(uint64_t amount, req.amounts)
  {
    COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::outs_for_amount& result_outs = *res.outs.insert(res.outs.end(), COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::outs_for_amount());
    result_outs.amount = amount;
    auto it = m_outputs.find(amount);
    if(it == m_outputs.end())
    {
      LOG_ERROR("COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS: not outs for amount " << amount << ", wallet should use some real outs when it lookup for some mix, so, at least one out for this amount should exist");
      continue;//actually this is strange situation, wallet should use some real outs when it lookup for some mix, so, at least one out for this amount should exist
    }
    std::vector<std::pair<crypto::hash, size_t> >& amount_outs  = it->second;
    //it is not good idea to use top fresh outs, because it increases possibility of transaction canceling on split
    //lets find upper bound of not fresh outs
    size_t up_index_limit = find_end_of_allowed_index(amount_outs);
    CHECK_AND_ASSERT_MES(up_index_limit <= amount_outs.size(), false, "internal error: find_end_of_allowed_index returned wrong index=" << up_index_limit << ", with amount_outs.size = " << amount_outs.size());
    if(amount_outs.size() > req.outs_count)
    {
      std::set<size_t> used;
      size_t try_count = 0;
      for(uint64_t j = 0; j != req.outs_count && try_count < up_index_limit;)
      {
        size_t i = rand()%up_index_limit;
        if(used.count(i))
          continue;
        bool added = add_out_to_get_random_outs(amount_outs, result_outs, amount, i);
        used.insert(i);
        if(added)
          ++j;
        ++try_count;
      }
    }else
    {
      for(size_t i = 0; i != up_index_limit; i++)
        add_out_to_get_random_outs(amount_outs, result_outs, amount, i);
    }
  }
  return true;
}
//------------------------------------------------------------------
//TODO: rewrite using BlockchainDB
bool Blockchain::find_blockchain_supplement(const std::list<crypto::hash>& qblock_ids, uint64_t& starter_offset)
{
  CRITICAL_REGION_LOCAL(m_blockchain_lock);

  if(!qblock_ids.size() /*|| !req.m_total_height*/)
  {
    LOG_ERROR("Client sent wrong NOTIFY_REQUEST_CHAIN: m_block_ids.size()=" << qblock_ids.size() << /*", m_height=" << req.m_total_height <<*/ ", dropping connection");
    return false;
  }
  //check genesis match
  if(qblock_ids.back() != get_block_hash(m_blocks[0].bl))
  {
    LOG_ERROR("Client sent wrong NOTIFY_REQUEST_CHAIN: genesis block missmatch: " << std::endl << "id: "
      << qblock_ids.back() << ", " << std::endl << "expected: " << get_block_hash(m_blocks[0].bl)
      << "," << std::endl << " dropping connection");
    return false;
  }

  /* Figure out what blocks we should request to get state_normal */
  size_t i = 0;
  auto bl_it = qblock_ids.begin();
  auto block_index_it = m_blocks_index.find(*bl_it);
  for(; bl_it != qblock_ids.end(); bl_it++, i++)
  {
    block_index_it = m_blocks_index.find(*bl_it);
    if(block_index_it != m_blocks_index.end())
      break;
  }

  if(bl_it == qblock_ids.end())
  {
    LOG_ERROR("Internal error handling connection, can't find split point");
    return false;
  }

  if(block_index_it == m_blocks_index.end())
  {
    //this should NEVER happen, but, dose of paranoia in such cases is not too bad
    LOG_ERROR("Internal error handling connection, can't find split point");
    return false;
  }

  //we start to put block ids INCLUDING last known id, just to make other side be sure
  starter_offset = block_index_it->second;
  return true;
}
//------------------------------------------------------------------
uint64_t Blockchain::block_difficulty(size_t i)
{
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  try
  {
    return m_db->get_block_difficulty(i);
  }
  catch (const BLOCK_DNE& e)
  {
    LOG_PRINT_L0("Attempted to get block difficulty for height above blockchain height");
  }
}
//------------------------------------------------------------------
template<class t_ids_container, class t_blocks_container, class t_missed_container>
void Blockchain::get_blocks(const t_ids_container& block_ids, t_blocks_container& blocks, t_missed_container& missed_bs)
{
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
  }
}
//------------------------------------------------------------------
template<class t_ids_container, class t_tx_container, class t_missed_container>
void Blockchain::get_transactions(const t_ids_container& txs_ids, t_tx_container& txs, t_missed_container& missed_txs)
{
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
  }
}
//------------------------------------------------------------------
void Blockchain::print_blockchain(uint64_t start_index, uint64_t end_index)
{
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
       << ", size " << m_db->get_block_size(i);
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
  std::stringstream ss;
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  for(uint64_t i = 0; i <= m_db->height(); i++)
  {
    ss << "height: " << i << ", hash: " << m_db->get_block_hash_from_height(i);
  }

  LOG_PRINT_L0("Current blockchain index:" << std::endl
               << ss.str()
              );
}
//------------------------------------------------------------------
//TODO: rewrite using BlockchainDB
void Blockchain::print_blockchain_outs(const std::string& file)
{
  std::stringstream ss;
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  BOOST_FOREACH(const outputs_container::value_type& v, m_outputs)
  {
    const std::vector<std::pair<crypto::hash, size_t> >& vals = v.second;
    if(vals.size())
    {
      ss << "amount: " <<  v.first << std::endl;
      for(size_t i = 0; i != vals.size(); i++)
        ss << "\t" << vals[i].first << ": " << vals[i].second << std::endl;
    }
  }
  if(epee::file_io_utils::save_string_to_file(file, ss.str()))
  {
    LOG_PRINT_L0("Current outputs index writen to file: " << file);
  }else
  {
    LOG_PRINT_L0("Failed to write current outputs index to file: " << file);
  }
}
//------------------------------------------------------------------
//TODO: rewrite using BlockchainDB
bool Blockchain::find_blockchain_supplement(const std::list<crypto::hash>& qblock_ids, NOTIFY_RESPONSE_CHAIN_ENTRY::request& resp)
{
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  if(!find_blockchain_supplement(qblock_ids, resp.start_height))
    return false;

  resp.total_height = get_current_blockchain_height();
  size_t count = 0;
  for(size_t i = resp.start_height; i != m_db->height() && count < BLOCKS_IDS_SYNCHRONIZING_DEFAULT_COUNT; i++, count++)
    resp.m_block_ids.push_back(get_block_hash(m_blocks[i].bl));
  return true;
}
//------------------------------------------------------------------
//TODO: rewrite using BlockchainDB
bool Blockchain::find_blockchain_supplement(const uint64_t req_start_block, const std::list<crypto::hash>& qblock_ids, std::list<std::pair<block, std::list<transaction> > >& blocks, uint64_t& total_height, uint64_t& start_height, size_t max_count)
{
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  if(req_start_block > 0) {
     start_height = req_start_block; 
  } else {
    if(!find_blockchain_supplement(qblock_ids, start_height))
      return false;
  }

  total_height = get_current_blockchain_height();
  size_t count = 0;
  for(size_t i = start_height; i != m_db->height() && count < max_count; i++, count++)
  {
    blocks.resize(blocks.size()+1);
    blocks.back().first = m_blocks[i].bl;
    std::list<crypto::hash> mis;
    get_transactions(m_blocks[i].bl.tx_hashes, blocks.back().second, mis);
    CHECK_AND_ASSERT_MES(!mis.size(), false, "internal error, transaction from block not found");
  }
  return true;
}
//------------------------------------------------------------------
bool Blockchain::add_block_as_invalid(const block& bl, const crypto::hash& h)
{
  block_extended_info bei = AUTO_VAL_INIT(bei);
  bei.bl = bl;
  return add_block_as_invalid(bei, h);
}
//------------------------------------------------------------------
bool Blockchain::add_block_as_invalid(const block_extended_info& bei, const crypto::hash& h)
{
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  auto i_res = m_invalid_blocks.insert(std::map<crypto::hash, block_extended_info>::value_type(h, bei));
  CHECK_AND_ASSERT_MES(i_res.second, false, "at insertion invalid by tx returned status existed");
  LOG_PRINT_L0("BLOCK ADDED AS INVALID: " << h << std::endl << ", prev_id=" << bei.bl.prev_id << ", m_invalid_blocks count=" << m_invalid_blocks.size());
  return true;
}
//------------------------------------------------------------------
bool Blockchain::have_block(const crypto::hash& id)
{
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  if(m_db->block_exists(id))
    return true;
  if(m_alternative_chains.count(id))
    return true;
  /*if(m_orphaned_blocks.get<by_id>().count(id))
    return true;*/

  /*if(m_orphaned_by_tx.count(id))
    return true;*/
  if(m_invalid_blocks.count(id))
    return true;

  return false;
}
//------------------------------------------------------------------
bool Blockchain::handle_block_to_main_chain(const block& bl, block_verification_context& bvc)
{
  crypto::hash id = get_block_hash(bl);
  return handle_block_to_main_chain(bl, id, bvc);
}
//------------------------------------------------------------------
//TODO: rewrite using BlockchainDB
size_t Blockchain::get_total_transactions()
{
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  return m_transactions.size();
}
//------------------------------------------------------------------
//TODO: rewrite using BlockchainDB
bool Blockchain::get_outs(uint64_t amount, std::list<crypto::public_key>& pkeys)
{
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  auto it = m_outputs.find(amount);
  if(it == m_outputs.end())
    return true;

  BOOST_FOREACH(const auto& out_entry, it->second)
  {
    auto tx_it = m_transactions.find(out_entry.first);
    CHECK_AND_ASSERT_MES(tx_it != m_transactions.end(), false, "transactions outs global index consistency broken: wrong tx id in index");
    CHECK_AND_ASSERT_MES(tx_it->second.tx.vout.size() > out_entry.second, false, "transactions outs global index consistency broken: index in tx_outx more then size");
    CHECK_AND_ASSERT_MES(tx_it->second.tx.vout[out_entry.second].target.type() == typeid(txout_to_key), false, "transactions outs global index consistency broken: index in tx_outx more then size");
    pkeys.push_back(boost::get<txout_to_key>(tx_it->second.tx.vout[out_entry.second].target).key);
  }

  return true;
}
//------------------------------------------------------------------
//TODO: rewrite using BlockchainDB
//  NOTE: this function will probably be removed, as its functionality
//  should be supplanted by BlockchainDB.
bool Blockchain::pop_transaction_from_global_index(const transaction& tx, const crypto::hash& tx_id)
{
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  size_t i = tx.vout.size()-1;
  BOOST_REVERSE_FOREACH(const auto& ot, tx.vout)
  {
    auto it = m_outputs.find(ot.amount);
    CHECK_AND_ASSERT_MES(it != m_outputs.end(), false, "transactions outs global index consistency broken");
    CHECK_AND_ASSERT_MES(it->second.size(), false, "transactions outs global index: empty index for amount: " << ot.amount);
    CHECK_AND_ASSERT_MES(it->second.back().first == tx_id , false, "transactions outs global index consistency broken: tx id missmatch");
    CHECK_AND_ASSERT_MES(it->second.back().second == i, false, "transactions outs global index consistency broken: in transaction index missmatch");
    it->second.pop_back();
    --i;
  }
  return true;
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
}
//------------------------------------------------------------------
//TODO: rewrite using BlockchainDB
bool Blockchain::get_tx_outputs_gindexs(const crypto::hash& tx_id, std::vector<uint64_t>& indexs)
{
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  auto it = m_transactions.find(tx_id);
  if(it == m_transactions.end())
  {
    LOG_PRINT_RED_L0("warning: get_tx_outputs_gindexs failed to find transaction with id = " << tx_id);
    return false;
  }

  CHECK_AND_ASSERT_MES(it->second.m_global_output_indexes.size(), false, "internal error: global indexes for transaction " << tx_id << " is empty");
  indexs = it->second.m_global_output_indexes;
  return true;
}
//------------------------------------------------------------------
// This function overloads its sister function with
// an extra value (hash of highest block that holds an output used as input)
// as a return-by-reference.
bool Blockchain::check_tx_inputs(const transaction& tx, uint64_t& max_used_block_height, crypto::hash& max_used_block_id)
{
  CRITICAL_REGION_LOCAL(m_blockchain_lock);
  bool res = check_tx_inputs(tx, &max_used_block_height);
  if(!res) return false;
  CHECK_AND_ASSERT_MES(max_used_block_height < m_db->height(), false,  "internal error: max used block index=" << max_used_block_height << " is not less then blockchain size = " << m_db->height());
  get_block_hash(m_db->get_block_hash_from_height(max_used_block_height), max_used_block_id);
  return true;
}
//------------------------------------------------------------------
bool Blockchain::have_tx_keyimges_as_spent(const transaction &tx)
{
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
  CRITICAL_REGION_LOCAL(m_blockchain_lock);

  struct outputs_visitor
  {
    std::vector<const crypto::public_key *>& m_results_collector;
    Blockchain& m_bch;
    outputs_visitor(std::vector<const crypto::public_key *>& results_collector, Blockchain& bch):m_results_collector(results_collector), m_bch(bch)
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

      m_results_collector.push_back(&boost::get<txout_to_key>(out.target).key);
      return true;
    }
  };

  //check ring signature
  std::vector<const crypto::public_key *> output_keys;
  outputs_visitor vi(output_keys, *this);
  if(!scan_outputkeys_for_indexes(txin, vi, pmax_related_block_height))
  {
    LOG_PRINT_L0("Failed to get output keys for tx with amount = " << print_money(txin.amount) << " and count indexes " << txin.key_offsets.size());
    return false;
  }

  if(txin.key_offsets.size() != output_keys.size())
  {
    LOG_PRINT_L0("Output keys for tx with amount = " << txin.amount << " and count indexes " << txin.key_offsets.size() << " returned wrong keys count " << output_keys.size());
    return false;
  }
  CHECK_AND_ASSERT_MES(sig.size() == output_keys.size(), false, "internal error: tx signatures count=" << sig.size() << " mismatch with outputs keys count for inputs=" << output_keys.size());
  if(m_is_in_checkpoint_zone)
    return true;
  return crypto::check_ring_signature(tx_prefix_hash, txin.k_image, output_keys, sig.data());
}
//------------------------------------------------------------------
//TODO: Is this intended to do something else?  Need to look into the todo there.
uint64_t Blockchain::get_adjusted_time()
{
  //TODO: add collecting median time
  return time(NULL);
}
//------------------------------------------------------------------
// This function grabs the timestamps from the most recent <n> blocks,
// where n = BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW.  If there are not those many
// blocks in the blockchain, the timestap is assumed to be valid.  If there
// are, this function returns:
//   true if the block's timestamp is not less than the timestamp of the
//       median of the selected blocks
//   false otherwise
bool Blockchain::check_block_timestamp_main(const block& b)
{
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
  size_t offset = h - BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW + 1;
  for(;offset <= h; ++offset)
  {
    timestamps.push_back(m_db->get_block_timestamp(offset));
  }


  uint64_t median_ts = epee::misc_utils::median(timestamps);

  if(b.timestamp < median_ts)
  {
    LOG_PRINT_L0("Timestamp of block with id: " << get_block_hash(b) << ", " << b.timestamp << ", less than median of last " << BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW << " blocks, " << median_ts);
    return false;
  }

  return true;
}
//------------------------------------------------------------------
//      Needs to validate the block and acquire each transaction from the
//      transaction mem_pool, then pass the block and transactions to
//      m_db->add_block()
bool Blockchain::handle_block_to_main_chain(const block& bl, const crypto::hash& id, block_verification_context& bvc)
{
  // if we already have the block, return false
  if (have_block(id))
  {
    LOG_PRINT_L0("Attempting to add block to main chain, but it's already either there or in an alternate chain.  hash: " << id);
    bvc.m_verification_failed = true;
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
    bvc.m_verification_failed = true;
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
    bvc.m_verification_failed = true;
    return false;
  }

  // If we're at a checkpoint, ensure that our hardcoded checkpoint hash
  // is correct.
  if(m_checkpoints.is_in_checkpoint_zone(get_current_blockchain_height()))
  {
    if(!m_checkpoints.check_block(get_current_blockchain_height(), id))
    {
      LOG_ERROR("CHECKPOINT VALIDATION FAILED");
      bvc.m_verification_failed = true;
      return false;
    }
  }

  TIME_MEASURE_FINISH(longhash_calculating_time);

  // sanity check basic miner tx properties
  if(!prevalidate_miner_transaction(bl, m_db->height()))
  {
    LOG_PRINT_L0("Block with id: " << id
      << " failed to pass prevalidation");
    bvc.m_verification_failed = true;
    return false;
  }

  size_t coinbase_blob_size = get_object_blobsize(bl.miner_tx);
  size_t cumulative_block_size = coinbase_blob_size;

  std::vector<transaction> txs;
  key_images_container keys;

  // add miner transaction to list of block's transactions.
  txs.push_back(bl.miner_tx);

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
      bvc.m_verification_failed = true;
      break;
    }

    // get transaction with hash <tx_id> from tx_pool
    if(!m_tx_pool.take_tx(tx_id, tx, blob_size, fee))
    {
      LOG_PRINT_L0("Block with id: " << id  << "have at least one unknown transaction with id: " << tx_id);
      bvc.m_verification_failed = true;
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
      bvc.m_verification_failed = true;
      break;
    }

    if (!check_for_double_spend(tx, keys))
    {
      LOG_PRINT_L0("Double spend detected in transaction (id: " << tx_id);
      bvc.m_verification_failed = true;
      break;
    }

    fee_summary += fee;
    cumulative_block_size += blob_size;
  }

  uint64_t base_reward = 0;
  uint64_t already_generated_coins = m_db->height() ? m_db->get_block_already_generated_coins(m_db->height() : 0;
  if(!validate_miner_transaction(bl, cumulative_block_size, fee_summary, base_reward, already_generated_coins))
  {
    LOG_PRINT_L0("Block with id: " << id
      << " have wrong miner transaction");
    bvc.m_verification_failed = true;
  }


  block_extended_info bei = boost::value_initialized<block_extended_info>();
  size_t block_size;
  difficulty_type cumulative_difficulty;
  uint64_t already_generated_coins;

  // populate various metadata about the block to be stored alongside it.
  block_size = cumulative_block_size;
  cumulative_difficulty = current_diffic;
  already_generated_coins = already_generated_coins + base_reward;
  if(m_db->height())
    cumulative_difficulty += m_db->get_block_cumulative_difficulty(m_db->height());

  update_next_cumulative_size_limit();

  TIME_MEASURE_FINISH(block_processing_time);

  uint64_t new_height = 0;
  bool add_success = true;
  try
  {
    new_height = m_db->add_block(bl, block_size, cumulative_difficulty, already_generated_coins, txs);
  }
  catch (const std::exception& e)
  {
    LOG_ERROR("Error adding block with hash: " << id << " to blockchain, what = " << e.what());
    add_success = false;
  }

  // if we failed for any reason to verify the block, return taken
  // transactions to the tx_pool.
  if (bvc.m_verification_failed || !add_success)
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
