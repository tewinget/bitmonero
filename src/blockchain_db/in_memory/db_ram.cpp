// Copyright (c) 2014, The Monero Project
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

#include "db_ram.h"

#include <boost/filesystem.hpp>
#include <boost/lexical_cast.hpp>
#include <memory>  // std::unique_ptr
#include <cstring>  // memcpy

#include "cryptonote_core/cryptonote_format_utils.h"
#include "crypto/crypto.h"
#include "profile_tools.h"

//TODO: Make blockchain insertion/deletion transactional?

using epee::string_tools::pod_to_hex;

namespace
{

template <typename T>
inline void throw0(const T &e)
{
  LOG_PRINT_L0(e.what());
  throw e;
}

template <typename T>
inline void throw1(const T &e)
{
  LOG_PRINT_L1(e.what());
  throw e;
}

} // anonymous namespace

namespace cryptonote
{

void BlockchainRAM::add_block( const block& blk
              , const size_t& block_size
              , const difficulty_type& cumulative_difficulty
              , const uint64_t& coins_generated
              , const crypto::hash& block_hash
              )
{
  LOG_PRINT_L3("BlockchainRAM::" << __func__);
  check_open();

  if (m_block_heights.count(block_hash) != 0)
  {
    throw1(BLOCK_EXISTS("Attempting to add block that's already in the db"));
  }

  if (m_height > 0)
  {
    if (m_block_hashes[m_height - 1] != blk.prev_id)
    {
      throw0(BLOCK_PARENT_DNE("Top block is not new block's parent"));
    }
  }

  block_extended_info bei{blk, m_height, block_size, cumulative_difficulty, coins_generated};

  m_blocks.push_back(bei);

  m_block_heights[block_hash] = m_height;
  m_block_hashes.push_back(block_hash);
}

void BlockchainRAM::remove_block()
{
  LOG_PRINT_L3("BlockchainRAM::" << __func__);
  check_open();

  if (m_blocks.size() == 0 || m_block_hashes.size() == 0)
  {
    throw1(BLOCK_DNE("Attempting to remove block that's not in the db"));
  }
  m_blocks.pop_back();

  if (m_block_heights.erase(m_block_hashes.back()) != 1)
  {
    throw1(DB_ERROR("Removing block -- block hash->height mapping not present"));
  }
  m_block_hashes.pop_back();
}

void BlockchainRAM::add_transaction_data(const crypto::hash& blk_hash, const transaction& tx, const crypto::hash& tx_hash)
{
  LOG_PRINT_L3("BlockchainRAM::" << __func__);
  check_open();

  if (m_txs.count(tx_hash) != 0)
  {
    throw1(TX_EXISTS("Attempting to add transaction that's already in the db"));
  }

  transaction_chain_entry te{tx, m_height};

  m_txs[tx_hash] = te;
}

void BlockchainRAM::remove_transaction_data(const crypto::hash& tx_hash, const transaction& tx)
{
  LOG_PRINT_L3("BlockchainRAM::" << __func__);
  check_open();

  if (m_txs.count(tx_hash) != 1)
  {
    throw1(TX_DNE("Attempting to remove transaction that isn't in the db"));
  }

  remove_tx_outputs(tx_hash, tx);

  m_txs.erase(tx_hash);
}

void BlockchainRAM::add_output(const crypto::hash& tx_hash, const tx_out& tx_output, const uint64_t& local_index)
{
  LOG_PRINT_L3("BlockchainRAM::" << __func__);
  check_open();

  outputs_container::mapped_type& outputs_vector = m_outputs[tx_output.amount];
  outputs_vector.push_back(std::pair<crypto::hash, size_t>(tx_hash, local_index));

  m_txs[tx_hash].m_amount_output_indices.push_back(outputs_vector.size() - 1);
}

void BlockchainRAM::remove_tx_outputs(const crypto::hash& tx_hash, const transaction& tx)
{
  LOG_PRINT_L3("BlockchainRAM::" << __func__);

  // need to remove in insertion order, so reverse iterate
  uint64_t index;
  for (index = tx.vout.size(); index != 0; --index)
  {
    auto amount = tx.vout[index - 1].amount;
    auto out_index = m_txs[tx_hash].m_amount_output_indices[index - 1];

    // need to make sure we're removing the correct output reference/index
    if ((m_outputs[amount].back().first != tx_hash)
        || (m_outputs[amount].back().second != index - 1)
        || (m_outputs[amount].size() != out_index + 1))
    {
      throw0(DB_ERROR("Attempting to remove output -- internal consistency error"));
    }

    m_outputs[amount].pop_back();
  }
}

// TODO: probably remove this function
void BlockchainRAM::remove_output(const tx_out& tx_output)
{
  LOG_PRINT_L3("BlockchainRAM::" << __func__ << " (unused version - does nothing)");
  return;
}

void BlockchainRAM::add_spent_key(const crypto::key_image& k_image)
{
  LOG_PRINT_L3("BlockchainRAM::" << __func__);
  check_open();

  if (m_spent_keys.count(k_image) != 0)
  {
    throw0(KEY_IMAGE_EXISTS("Attempting to add spent key, but key already present; potential double spend attempted."));
  }

  m_spent_keys.insert(k_image);
}

void BlockchainRAM::remove_spent_key(const crypto::key_image& k_image)
{
  LOG_PRINT_L3("BlockchainRAM::" << __func__);
  check_open();

  if (m_spent_keys.count(k_image) != 1)
  {
    throw0(DB_ERROR("Attempting to remove inexistent spent key"));
  }
}

blobdata BlockchainRAM::output_to_blob(const tx_out& output)
{
  LOG_PRINT_L3("BlockchainRAM::" << __func__);

  return blobdata();
}

tx_out BlockchainRAM::output_from_blob(const blobdata& blob) const
{
  LOG_PRINT_L3("BlockchainRAM::" << __func__);

  return tx_out();
}

void BlockchainRAM::check_open() const
{
  LOG_PRINT_L3("BlockchainRAM::" << __func__);
  if (!m_open)
    throw0(DB_ERROR("DB operation attempted on a not-open DB instance"));
}

BlockchainRAM::~BlockchainRAM()
{
  LOG_PRINT_L3("BlockchainRAM::" << __func__);

}

BlockchainRAM::BlockchainRAM(bool batch_transactions)
{
  LOG_PRINT_L3("BlockchainRAM::" << __func__);

  // initialize folder to something "safe" just in case
  // someone accidentally misuses this class...
  m_folder = "thishsouldnotexistbecauseitisgibberish";
  m_open = false;

  m_height = 0;
}

void BlockchainRAM::open(const std::string& filename, const int db_flags)
{
  LOG_PRINT_L3("BlockchainRAM::" << __func__);

  if (m_open)
    throw0(DB_OPEN_FAILURE("Attempted to open db, but it's already open"));

  m_folder = filename;

  m_open = true;
}

// unused for now, create will happen on open if doesn't exist
void BlockchainRAM::create(const std::string& filename)
{
  LOG_PRINT_L3("BlockchainRAM::" << __func__);
  throw DB_CREATE_FAILURE("create() is not implemented for this BlockchainDB, open() will create files if needed.");
}

void BlockchainRAM::close()
{
  LOG_PRINT_L3("BlockchainRAM::" << __func__);

  if (m_open)
  {
    sync();
  }
}

void BlockchainRAM::sync()
{
  LOG_PRINT_L3("BlockchainRAM::" << __func__);
  check_open();
}

void BlockchainRAM::reset()
{
  LOG_PRINT_L3("BlockchainRAM::" << __func__);
  // TODO: this
}

std::vector<std::string> BlockchainRAM::get_filenames() const
{
  LOG_PRINT_L3("BlockchainRAM::" << __func__);

  return std::vector<std::string>();
}

std::string BlockchainRAM::get_db_name() const
{
  LOG_PRINT_L3("BlockchainRAM::" << __func__);

  return std::string("in_memory");
}

// TODO: this?
bool BlockchainRAM::lock()
{
  LOG_PRINT_L3("BlockchainRAM::" << __func__);
  check_open();
  return false;
}

// TODO: this?
void BlockchainRAM::unlock()
{
  LOG_PRINT_L3("BlockchainRAM::" << __func__);
  check_open();
}

bool BlockchainRAM::block_exists(const crypto::hash& h) const
{
  LOG_PRINT_L3("BlockchainRAM::" << __func__);
  check_open();

  return m_block_heights.count(h) != 0;
}

block BlockchainRAM::get_block(const crypto::hash& h) const
{
  LOG_PRINT_L3("BlockchainRAM::" << __func__);
  check_open();

  if (!block_exists(h))
  {
    throw1(BLOCK_DNE("Attempted to get block by hash, block not present"));
  }

  return m_blocks[m_block_heights.at(h)].bl;
}

uint64_t BlockchainRAM::get_block_height(const crypto::hash& h) const
{
  LOG_PRINT_L3("BlockchainRAM::" << __func__);
  check_open();

  if (!block_exists(h))
  {
    throw1(BLOCK_DNE("Attempted to get block height by hash, block not present"));
  }

  return m_block_heights.at(h);
}

block_header BlockchainRAM::get_block_header(const crypto::hash& h) const
{
  LOG_PRINT_L3("BlockchainRAM::" << __func__);

  return get_block(h);
}

block BlockchainRAM::get_block_from_height(const uint64_t& height) const
{
  LOG_PRINT_L3("BlockchainRAM::" << __func__);
  check_open();

  if (m_height <= height)
  {
    throw0(BLOCK_DNE(std::string("Attempted to get block #").append(boost::lexical_cast<std::string>(height)).append("but blockchain max height is ").append(boost::lexical_cast<std::string>(m_height - 1)).c_str()));
  }

  return m_blocks[height].bl;
}

uint64_t BlockchainRAM::get_block_timestamp(const uint64_t& height) const
{
  LOG_PRINT_L3("BlockchainRAM::" << __func__);
  check_open();

  if (m_height <= height)
  {
    throw0(BLOCK_DNE(std::string("Attempted to get timestamp of block #").append(boost::lexical_cast<std::string>(height)).append("but blockchain max height is ").append(boost::lexical_cast<std::string>(m_height - 1)).c_str()));
  }

  return m_blocks[height].bl.timestamp;
}

uint64_t BlockchainRAM::get_top_block_timestamp() const
{
  LOG_PRINT_L3("BlockchainRAM::" << __func__);

  if (m_height == 0)
  {
    return 0;
  }

  return get_block_timestamp(m_height - 1);
}

size_t BlockchainRAM::get_block_size(const uint64_t& height) const
{
  LOG_PRINT_L3("BlockchainRAM::" << __func__);
  check_open();

  if (m_height <= height)
  {
    throw0(BLOCK_DNE(std::string("Attempted to get size of block #").append(boost::lexical_cast<std::string>(height)).append("but blockchain max height is ").append(boost::lexical_cast<std::string>(m_height - 1)).c_str()));
  }

  return m_blocks[height].block_cumulative_size;
}

difficulty_type BlockchainRAM::get_block_cumulative_difficulty(const uint64_t& height) const
{
  LOG_PRINT_L3("BlockchainRAM::" << __func__ << "  height: " << height);
  check_open();

  if (m_height <= height)
  {
    throw0(BLOCK_DNE(std::string("Attempted to get cumulative difficulty at block #").append(boost::lexical_cast<std::string>(height)).append("but blockchain max height is ").append(boost::lexical_cast<std::string>(m_height - 1)).c_str()));
  }

  return m_blocks[height].cumulative_difficulty;
}

difficulty_type BlockchainRAM::get_block_difficulty(const uint64_t& height) const
{
  LOG_PRINT_L3("BlockchainRAM::" << __func__);
  check_open();

  return get_block_cumulative_difficulty(height) - get_block_cumulative_difficulty(height - 1);
}

uint64_t BlockchainRAM::get_block_already_generated_coins(const uint64_t& height) const
{
  LOG_PRINT_L3("BlockchainRAM::" << __func__);
  check_open();

  if (m_height <= height)
  {
    throw0(BLOCK_DNE(std::string("Attempted to get total generated coins at block #").append(boost::lexical_cast<std::string>(height)).append("but blockchain max height is ").append(boost::lexical_cast<std::string>(m_height - 1)).c_str()));
  }

  return m_blocks[height].already_generated_coins;
}

crypto::hash BlockchainRAM::get_block_hash_from_height(const uint64_t& height) const
{
  LOG_PRINT_L3("BlockchainRAM::" << __func__);
  check_open();

  if (m_height <= height)
  {
    throw0(BLOCK_DNE(std::string("Attempted to get hash of block #").append(boost::lexical_cast<std::string>(height)).append("but blockchain max height is ").append(boost::lexical_cast<std::string>(m_height - 1)).c_str()));
  }

  return m_block_hashes.at(height);
}

std::vector<block> BlockchainRAM::get_blocks_range(const uint64_t& h1, const uint64_t& h2) const
{
  LOG_PRINT_L3("BlockchainRAM::" << __func__);
  check_open();

  std::vector<block> v;

  for (uint64_t height = h1; height <= h2; ++height)
  {
    v.push_back(get_block_from_height(height));
  }

  return v;
}

std::vector<crypto::hash> BlockchainRAM::get_hashes_range(const uint64_t& h1, const uint64_t& h2) const
{
  LOG_PRINT_L3("BlockchainRAM::" << __func__);
  check_open();

  std::vector<crypto::hash> v;

  for (uint64_t height = h1; height <= h2; ++height)
  {
    v.push_back(get_block_hash_from_height(height));
  }

  return v;
}

crypto::hash BlockchainRAM::top_block_hash() const
{
  LOG_PRINT_L3("BlockchainRAM::" << __func__);

  if (m_height == 0)
  {
    return null_hash;
  }

  return get_block_hash_from_height(m_height - 1);
}

block BlockchainRAM::get_top_block() const
{
  LOG_PRINT_L3("BlockchainRAM::" << __func__);

  if (m_height == 0)
  {
    return block();
  }

  return get_block_from_height(m_height - 1);
}

uint64_t BlockchainRAM::height() const
{
  LOG_PRINT_L3("BlockchainRAM::" << __func__);
  check_open();

  return m_height;
}

bool BlockchainRAM::tx_exists(const crypto::hash& h) const
{
  LOG_PRINT_L3("BlockchainRAM::" << __func__);
  check_open();

  return m_txs.count(h) != 0;
}

uint64_t BlockchainRAM::get_tx_unlock_time(const crypto::hash& h) const
{
  LOG_PRINT_L3("BlockchainRAM::" << __func__);
  check_open();

  if (!tx_exists(h))
  {
    throw0(TX_DNE("Attempted to get unlock time for transaction that does not exist"));
  }

  return m_txs.at(h).tx.unlock_time;
}

transaction BlockchainRAM::get_tx(const crypto::hash& h) const
{
  LOG_PRINT_L3("BlockchainRAM::" << __func__);
  check_open();

  if (!tx_exists(h))
  {
    throw0(TX_DNE("Attempted to get transaction that does not exist"));
  }

  return m_txs.at(h).tx;
}

uint64_t BlockchainRAM::get_tx_count() const
{
  LOG_PRINT_L3("BlockchainRAM::" << __func__);
  check_open();

  return m_txs.size();
}

std::vector<transaction> BlockchainRAM::get_tx_list(const std::vector<crypto::hash>& hlist) const
{
  LOG_PRINT_L3("BlockchainRAM::" << __func__);
  check_open();

  std::vector<transaction> v;

  for (auto& h : hlist)
  {
    v.push_back(get_tx(h));
  }

  return v;
}

uint64_t BlockchainRAM::get_tx_block_height(const crypto::hash& h) const
{
  LOG_PRINT_L3("BlockchainRAM::" << __func__);
  check_open();

  if (!tx_exists(h))
  {
    throw0(TX_DNE("Attempted to get block height for transaction that does not exist"));
  }

  return m_txs.at(h).m_block_height;
}

uint64_t BlockchainRAM::get_num_outputs(const uint64_t& amount) const
{
  LOG_PRINT_L3("BlockchainRAM::" << __func__);
  check_open();

  return m_outputs.at(amount).size();
}

crypto::public_key BlockchainRAM::get_output_key(const uint64_t& amount, const uint64_t& index) const
{
  LOG_PRINT_L3("BlockchainRAM::" << __func__);
  check_open();

  if (m_outputs.at(amount).size() <= index)
  {
    throw0(OUTPUT_DNE(std::string("Attempting to get output for amount ").append(boost::lexical_cast<std::string>(amount)).append(", but the index is too high").c_str()));
  }

  std::pair<crypto::hash, size_t> tx_data = m_outputs.at(amount)[index];

  return boost::get<txout_to_key>(m_txs.at(tx_data.first).tx.vout[tx_data.second].target).key;
}

tx_out BlockchainRAM::get_output(const crypto::hash& h, const uint64_t& index) const
{
  LOG_PRINT_L3("BlockchainRAM::" << __func__);
  check_open();

  if (!tx_exists(h))
  {
    throw0(TX_DNE("Attempt to get output from transaction failed -- transaction not in db"));
  }
  if (m_txs.at(h).tx.vout.size() <= index)
  {
    throw0(OUTPUT_DNE("Attempt to get output from transaction failed -- output index too high"));
  }

  return m_txs.at(h).tx.vout[index];
}

// As this is not used, its return is now a blank output.
// This will save on space in the db.
tx_out BlockchainRAM::get_output(const uint64_t& index) const
{
  LOG_PRINT_L3("BlockchainRAM::" << __func__);
  return tx_out();
}

tx_out_index BlockchainRAM::get_output_tx_and_index(const uint64_t& amount, const uint64_t& index) const
{
  LOG_PRINT_L3("BlockchainRAM::" << __func__);
  check_open();

  if (m_outputs.at(amount).size() <= index)
  {
    throw0(OUTPUT_DNE(std::string("Attempt to get output with amount ").append(boost::lexical_cast<std::string>(amount)).append(" and index ").append(boost::lexical_cast<std::string>(index)).append(" failed -- output index too high").c_str()));
  }

  return m_outputs.at(amount)[index];
}

std::vector<uint64_t> BlockchainRAM::get_tx_amount_output_indices(const crypto::hash& h) const
{
  LOG_PRINT_L3("BlockchainRAM::" << __func__);
  check_open();

  if (!tx_exists(h))
  {
    throw0(TX_DNE("Attempted to get amount-local output indices for transaction that does not exist"));
  }

  return m_txs.at(h).m_amount_output_indices;
}



bool BlockchainRAM::has_key_image(const crypto::key_image& img) const
{
  LOG_PRINT_L3("BlockchainRAM::" << __func__);
  check_open();

  return m_spent_keys.count(img) != 0;
}

void BlockchainRAM::batch_start()
{
  LOG_PRINT_L3("BlockchainRAM::" << __func__);
}

void BlockchainRAM::batch_commit()
{
  LOG_PRINT_L3("BlockchainRAM::" << __func__);
}

void BlockchainRAM::batch_stop()
{
  LOG_PRINT_L3("BlockchainRAM::" << __func__);
}

void BlockchainRAM::batch_abort()
{
  LOG_PRINT_L3("BlockchainRAM::" << __func__);
}

void BlockchainRAM::set_batch_transactions(bool batch_transactions)
{
  LOG_PRINT_L3("BlockchainRAM::" << __func__);
}


uint64_t BlockchainRAM::add_block( const block& blk
                                  , const size_t& block_size
                                  , const difficulty_type& cumulative_difficulty
                                  , const uint64_t& coins_generated
                                  , const std::vector<transaction>& txs
                                  )
{
  LOG_PRINT_L3("BlockchainRAM::" << __func__);
  check_open();

  BlockchainDB::add_block(blk, block_size, cumulative_difficulty, coins_generated, txs);

  return ++m_height;
}

void BlockchainRAM::pop_block(block& blk, std::vector<transaction>& txs)
{
  LOG_PRINT_L3("BlockchainRAM::" << __func__);
  check_open();

  BlockchainDB::pop_block(blk, txs);

  --m_height;
}

}  // namespace cryptonote
