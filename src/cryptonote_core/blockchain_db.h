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

#include <list>
#include <string>
#include <exception>
#include "crypto/hash.h"
#include "cryptonote_core/cryptonote_basic.h"

/* DB Driver Interface
 *
 * The DB interface is a store for the canonical block chain.
 * It serves as a persistent storage for the blockchain.
 * For the sake of efficiency, it also stores some blockchain data outside
 * of the blocks, such as spent transfer key images, unspent transaction
 * outputs, etc.
 *
 * Transactions are duplicated so that we don't have to fetch a whole block
 * in order to fetch a transaction from that block.  If this is deemed
 * unnecessary later, this can change.
 *
 * Spent key images are duplicated outside of the blocks so it is quick
 * to verify an output hasn't already been spent
 *
 * Unspent transaction outputs are duplicated to quickly gather random
 * outputs to use for mixins
 *
 * IMPORTANT:
 * A concrete implementation of this interface should populate these
 * duplicated members!  It is possible to have a partial implementation
 * of this interface call to private members of the interface to be added
 * later that will then populate as needed.
 *
 * General:
 *   open()
 *   close()
 *   sync()
 *   reset()
 *
 *   Lock and unlock provided for reorg externally, and for block
 *   additions internally, this way threaded reads are completely fine
 *   unless the blockchain is changing.
 *   bool lock()
 *   unlock()
 *
 * Blocks:
 *   bool        block_exists(hash)
 *   height      add_block(block, block_size, cumulative_difficulty, coins_generated)
 *   block       get_block(hash)
 *   height      get_block_height(hash)
 *   header      get_block_header(hash)
 *   block       get_block_from_height(height)
 *   size_t      get_block_size(height)
 *   difficulty  get_block_cumulative_difficulty(height)
 *   uint64_t    get_block_already_generated_coins(height)
 *   uint64_t    get_block_timestamp(height) 
 *   hash        get_block_hash_from_height(height)
 *   blocks      get_blocks_range(height1, height2)
 *   hashes      get_hashes_range(height1, height2)
 *   hash        top_block_hash()
 *   height      height()
 *   block       pop_block()
 *
 * Transactions:
 *   bool        tx_exists(hash)
 *   tx          get_tx(hash)
 *   tx_list     get_tx_list(hash_list)
 *
 * Outputs:
 *   index       get_random_output(amount)
 *   txout_key   get_output_key(index)
 *
 * Spent Output Key Images:
 *   bool        has_key_image(key_image)
 *
 * Exceptions:
 *   DB_ERROR -- generic
 *   DB_OPEN_FAILURE
 *   DB_CREATE_FAILURE
 *   DB_SYNC_FAILURE
 *   BLOCK_DNE
 *   BLOCK_PARENT_DNE
 *   BLOCK_EXISTS
 *   BLOCK_INVALID -- considering making this multiple errors
 *   TX_DNE
 *   TX_EXISTS
 */

namespace cryptonote
{

/***********************************
 * Exception Definitions
 ***********************************/
class DB_ERROR : public std::exception
{
  private:
    std::string m;
  public:
    DB_ERROR() : m("Generic DB Error") { }
    DB_ERROR(const char* s) : m(s) { }

    virtual ~DB_ERROR() { }

    const char* what() const throw()
    {
      return m.c_str();
    }
};

class DB_OPEN_FAILURE : public std::exception
{
  private:
    std::string m;
  public:
    DB_OPEN_FAILURE() : m("Failed to open the db") { }
    DB_OPEN_FAILURE(const char* s) : m(s) { }

    virtual ~DB_OPEN_FAILURE() { }

    const char* what() const throw()
    {
      return m.c_str();
    }
};

class DB_CREATE_FAILURE : public std::exception
{
  private:
    std::string m;
  public:
    DB_CREATE_FAILURE() : m("Failed to create the db") { }
    DB_CREATE_FAILURE(const char* s) : m(s) { }

    virtual ~DB_CREATE_FAILURE() { }

    const char* what() const throw()
    {
      return m.c_str();
    }
};

class DB_SYNC_FAILURE : public std::exception
{
  private:
    std::string m;
  public:
    DB_SYNC_FAILURE() : m("Failed to sync the db") { }
    DB_SYNC_FAILURE(const char* s) : m(s) { }

    virtual ~DB_SYNC_FAILURE() { }

    const char* what() const throw()
    {
      return m.c_str();
    }
};

class BLOCK_DNE : public std::exception
{
  private:
    std::string m;
  public:
    BLOCK_DNE() : m("The block requested does not exist") { }
    BLOCK_DNE(const char* s) : m(s) { }

    virtual ~BLOCK_DNE() { }

    const char* what() const throw()
    {
      return m.c_str();
    }
};

class BLOCK_PARENT_DNE : public std::exception
{
  private:
    std::string m;
  public:
    BLOCK_PARENT_DNE() : m("The parent of the block does not exist") { }
    BLOCK_PARENT_DNE(const char* s) : m(s) { }

    virtual ~BLOCK_PARENT_DNE() { }

    const char* what() const throw()
    {
      return m.c_str();
    }
};

class BLOCK_EXISTS : public std::exception
{
  private:
    std::string m;
  public:
    BLOCK_EXISTS() : m("The block to be added already exists!") { }
    BLOCK_EXISTS(const char* s) : m(s) { }

    virtual ~BLOCK_EXISTS() { }

    const char* what() const throw()
    {
      return m.c_str();
    }
};

class BLOCK_INVALID : public std::exception
{
  private:
    std::string m;
  public:
    BLOCK_INVALID() : m("The block to be added did not pass validation!") { }
    BLOCK_INVALID(const char* s) : m(s) { }

    virtual ~BLOCK_INVALID() { }

    const char* what() const throw()
    {
      return m.c_str();
    }
};

class TX_DNE : public std::exception
{
  private:
    std::string m;
  public:
    TX_DNE() : m("The transaction requested does not exist") { }
    TX_DNE(const char* s) : m(s) { }

    virtual ~TX_DNE() { }

    const char* what() const throw()
    {
      return m.c_str();
    }
};

class TX_EXISTS : public std::exception
{
  private:
    std::string m;
  public:
    TX_EXISTS() : m("The transaction to be added already exists!") { }
    TX_EXISTS(const char* s) : m(s) { }

    virtual ~TX_EXISTS() { }

    const char* what() const throw()
    {
      return m.c_str();
    }
};

/***********************************
 * End of Exception Definitions
 ***********************************/


class BlockchainDB
{
protected:
  // open the db at location <filename>, or create it if there isn't one.
  virtual void open(const std::string& filename) = 0;

  // make sure implementation has a create function as well
  virtual void create(const std::string& filename) = 0;

  // close and sync the db
  virtual void close() = 0;

  // sync the db
  virtual void sync() = 0;

  // reset the db -- USE WITH CARE
  virtual void reset() = 0;


  // FIXME: these are just for functionality mocking, need to implement
  // RAII-friendly and multi-read one-write friendly locking mechanism
  //
  // acquire db lock
  virtual bool lock() = 0;

  // release db lock
  virtual void unlock() = 0;


  // adds a block with the given metadata to the top of the blockchain, returns the new height
  virtual uint64_t add_block(const block& blk, const size_t& block_size, const difficulty_type& cumulative_difficulty, const uint64_t& coins_generated) = 0;

  // return true if a block with hash <h> exists in the blockchain
  virtual bool block_exists(const crypto::hash& h) = 0;

  // return block with hash <h>
  virtual block get_block(const crypto::hash& h) = 0;

  // return the height of the block with hash <h> on the blockchain,
  // throw if it doesn't exist
  virtual uint64_t get_block_height(const crypto::hash& h) = 0;

  // return header for block with hash <h>
  virtual block_header get_block_header(const crypto::hash& h) = 0;

  // return block at height <height>
  virtual block get_block_from_height(const uint64_t& height) = 0;

  // return timestamp of block at height <height>
  virtual uint64_t get_block_timestamp(height)  = 0;

  // return block size of block at height <height>
  virtual size_t get_block_size(const uint64_t& height) = 0;

  // return cumulative difficulty up to and including block at height <height>
  virtual difficulty_type get_block_cumulative_difficulty(const uint64_t& height) = 0;

  // return number of coins generated up to and including block at height <height>
  virtual uint64_t get_block_already_generated_coins(const uint64_t& height) = 0;

  // return hash of block at height <height>
  virtual crypto::hash get_block_hash_from_height(const uint64_t& height) = 0;

  // return list of blocks in range <h1,h2> of height.
  virtual std::list<block> get_blocks_range(const uint64_t& h1, const uint64_t& h2) = 0;

  // return list of block hashes in range <h1, h2> of height
  virtual std::list<crypto::hash> get_hashes_range(const uint64_t& h1, const uint64_t& h2) = 0;

  // return the hash of the top block on the chain
  virtual crypto::hash top_block_hash() = 0;

  // return the height of the top block on the chain
  virtual uint64_t height() = 0;

  // pops the top block off the blockchain and removes its associated transactions
  // returns the block, so that the blockchain can do any cleanup such as returning
  // any transactions in that block to the tx pool.
  virtual block pop_block() = 0;


  // return true if a transaction with hash <h> exists
  virtual bool tx_exists(const crypto::hash& h) = 0;

  // return tx with hash <h>
  // throw if no such tx exists
  virtual transaction get_tx(const crypto::hash& h) = 0;

  // return list of tx with hashes <hlist>.
  // TODO: decide if a missing hash means return empty list
  // or just skip that hash
  virtual std::list<transaction> get_tx_list(const std::list<crypto::hash>& hlist) = 0;


  // return global output index of a random output of amount <amount>
  virtual uint64_t get_random_out(const uint64_t& amount) = 0;

  // return public key for output with global output index <index>
  virtual txout_to_key get_output_key(const uint64_t& index) = 0;


  // returns true if key image <img> is present in spent key images storage
  virtual bool has_key_image(const crypto::key_image& img) = 0;

};  // class BlockchainDB


}  // namespace cryptonote
