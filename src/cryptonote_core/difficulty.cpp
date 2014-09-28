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
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <vector>

#include "common/int-util.h"
#include "crypto/hash.h"
#include "cryptonote_config.h"
#include "difficulty.h"

namespace cryptonote {

  using std::size_t;
  using std::uint64_t;
  using std::vector;

#if defined(_MSC_VER) || defined(__MINGW32__)
#include <windows.h>
#include <winnt.h>

  static inline void mul(uint64_t a, uint64_t b, uint64_t &low, uint64_t &high) {
    low = mul128(a, b, &high);
  }

#else

  static inline void mul(uint64_t a, uint64_t b, uint64_t &low, uint64_t &high) {
    typedef unsigned __int128 uint128_t;
    uint128_t res = (uint128_t) a * (uint128_t) b;
    low = (uint64_t) res;
    high = (uint64_t) (res >> 64);
  }

#endif

  static inline bool cadd(uint64_t a, uint64_t b) {
    return a + b < a;
  }

  static inline bool cadc(uint64_t a, uint64_t b, bool c) {
    return a + b < a || (c && a + b == (uint64_t) -1);
  }

  bool check_hash(const crypto::hash &hash, difficulty_type difficulty) {
    uint64_t low, high, top, cur;
    // First check the highest word, this will most likely fail for a random hash.
    mul(swap64le(((const uint64_t *) &hash)[3]), difficulty, top, high);
    if (high != 0) {
      return false;
    }
    mul(swap64le(((const uint64_t *) &hash)[0]), difficulty, low, cur);
    mul(swap64le(((const uint64_t *) &hash)[1]), difficulty, low, high);
    bool carry = cadd(cur, low);
    cur = high;
    mul(swap64le(((const uint64_t *) &hash)[2]), difficulty, low, high);
    carry = cadc(cur, low, carry);
    carry = cadc(high, top, carry);
    return !carry;
  }

  /**
   * @brief New difficulty function for Monero, returns difficulty for next block
   *
   * NOTE: this function is being written for use on a blockchain that long
   * since had enough blocks to not worry about having enough for the
   * difficulty windows, so it will not deal with the case of a new blockchain
   * that does not have enough blocks and the technicalities therein.
   *
   * @param timestamps the most recent N timestamps,
   * where N = DIFFICULTY_WINDOW_SIZE * DIFFICULTY_WINDOW_COUNT
   *
   * @param cumulative_difficulties the most recent N cumulative difficulties,
   * where N = DIFFICULTY_WINDOW_SIZE * DIFFICULTY_WINDOW_COUNT
   *
   * @param target_seconds the target block time in seconds
   *
   * @return the difficulty for the block after the the blocks' whose data was passed
   */
  difficulty_type next_difficulty(vector<uint64_t> timestamps, vector<difficulty_type> cumulative_difficulties, size_t target_seconds)
  {
    // FIXME: this should be changed for new coins!
    if (timestamps.size() < (DIFFICULTY_WINDOW_SIZE * DIFFICULTY_WINDOW_COUNT)
          || cumulative_difficulties.size() < (DIFFICULTY_WINDOW_SIZE * DIFFICULTY_WINDOW_COUNT)
          || timestamps.size() != cumulative_difficulties.size()
       )
    {
      // TODO: make sure this is the correct invalid difficulty to return;
      // this appears to be the case, as in the old diff algo, but should make sure.
      return 0;
    }

    uint64_t time_span = 0;
    difficulty_type total_work = 0;
    uint64_t last_index = timestamps.size() - 1;  // go from end of list, in case too many blocks are passed

    uint64_t total_weight_multipliers = 0;
    for (unsigned int i = DIFFICULTY_WINDOW_COUNT; i > 0 ; i++)
    {
      total_weight_multipliers += i;
    }

    // windows would be, e.g. [10 - 8] [8 - 6] [6 - 4] [4 - 2] [2 - 0],
    // which overlaps so that no singular difference in time or difficulty is
    // left out of the calculation.
    // For that case, DIFFICULTY_WINDOW_COUNT == 5 and DIFFICULTY_WINDOW_SIZE == 3
    // TODO: overflow possibility is ignored for now, to aid in ease of debugging.
    // at some point years down the road difficulty overflow might be possible,
    // but for now it is not an issue.
    for (unsigned int i = 0; i < DIFFICULTY_WINDOW_COUNT ; ++i)
    {
      uint64_t top_index = last_index - ((DIFFICULTY_WINDOW_SIZE - 1) * i);
      uint64_t time_diff = timestamps[top_index] - timestamps[top_index - DIFFICULTY_WINDOW_SIZE + 1];
      difficulty_type window_work = cumulative_difficulties[top_index] - cumulative_difficulties[top_index - DIFFICULTY_WINDOW_SIZE + 1];

      time_span += time_diff * (DIFFICULTY_WINDOW_SIZE - i);
      total_work += window_work * (DIFFICULTY_WINDOW_SIZE - i);
    }

    // divide by the total of weight multipliers
    time_span /= total_weight_multipliers;
    total_work /= total_weight_multipliers;

    assert(total_work > 0);
    uint64_t low, high;
    mul(total_work, target_seconds, low, high);
    if (high != 0 || low + time_span - 1 < low) {
      return 0;
    }
    return (low + time_span - 1) / time_span;
  }

  difficulty_type next_difficulty(vector<uint64_t> timestamps, vector<difficulty_type> cumulative_difficulties)
  {
    return next_difficulty(std::move(timestamps), std::move(cumulative_difficulties), DIFFICULTY_TARGET);
  }

  difficulty_type next_difficulty_old(vector<uint64_t> timestamps, vector<difficulty_type> cumulative_difficulties, size_t target_seconds) {
    //cutoff DIFFICULTY_LAG
    if(timestamps.size() > DIFFICULTY_WINDOW)
    {
      timestamps.resize(DIFFICULTY_WINDOW);
      cumulative_difficulties.resize(DIFFICULTY_WINDOW);
    }


    size_t length = timestamps.size();
    assert(length == cumulative_difficulties.size());
    if (length <= 1) {
      return 1;
    }
    static_assert(DIFFICULTY_WINDOW >= 2, "Window is too small");
    assert(length <= DIFFICULTY_WINDOW);
    sort(timestamps.begin(), timestamps.end());
    size_t cut_begin, cut_end;
    static_assert(2 * DIFFICULTY_CUT <= DIFFICULTY_WINDOW - 2, "Cut length is too large");
    if (length <= DIFFICULTY_WINDOW - 2 * DIFFICULTY_CUT) {
      cut_begin = 0;
      cut_end = length;
    } else {
      cut_begin = (length - (DIFFICULTY_WINDOW - 2 * DIFFICULTY_CUT) + 1) / 2;
      cut_end = cut_begin + (DIFFICULTY_WINDOW - 2 * DIFFICULTY_CUT);
    }
    assert(/*cut_begin >= 0 &&*/ cut_begin + 2 <= cut_end && cut_end <= length);
    uint64_t time_span = timestamps[cut_end - 1] - timestamps[cut_begin];
    if (time_span == 0) {
      time_span = 1;
    }
    difficulty_type total_work = cumulative_difficulties[cut_end - 1] - cumulative_difficulties[cut_begin];
    assert(total_work > 0);
    uint64_t low, high;
    mul(total_work, target_seconds, low, high);
    if (high != 0 || low + time_span - 1 < low) {
      return 0;
    }
    return (low + time_span - 1) / time_span;
  }

  difficulty_type next_difficulty_old(vector<uint64_t> timestamps, vector<difficulty_type> cumulative_difficulties)
  {
    return next_difficulty_old(std::move(timestamps), std::move(cumulative_difficulties), DIFFICULTY_TARGET);
  }
}
