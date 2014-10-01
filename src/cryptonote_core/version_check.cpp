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

#include "version_check.h"
#include <vector>

namespace cryptonote
{

bool block_version_too_new(uint8_t major, uint8_t minor)
{
  // if two major versions ahead, too new
  // NOTE: this should hopefully never happen...
  if (major > CURRENT_BLOCK_MAJOR_VERSION + 1)
  {
    return true;
  }

  // if one major version ahead, but minor version too large, too new
  if ((major > CURRENT_BLOCK_MAJOR_VERSION) && (minor > VERSION_CHANGE_MINOR_LABEL))
  {
    return true;
  }

  // else not too new
  return false;
}

inline bool yes_vote(uint8_t major, uint8_t minor)
{
  if ((major == CURRENT_BLOCK_MAJOR_VERSION + 1) && (minor <= VERSION_CHANGE_MINOR_LABEL))
  {
    return true;
  }
  return false;
}

bool version_change_vote_passed(const std::vector<uint8_t>& major, const std::vector<uint8_t>& minor)
{
  // sanity check
  if (major.size() != minor.size()) return false;

  // make sure we're passed enough blocks
  if (major.size() != VERSION_CHANGE_VOTES_WINDOW) return false;

  // if any VERSION_CHANGE_VOTES_NEEDED consecutive blocks in the last
  // VERSION_CHANGE_VOTES_WINDOW blocks have enough yes votes, the vote passes.
  unsigned int yes_count = 0;
  for (unsigned int i = 0; i < VERSION_CHANGE_VOTES_WINDOW; i++)
  {
    // if yes vote, increment yes count
    yes_count += yes_vote(major[i], minor[i]) ? 1 : 0;

    // if VERSION_CHANGE_VOTES_NEEDED votes ago was a no vote, decrement yes count
    if (i >= VERSION_CHANGE_VOTES_NEEDED)
    {
      yes_count -= yes_vote(major[i - VERSION_CHANGE_VOTES_NEEDED], minor[i - VERSION_CHANGE_VOTES_NEEDED]) ? 0 : 1;
    }

    // if enough yes votes, vote passes
    if (yes_count >= VERSION_CHANGE_VOTES_MAJORITY)
    {
      return true;
    }
  }

  return false;
}

}  // namespace cryptonote
