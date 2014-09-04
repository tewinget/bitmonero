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

#include <alloca.h>
#include <assert.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>

#include "hash-ops.h"

// HASH_SIZE = 32
void tree_hash(const char (*hashes)[HASH_SIZE], size_t count, char *root_hash) {
  assert(count > 0); // old code
	size_t size_hashes = count;

	if (count >= 500) printf("\n================================================= bigblock \n");
	printf("tree_hash() count=%zu \n", count);

	assert(root_hash!=NULL);
	assert(hashes!=NULL);

  if (count == 1) {
    memcpy(root_hash, hashes, HASH_SIZE); // ok?
  } else if (count == 2) {
    cn_fast_hash(hashes, 2 * HASH_SIZE, root_hash); // ok?
  } else {
    size_t i, j;

		// orginal way ----
    size_t cnt = count - 1;
    char (*ints)[HASH_SIZE];
    for (i = 1; i < sizeof(size_t); i <<= 1) {
      cnt |= cnt >> i;
    }
    cnt &= ~(cnt >> 1);
		// cnt is the result

		{
			// TODO use correct type 
			int cnt2 = -1;
			int tmp = count -1; //using input minus 1 to get fun(2**n)= 2**(n-1)
			for (int j = 1; tmp != 0;++j) {
				tmp/=2; //dividing by 2 until to get how many powers of 2 fits into tmp
				//                              tmp >>= 1; //will do as well
				cnt2 = 2<<(j-2);
				//if(tmp == 0) printf("%d: %d\n",i, 2<<(j-2)); // returning i and result of rounding
			}
			if (cnt != cnt2) {
				printf("wrong counter: cnt=%zu versus correct cnt2=%d.", cnt, cnt2);
			}
			assert( cnt == cnt2 );
		}


		const size_t size_ints = cnt * HASH_SIZE; // dbg
		assert( size_ints > 0);  assert( size_ints < 1024*1024 );  // dbg
    ints = alloca(size_ints); // ok
		assert(ints!=NULL);

		const size_t size_memcpy = (2 * cnt - count) * HASH_SIZE;
		printf("calculate size_memcpy: cnt=%zu count=%zu size_memcpy=%zu \n" , cnt,count,size_memcpy);
		assert( size_memcpy >= 0);  // dbg, allow 0 ?
		assert( size_memcpy < 1024*1024); // dbg

		assert( size_memcpy <= size_ints); // dbg - test for memcpy()   ???? <
	//	assert( size_memcpy <= HASH_SIZE); // dbg - test for memcpy()   ???? <
    memcpy(ints, hashes, size_memcpy); // ok?

    for (i = 2 * cnt - count, j = 2 * cnt - count; j < cnt; i += 2, ++j) {
			assert( i < size_hashes );  // hashes[] <<<< haha
	//		assert( i < count );
			assert( j < size_ints  ); // ints[]
	//		assert( j < count );
      cn_fast_hash(hashes[i], 64, ints[j]);
    }

    assert(i == count); // dbg

    while (cnt > 2) {
      cnt >>= 1;
      for (i = 0, j = 0; j < cnt; i += 2, ++j) {
				assert( i < size_ints );  // ints[i]
				assert( j < size_ints  ); // ints[j]
        cn_fast_hash(ints[i], 64, ints[j]);
      }
    }

    cn_fast_hash(ints[0], 64, root_hash);
  }
}
