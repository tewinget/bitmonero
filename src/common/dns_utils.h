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

#include <vector>
#include <string>
#include <functional>

namespace tools
{

// RFC defines for record types and classes for DNS, gleaned from ldns source
const static int DNS_CLASS_IN  = 1;
const static int DNS_TYPE_A    = 1;
const static int DNS_TYPE_TXT  = 16;
const static int DNS_TYPE_AAAA = 8;

struct DNSResolverData;

typedef std::function<void(std::vector<std::string>&)> DNSCallback;

/**
 * @brief Provides high-level access to DNS resolution
 *
 * This class is designed to provide a high-level abstraction to DNS resolution
 * functionality, including access to TXT records and such.  It will also
 * handle DNSSEC validation of the results.
 */
class DNSResolver
{
public:

  /**
   * @brief Constructs an instance of DNSResolver
   *
   * Constructs a class instance and does setup stuff for the backend resolver.
   */
  DNSResolver();

  /**
   * @brief takes care of freeing C pointers and such
   */
  ~DNSResolver();

  /**
   * @brief gets ipv4 addresses from DNS query of a URL
   *
   * returns a vector of all IPv4 "A" records for given URL.
   * If no "A" records found, returns an empty vector.
   *
   * @param url A string containing a URL to query for
   *
   * @param dnssec_available 
   *
   * @return vector of strings containing ipv4 addresses
   */
  std::vector<std::string> get_ipv4(const std::string& url, bool& dnssec_available, bool& dnssec_valid);

  /**
   * @brief gets ipv4 addresses from DNS query of a URL, async version
   *
   * returns true of the query can be completed as requested, otherwise false
   * NOTE: as this is asynchronous, the caller should maintain his own instance
   * of DNSResolver.
   *
   * @param url A string containing a URL to query for
   *
   * @param cb_func A reference to a function to call after the query completes
   *
   * @param dnssec_available 
   *
   * @return vector of strings containing ipv4 addresses
   */
  bool get_ipv4_async(const std::string& url, DNSCallback& cb_func, bool& dnssec_available, bool& dnssec_valid);

  /**
   * @brief gets ipv6 addresses from DNS query
   *
   * returns a vector of all IPv6 "A" records for given URL.
   * If no "A" records found, returns an empty vector.
   *
   * @param url A string containing a URL to query for
   *
   * @return vector of strings containing ipv6 addresses
   */
   std::vector<std::string> get_ipv6(const std::string& url, bool& dnssec_available, bool& dnssec_valid);

  /**
   * @brief gets all TXT records from a DNS query for the supplied URL;
   * if no TXT record present returns an empty vector.
   *
   * @param url A string containing a URL to query for
   *
   * @return A vector of strings containing a TXT record; or an empty vector
   */
   std::vector<std::string> get_txt_record(const std::string& url, bool& dnssec_available, bool& dnssec_valid);

  /**
   * @brief Gets the singleton instance of DNSResolver
   *
   * @return returns a pointer to the singleton
   */
  static DNSResolver& instance();

private:

  /**
   * @brief Checks a string to see if it looks like a URL
   *
   * @param addr the string to be checked
   *
   * @return true if it looks enough like a URL, false if not
   */
  static bool check_address_syntax(const std::string& addr);

  DNSResolverData *m_data;
}; // class DNSResolver

}  // namespace tools
