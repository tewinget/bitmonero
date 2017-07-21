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

#include "rpc/daemon_rpc_client_zmq.h"
#include "serialization/json_object.h"
#include "include_base_utils.h"

namespace cryptonote
{

namespace rpc
{

DaemonRPCClientZMQ::DaemonRPCClientZMQ(const std::string& address)
{
  connect(address);
}

DaemonRPCClientZMQ::~DaemonRPCClientZMQ()
{
}

boost::optional<std::string> DaemonRPCClientZMQ::checkConnection(
    uint32_t timeout,
    uint32_t& version)
{
  return getRPCVersion(version);
}

boost::optional<std::string> DaemonRPCClientZMQ::getHeight(
    uint64_t& height)
{
  std::string error_details = "Error handling RPC request";
  std::shared_ptr<FullMessage> full_message_ptr;
  rapidjson::Value response_json;

  try
  {
    GetHeight::Request request;

    response_json = doRequest<GetHeight>(full_message_ptr, request);
  }
  catch (...)
  {
    return error_details;
  }

  try
  {
    GetHeight::Response response = parseResponse<GetHeight>(response_json);

    height = response.height;

    return boost::none;
  }
  catch (...)
  {
  }

  return error_details;
}

boost::optional<std::string> DaemonRPCClientZMQ::getDaemonInfo(
    cryptonote::rpc::DaemonInfo& info)
{
  std::string error_details = "Error handling RPC request";
  std::shared_ptr<FullMessage> full_message_ptr;
  rapidjson::Value response_json;

  try
  {
    GetInfo::Request request;

    response_json = doRequest<GetInfo>(full_message_ptr, request);
  }
  catch (...)
  {
    return error_details;
  }

  try
  {
    GetInfo::Response response = parseResponse<GetInfo>(response_json);

    info = response.info;

    return boost::none;
  }
  catch (...)
  {
    try
    {
      cryptonote::rpc::error err = parseError(response_json);

      error_details = err.error_str;
    }
    catch (...)
    {
      error_details = "Daemon returned improper JSON-RPC response.";
    }
  }

  return error_details;
}

boost::optional<std::string> DaemonRPCClientZMQ::getTargetHeight(
    uint64_t& target_height)
{
  cryptonote::rpc::DaemonInfo info;
  boost::optional<std::string> r = getDaemonInfo(info);
  if (r) return *r;

  target_height = info.target_height;

  return boost::none;
}

boost::optional<std::string> DaemonRPCClientZMQ::getNetworkDifficulty(
    uint64_t& difficulty)
{
  cryptonote::rpc::DaemonInfo info;
  boost::optional<std::string> r = getDaemonInfo(info);
  if (r) return *r;

  difficulty = info.difficulty;

  return boost::none;
}

boost::optional<std::string> DaemonRPCClientZMQ::getDifficultyTarget(
    uint64_t& target)
{
  cryptonote::rpc::DaemonInfo info;
  boost::optional<std::string> r = getDaemonInfo(info);
  if (r) return *r;

  target = info.target;

  return boost::none;
}

boost::optional<std::string> DaemonRPCClientZMQ::getBlocksFast(
    const std::list<crypto::hash>& short_chain_history,
    const uint64_t start_height_in,
    const bool prune,
    std::vector<cryptonote::rpc::block_with_transactions>& blocks,
    uint64_t& start_height_out,
    uint64_t& current_height,
    std::vector<cryptonote::rpc::block_output_indices>& output_indices)
{
  std::string error_details = "Error handling RPC request";
  std::shared_ptr<FullMessage> full_message_ptr;
  rapidjson::Value response_json;

  try
  {
    GetBlocksFast::Request request;

    request.block_ids = short_chain_history;
    request.start_height = start_height_in;

    response_json = doRequest<GetBlocksFast>(full_message_ptr, request);
  }
  catch (...)
  {
    return error_details;
  }

  try
  {
    GetBlocksFast::Response response = parseResponse<GetBlocksFast>(response_json);

    blocks = response.blocks;
    start_height_out = response.start_height;
    current_height = response.current_height;
    output_indices = response.output_indices;

    return boost::none;
  }
  catch (...)
  {
    try
    {
      cryptonote::rpc::error err = parseError(response_json);

      error_details = err.error_str;
    }
    catch (...)
    {
      error_details = "Daemon returned improper JSON-RPC response.";
    }
  }

  return error_details;
}

boost::optional<std::string> DaemonRPCClientZMQ::getHashesFast(
    const std::list<crypto::hash>& short_chain_history,
    const uint64_t start_height_in,
    std::list<crypto::hash>& hashes,
    uint64_t& start_height_out,
    uint64_t& current_height)
{
  std::string error_details = "Error handling RPC request";
  std::shared_ptr<FullMessage> full_message_ptr;
  rapidjson::Value response_json;

  try
  {
    GetHashesFast::Request request;

    request.known_hashes = hashes;
    request.start_height = start_height_in;

    response_json = doRequest<GetHashesFast>(full_message_ptr, request);
  }
  catch (...)
  {
    return error_details;
  }

  try
  {
    GetHashesFast::Response response = parseResponse<GetHashesFast>(response_json);

    hashes = response.hashes;
    start_height_out = response.start_height;
    current_height = response.current_height;

    return boost::none;
  }
  catch (...)
  {
    try
    {
      cryptonote::rpc::error err = parseError(response_json);

      error_details = err.error_str;
    }
    catch (...)
    {
      error_details = "Daemon returned improper JSON-RPC response.";
    }
  }

  return error_details;
}

boost::optional<std::string> DaemonRPCClientZMQ::getTransactions(
    const std::vector<crypto::hash>& tx_hashes,
    std::unordered_map<crypto::hash, cryptonote::rpc::transaction_info> txs,
    std::vector<crypto::hash> missed_hashes)
{
  std::string error_details = "Error handling RPC request";
  std::shared_ptr<FullMessage> full_message_ptr;
  rapidjson::Value response_json;

  try
  {
    GetTransactions::Request request;

    request.tx_hashes = tx_hashes;

    response_json = doRequest<GetTransactions>(full_message_ptr, request);
  }
  catch (...)
  {
    return error_details;
  }

  try
  {
    GetTransactions::Response response = parseResponse<GetTransactions>(response_json);

    txs = response.txs;
    missed_hashes = response.missed_hashes;

    return boost::none;
  }
  catch (...)
  {
    try
    {
      cryptonote::rpc::error err = parseError(response_json);

      error_details = err.error_str;
    }
    catch (...)
    {
      error_details = "Daemon returned improper JSON-RPC response.";
    }
  }

  return error_details;
}

boost::optional<std::string> DaemonRPCClientZMQ::getBlockHeadersByHeight(
    const std::vector<uint64_t>& heights,
    std::vector<cryptonote::rpc::BlockHeaderResponse> headers)
{
  std::string error_details = "Error handling RPC request";
  std::shared_ptr<FullMessage> full_message_ptr;
  rapidjson::Value response_json;

  try
  {
    GetBlockHeadersByHeight::Request request;

    request.heights = heights;

    response_json = doRequest<GetBlockHeadersByHeight>(full_message_ptr, request);
  }
  catch (...)
  {
    return error_details;
  }

  try
  {
    GetBlockHeadersByHeight::Response response = parseResponse<GetBlockHeadersByHeight>(response_json);

    headers = response.headers;

    return boost::none;
  }
  catch (...)
  {
    try
    {
      cryptonote::rpc::error err = parseError(response_json);

      error_details = err.error_str;
    }
    catch (...)
    {
      error_details = "Daemon returned improper JSON-RPC response.";
    }
  }

  return error_details;
}

boost::optional<std::string> DaemonRPCClientZMQ::keyImagesSpent(
    const std::vector<crypto::key_image>& images,
    std::vector<bool>& spent,
    std::vector<bool>& spent_in_chain,
    std::vector<bool>& spent_in_pool)
{
  std::string error_details = "Error handling RPC request";
  std::shared_ptr<FullMessage> full_message_ptr;
  rapidjson::Value response_json;

  try
  {
    KeyImagesSpent::Request request;

    request.key_images = images;

    response_json = doRequest<KeyImagesSpent>(full_message_ptr, request);
  }
  catch (...)
  {
    return error_details;
  }

  try
  {
    KeyImagesSpent::Response response = parseResponse<KeyImagesSpent>(response_json);

    spent.resize(images.size());
    spent_in_chain.resize(images.size());
    spent_in_pool.resize(images.size());

    for (size_t i=0; i < response.spent_status.size(); i++)
    {
      spent[i] = (response.spent_status[i] != KeyImagesSpent::UNSPENT);
      spent_in_chain[i] = (response.spent_status[i] == KeyImagesSpent::SPENT_IN_BLOCKCHAIN);
      spent_in_pool[i] = (response.spent_status[i] == KeyImagesSpent::SPENT_IN_POOL);
    }

    return boost::none;
  }
  catch (...)
  {
    try
    {
      cryptonote::rpc::error err = parseError(response_json);

      error_details = err.error_str;
    }
    catch (...)
    {
      error_details = "Daemon returned improper JSON-RPC response.";
    }
  }

  return error_details;
}

boost::optional<std::string> DaemonRPCClientZMQ::getTransactionPool(
    std::unordered_map<crypto::hash, cryptonote::rpc::tx_in_pool>& transactions,
    std::unordered_map<crypto::key_image, std::vector<crypto::hash> >& key_images)
{
  std::string error_details = "Error handling RPC request";
  std::shared_ptr<FullMessage> full_message_ptr;
  rapidjson::Value response_json;

  try
  {
    GetTransactionPool::Request request;

    response_json = doRequest<GetTransactionPool>(full_message_ptr, request);
  }
  catch (...)
  {
    return error_details;
  }

  try
  {
    GetTransactionPool::Response response = parseResponse<GetTransactionPool>(response_json);

    if (response.status != Message::STATUS_OK)
    {
      return error_details;
    }

    for (const auto& poolTx : response.transactions)
    {
      transactions[poolTx.tx_hash] = poolTx;
    }
    key_images = response.key_images;

    return boost::none;
  }
  catch (...)
  {
    try
    {
      cryptonote::rpc::error err = parseError(response_json);

      error_details = err.error_str;
    }
    catch (...)
    {
      error_details = "Daemon returned improper JSON-RPC response.";
    }
  }

  return error_details;
}

boost::optional<std::string> DaemonRPCClientZMQ::getRandomOutputsForAmounts(
    const std::vector<uint64_t>& amounts,
    const uint64_t count,
    std::vector<amount_with_random_outputs>& amounts_with_outputs)
{
  std::string error_details = "Error handling RPC request";
  std::shared_ptr<FullMessage> full_message_ptr;
  rapidjson::Value response_json;

  try
  {
    GetRandomOutputsForAmounts::Request request;

    request.amounts = amounts;
    request.count = count;

    response_json = doRequest<GetRandomOutputsForAmounts>(full_message_ptr, request);
  }
  catch (...)
  {
    return error_details;
  }

  try
  {
    GetRandomOutputsForAmounts::Response response = parseResponse<GetRandomOutputsForAmounts>(response_json);

    amounts_with_outputs = response.amounts_with_outputs;

    return boost::none;
  }
  catch (...)
  {
    try
    {
      cryptonote::rpc::error err = parseError(response_json);

      error_details = err.error_str;
    }
    catch (...)
    {
      error_details = "Daemon returned improper JSON-RPC response.";
    }
  }

  return error_details;
}

boost::optional<std::string> DaemonRPCClientZMQ::sendRawTx(
    const cryptonote::transaction& tx,
    bool& relayed,
    bool relay)
{
  std::string error_details = "Error handling RPC request";
  std::shared_ptr<FullMessage> full_message_ptr;
  rapidjson::Value response_json;

  try
  {
    SendRawTx::Request request;

    request.tx = tx;
    request.relay = relay;

    response_json = doRequest<SendRawTx>(full_message_ptr, request);
  }
  catch (...)
  {
    return error_details;
  }

  try
  {
    SendRawTx::Response response = parseResponse<SendRawTx>(response_json);

    relayed = response.relayed;

    return boost::none;
  }
  catch (...)
  {
    try
    {
      cryptonote::rpc::error err = parseError(response_json);

      error_details = err.error_str;
    }
    catch (...)
    {
      error_details = "Daemon returned improper JSON-RPC response.";
    }
  }

  return error_details;
}

boost::optional<std::string> DaemonRPCClientZMQ::hardForkInfo(
    const uint8_t version,
    hard_fork_info& info)
{
  std::string error_details = "Error handling RPC request";
  std::shared_ptr<FullMessage> full_message_ptr;
  rapidjson::Value response_json;

  try
  {
    HardForkInfo::Request request;

    request.version = version;

    response_json = doRequest<HardForkInfo>(full_message_ptr, request);
  }
  catch (...)
  {
    return error_details;
  }

  try
  {
    HardForkInfo::Response response = parseResponse<HardForkInfo>(response_json);

    info = response.info;

    return boost::none;
  }
  catch (...)
  {
  }

  return error_details;
}

boost::optional<std::string> DaemonRPCClientZMQ::getHardForkEarliestHeight(
    const uint8_t version,
    uint64_t& earliest_height)
{
  cryptonote::rpc::hard_fork_info info;
  boost::optional<std::string> r = hardForkInfo(version, info);
  if (r) return *r;

  earliest_height = info.earliest_height;

  return boost::none;
}

boost::optional<std::string> DaemonRPCClientZMQ::getOutputHistogram(
    const std::vector<uint64_t>& amounts,
    uint64_t min_count,
    uint64_t max_count,
    bool unlocked,
    uint64_t recent_cutoff,
    std::vector<output_amount_count>& histogram)
{
  std::string error_details = "Error handling RPC request";
  std::shared_ptr<FullMessage> full_message_ptr;
  rapidjson::Value response_json;

  try
  {
    GetOutputHistogram::Request request;

    request.amounts = amounts;
    request.min_count = min_count;
    request.max_count = max_count;
    request.unlocked = unlocked;
    request.recent_cutoff = recent_cutoff;

    response_json = doRequest<GetOutputHistogram>(full_message_ptr, request);
  }
  catch (...)
  {
    return error_details;
  }

  try
  {
    GetOutputHistogram::Response response = parseResponse<GetOutputHistogram>(response_json);

    histogram = response.histogram;

    return boost::none;
  }
  catch (...)
  {
    try
    {
      cryptonote::rpc::error err = parseError(response_json);

      error_details = err.error_str;
    }
    catch (...)
    {
      error_details = "Daemon returned improper JSON-RPC response.";
    }
  }

  return error_details;
}

boost::optional<std::string> DaemonRPCClientZMQ::getOutputKeys(
    const std::vector<output_amount_and_index>& outputs,
    std::vector<output_key_mask_unlocked>& keys)
{
  std::string error_details = "Error handling RPC request";
  std::shared_ptr<FullMessage> full_message_ptr;
  rapidjson::Value response_json;

  try
  {
    GetOutputKeys::Request request;

    request.outputs = outputs;

    response_json = doRequest<GetOutputKeys>(full_message_ptr, request);
  }
  catch (...)
  {
    return error_details;
  }

  try
  {
    GetOutputKeys::Response response = parseResponse<GetOutputKeys>(response_json);

    keys = response.keys;

    return boost::none;
  }
  catch (...)
  {
    try
    {
      cryptonote::rpc::error err = parseError(response_json);

      error_details = err.error_str;
    }
    catch (...)
    {
      error_details = "Daemon returned improper JSON-RPC response.";
    }
  }

  return error_details;
}

boost::optional<std::string> DaemonRPCClientZMQ::getRPCVersion(
    uint32_t& version)
{
  std::string error_details = "Error handling RPC request";
  std::shared_ptr<FullMessage> full_message_ptr;
  rapidjson::Value response_json;

  try
  {
    GetRPCVersion::Request request;

    response_json = doRequest<GetRPCVersion>(full_message_ptr, request);
  }
  catch (...)
  {
    return error_details;
  }

  try
  {
    GetRPCVersion::Response response = parseResponse<GetRPCVersion>(response_json);

    version = response.version;

    return boost::none;
  }
  catch (...)
  {
    try
    {
      cryptonote::rpc::error err = parseError(response_json);

      error_details = err.error_str;
    }
    catch (...)
    {
      error_details = "Daemon returned improper JSON-RPC response.";
    }
  }

  return error_details;
}

boost::optional<std::string> DaemonRPCClientZMQ::getPerKBFeeEstimate(
    const uint64_t num_grace_blocks,
    uint64_t& estimated_per_kb_fee)
{
  std::string error_details = "Error handling RPC request";
  std::shared_ptr<FullMessage> full_message_ptr;
  rapidjson::Value response_json;

  try
  {
    GetPerKBFeeEstimate::Request request;

    request.num_grace_blocks = num_grace_blocks;

    response_json = doRequest<GetPerKBFeeEstimate>(full_message_ptr, request);
  }
  catch (...)
  {
    return error_details;
  }

  try
  {
    GetPerKBFeeEstimate::Response response = parseResponse<GetPerKBFeeEstimate>(response_json);

    estimated_per_kb_fee = response.estimated_fee_per_kb;

    return boost::none;
  }
  catch (...)
  {
    try
    {
      cryptonote::rpc::error err = parseError(response_json);

      error_details = err.error_str;
    }
    catch (...)
    {
      error_details = "Daemon returned improper JSON-RPC response.";
    }
  }

  return error_details;
}

boost::optional<std::string> DaemonRPCClientZMQ::getMiningStatus(
    bool& active,
    uint64_t& speed,
    uint64_t& threads_count,
    std::string& address,
    bool& is_background_mining_enabled)
{
  std::string error_details = "Error handling RPC request";
  std::shared_ptr<FullMessage> full_message_ptr;
  rapidjson::Value response_json;

  try
  {
    MiningStatus::Request request;

    response_json = doRequest<MiningStatus>(full_message_ptr, request);
  }
  catch (...)
  {
    return error_details;
  }

  try
  {
    MiningStatus::Response response = parseResponse<MiningStatus>(response_json);

    active = response.active;
    speed = response.speed;
    threads_count = response.threads_count;
    address = response.address;
    is_background_mining_enabled = response.is_background_mining_enabled;

    return boost::none;
  }
  catch (...)
  {
    try
    {
      cryptonote::rpc::error err = parseError(response_json);

      error_details = err.error_str;
    }
    catch (...)
    {
      error_details = "Daemon returned improper JSON-RPC response.";
    }
  }

  return error_details;
}

boost::optional<std::string> DaemonRPCClientZMQ::getMiningHashRate(
    uint64_t& speed)
{
  bool activeVal;
  uint64_t speedVal;
  uint64_t threads_countVal;
  std::string addressVal;
  bool is_background_mining_enabledVal;

  boost::optional<std::string> r = getMiningStatus(
      activeVal,
      speedVal,
      threads_countVal,
      addressVal,
      is_background_mining_enabledVal);

  if (r) return *r;

  speed = speedVal;

  return boost::none;
}

boost::optional<std::string> DaemonRPCClientZMQ::isMining(
    bool& status)
{
  bool activeVal;
  uint64_t speedVal;
  uint64_t threads_countVal;
  std::string addressVal;
  bool is_background_mining_enabledVal;

  boost::optional<std::string> r = getMiningStatus(
      activeVal,
      speedVal,
      threads_countVal,
      addressVal,
      is_background_mining_enabledVal);

  if (r) return *r;

  status = activeVal;

  return boost::none;
}

boost::optional<std::string> DaemonRPCClientZMQ::startMining(
    const std::string& miner_address,
    const uint64_t threads_count,
    const bool do_background_mining,
    const bool ignore_battery)
{
  std::string error_details = "Error handling RPC request";
  std::shared_ptr<FullMessage> full_message_ptr;
  rapidjson::Value response_json;

  try
  {
    StartMining::Request request;

    request.miner_address = miner_address;
    request.threads_count = threads_count;
    request.do_background_mining = do_background_mining;
    request.ignore_battery = ignore_battery;

    response_json = doRequest<StartMining>(full_message_ptr, request);
  }
  catch (...)
  {
    return error_details;
  }

  try
  {
    StartMining::Response response = parseResponse<StartMining>(response_json);

    return boost::none;
  }
  catch (...)
  {
    try
    {
      cryptonote::rpc::error err = parseError(response_json);

      error_details = err.error_str;
    }
    catch (...)
    {
      error_details = "Daemon returned improper JSON-RPC response.";
    }
  }

  return error_details;
}

boost::optional<std::string> DaemonRPCClientZMQ::stopMining()
{
  std::string error_details = "Error handling RPC request";
  std::shared_ptr<FullMessage> full_message_ptr;
  rapidjson::Value response_json;

  try
  {
    StopMining::Request request;

    response_json = doRequest<StopMining>(full_message_ptr, request);
  }
  catch (...)
  {
    return error_details;
  }

  try
  {
    StopMining::Response response = parseResponse<StopMining>(response_json);

    return boost::none;
  }
  catch (...)
  {
    try
    {
      cryptonote::rpc::error err = parseError(response_json);

      error_details = err.error_str;
    }
    catch (...)
    {
      error_details = "Daemon returned improper JSON-RPC response.";
    }
  }

  return error_details;
}

uint32_t DaemonRPCClientZMQ::getOurRPCVersion()
{
  return cryptonote::rpc::DAEMON_RPC_VERSION_ZMQ;
}

template <typename ReqType>
rapidjson::Value DaemonRPCClientZMQ::doRequest(std::shared_ptr<FullMessage>& full_message_ptr, typename ReqType::Request& request)
{
  // rapidjson doesn't take a copy, and ephemeral conversion behaves poorly
  std::string request_method = ReqType::name;

  auto full_request = FullMessage::requestMessage(request_method, &request);

  std::string resp = zmq_client.doRequest(full_request.getJson());

  if (resp.empty())
  {
    full_message_ptr.reset(FullMessage::timeoutMessage());
  }

  full_message_ptr.reset(new FullMessage(resp));

  return full_message_ptr->getMessageCopy();
}

template <typename ReqType>
typename ReqType::Response DaemonRPCClientZMQ::parseResponse(rapidjson::Value& resp)
{
  typename ReqType::Response response;

  response.fromJson(resp);

  return response;
}

cryptonote::rpc::error DaemonRPCClientZMQ::parseError(rapidjson::Value& err)
{
  cryptonote::rpc::error error;
  cryptonote::json::fromJsonValue(err, error);
  LOG_ERROR("ZMQ RPC client received error: " << error.error_str);
  return error;
}

void DaemonRPCClientZMQ::connect(const std::string& address_with_port)
{
  zmq_client.connect(address_with_port);
}

void DaemonRPCClientZMQ::connect(const std::string& addr, const std::string& port)
{
  zmq_client.connect(addr, port);
}

}  // namespace rpc

}  // namespace cryptonote
