// Copyright (c) 2012-2013 The Cryptonote developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.


#include "include_base_utils.h"
using namespace epee;

#include "wallet_rpc_server.h"
#include "common/command_line.h"
#include "cryptonote_core/cryptonote_format_utils.h"
#include "cryptonote_core/account.h"
#include "wallet_rpc_server_commands_defs.h"
#include "misc_language.h"
#include "string_tools.h"
#include "crypto/hash.h"
#include "common/util.h"
#include "version.h"
#include <ctime>
#include <iostream>

namespace tools
{

  /* Removes '<' and '>' */
  const std::string make_proper_tx_hash(const std::string& tx_hash_dirty)
  {
    
    if (tx_hash_dirty.size() == 66) {
      return tx_hash_dirty.substr(1,tx_hash_dirty.size()-2);
    }
    else {
      throw(std::invalid_argument("Tx hash '" + tx_hash_dirty + "' is not a valid <hash>"));
    }
  }
  //-----------------------------------------------------------------------------------
  const command_line::arg_descriptor<std::string> wallet_rpc_server::arg_rpc_bind_port = {"rpc-bind-port", "Starts wallet as rpc server for wallet operations, sets bind port for server", "", true};
  const command_line::arg_descriptor<std::string> wallet_rpc_server::arg_rpc_bind_ip = {"rpc-bind-ip", "Specify ip to bind rpc server", "127.0.0.1"};

  void wallet_rpc_server::init_options(boost::program_options::options_description& desc)
  {
    command_line::add_arg(desc, arg_rpc_bind_ip);
    command_line::add_arg(desc, arg_rpc_bind_port);
  }
  //------------------------------------------------------------------------------------------------------------------------------
  wallet_rpc_server::wallet_rpc_server(wallet2& w):m_wallet(w), m_last_refresh(0)
  {}
  //------------------------------------------------------------------------------------------------------------------------------

  // check if the time since the last refresh is too long
  bool wallet_rpc_server::check_time(epee::json_rpc::error& er)
  {
    if (difftime(time(NULL), m_last_refresh) > STALE_WALLET_TIME)
    {
      // try to refresh just in case a daemon has been started in between auto-refresh
      try
      {
        m_wallet.refresh();
        m_last_refresh = time(NULL);
      }
      catch(...)
      {
        er.code = WALLET_RPC_ERROR_CODE_STALE_WALLET;
        er.message = "Too much time has passed since the last successful refresh.  The wallet may not be able to connect to a running daemon.";
        return false;
      }
    }
    return true;
  }

  bool wallet_rpc_server::run()
  {
    m_net_server.add_idle_handler([this](){
      try
      {
        m_wallet.refresh();
        m_last_refresh = time(NULL); // if refresh successful, update last refresh time
      }
      catch(...)
      {
        LOG_PRINT_L0("Error refreshing wallet balance, possible lost connection to daemon.");
      }
      return true;
    }, 20000);

    //DO NOT START THIS SERVER IN MORE THEN 1 THREADS WITHOUT REFACTORING
    return epee::http_server_impl_base<wallet_rpc_server, connection_context>::run(1, true);
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::handle_command_line(const boost::program_options::variables_map& vm)
  {
    m_bind_ip = command_line::get_arg(vm, arg_rpc_bind_ip);
    m_port = command_line::get_arg(vm, arg_rpc_bind_port);
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::init(const boost::program_options::variables_map& vm)
  {
    m_net_server.set_threads_prefix("RPC");
    bool r = handle_command_line(vm);
    CHECK_AND_ASSERT_MES(r, false, "Failed to process command line in core_rpc_server");
    return epee::http_server_impl_base<wallet_rpc_server, connection_context>::init(m_port, m_bind_ip);
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_getbalance(const wallet_rpc::COMMAND_RPC_GET_BALANCE::request& req, wallet_rpc::COMMAND_RPC_GET_BALANCE::response& res, epee::json_rpc::error& er, connection_context& cntx)
  {
    // return failure if balance is stale
    if (!check_time(er))
    {
      return false;
    }

    try
    {
      res.balance = m_wallet.balance();
      res.unlocked_balance = m_wallet.unlocked_balance();
    }
    catch (std::exception& e)
    {
      er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
      er.message = e.what();
      return false;
    }
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_getaddress(const wallet_rpc::COMMAND_RPC_GET_ADDRESS::request& req, wallet_rpc::COMMAND_RPC_GET_ADDRESS::response& res, epee::json_rpc::error& er, connection_context& cntx)
  {
    try
    {
      res.address = m_wallet.get_account().get_public_address_str();
    }
    catch (std::exception& e)
    {
      er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
      er.message = e.what();
      return false;
    }
    return true;
  }

  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::validate_transfer(const std::list<wallet_rpc::transfer_destination> destinations, const std::string payment_id, std::vector<cryptonote::tx_destination_entry>& dsts, std::vector<uint8_t> extra, uint64_t fee, epee::json_rpc::error& er)
  {
    for (auto it = destinations.begin(); it != destinations.end(); it++)
    {
      cryptonote::tx_destination_entry de;
      if(!get_account_address_from_str(de.addr, it->address))
      {
        er.code = WALLET_RPC_ERROR_CODE_WRONG_ADDRESS;
        er.message = std::string("WALLET_RPC_ERROR_CODE_WRONG_ADDRESS: ") + it->address;
        return false;
      }
      de.amount = it->amount;
      dsts.push_back(de);
    }

    if (!payment_id.empty())
    {

      /* Just to clarify */
      const std::string& payment_id_str = payment_id;

      crypto::hash payment_id;
      /* Parse payment ID */
      if (!wallet2::parse_payment_id(payment_id_str, payment_id)) {
        er.code = WALLET_RPC_ERROR_CODE_WRONG_PAYMENT_ID;
        er.message = "Payment id has invalid format: \"" + payment_id_str + "\", expected 64-character string";
        return false;
      }

      std::string extra_nonce;
      cryptonote::set_payment_id_to_tx_extra_nonce(extra_nonce, payment_id);
      
      /* Append Payment ID data into extra */
      if (!cryptonote::add_extra_nonce_to_tx_extra(extra, extra_nonce)) {
        er.code = WALLET_RPC_ERROR_CODE_WRONG_PAYMENT_ID;
        er.message = "Something went wront with payment_id. Please check its format: \"" + payment_id_str + "\", expected 64-character string";
        return false;
      }

    }

    if (fee < DEFAULT_FEE) {
      er.code = WALLET_RPC_ERROR_CODE_INVALID_TRANSFER_FEE;
      er.message = "Fee value is too low. Minimal value is " + std::to_string(DEFAULT_FEE);
      return false;    
    }
    
    return true;
  }

  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_transfer(const wallet_rpc::COMMAND_RPC_TRANSFER::request& req, wallet_rpc::COMMAND_RPC_TRANSFER::response& res, epee::json_rpc::error& er, connection_context& cntx)
  {
    // return failure if balance is stale
    if (!check_time(er))
    {
      return false;
    }

    uint64_t effective_fee = req.fee;
    if (effective_fee <= 0) {
      effective_fee = DEFAULT_FEE;
    }

    std::vector<cryptonote::tx_destination_entry> dsts;
    std::vector<uint8_t> extra;

    // validate the transfer requested and populate dsts & extra
    if (!validate_transfer(req.destinations, req.payment_id, dsts, extra, effective_fee, er))
    {
      return false;
    }

    try
    {
      std::vector<wallet2::pending_tx> ptx_vector = m_wallet.create_transactions(dsts, req.mixin, req.unlock_time, effective_fee, extra);

      // reject proposed transactions if there are more than one.  see on_transfer_split below.
      if (ptx_vector.size() != 1)
      {
        er.code = WALLET_RPC_ERROR_CODE_GENERIC_TRANSFER_ERROR;
        er.message = "Transaction would be too large.  try /transfer_split.";
        return false;
      }

      m_wallet.commit_tx(ptx_vector);

      // populate response with tx hash
      const std::string tx_hash_dirty = boost::lexical_cast<std::string>(cryptonote::get_transaction_hash(ptx_vector.back().tx));
      res.tx_hash = tx_hash_dirty;
      
      try {
        res.tx_hash_proper = make_proper_tx_hash(tx_hash_dirty);
      }
      catch(std::invalid_argument e) {
        LOG_PRINT_L0(e.what());
        er.code = WALLET_RPC_ERROR_CODE_GENERIC_TRANSFER_ERROR;
        er.message = e.what();
        return false;
      }
      
      return true;
    }
    catch (const tools::error::daemon_busy& e)
    {
      er.code = WALLET_RPC_ERROR_CODE_DAEMON_IS_BUSY;
      er.message = e.what();
      return false;
    }
    catch (const std::exception& e)
    {
      er.code = WALLET_RPC_ERROR_CODE_GENERIC_TRANSFER_ERROR;
      er.message = e.what();
      return false;
    }
    catch (...)
    {
      er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
      er.message = "WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR";
      return false;
    }
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_transfer_split(const wallet_rpc::COMMAND_RPC_TRANSFER_SPLIT::request& req, wallet_rpc::COMMAND_RPC_TRANSFER_SPLIT::response& res, epee::json_rpc::error& er, connection_context& cntx)
  {
    // return failure if balance is stale
    if (!check_time(er))
    {
      return false;
    }

    uint64_t effective_fee = req.fee;
    if (effective_fee <= 0) {
      effective_fee = DEFAULT_FEE;
    }

    std::vector<cryptonote::tx_destination_entry> dsts;
    std::vector<uint8_t> extra;

    // validate the transfer requested and populate dsts & extra; RPC_TRANSFER::request and RPC_TRANSFER_SPLIT::request are identical types.
    if (!validate_transfer(req.destinations, req.payment_id, dsts, extra, effective_fee, er))
    {
      return false;
    }

    try
    {
      std::vector<wallet2::pending_tx> ptx_vector = m_wallet.create_transactions(dsts, req.mixin, req.unlock_time, effective_fee, extra);

      m_wallet.commit_tx(ptx_vector);

      // populate response with tx hashes
      for (auto & ptx : ptx_vector)
      {
        const std::string tx_hash_dirty = boost::lexical_cast<std::string>(cryptonote::get_transaction_hash(ptx.tx));
        try {
          res.tx_hash_list.push_back(make_proper_tx_hash(tx_hash_dirty));
        }
        /* Break the loop, since the exception should never happen */
        catch(std::invalid_argument e) {
          LOG_PRINT_L0(e.what());
          er.code = WALLET_RPC_ERROR_CODE_GENERIC_TRANSFER_ERROR;
          er.message = e.what();
          return false;
        }
      }

      return true;
    }
    catch (const tools::error::daemon_busy& e)
    {
      er.code = WALLET_RPC_ERROR_CODE_DAEMON_IS_BUSY;
      er.message = e.what();
      return false;
    }
    catch (const std::exception& e)
    {
      er.code = WALLET_RPC_ERROR_CODE_GENERIC_TRANSFER_ERROR;
      er.message = e.what();
      return false;
    }
    catch (...)
    {
      er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
      er.message = "WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR";
      return false;
    }
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_store(const wallet_rpc::COMMAND_RPC_STORE::request& req, wallet_rpc::COMMAND_RPC_STORE::response& res, epee::json_rpc::error& er, connection_context& cntx)
  {
    try
    {
      m_wallet.store();
    }
    catch (std::exception& e)
    {
      er.code = WALLET_RPC_ERROR_CODE_UNKNOWN_ERROR;
      er.message = e.what();
      return false;
    }
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_get_payments(const wallet_rpc::COMMAND_RPC_GET_PAYMENTS::request& req, wallet_rpc::COMMAND_RPC_GET_PAYMENTS::response& res, epee::json_rpc::error& er, connection_context& cntx)
  {
    // return failure if balance is stale
    if (!check_time(er))
    {
      return false;
    }

    crypto::hash payment_id;
    cryptonote::blobdata payment_id_blob;
    if(!epee::string_tools::parse_hexstr_to_binbuff(req.payment_id, payment_id_blob))
    {
      er.code = WALLET_RPC_ERROR_CODE_WRONG_PAYMENT_ID;
      er.message = "Payment ID has invald format";
      return false;
    }

    if(sizeof(payment_id) != payment_id_blob.size())
    {
      er.code = WALLET_RPC_ERROR_CODE_WRONG_PAYMENT_ID;
      er.message = "Payment ID has invalid size";
      return false;
    }

    payment_id = *reinterpret_cast<const crypto::hash*>(payment_id_blob.data());

    res.payments.clear();
    std::list<wallet2::payment_details> payment_list;
    m_wallet.get_payments(payment_id, payment_list);
    for (auto payment : payment_list)
    {
      wallet_rpc::payment_details rpc_payment;
      rpc_payment.tx_hash      = epee::string_tools::pod_to_hex(payment.m_tx_hash);
      /* Adding duplicate for consistency. Few impact on perfs */
      rpc_payment.tx_hash_proper  = rpc_payment.tx_hash;
      rpc_payment.amount       = payment.m_amount;
      rpc_payment.block_height = payment.m_block_height;
      rpc_payment.unlock_time  = payment.m_unlock_time;
      res.payments.push_back(rpc_payment);
    }

    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::on_incoming_transfers(const wallet_rpc::COMMAND_RPC_INCOMING_TRANSFERS::request& req, wallet_rpc::COMMAND_RPC_INCOMING_TRANSFERS::response& res, epee::json_rpc::error& er, connection_context& cntx)
  {
    // return failure if balance is stale
    if (!check_time(er))
    {
      return false;
    }

    if(req.transfer_type.compare("all") != 0 && req.transfer_type.compare("available") != 0 && req.transfer_type.compare("unavailable") != 0)
    {
      er.code = WALLET_RPC_ERROR_CODE_TRANSFER_TYPE;
      er.message = "Transfer type must be one of: all, available, or unavailable";
      return false;
    }

    bool filter = false;
    bool available = false;
    if (req.transfer_type.compare("available") == 0)
    {
      filter = true;
      available = true;
    }
    else if (req.transfer_type.compare("unavailable") == 0)
    {
      filter = true;
      available = false;
    }

    wallet2::transfer_container transfers;
    m_wallet.get_transfers(transfers);

    bool transfers_found = false;
    for (const auto& td : transfers)
    {
      if (!filter || available != td.m_spent)
      {
        if (!transfers_found)
        {
          transfers_found = true;
        }
        wallet_rpc::transfer_details rpc_transfers;
        rpc_transfers.amount       = td.amount();
        rpc_transfers.spent        = td.m_spent;
        rpc_transfers.global_index = td.m_global_output_index;
        rpc_transfers.tx_hash      = boost::lexical_cast<std::string>(cryptonote::get_transaction_hash(td.m_tx));
        try {
          rpc_transfers.tx_hash_proper = make_proper_tx_hash(rpc_transfers.tx_hash);
        }
        catch(std::invalid_argument e) {
          rpc_transfers.tx_hash_proper = "";
        }
        res.transfers.push_back(rpc_transfers);
      }
    }

    if (!transfers_found)
    {
      return false;
    }
  
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
}  // namespace tools

using namespace std;
using namespace epee;
using namespace cryptonote;
using boost::lexical_cast;
namespace po = boost::program_options;

namespace
{
  const command_line::arg_descriptor<std::string>   arg_wallet_file      = {"wallet-file", "Use wallet <arg>", ""};
  const command_line::arg_descriptor<std::string>   arg_password         = {"password", "Wallet password", "", true};
  const command_line::arg_descriptor<std::string>   arg_daemon_address   = {"daemon-address", "Use daemon instance at <host>:<port>", ""};
  const command_line::arg_descriptor<std::string>   arg_daemon_host      = {"daemon-host", "Use daemon instance at host <arg> instead of localhost", ""};
  const command_line::arg_descriptor<int>           arg_daemon_port      = {"daemon-port", "Use daemon instance at port <arg> instead of 8081", 0};
  const command_line::arg_descriptor<std::string>   arg_rpc_bind_port    = {"rpc-bind-port", "Use port <arg> as RPC listening port"};
  const command_line::arg_descriptor<uint32_t>      arg_log_level        = {"set_log", "", 0, true};
}  // file-local namespace


void print_version() 
{
  cout << CRYPTONOTE_NAME << " wallet v" << PROJECT_VERSION_LONG << endl;
}

void print_usage()
{
  cout << "Usage: rpcwallet --wallet-file=<file> --password=<password> --rpc-bind-port=<port> [--daemon-address=<host>:<port>] [--rpc-bind-address=127.0.0.1]" << endl;
}

int main(int argc, char* argv[])
{
#ifdef WIN32
  _CrtSetDbgFlag ( _CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF );
#endif

  string_tools::set_module_name_and_folder(argv[0]);

  po::options_description desc_general("General options");
  command_line::add_arg(desc_general, command_line::arg_help);
  command_line::add_arg(desc_general, command_line::arg_version);

  po::options_description desc_params("Wallet options");
  command_line::add_arg(desc_params, arg_wallet_file);
  command_line::add_arg(desc_params, arg_password);
  command_line::add_arg(desc_params, arg_daemon_address);
  command_line::add_arg(desc_params, arg_daemon_host);
  command_line::add_arg(desc_params, arg_daemon_port);
  command_line::add_arg(desc_params, arg_log_level);
  tools::wallet_rpc_server::init_options(desc_params);

  po::positional_options_description positional_options;

  po::options_description desc_all;
  desc_all.add(desc_general).add(desc_params);
  po::variables_map vm;

  bool r = command_line::handle_error_helper(desc_all, [&]()
  {
    po::store(command_line::parse_command_line(argc, argv, desc_general, true), vm);

    if (command_line::get_arg(vm, command_line::arg_help))
    {
      print_usage();
      return false;
    }
    else if (command_line::get_arg(vm, command_line::arg_version))
    {
      print_version();
      return false;
    }

    auto parser = po::command_line_parser(argc, argv).options(desc_params).positional(positional_options);
    po::store(parser.run(), vm);
    po::notify(vm);
    return true;
  });
  if (!r)
    return 0;

  //set up logging options
  log_space::get_set_log_detalisation_level(true, LOG_LEVEL_2);
  //log_space::log_singletone::add_logger(LOGGER_CONSOLE, NULL, NULL, LOG_LEVEL_0);
  log_space::log_singletone::add_logger(LOGGER_FILE,
    log_space::log_singletone::get_default_log_file().c_str(),
    log_space::log_singletone::get_default_log_folder().c_str(), LOG_LEVEL_4);

  print_version();

  if(command_line::has_arg(vm, arg_log_level))
  {
    LOG_PRINT_L0("Setting log level = " << command_line::get_arg(vm, arg_log_level));
    log_space::get_set_log_detalisation_level(true, command_line::get_arg(vm, arg_log_level));
  }


  log_space::log_singletone::add_logger(LOGGER_CONSOLE, NULL, NULL, LOG_LEVEL_2);
  //runs wallet with rpc interface
  if(!command_line::has_arg(vm, arg_wallet_file) )
  {
    LOG_ERROR("Wallet file not set.");
    print_usage();
    return tools::wallet2::ReturnCode::BAD_ARGUMENT_ERROR;
  }
  if(!command_line::has_arg(vm, arg_daemon_address) )
  {
    LOG_ERROR("Daemon address not set.");
    print_usage();
    return tools::wallet2::ReturnCode::BAD_ARGUMENT_ERROR;
  }
  if(!command_line::has_arg(vm, arg_password) )
  {
    LOG_ERROR("Wallet password not set.");
    print_usage();
    return tools::wallet2::ReturnCode::BAD_ARGUMENT_ERROR;
  }
  if(!command_line::has_arg(vm, arg_rpc_bind_port) )
  {
    LOG_ERROR("RPC bind port not set.");
    print_usage();
    return tools::wallet2::ReturnCode::BAD_ARGUMENT_ERROR;
  }

  std::string wallet_file     = command_line::get_arg(vm, arg_wallet_file);
  std::string wallet_password = command_line::get_arg(vm, arg_password);
  std::string daemon_address  = command_line::get_arg(vm, arg_daemon_address);
  std::string daemon_host = command_line::get_arg(vm, arg_daemon_host);
  int daemon_port = command_line::get_arg(vm, arg_daemon_port);
  if (daemon_host.empty())
    daemon_host = "localhost";
  if (!daemon_port)
    daemon_port = RPC_DEFAULT_PORT;
  if (daemon_address.empty())
    daemon_address = std::string("http://") + daemon_host + ":" + std::to_string(daemon_port);

  tools::wallet2 wal;
  try
  {
    LOG_PRINT_L0("Loading wallet...");
    wal.load(wallet_file, wallet_password);
    wal.init(daemon_address);
    LOG_PRINT_GREEN("Loaded ok", LOG_LEVEL_0);
  }
  catch (const std::exception& e)
  {
    LOG_ERROR("Wallet initialize failed: " << e.what());
    return tools::wallet2::ReturnCode::INITIALIZATION_ERROR;
  }
  try
  {
    wal.refresh();
  }
  catch(...)
  {
    LOG_PRINT_L0("Error refreshing wallet, possible lost connection to daemon. Is 'bitmonerod' running ?");
    return tools::wallet2::ReturnCode::REFRESH_ERROR;
  }

  LOG_PRINT_L0("Initializing RPC server");
  tools::wallet_rpc_server wrpc(wal);

  CHECK_AND_ASSERT_MES(wrpc.init(vm), 1, "Failed to initialize wallet rpc server");
  LOG_PRINT_L0("RPC server ready to start")

  tools::signal_handler::install([&wrpc, &wal] {
    wrpc.send_stop_signal();
    wal.store();
  });
  LOG_PRINT_L0("Starting wallet rpc server");
  wrpc.run();
  LOG_PRINT_L0("Stopped wallet rpc server");
  try
  {
    LOG_PRINT_L0("Storing wallet...");
    wal.store();
    LOG_PRINT_GREEN("Stored ok", LOG_LEVEL_0);
  }
  catch (const std::exception& e)
  {
    LOG_ERROR("Failed to store wallet: " << e.what());
    return tools::wallet2::ReturnCode::STORAGE_ERROR;
  }
}
