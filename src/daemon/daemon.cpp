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

// node.cpp : Defines the entry point for the console application.
// Does this file exist?


#include "include_base_utils.h"
#include "version.h"

using namespace epee;

#include <boost/program_options.hpp>

#include "crypto/hash.h"
#include "console_handler.h"
#include "p2p/net_node.h"
#include "cryptonote_config.h"
#include "cryptonote_core/checkpoints_create.h"
#include "cryptonote_core/checkpoints.h"
#include "cryptonote_core/cryptonote_core.h"
#include "rpc/core_rpc_server.h"
#include "cryptonote_protocol/cryptonote_protocol_handler.h"
#include "daemon_commands_handler.h"
#include "version.h"
#include "rpc/json_rpc_handlers.h"
#include "rpc/json_rpc_http_server.h"

#if defined(WIN32)
#include <crtdbg.h>
#endif

namespace po = boost::program_options;

namespace
{
  const command_line::arg_descriptor<std::string> arg_config_file = {"config-file", "Specify configuration file", std::string(CRYPTONOTE_NAME ".conf")};
  const command_line::arg_descriptor<bool>        arg_os_version  = {"os-version", ""};
  const command_line::arg_descriptor<std::string> arg_log_file    = {"log-file", "", ""};
  const command_line::arg_descriptor<int>         arg_log_level   = {"log-level", "", LOG_LEVEL_0};
  const command_line::arg_descriptor<bool>        arg_console     = {"no-console", "Disable daemon console commands"};
  const command_line::arg_descriptor<bool>        arg_testnet_on  = {
      "testnet"
    , "Run on testnet. The wallet must be launched with --testnet flag."
    , false
    };
  const command_line::arg_descriptor<bool>        arg_dns_checkpoints  = {"enforce-dns-checkpointing", "checkpoints from DNS server will be enforced", false};
}

bool command_line_preprocessor(const boost::program_options::variables_map& vm)
{
  bool exit = false;
  if (command_line::get_arg(vm, command_line::arg_version))
  {
    std::cout << CRYPTONOTE_NAME  << " v" << MONERO_VERSION_FULL << ENDL;
    exit = true;
  }
  if (command_line::get_arg(vm, arg_os_version))
  {
    std::cout << "OS: " << tools::get_os_version_string() << ENDL;
    exit = true;
  }

  if (exit)
  {
    return true;
  }

  int new_log_level = command_line::get_arg(vm, arg_log_level);
  if(new_log_level < LOG_LEVEL_MIN || new_log_level > LOG_LEVEL_MAX)
  {
    LOG_PRINT_L0("Wrong log level value: ");
  }
  else if (log_space::get_set_log_detalisation_level(false) != new_log_level)
  {
    log_space::get_set_log_detalisation_level(true, new_log_level);
    LOG_PRINT_L0("LOG_LEVEL set to " << new_log_level);
  }

  return false;
}

int main(int argc, char* argv[])
{
  RPC::Json_rpc_http_server server2("127.0.0.1", "9997", &RPC::ev_handler);
  if(!server2.start()) std::cout << "Couldn't start net_skeleton server\n";

  string_tools::set_module_name_and_folder(argv[0]);
#ifdef WIN32
  _CrtSetDbgFlag ( _CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF );
#endif
  log_space::get_set_log_detalisation_level(true, LOG_LEVEL_0);
  log_space::log_singletone::add_logger(LOGGER_CONSOLE, NULL, NULL);
  LOG_PRINT_L0("Starting...");

  TRY_ENTRY();  

  boost::filesystem::path default_data_path {tools::get_default_data_dir()};
  boost::filesystem::path default_testnet_data_path {default_data_path / "testnet"};

  po::options_description desc_cmd_only("Command line options");
  po::options_description desc_cmd_sett("Command line options and settings options");

  command_line::add_arg(desc_cmd_only, command_line::arg_help);
  command_line::add_arg(desc_cmd_only, command_line::arg_version);
  command_line::add_arg(desc_cmd_only, arg_os_version);
  // tools::get_default_data_dir() can't be called during static initialization
  command_line::add_arg(desc_cmd_only, command_line::arg_data_dir, default_data_path.string());
  command_line::add_arg(desc_cmd_only, command_line::arg_testnet_data_dir, default_testnet_data_path.string());
  command_line::add_arg(desc_cmd_only, arg_config_file);

  command_line::add_arg(desc_cmd_sett, arg_log_file);
  command_line::add_arg(desc_cmd_sett, arg_log_level);
  command_line::add_arg(desc_cmd_sett, arg_console);
  command_line::add_arg(desc_cmd_sett, arg_testnet_on);
  command_line::add_arg(desc_cmd_sett, arg_dns_checkpoints);

  cryptonote::core::init_options(desc_cmd_sett);
  RPC::init_options(desc_cmd_sett);
  nodetool::node_server<cryptonote::t_cryptonote_protocol_handler<cryptonote::core> >::init_options(desc_cmd_sett);
  cryptonote::miner::init_options(desc_cmd_sett);

  po::options_description desc_options("Allowed options");
  desc_options.add(desc_cmd_only).add(desc_cmd_sett);

  po::variables_map vm;
  bool r = command_line::handle_error_helper(desc_options, [&]()
  {
    po::store(po::parse_command_line(argc, argv, desc_options), vm);
    po::notify(vm);

    return true;
  });
  if (!r)
    return 1;

  if (command_line::get_arg(vm, command_line::arg_help))
  {
    std::cout << CRYPTONOTE_NAME << " v" << MONERO_VERSION_FULL << ENDL << ENDL;
    std::cout << desc_options << std::endl;
    return false;
  }

  bool testnet_mode = command_line::get_arg(vm, arg_testnet_on);

  auto data_dir_arg = testnet_mode ? command_line::arg_testnet_data_dir : command_line::arg_data_dir;

  std::string data_dir = command_line::get_arg(vm, data_dir_arg);
  tools::create_directories_if_necessary(data_dir);
  std::string config = command_line::get_arg(vm, arg_config_file);

  boost::filesystem::path data_dir_path(data_dir);
  boost::filesystem::path config_path(config);
  if (!config_path.has_parent_path())
  {
    config_path = data_dir_path / config_path;
  }

  boost::system::error_code ec;
  if (boost::filesystem::exists(config_path, ec))
  {
    po::store(po::parse_config_file<char>(config_path.string<std::string>().c_str(), desc_cmd_sett), vm);
  }

  //set up logging options
  boost::filesystem::path log_file_path(command_line::get_arg(vm, arg_log_file));
  if (log_file_path.empty())
    log_file_path = log_space::log_singletone::get_default_log_file();
  std::string log_dir;
  log_dir = log_file_path.has_parent_path() ? log_file_path.parent_path().string() : log_space::log_singletone::get_default_log_folder();

  log_space::log_singletone::add_logger(LOGGER_FILE, log_file_path.filename().string().c_str(), log_dir.c_str());
  LOG_PRINT_L0(CRYPTONOTE_NAME << " v" << MONERO_VERSION_FULL);

  if (command_line_preprocessor(vm))
  {
    return 0;
  }

  LOG_PRINT("Module folder: " << argv[0], LOG_LEVEL_0);

  bool res = true;
  cryptonote::checkpoints checkpoints;
  res = cryptonote::create_checkpoints(checkpoints);
  CHECK_AND_ASSERT_MES(res, 1, "Failed to initialize checkpoints");
  boost::filesystem::path json(JSON_HASH_FILE_NAME);
  boost::filesystem::path checkpoint_json_hashfile_fullpath = data_dir / json;

  //create objects and link them
  cryptonote::core ccore(NULL);

  // tell core if we're enforcing dns checkpoints
  bool enforce_dns = command_line::get_arg(vm, arg_dns_checkpoints);
  ccore.set_enforce_dns_checkpoints(enforce_dns);

  if (testnet_mode) {
    LOG_PRINT_L0("Starting in testnet mode!");
  } else {
    ccore.set_checkpoints(std::move(checkpoints));
    ccore.set_checkpoints_file_path(checkpoint_json_hashfile_fullpath.string());
  }

  cryptonote::t_cryptonote_protocol_handler<cryptonote::core> cprotocol(ccore, NULL);
  nodetool::node_server<cryptonote::t_cryptonote_protocol_handler<cryptonote::core> > p2psrv {
      cprotocol
    , testnet_mode ? std::move(config::testnet::NETWORK_ID) : std::move(config::NETWORK_ID)
    };

  cprotocol.set_p2p_endpoint(&p2psrv);
  ccore.set_cryptonote_protocol(&cprotocol);
  daemon_cmmands_handler dch(p2psrv, testnet_mode);

  //initialize objects
  LOG_PRINT_L0("Initializing P2P server...");
  res = p2psrv.init(vm, testnet_mode);
  CHECK_AND_ASSERT_MES(res, 1, "Failed to initialize P2P server.");
  LOG_PRINT_L0("P2P server initialized OK");

  LOG_PRINT_L0("Initializing protocol...");
  res = cprotocol.init(vm);
  CHECK_AND_ASSERT_MES(res, 1, "Failed to initialize protocol.");
  LOG_PRINT_L0("Protocol initialized OK");

  LOG_PRINT_L0("Initializing core RPC server...");
  RPC::init(&ccore, &p2psrv, testnet_mode);
  std::string ip_address, port;
  RPC::get_address_and_port(vm, ip_address, port);
  RPC::Json_rpc_http_server rpc_server(ip_address, port, &RPC::ev_handler);
  LOG_PRINT_GREEN("Core RPC server initialized on port: " << port, LOG_LEVEL_0);

  //initialize core here
  LOG_PRINT_L0("Initializing core...");
  res = ccore.init(vm, testnet_mode);
  CHECK_AND_ASSERT_MES(res, 1, "Failed to initialize core");
  LOG_PRINT_L0("Core initialized OK");
  
  // start components
  if(!command_line::has_arg(vm, arg_console))
  {
    dch.start_handling();
  }

  LOG_PRINT_L0("Starting core RPC server...");
  res = rpc_server.start();
  CHECK_AND_ASSERT_MES(res, 1, "Failed to start core RPC server.");
  LOG_PRINT_L0("Core RPC server started ok");

  tools::signal_handler::install([&dch, &p2psrv] {
    dch.stop_handling();
    p2psrv.send_stop_signal();
  });

  LOG_PRINT_L0("Starting P2P net loop...");
  p2psrv.run();
  LOG_PRINT_L0("P2P net loop stopped");

  //stop components
  LOG_PRINT_L0("Stopping core rpc server...");
  rpc_server.stop();

  //deinitialize components
  LOG_PRINT_L0("Deinitializing core...");
  ccore.deinit();
  LOG_PRINT_L0("Deinitializing protocol...");
  cprotocol.deinit();
  LOG_PRINT_L0("Deinitializing P2P...");
  p2psrv.deinit();


  ccore.set_cryptonote_protocol(NULL);
  cprotocol.set_p2p_endpoint(NULL);

  LOG_PRINT("Node stopped.", LOG_LEVEL_0);
  return 0;

  CATCH_ENTRY_L0("main", 1);
}

