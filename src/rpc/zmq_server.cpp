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

#include <chrono>

#include "zmq_server.h"
#include "rpc_constants.h"
#include "misc_log_ex.h"

namespace cryptonote
{

namespace rpc
{

ZmqServer::ZmqServer(RpcHandler& h) :
    handler(h),
    stop_signal(false),
    running(false),
    context(DEFAULT_NUM_ZMQ_THREADS) // TODO: make this configurable
{
  have_new_notify_message = false;

  handler.bindNotify(std::bind(&ZmqServer::notify, this, std::placeholders::_1, std::placeholders::_2));
}

ZmqServer::~ZmqServer()
{
}

void ZmqServer::serveRPC()
{

  while (1)
  {
    if (rep_socket)
    {
      try
      {
        zmq::message_t message;

        while (rep_socket->recv(&message))
        {
          std::string message_string(reinterpret_cast<const char *>(message.data()), message.size());

          MDEBUG(std::string("Received RPC request: \"") + message_string + "\"");

          std::string response = handler.handle(message_string);

          zmq::message_t reply(response.size());
          memcpy((void *) reply.data(), response.c_str(), response.size());

          rep_socket->send(reply);
          MDEBUG(std::string("Sent RPC reply: \"") + response + "\"");

        }
      }
      catch (boost::thread_interrupted& e)
      {
        MDEBUG("ZMQ Server thread interrupted.");
      }
    }
    boost::this_thread::interruption_point();
  }
}

void ZmqServer::serveNotify()
{
  const std::chrono::milliseconds wait_time(DEFAULT_RPC_RECV_TIMEOUT_MS);
  while (1)
  {
    std::unique_lock<std::mutex> lk(mutex_new_notify_message);

    if (cv_new_notify_message.wait_for(lk, wait_time, [&]{return have_new_notify_message;}))
    {

      publishNotification();

      have_new_notify_message = false;

      lk.unlock();
    }

    boost::this_thread::interruption_point();
  }
}

bool ZmqServer::addIPCSocket(std::string address, std::string port)
{
  MERROR("ZmqServer::addIPCSocket not yet implemented!");
  return false;
}

bool ZmqServer::addTCPSocket(std::string address, std::string port)
{
  // don't mess with sockets while running, sockets aren't
  // thread safe in zmq (though contexts are)
  if (running) return false;

  try
  {
    std::string addr_prefix("tcp://");

    rep_socket.reset(new zmq::socket_t(context, ZMQ_REP));

    rep_socket->setsockopt(ZMQ_RCVTIMEO, DEFAULT_RPC_RECV_TIMEOUT_MS);

    std::string bind_address = addr_prefix + address + std::string(":") + port;
    rep_socket->bind(bind_address.c_str());
  }
  catch (std::exception& e)
  {
    MERROR(std::string("Error creating ZMQ Socket: ") + e.what());
    return false;
  }
  return true;
}

bool ZmqServer::addNotifySocket(std::string address, std::string port)
{
  // don't mess with sockets while running, sockets aren't
  // thread safe in zmq (though contexts are)
  if (running) return false;

  try
  {
    std::string addr_prefix("tcp://");

    pub_socket.reset(new zmq::socket_t(context, ZMQ_PUB));

    std::string bind_address = addr_prefix + address + std::string(":") + port;
    pub_socket->bind(bind_address.c_str());
  }
  catch (std::exception& e)
  {
    MERROR(std::string("Error creating ZMQ Socket: ") + e.what());
    return false;
  }
  return true;
}

void ZmqServer::run()
{
  running = true;
  rpc_thread = boost::thread(boost::bind(&ZmqServer::serveRPC, this));
  notify_thread = boost::thread(boost::bind(&ZmqServer::serveNotify, this));
}

void ZmqServer::stop()
{
  if (!running) return;

  stop_signal = true;

  rpc_thread.interrupt();
  notify_thread.interrupt();
  rpc_thread.join();
  notify_thread.join();

  running = false;

  return;
}

void ZmqServer::notify(const std::string& notify_context_in, const std::string& notify_message_in)
{
  {
    std::lock_guard<std::mutex> lk(mutex_new_notify_message);

    notify_message = notify_message_in;
    notify_context = notify_context_in;
    have_new_notify_message = true;
  }
  cv_new_notify_message.notify_one();
}

void ZmqServer::publishNotification()
{
  if (pub_socket)
  {
    std::string to_send = notify_context + " " + notify_message;
    zmq::message_t notification(to_send.size());
    memcpy((void *) notification.data(), to_send.c_str(), to_send.size());

    pub_socket->send(notification);
    MDEBUG(std::string("Sent Notification: \"") + to_send + "\"");
  }
}


}  // namespace cryptonote

}  // namespace rpc
