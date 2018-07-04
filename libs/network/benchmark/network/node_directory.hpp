#ifndef NODE_DIRECTORY_HPP
#define NODE_DIRECTORY_HPP

// This file holds and manages connections to other nodes

#include "core/logger.hpp"
#include "network/service/client.hpp"
#include "network/service/server.hpp"
#include "ledger/chain/transaction.hpp"
#include "./protocols/fetch_protocols.hpp"
#include "./protocols/network_benchmark/commands.hpp" // TODO: (`HUT`) : delete this
#include "./protocols/network_mine_test/commands.hpp"
#include "./network_classes.hpp"
#include "../tests/include/helper_functions.hpp"

#include "core/byte_array/referenced_byte_array.hpp"

#include <set>
#include <utility>

namespace fetch
{
namespace network_benchmark
{

class NodeDirectory
{
public:

  using clientType = service::ServiceClient<network::TCPClient>;

  NodeDirectory(network::ThreadManager tm) :
  tm_{tm}
  {}

  NodeDirectory(NodeDirectory &rhs)            = delete;
  NodeDirectory(NodeDirectory &&rhs)           = delete;
  NodeDirectory operator=(NodeDirectory& rhs)  = delete;
  NodeDirectory operator=(NodeDirectory&& rhs) = delete;

  ~NodeDirectory()
  {
    for(auto &i : serviceClients_)
    {
      delete i.second;
    }
  }

  // Only call this during node setup (not thread safe)
  void AddEndpoint(const Endpoint &endpoint)
  {
    LOG_STACK_TRACE_POINT;
    if (serviceClients_.find(endpoint) == serviceClients_.end())
    {
      auto client = new clientType {endpoint.IP(), endpoint.TCPPort(), tm_};
      serviceClients_[endpoint] = client;
    }
  }


  // push blocks to the rest of the network 
  template <typename T>
  void PushBlock(T block)
  {
    LOG_STACK_TRACE_POINT;

    for(auto &i : serviceClients_)
    {
      auto client = i.second;

      if(!client->is_alive())
      {
        std::cerr << "Client has died (pushing)!\n\n" << std::endl;
        fetch::logger.Error("Client has died in node direc");
      }

      client->Call(protocols::FetchProtocols::NETWORK_MINE_TEST,
          protocols::NetworkMineTest::PUSH_NEW_HEADER, block);
    }
  }

  template <typename H, typename T>
  bool GetHeader(H hash, T &block)
  {
    LOG_STACK_TRACE_POINT;

    for(auto &i : serviceClients_)
    {
      auto client = i.second;

      if(!client->is_alive())
      {
        std::cerr << "Client has died (pulling)!\n\n" << std::endl;
        fetch::logger.Error("Client has died in node direc");
      }

      std::pair<bool, T> result = client->Call(protocols::FetchProtocols::NETWORK_MINE_TEST,
          protocols::NetworkMineTest::PROVIDE_HEADER, hash);

      if(result.first)
      {

        {
          result.second.UpdateDigest();
          std::cout << "remote0.hash      " << ToHex(result.second.hash()) << std::endl;
          std::cout << "remote0.prev hash " << ToHex(result.second.body().previous_hash) << std::endl;
          std::cout << "remote0.Block number " << result.second.body().block_number << std::endl;
        }

        block = result.second;
        return true;
      }
    }

    return false;
  }

  // temporarily replicate invite functionality for easier debugging
  void InviteAllForw(block_hash const &blockHash, block_type &block)
  {
    LOG_STACK_TRACE_POINT;

    for(auto &i : serviceClients_)
    {
      auto client = i.second;

      if(!client->is_alive())
      {
        std::cerr << "Client has died (forw)!\n\n" << std::endl;
      }

      bool clientWants = client->Call(protocols::FetchProtocols::NETWORK_BENCHMARK,
          protocols::NetworkBenchmark::INVITE_PUSH, blockHash);

      if(clientWants)
      {
        fetch::logger.Info("Client wants forwarded push");
        client->Call(protocols::FetchProtocols::NETWORK_BENCHMARK,
          protocols::NetworkBenchmark::PUSH, blockHash, block);
      }
    }
  }

  void InviteAllDirect(block_hash const &blockHash, block_type const &block)
  {
    LOG_STACK_TRACE_POINT;

    for(auto &i : serviceClients_)
    {
      auto client = i.second;

      if(!client->is_alive())
      {
        std::cerr << "Client has died!\n\n" << std::endl;
        exit(1);
      }

      client->Call(protocols::FetchProtocols::NETWORK_BENCHMARK,
        protocols::NetworkBenchmark::PUSH_CONFIDENT, blockHash, block);
    }
  }

  void InviteAllBlocking(block_hash const &blockHash, block_type const &block)
  {
    LOG_STACK_TRACE_POINT;

    for(auto &i : serviceClients_)
    {
      auto client = i.second;

      if(!client->is_alive())
      {
        std::cerr << "Client has died!\n\n" << std::endl;
        exit(1);
      }

      auto p1 = client->Call(protocols::FetchProtocols::NETWORK_BENCHMARK,
        protocols::NetworkBenchmark::PUSH_CONFIDENT, blockHash, block);
      p1.Wait();
    }
  }

  void ControlSlaves()
  {
    LOG_STACK_TRACE_POINT;

    for(auto &i : serviceClients_)
    {
      auto client = i.second;

      if(!client->is_alive())
      {
        std::cerr << "Client to slave has died!\n\n" << std::endl;
        exit(1);
      }

      while(client->Call(protocols::FetchProtocols::NETWORK_BENCHMARK,
        protocols::NetworkBenchmark::SEND_NEXT).As<bool>()) {}
    }
  }

  void Reset()
  {
    for(auto &i : serviceClients_)
    {
      delete i.second;
    }
    serviceClients_.clear();
  }

private:
  fetch::network::ThreadManager            tm_;
  std::map<Endpoint, clientType *>         serviceClients_;
};

}
}
#endif
