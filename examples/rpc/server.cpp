#include"service_consts.hpp"
#include<iostream>
#include"service/server.hpp"
using namespace fetch::service;
using namespace fetch::byte_array;




// First we make a service implementation
class Implementation {
public:
  int SlowFunction(int a, int b) {
    std::this_thread::sleep_for( std::chrono::milliseconds(20) );
    return a + b;
  }
  
  int Add(int a, int b) {
    return a + b;
  }
  
  std::string Greet(std::string name) {
    return "Hello, " + name;
  }      
};


// Next we make a protocol for the implementation
class ServiceProtocol : public Implementation, public Protocol {
public:
  
  ServiceProtocol() : Implementation(), Protocol() {
    
    this->Expose(SLOWFUNCTION, new CallableClassMember<Implementation, int(int, int)>(this, &Implementation::SlowFunction) );
    this->Expose(ADD, new CallableClassMember<Implementation, int(int, int)>(this, &Implementation::Add) );
    this->Expose(GREET, new CallableClassMember<Implementation, std::string(std::string)>(this, &Implementation::Greet) );
  }  
};


// And finanly we build the service
class MyCoolService : public ServiceServer< fetch::network::TCPServer > {
public:
  MyCoolService(uint16_t port, fetch::network::ThreadManager *tm) : ServiceServer(port, tm) {
    this->Add(MYPROTO, new ServiceProtocol() );
  }
};


int main() {
  fetch::network::ThreadManager tm(8);  
  MyCoolService serv(8080, &tm);
  tm.Start();

  std::string dummy;
  std::cout << "Press ENTER to quit" << std::endl;                                       
  std::cin >> dummy;
  
  tm.Stop();

  return 0;

}
