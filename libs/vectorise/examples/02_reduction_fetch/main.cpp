#include "vectorise/memory/shared_array.hpp"
#include <chrono>
#include <cmath>
#include <iostream>
#include <vector>

using type        = float;
using array_type  = fetch::memory::SharedArray<type>;
using vector_type = typename array_type::vector_register_type;

type Reduction(array_type const &A)
{
  type ret = 0;

  ret = A.in_parallel().Reduce([](vector_type const &a, vector_type const &b) { return a + b; });

  return ret;
}

int main(int argc, char const **argv)
{
  if (argc != 2)
  {
    std::cout << std::endl;
    std::cout << "Usage: " << argv[0] << " [array size] " << std::endl;
    std::cout << std::endl;
    return 0;
  }

  std::size_t N = std::size_t(atoi(argv[1]));

  array_type A(N);

  for (std::size_t i = 0; i < N; ++i)
  {
    A[i] = type(std::exp(-0.1 * type(i)));
  }

  std::chrono::high_resolution_clock::time_point t1  = std::chrono::high_resolution_clock::now();
  type                                           ret = Reduction(A);
  std::chrono::high_resolution_clock::time_point t2  = std::chrono::high_resolution_clock::now();
  double time_span = std::chrono::duration_cast<std::chrono::duration<double>>(t2 - t1).count();
  std::cout << time_span << " s to get " << ret << std::endl;

  return 0;
}