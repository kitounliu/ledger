#ifndef LIBFETCHCORE_BYTE_ARRAY_REFERENCED_BYTE_ARRAY_HPP
#define LIBFETCHCORE_BYTE_ARRAY_REFERENCED_BYTE_ARRAY_HPP
#include "byte_array/referenced_byte_array.hpp"

#include <pybind11/pybind11.h>
namespace fetch
{
namespace byte_array
{

void BuildByteArray(pybind11::module &module) {
  namespace py = pybind11;
  py::class_<ByteArray, fetch::byte_array::BasicByteArray>(module, "ByteArray" )
    .def(py::init<  >())
    .def(py::init< const char * >())
    .def(py::init< const std::string & >())
    .def(py::init< const fetch::byte_array::ByteArray & >())
    .def(py::init< std::initializer_list<container_type> >())
    .def(py::init< const fetch::byte_array::ByteArray &, const std::size_t &, const std::size_t & >())
    .def(py::init< const fetch::byte_array::ByteArray::super_type & >())
    .def(py::init< const fetch::byte_array::ByteArray::super_type &, const std::size_t &, const std::size_t & >())
    .def(py::self + fetch::byte_array::ByteArray() )
    .def("Resize", &ByteArray::Resize)
    .def("operator[]", ( fetch::byte_array::BasicByteArray::container_type & (ByteArray::*)(const std::size_t &) ) &ByteArray::operator[])
    .def("operator[]", ( const fetch::byte_array::BasicByteArray::container_type & (ByteArray::*)(const std::size_t &) const ) &ByteArray::operator[])
    .def("pointer", ( const fetch::byte_array::BasicByteArray::container_type * (ByteArray::*)() const ) &ByteArray::pointer)
    .def("pointer", ( fetch::byte_array::BasicByteArray::container_type * (ByteArray::*)() ) &ByteArray::pointer)
    .def("char_pointer", ( const char * (ByteArray::*)() const ) &ByteArray::char_pointer)
    .def("char_pointer", ( char * (ByteArray::*)() ) &ByteArray::char_pointer)
    .def("Reserve", &ByteArray::Reserve);

}
};
};

#endif