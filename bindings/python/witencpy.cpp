#include <pybind11/operators.h>
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include "../../src/witenc.hpp"

namespace py = pybind11;

using namespace witenc;


PYBIND11_MODULE(witencpy, m)
{
    py::class_<CipherText>(m, "CipherText")
        .def_readwrite("c1", &CipherText::c1)
        .def_readwrite("c2", &CipherText::c2)
        .def_readwrite("c3", &CipherText::c3)

        .def(py::init([](){
            py::gil_scoped_release release;
            return CipherText();
        }))

        .def("to_hex", [](const CipherText &ct) {
            py::gil_scoped_release release;
            return ct.ToHexStr();
        })

        .def_static("from_hex", [](const std::string &s) {
            py::gil_scoped_release release;

            return CipherText::FromHexStr(s);
        })

        .def("validate", [](const CipherText &ct) {
            py::gil_scoped_release release;
            return ct.Validate();
        })

        .def("__eq__", [](const CipherText &ct1, const CipherText &ct2) {
            py::gil_scoped_release release;
            return ct1 == ct2;
        })

        .def("__bytes__", [](const CipherText &ct) {
            vector<uint8_t> out;
            {
                py::gil_scoped_release release;
                out = ct.Serialize();
            }
            py::bytes ans = py::bytes(
                reinterpret_cast<const char *>(out.data()), out.size());
            return ans;
        })

        .def("from_bytes", [](py::buffer const b) {
            py::buffer_info info = b.request();
            if (info.format != py::format_descriptor<uint8_t>::format() ||
                info.ndim != 1)
                throw std::runtime_error("Incompatible buffer format!");

            auto data_ptr = static_cast<uint8_t *>(info.ptr);
            std::vector<uint8_t> data;
            std::copy(data_ptr, data_ptr + info.size, std::back_inserter(data));
            py::gil_scoped_release release;
            return CipherText::Deserialize(data);
        });

    py::class_<Scheme>(m, "Scheme")
        .def_static("encrypt", [](const py::bytes& pk_bytes, const py::bytes& tag0, const py::bytes& msg0) {
            py::gil_scoped_release release;

            std::string pk_str(pk_bytes);
            std::string msg_str(msg0);
            std::string tag_str(tag0);

            vector<uint8_t> msg(msg_str.begin(), msg_str.end());
            vector<uint8_t> tag(tag_str.begin(), tag_str.end());
            G1Element pk = G1Element::FromByteVector(vector<uint8_t>(pk_str.begin(), pk_str.end()));

            return Scheme::Encrypt(pk, tag, msg);
        })
        
        .def_static("decrypt", [](const py::bytes& sig_bytes, const CipherText& ct) {
            py::gil_scoped_release release;
            
            std::string sig_str(sig_bytes);
            G2Element sig = G2Element::FromByteVector(vector<uint8_t>(sig_str.begin(), sig_str.end()));
            
            return Scheme::Decrypt(sig, ct);
        });

    py::class_<OTP>(m, "OTP")
        .def_static("encrypt", [](const py::bytes& key0, const py::bytes& msg0) {
            py::gil_scoped_release release;

            std::string msg_str(msg0);
            std::string key_str(key0);
            vector<uint8_t> msg(msg_str.begin(), msg_str.end());
            vector<uint8_t> key(key_str.begin(), key_str.end());

            return OTP::Encrypt(key, msg);
        })
        
        .def_static("decrypt", [](const py::bytes& key0, const py::bytes& ct0) {
            py::gil_scoped_release release;

            std::string ct_str(ct0);
            std::string key_str(key0);
            vector<uint8_t> ct(ct_str.begin(), ct_str.end());
            vector<uint8_t> key(key_str.begin(), key_str.end());

            return OTP::Decrypt(key, ct);
        });

#ifdef VERSION_INFO
    m.attr("__version__") = VERSION_INFO;
#else
    m.attr("__version__") = "dev";
#endif
}
