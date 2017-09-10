#include "ProbeRoute.hpp"

#include <errno.h>
using namespace std;


ProbeException::ProbeException(const string &message, ErrType type) throw() {
    if (type == SYS && errno)
        msg = message + ": " + strerror(errno);
    else
        msg = message;
}

ProbeException::ProbeException(const string &message, const string &detail) throw() :
    msg(message + ": " + detail) {
}

const char *ProbeException::what() const throw() {
    return msg.c_str();
}

