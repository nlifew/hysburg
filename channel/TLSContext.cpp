
#include "TLSContext.hpp"
using namespace hysburg;

TLSContextPtr TLSContextFactory::newInstance(TLSMode mode) noexcept {
    return std::make_shared<TLSContext>(*this, mode);
}

