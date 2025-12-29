
#include "TLSContext.hpp"

using namespace hysburg;

TLSContextFactory *TLSContext::factory() {
    auto ctx = SSL_get_SSL_CTX(mSSL);
    auto self = SSL_CTX_get_app_data(ctx);
    return self ? static_cast<TLSContextFactory*>(self) : nullptr;
}
