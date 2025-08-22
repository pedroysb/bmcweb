#include "http/app.hpp"
#include "http/http2_connection.hpp"
#include "http/test_stream.hpp"
#include "logging.hpp"
#include "persistent_data.hpp"

#include <fuzzer/FuzzedDataProvider.h>

#include <memory>
#include <string_view>

#include <boost/beast/_experimental/test/impl/stream.ipp>

// NOTE: Omitted load_server_certificate function. It is not needed.

struct MockHandler
{
    void handle(const std::shared_ptr<crow::Request>&,
                const std::shared_ptr<bmcweb::AsyncResp>&)
    {
    }
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    // --- Create a fresh environment for each fuzz input ---
    // This is the key fix: By making these local variables, we ensure
    // a clean state for every run, preventing any memory or state leaks
    // between fuzzing iterations.
    boost::asio::io_context io;
    MockHandler handler;
    std::function<std::string()> getCachedDateStr = []() { return ""; };
    std::shared_ptr<persistent_data::UserSession> mtlsSession = nullptr;
    boost::asio::ssl::context sslContext{boost::asio::ssl::context::tlsv12};

    crow::TestStream testSocket(io);
    boost::asio::ssl::stream<crow::TestStream> sslStream(
        std::move(testSocket), sslContext);

    auto conn =
        std::make_shared<crow::HTTP2Connection<crow::TestStream, MockHandler>>(
            std::move(sslStream), &handler, getCachedDateStr,
            // Use plain HTTP mode to avoid all SSL complexities
            crow::HttpType::HTTP, mtlsSession);

    // Initialize the internal state.
    conn->streams[0];
    conn->sendServerConnectionHeader();

    // Directly inject fuzzer data.
    if (size > conn->inBuffer.size())
    {
        size = conn->inBuffer.size();
    }
    std::copy(data, data + size, conn->inBuffer.begin());

    // Directly call the data processing function.
    conn->afterDoRead(conn, {}, size);

    // Poll for any simple posted handlers.
    io.poll();

    return 0;
}