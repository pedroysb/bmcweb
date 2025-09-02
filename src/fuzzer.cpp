#include "bmcweb_config.h"

#include "dbus_monitor.hpp"
#include "event_service_manager.hpp"
#include "hostname_monitor.hpp"
#include "http/app.hpp"
#include "http/http2_connection.hpp"
#include "http/http_body.hpp"
#include "http/test_stream.hpp"
#include "http/utility.hpp"
#include "logging.hpp"
#include "persistent_data.hpp"
#include "redfish.hpp"
#include "redfish_aggregator.hpp"
#include "user_monitor.hpp"
#include "watchdog.hpp"

// Route includes
#include "google_service_root.hpp"
#include "ibm_management_console_rest.hpp"
#include "image_upload.hpp"
#include "kvm_websocket.hpp"
#include "login_routes.hpp"
#include "obmc_console.hpp"
#include "openbmc_dbus_rest.hpp"
#include "vm_websocket.hpp"
#include "webassets.hpp"

#include <memory>
#include <string_view>

#include <boost/beast/_experimental/test/impl/stream.ipp>
#include <sdbusplus/asio/connection.hpp>
#include <sdbusplus/asio/object_server.hpp>
#include <sdbusplus/bus.hpp>

static void setLogLevel(const std::string& logLevel)
{
    const std::basic_string_view<char>* iter =
        std::ranges::find(crow::mapLogLevelFromName, logLevel);
    if (iter == crow::mapLogLevelFromName.end())
    {
        BMCWEB_LOG_ERROR("log-level {} not found", logLevel);
        return;
    }
    crow::getBmcwebCurrentLoggingLevel() = crow::getLogLevelFromName(logLevel);
    BMCWEB_LOG_INFO("Requested log-level change to: {}", logLevel);
}

// Use a static struct to hold the global state that we want to initialize
// only once.
struct FuzzGlobals
{
    boost::asio::io_context io;
    crow::App app;
    std::shared_ptr<sdbusplus::asio::connection> systemBus;

    FuzzGlobals()
    {
        // Mirror the initialization from webserver_run.cpp
        systemBus =
            std::make_shared<sdbusplus::asio::connection>(io);
        crow::connections::systemBus = systemBus.get();

        auto server = sdbusplus::asio::object_server(systemBus);

        std::shared_ptr<sdbusplus::asio::dbus_interface> iface =
            server.add_interface("/xyz/openbmc_project/bmcweb",
                                "xyz.openbmc_project.bmcweb");

        iface->register_method("SetLogLevel", setLogLevel);

        iface->initialize();

        // Load the peristent data
        persistent_data::getConfig();

        // Static assets need to be initialized before Authorization, because auth
        // needs to build the whitelist from the static routes

        if constexpr (BMCWEB_STATIC_HOSTING)
        {
            crow::webassets::requestRoutes(app);
        }

        if constexpr (BMCWEB_KVM)
        {
            crow::obmc_kvm::requestRoutes(app);
        }

        if constexpr (BMCWEB_REDFISH)
        {
            redfish::RedfishService::getInstance(app);

            // Create EventServiceManager instance and initialize Config
            redfish::EventServiceManager::getInstance();

            if constexpr (BMCWEB_REDFISH_AGGREGATION)
            {
                // Create RedfishAggregator instance and initialize Config
                redfish::RedfishAggregator::getInstance();
            }
        }

        if constexpr (BMCWEB_REST)
        {
            crow::dbus_monitor::requestRoutes(app);
            crow::image_upload::requestRoutes(app);
            crow::openbmc_mapper::requestRoutes(app);
        }

        if constexpr (BMCWEB_HOST_SERIAL_SOCKET)
        {
            crow::obmc_console::requestRoutes(app);
        }

        crow::obmc_vm::requestRoutes(app);

        if constexpr (BMCWEB_IBM_MANAGEMENT_CONSOLE)
        {
            crow::ibm_mc::requestRoutes(app);
        }

        if constexpr (BMCWEB_GOOGLE_API)
        {
            crow::google_api::requestRoutes(app);
        }

        crow::login_routes::requestRoutes(app);

        if constexpr (!BMCWEB_INSECURE_DISABLE_SSL)
        {
            BMCWEB_LOG_INFO("Start Hostname Monitor Service...");
            crow::hostname_monitor::registerHostnameSignal();
        }

        bmcweb::registerUserRemovedSignal();

        bmcweb::ServiceWatchdog watchdog;
        
        app.validate();

        systemBus->request_name("xyz.openbmc_project.bmcweb");
    }
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    // This will be initialized only once across all fuzzing runs.
    static FuzzGlobals globals;

    std::function<std::string()> getCachedDateStr = []() { return ""; };
    std::shared_ptr<persistent_data::UserSession> mtlsSession = nullptr;
    boost::asio::ssl::context sslContext{boost::asio::ssl::context::tlsv12};

    crow::TestStream testSocket(globals.io);
    boost::asio::ssl::stream<crow::TestStream> sslStream(
        std::move(testSocket), sslContext);

    auto conn =
        std::make_shared<crow::HTTP2Connection<crow::TestStream, crow::App>>(
            std::move(sslStream), &globals.app, getCachedDateStr,
            // Use plain HTTP mode to avoid all SSL complexities
            crow::HttpType::HTTP, mtlsSession);

    // Mimics the setup from HTTP2Connection::start()
    conn->streams[0];
    conn->sendServerConnectionHeader();

    // Directly inject fuzzer data.
    if (size > conn->inBuffer.size())
    {
        size = conn->inBuffer.size();
    }
    std::copy(data, data + size, conn->inBuffer.begin());
    // Directly call the data processing functions.
    conn->afterDoRead(conn, {}, size);

    // Poll for any simple posted handlers.
    globals.io.poll();
    globals.io.restart();

    return 0;
}