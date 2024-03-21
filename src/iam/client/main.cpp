#include <iostream>

#include <aos/iam/permhandler.hpp>

#include "iamclient.hpp"
#include "logger/logger.hpp"

int main(int argC, const char* const argV[])
{
    (void)argC;
    (void)argV;

    static Logger mLogger;

    mLogger.SetBackend(Logger::Backend::eStdIO);
    mLogger.SetLogLevel(aos::LogLevelEnum::eDebug);
    mLogger.Init();

    Config config;
    config.mCertStorage = "iam";
    config.mRemoteIAMs.push_back(RemoteIAM {"node-0", "10.0.0.100:80189", UtilsTime::ParseDuration("2s").mValue});
    config.mRemoteIAMs.push_back(RemoteIAM {"node0", "10.0.0.100:8089", UtilsTime::ParseDuration("2s").mValue});

    iam::RemoteIAMClient client;

    aos::iam::certhandler::CertHandler certHandler;
    aos::cryptoutils::CertLoader       certLoader;

    auto err = client.Init(config, certHandler, certLoader, false);
    if (!err.IsNone()) {
        std::cerr << __FILE__ << ":" << __LINE__ << " err = " << err.Message() << std::endl;
    }

    aos::StaticArray<aos::StaticString<aos::iam::certhandler::cCertTypeLen>, 10> certTypes;
    err = client.GetCertTypes("node0", certTypes);
    if (!err.IsNone()) {
        std::cerr << __FILE__ << ":" << __LINE__ << " file = " << err.FileName() << " , line = " << err.LineNumber()
                  << " ,err = " << err.Message() << std::endl;

        return EXIT_FAILURE;
    }

    for (const auto& certType : certTypes) {
        std::cout << "got cert type = " << certType.CStr() << std::endl;
    }

    return EXIT_SUCCESS;
}
