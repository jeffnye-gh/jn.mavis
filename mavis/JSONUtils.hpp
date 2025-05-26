#pragma once

#include <fstream>
#include <string_view>

#ifdef USE_NLOHMANN_JSON
#include <nlohmann/json.hpp>
#else
#include <boost/json.hpp>
#endif
#include <boost/system/system_error.hpp>

namespace mavis
{

#ifdef USE_NLOHMANN_JSON
    using json_value = nlohmann::json;
#else
    using json_value = boost::json::value;
#endif

    // Parses the JSON file at the given path
    inline json_value parseJSON(const std::string& path)
    {
        std::ifstream fs;

#ifndef TARGET_OS_MAC
        std::ios_base::iostate exceptionMask = fs.exceptions() | std::ios::failbit;
        fs.exceptions(exceptionMask);
#endif

        fs.open(path);

#ifndef TARGET_OS_MAC
        exceptionMask &= ~std::ios::failbit;
        fs.exceptions(exceptionMask);
#endif

#ifdef USE_NLOHMANN_JSON
        try {
            json_value json;
            fs >> json;
            return json;
        } catch (const std::exception& ex) {
            throw std::runtime_error("Error parsing JSON " + path + ": " + ex.what());
        }
#else
        boost::system::error_code ec;

        try
        {
#if (BOOST_VERSION / 100 >= 1081)
            const boost::json::value json = boost::json::parse(fs, ec);
            if (json.is_null() || ec)
            {
                throw boost::system::system_error(ec);
            }
#else
            boost::json::stream_parser parser;
            std::string buf;
            while (std::getline(fs, buf))
            {
                parser.write(buf);
            }
            parser.finish(ec);

            if (ec)
            {
                throw boost::system::system_error(ec);
            }

            const boost::json::value json = parser.release();
#endif
            return json;
        }
        catch (const boost::system::system_error& ex)
        {
            throw boost::system::system_error(ex.code(), "Error parsing JSON " + path);
        }
#endif
    }

    template<typename OpenFailedExceptionType>
    inline json_value parseJSONWithException(const std::string& path)
    {
        try
        {
            return parseJSON(path);
        }
        catch (const std::ifstream::failure&)
        {
            throw OpenFailedExceptionType(path);
        }
    }

    struct JSONStringMapCompare : public std::less<std::string>
    {
        using is_transparent = void;
        using std::less<std::string>::operator();

#ifdef USE_NLOHMANN_JSON
        inline bool operator()(const nlohmann::json::string_t& lhs, const std::string& rhs) const
        {
            return std::string_view(lhs) < std::string_view(rhs);
        }
#else
        inline bool operator()(const boost::json::string& lhs, const std::string& rhs) const
        {
            return std::string_view(lhs) < std::string_view(rhs);
        }

        inline bool operator()(const std::string& lhs, const boost::json::string& rhs) const
        {
            return std::string_view(lhs) < std::string_view(rhs);
        }
#endif
    };

} // namespace mavis

