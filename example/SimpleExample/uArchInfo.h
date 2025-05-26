#pragma once

#include <ostream>
#include <string>
#include <memory>
#include <map>
#include <iostream>

#ifdef USE_NLOHMANN_JSON
    #include <nlohmann/json.hpp>
    namespace json = nlohmann;
#else
    #include <boost/json.hpp>
    namespace json = boost::json;
#endif

#include "mavis/DecoderTypes.h"
#include "mavis/DecoderExceptions.h"
#include "mavis/JSONUtils.hpp"
#include "uArchInfoExceptions.hpp"

class uArchInfo
{
public:
    typedef std::shared_ptr<uArchInfo> PtrType;

    enum class UnitSet : uint64_t {
        AGU     = 1ull << 0,
        INT     = 1ull << 1,
        FLOAT   = 1ull << 2,
        MULTIPLY= 1ull << 3,
        DIVIDE  = 1ull << 4,
        BRANCH  = 1ull << 5,
        LOAD    = 1ull << 6,
        STORE   = 1ull << 7,
        SYSTEM  = 1ull << 8,
        VECTOR  = 1ull << 9,
    };

    enum RegFile {
        INTEGER,
        FLOAT,
        INVALID,
        N_REGFILES = INVALID
    };

    static inline const char* const regfile_names[] = {"integer", "float"};

    enum IssueTarget : std::uint16_t {
        IEX,
        FEX,
        BR,
        LSU,
        ROB,
        N_ISSUE_TARGETS
    };

    static constexpr uint32_t MAX_ARCH_REGS = 5;

private:
    static inline std::map<std::string, UnitSet> umap_ = {
        {"agu",    UnitSet::AGU},
        {"int",    UnitSet::INT},
        {"float",  UnitSet::FLOAT},
        {"mul",    UnitSet::MULTIPLY},
        {"div",    UnitSet::DIVIDE},
        {"branch", UnitSet::BRANCH},
        {"load",   UnitSet::LOAD},
        {"store",  UnitSet::STORE},
        {"system", UnitSet::SYSTEM},
        {"vector", UnitSet::VECTOR},
    };

    static inline std::map<std::string, IssueTarget, mavis::JSONStringMapCompare> issue_target_map_ = {
        {"int",    IssueTarget::IEX},
        {"float",  IssueTarget::FEX},
        {"branch", IssueTarget::BR },
        {"load",   IssueTarget::LSU},
        {"store",  IssueTarget::LSU},
        {"system", IssueTarget::ROB},
        {"vector", IssueTarget::FEX},
        {"rob",    IssueTarget::ROB},
    };

public:
    explicit uArchInfo(const json::object_t & jobj) { parse_(jobj); }

    uArchInfo() = default;
    uArchInfo(const uArchInfo &) = delete;

    void update(const json::object_t & jobj) { parse_(jobj); }

    bool isUnit(UnitSet u) const { return (static_cast<uint64_t>(u) & units_) != 0; }

    IssueTarget getIssueTarget() const { return issue_target_; }

    uint32_t getLatency() const { return latency_; }

    bool isPipelined() const { return pipelined_; }

    bool isSerialized() const { return serialize_; }

    bool isROBGrpStart() const { return rob_grp_start_; }

    bool isROBGrpEnd() const { return rob_grp_end_; }

private:
    uint64_t units_ = 0;
    IssueTarget issue_target_ = IssueTarget::N_ISSUE_TARGETS;
    uint32_t latency_ = 0;
    bool pipelined_ = true;
    bool serialize_ = false;
    bool rob_grp_start_ = false;
    bool rob_grp_end_ = false;

    friend std::ostream & operator<<(std::ostream & os, const uArchInfo & ui);

    void print(std::ostream & os) const {
        os << "{units: 0x" << std::hex << units_
           << ", lat: " << std::dec << latency_
           << ", piped: " << pipelined_
           << ", serialize: " << serialize_
           << ", ROB group begin: " << rob_grp_start_
           << ", ROB group end: " << rob_grp_end_ << "}";
    }

    void parse_(const json::object_t & jobj)
    {
        if (auto iss_it = jobj.find("issue"); iss_it != jobj.end()) {
#ifdef USE_NLOHMANN_JSON
            std::string mnemonic = jobj.at("mnemonic").get<std::string>();
            std::string value = iss_it->second.get<std::string>();
#else
            std::string mnemonic = json::value_to<std::string>(jobj.at("mnemonic"));
            std::string value = json::value_to<std::string>(iss_it->value());
#endif
            const auto itr = issue_target_map_.find(value);
            if (itr == issue_target_map_.end()) {
                throw uArchInfoUnknownIssueTarget(mnemonic, value);
            }
            issue_target_ = itr->second;
        }

        if (auto unit_it = jobj.find("unit"); unit_it != jobj.end()) {
#ifdef USE_NLOHMANN_JSON
            for (const auto& u : unit_it->second) {
                const std::string unit = u.get<std::string>();
#else
            mavis::UnitNameListType ulist = json::value_to<mavis::UnitNameListType>(unit_it->value());
            for (const auto& unit : ulist) {
#endif
                const auto itr = umap_.find(unit);
                if (itr == umap_.end()) {
#ifdef USE_NLOHMANN_JSON
                    throw uArchInfoUnknownUnit(jobj.at("mnemonic").get<std::string>(), unit);
#else
                    throw uArchInfoUnknownUnit(json::value_to<std::string>(jobj.at("mnemonic")), unit);
#endif
                }
                units_ |= static_cast<uint64_t>(itr->second);
            }
        }

        if (auto it = jobj.find("latency"); it != jobj.end()) {
#ifdef USE_NLOHMANN_JSON
            latency_ = it->second.get<uint32_t>();
#else
            latency_ = json::value_to<uint32_t>(it->value());
#endif
        }

        if (auto it = jobj.find("pipelined"); it != jobj.end()) {
#ifdef USE_NLOHMANN_JSON
            pipelined_ = it->second.get<bool>();
#else
            pipelined_ = it->value().as_bool();
#endif
        }

        if (auto it = jobj.find("serialize"); it != jobj.end()) {
#ifdef USE_NLOHMANN_JSON
            serialize_ = it->second.get<bool>();
#else
            serialize_ = it->value().as_bool();
#endif
        }

        if (auto it = jobj.find("rob_group"); it != jobj.end()) {
#ifdef USE_NLOHMANN_JSON
            for (const auto& s : it->second) {
                std::string str = s.get<std::string>();
#else
            mavis::StringListType slist = json::value_to<mavis::StringListType>(it->value());
            for (const auto& str : slist) {
#endif
                if (str == "begin") rob_grp_start_ = true;
                else if (str == "end") rob_grp_end_ = true;
                else {
#ifdef USE_NLOHMANN_JSON
                    throw uArchInfoROBGroupParseError(jobj.at("mnemonic").get<std::string>(), str);
#else
                    throw uArchInfoROBGroupParseError(json::value_to<std::string>(jobj.at("mnemonic")), str);
#endif
                }
            }
        }

#ifdef USE_NLOHMANN_JSON
        std::cout << "uArchInfo: " << jobj.at("mnemonic").get<std::string>() << std::endl;
#else
        std::cout << "uArchInfo: " << jobj.at("mnemonic").as_string() << std::endl;
#endif
    }
};

inline std::ostream & operator<<(std::ostream & os, const uArchInfo & ui) {
    ui.print(os);
    return os;
}

