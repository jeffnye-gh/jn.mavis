#ifndef DABBLE_UARCHINFO_HPP
#define DABBLE_UARCHINFO_HPP

#include "mavis/JsonMacros.hpp"

#ifdef USE_NLOHMANN_JSON
  #include <nlohmann/json.hpp>
  using json = nlohmann::json;
  using json_value = nlohmann::json;
  using json_object = nlohmann::json;
#else
  #include <boost/json.hpp>
  using json = boost::json::object;
  using json_value = boost::json::value;
  using json_object = boost::json::object;
#endif

#include <ostream>
#include <string>
#include <memory>
#include "mavis/DecoderTypes.h"
#include "mavis/DecoderExceptions.h"
#include "mavis/JSONUtils.hpp"
#include "uArchInfoExceptions.hpp"

class uArchInfo
{
public:
    typedef std::shared_ptr<uArchInfo> PtrType;

    enum class UnitSet : uint64_t {
        AGU      = 1ull << 0,
        INT      = 1ull << 1,
        FLOAT    = 1ull << 2,
        MULTIPLY = 1ull << 3,
        DIVIDE   = 1ull << 4,
        BRANCH   = 1ull << 5,
        LOAD     = 1ull << 6,
        STORE    = 1ull << 7,
        SYSTEM   = 1ull << 8,
        VECTOR   = 1ull << 9,
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
        {"agu",    UnitSet::AGU     },
        {"int",    UnitSet::INT     },
        {"float",  UnitSet::FLOAT   },
        {"mul",    UnitSet::MULTIPLY},
        {"div",    UnitSet::DIVIDE  },
        {"branch", UnitSet::BRANCH  },
        {"load",   UnitSet::LOAD    },
        {"store",  UnitSet::STORE   },
        {"system", UnitSet::SYSTEM  },
        {"vector", UnitSet::VECTOR  },
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
    explicit uArchInfo(const json_object & jobj) { parse_(jobj); }

    uArchInfo() = default;
    uArchInfo(const uArchInfo &) = delete;

    void update(const json_object & jobj) { parse_(jobj); }

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

private:
    friend std::ostream & operator<<(std::ostream & os, const uArchInfo & ui);

    void print(std::ostream & os) const
    {
        os << "{units: 0x" << std::hex << units_ << ", lat: " << std::dec << latency_
           << ", piped: " << pipelined_ << ", serialize: " << serialize_
           << ", ROB group begin: " << rob_grp_start_ << ", ROB group end: " << rob_grp_end_ << "}";
    }

    void parse_(const json_object & jobj)
    {
        if (jobj.find("issue") != jobj.end()) {
            const auto& issue_str = JSON_CAST(jobj.at("issue"), std::string);
            const auto itr = issue_target_map_.find(issue_str);
            if (itr == issue_target_map_.end()) {
                throw uArchInfoUnknownIssueTarget(JSON_CAST(jobj.at("mnemonic"), std::string), issue_str);
            }
            issue_target_ = itr->second;
        }

        if (jobj.find("unit") != jobj.end()) {
            mavis::UnitNameListType ulist = JSON_CAST(jobj.at("unit"), mavis::UnitNameListType);
            for (const auto & u : ulist) {
                const auto itr = umap_.find(u);
                if (itr == umap_.end()) {
                    throw uArchInfoUnknownUnit(JSON_CAST(jobj.at("mnemonic"), std::string), u);
                }
                units_ |= static_cast<uint64_t>(itr->second);
            }
        }

        if (const auto it = jobj.find("latency"); it != jobj.end()) {
            latency_ = JSON_CAST(JSON_IT_VAL(it), uint32_t);
        }

        if (const auto it = jobj.find("pipelined"); it != jobj.end()) {
            pipelined_ = JSON_IT_VAL(it).template get<bool>();
        }

        if (const auto it = jobj.find("serialize"); it != jobj.end()) {
            serialize_ = JSON_IT_VAL(it).template get<bool>();
        }

        if (const auto it = jobj.find("rob_group"); it != jobj.end()) {
            mavis::StringListType slist = JSON_CAST(JSON_IT_VAL(it), mavis::StringListType);
            for (const auto & str : slist) {
                if (str == "begin") {
                    rob_grp_start_ = true;
                } else if (str == "end") {
                    rob_grp_end_ = true;
                } else {
                    throw uArchInfoROBGroupParseError(JSON_CAST(jobj.at("mnemonic"), std::string), str);
                }
            }
        }
    }
};

inline std::ostream & operator<<(std::ostream & os, const uArchInfo & ui)
{
    ui.print(os);
    return os;
}

#endif // DABBLE_UARCHINFO_HPP
