#pragma once

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

#include "DecoderExceptions.h"
#include <vector>
#include "InstMetaData.h"
#include "Extractor.h"

namespace mavis
{

class FormGeneric
{
public:
    typedef std::shared_ptr<FormGeneric> PtrType;
    static constexpr uint32_t INVALID_LIST_POS = -1;

private:
    typedef std::vector<std::string> OperandNameListType;
    typedef std::vector<std::string> SpecialFieldNameListType;

    struct OperandFormElement {
        InstMetaData::OperandFieldID    oid;
        InstMetaData::OperandTypes      otype;
    };
    typedef std::vector<OperandFormElement>     OperandFormList;

    class UnknownFieldID : public BaseException
    {
    public:
        UnknownFieldID(const std::string &otype, const std::string &field_name)
        {
            std::stringstream ss;
            ss << otype << " operand ID '" << field_name << "': "
               << "is not known to the decoder (InstMetaData ID lookup in FormGeneric object)";
            why_ = ss.str();
        }
    };

    class UnknownSpecialFieldID : public BaseException
    {
    public:
        UnknownSpecialFieldID(const std::string &field_name)
        {
            std::stringstream ss;
            ss << "Special field ID '" << field_name << "': "
               << "is not known to the decoder (ExtractorIF::SpecialFieldMap ID lookup in FormGeneric object)";
            why_ = ss.str();
        }
    };

    class UnsupportedOperandInfoID : public BaseException
    {
    public:
        UnsupportedOperandInfoID(const std::string &id_name, uint32_t pos)
        {
            std::stringstream ss;
            ss << "Unsupported OperandInfo element ID '" << id_name << "' at list position " << pos << ": "
               << "FormGeneric object expects OperandTypes::NONE";
            why_ = ss.str();
        }
    };

public:
    FormGeneric(const json& inst, const InstMetaData::PtrType& meta)
    {
        for (auto& i : spec_indices_) {
            i = INVALID_LIST_POS;
        }

        if (const auto it = inst.find("sources"); it != inst.end()) {
            OperandNameListType olist = JSON_CAST(JSON_IT_VAL(it), OperandNameListType);

            for (const auto& oname : olist) {
                InstMetaData::OperandFieldID fid = meta->getFieldID(oname);
                if (fid == InstMetaData::OperandFieldID::NONE) {
                    throw UnknownFieldID("Source", oname);
                }

                InstMetaData::OperandTypes otype = meta->getOperandType(fid);
                src_oper_list_.push_back({fid, otype});
            }
        }

        if (const auto it = inst.find("dests"); it != inst.end()) {
            OperandNameListType olist = JSON_CAST(JSON_IT_VAL(it), OperandNameListType);

            for (const auto& oname : olist) {
                InstMetaData::OperandFieldID fid = meta->getFieldID(oname);
                if (fid == InstMetaData::OperandFieldID::NONE) {
                    throw UnknownFieldID("Destination", oname);
                }

                InstMetaData::OperandTypes otype = meta->getOperandType(fid);
                dest_oper_list_.push_back({fid, otype});
            }
        }

        if (const auto it = inst.find("specials"); it != inst.end()) {
            SpecialFieldNameListType slist = JSON_CAST(JSON_IT_VAL(it), SpecialFieldNameListType);

            uint32_t pos = 0;
            for (const auto& sname : slist) {
                const auto itr = ExtractorIF::SpecialFieldMap.find(sname);
                if (itr == ExtractorIF::SpecialFieldMap.end()) {
                    throw UnknownSpecialFieldID(sname);
                } else {
                    spec_indices_[static_cast<std::underlying_type_t<ExtractorIF::SpecialField>>(itr->second)] = pos;
                }
                ++pos;
            }
        }
    }

    FormGeneric(const FormGeneric&) = default;

    OperandInfo fixupOISources(const OperandInfo& oi) const
    {
        return fixupOIList_(oi, src_oper_list_);
    }

    OperandInfo fixupOIDests(const OperandInfo& oi) const
    {
        return fixupOIList_(oi, dest_oper_list_);
    }

    uint32_t getSpecialFieldIndex(ExtractorIF::SpecialField sid) const
    {
        return spec_indices_[static_cast<std::underlying_type_t<ExtractorIF::SpecialField>>(sid)];
    }

private:
    OperandFormList    src_oper_list_;
    OperandFormList    dest_oper_list_;
    std::array<uint32_t, static_cast<std::underlying_type_t<ExtractorIF::SpecialField>>(ExtractorIF::SpecialField::__N)> spec_indices_;

    OperandInfo fixupOIList_(const OperandInfo& oi, const OperandFormList& flist) const
    {
        OperandInfo::ElementList oil = oi.getElements();
        auto flist_itr = flist.begin();
        for (auto& elem : oil) {
            if (flist_itr == flist.end()) {
                break;
            }
            if (elem.field_id == InstMetaData::OperandFieldID::NONE) {
                elem.field_id = flist_itr->oid;
                elem.operand_type = flist_itr->otype;
            }
            ++flist_itr;
        }
        return oil;
    }
};

} // namespace mavis
