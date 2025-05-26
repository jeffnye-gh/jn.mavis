#pragma once

#include <map>
#include <set>
#include <fstream>
#include <algorithm>
#include <cctype>
#include <iostream>

#include "JSONUtils.hpp"
#include "DecoderTypes.h"
#include "Extractor.h"
#include "DecoderExceptions.h"

#include "mavis/JsonMacros.hpp"
#ifdef USE_NLOHMANN_JSON
#include <nlohmann/json.hpp>
  using json_value = nlohmann::json;
  using json_object = nlohmann::json;
#else
#include <boost/json.hpp>
  using json_value = boost::json::value;
  using json_object = boost::json::object;
#endif

namespace mavis {

template<typename AnnotationType, typename AnnotationTypeAllocator>
class AnnotationRegistry
{
public:
    typedef std::shared_ptr<AnnotationRegistry> PtrType;

    explicit AnnotationRegistry(const FileNameListType &anno_files,
                                AnnotationTypeAllocator & annotation_allocator,
                                const AnnotationOverrides & anno_overrides)
        : anno_file_list_(anno_files),
          not_found_(nullptr)
    {
        for (const auto &afile : anno_file_list_) {
            if (afile.empty()) continue;

            json_value json;
            try {
                json = parseJSON(afile);
            } catch (const std::ifstream::failure &) {
                throw BadAnnotationFile(afile);
            } catch (const std::exception &ex) {
                std::cerr << __FUNCTION__ << ": ERROR parsing '" << afile << "': " << ex.what() << std::endl;
                throw;
            }

            #ifdef USE_NLOHMANN_JSON
            auto &jobj = json;
            #else
            auto &jobj = json.as_array();
            #endif

            std::map<std::string, json_object> jobj_annotations;
            for (const auto &ann : anno_overrides) {
                const std::string mnemonic  = string_ws_trim(ann.first);
                const std::string attribute = string_ws_trim(ann.second);
                if (attribute.find(':') == std::string::npos) {
                    std::cerr << __FUNCTION__ << ": ERROR: Bad annotation override format: " << attribute
                              << " (expected name:value)" << std::endl;
                    throw;
                }
                const std::string attr_name  = string_ws_trim(attribute.substr(0, attribute.find(':')));
                const std::string attr_value = string_ws_trim(attribute.substr(attribute.find(':') + 1));
                if (attr_name.empty() || attr_value.empty()) {
                    std::cerr << __FUNCTION__ << ": ERROR: Bad annotation override format: " << attribute
                              << " (expected name:value)" << std::endl;
                    throw;
                }
                #ifdef USE_NLOHMANN_JSON
                jobj_annotations[mnemonic][attr_name] = nlohmann::json::parse(attr_value);
                #else
                jobj_annotations[mnemonic][attr_name] = boost::json::parse(attr_value);
                #endif
            }

            std::set<std::string> processed;

            for (auto &inst_value : jobj)
            {
                #ifdef USE_NLOHMANN_JSON
                auto &inst = inst_value;
                const std::string mnemonic = inst["mnemonic"].get<std::string>();
                #else
                auto &inst = inst_value.as_object();
                const std::string mnemonic = boost::json::value_to<std::string>(inst["mnemonic"]);
                #endif
                if (const auto it = jobj_annotations.find(mnemonic); it != jobj_annotations.end()) {
                    #ifdef USE_NLOHMANN_JSON
                    for (auto item = it->second.begin(); item != it->second.end(); ++item) {
                        inst[JSON_IT_KEY(item)] = JSON_IT_VAL(item);
                    }
                    #else
                    for (const auto &item : it->second) {
                        inst.insert_or_assign(item.key(), item.value());
                    }
                    #endif
                }

                const typename AnnotationType::PtrType &anno = privateFindAnnotation_(mnemonic);
                if (anno == not_found_) {
                    typename AnnotationType::PtrType new_anno = annotation_allocator(inst);
                    registry_[mnemonic] = new_anno;
                } else if (processed.find(mnemonic) == processed.end()) {
                    anno->update(inst);
                } else {
                    throw AnnotationNotUniqueInFile(mnemonic, afile);
                }
                processed.insert(mnemonic);
            }
        }
    }

    const typename AnnotationType::PtrType &findAnnotation(const std::string &mnemonic,
                                                           bool suppress_exception = false) const
    {
        const typename AnnotationType::PtrType &anno = privateFindAnnotation_(mnemonic);
        if (anno == not_found_) {
            if (anno_file_list_.empty() || suppress_exception) {
                return not_found_;
            }
            return not_found_;
        } else {
            return anno;
        }
    }

    bool isVacant() const
    {
        return registry_.empty();
    }

    bool isPopulated() const
    {
        return !isVacant();
    }

private:
    const FileNameListType anno_file_list_;
    std::map<std::string, typename AnnotationType::PtrType> registry_;
    const typename AnnotationType::PtrType not_found_;

    const typename AnnotationType::PtrType &privateFindAnnotation_(const std::string &mnemonic) const
    {
        const auto elem = registry_.find(mnemonic);
        if (elem == registry_.end()) {
            return not_found_;
        } else {
            return elem->second;
        }
    }

    inline std::string string_ws_trim(std::string s) {
        s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](unsigned char ch) {
            return !std::isspace(ch);
        }));
        s.erase(std::find_if(s.rbegin(), s.rend(), [](unsigned char ch) {
            return !std::isspace(ch);
        }).base(), s.end());
        return s;
    }
};

} // namespace mavis

