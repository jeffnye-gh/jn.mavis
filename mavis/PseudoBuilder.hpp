#pragma once

#include <map>
#include <fstream>

#ifdef USE_NLOHMANN_JSON
#include <nlohmann/json.hpp>
using json_value = nlohmann::json;
using json_object = nlohmann::json;
#else
#include <boost/json.hpp>
using json_value = boost::json::value;
using json_object = boost::json::object;
#endif

#include "JSONUtils.hpp"
#include "BuilderBase.hpp"
#include "Extractor.h"
#include "IFactoryPseudo.hpp"
#include "FormGeneric.hpp"

namespace mavis {

template<typename InstType, typename AnnotationType, typename AnnotationTypeAllocator>
class PseudoBuilder : public FactoryBuilderBase<IFactoryPseudo<InstType,AnnotationType>, InstType, AnnotationType, AnnotationTypeAllocator>
{
public:
    typedef std::shared_ptr<PseudoBuilder<InstType,AnnotationType,AnnotationTypeAllocator>> PtrType;

private:
    typedef IFactoryPseudo<InstType, AnnotationType> FactoryType;
    using FactoryBuilderBase<FactoryType, InstType, AnnotationType, AnnotationTypeAllocator>::registry_;

public:
    explicit PseudoBuilder(const FileNameListType& anno_files,
                           AnnotationTypeAllocator & annotation_allocator,
                           const InstUIDList& uid_list = {}) :
        FactoryBuilderBase<FactoryType,InstType,AnnotationType,AnnotationTypeAllocator>(anno_files, annotation_allocator, uid_list)
    {}

    PseudoBuilder(const PseudoBuilder&) = delete;

    void configure(const FileNameListType &isa_files)
    {
        for (const auto &jfile : isa_files) {
            const json_value json = parseJSONWithException<BadISAFile>(jfile);
#ifdef USE_NLOHMANN_JSON
            const auto& jobj = json;
#else
            const auto& jobj = json.as_array();
#endif
            for (const auto &inst_value : jobj) {
#ifdef USE_NLOHMANN_JSON
                const auto& inst = inst_value;
                if (inst.contains("pseudo")) {
                    std::string mnemonic = inst["pseudo"].get<std::string>();
#else
                const auto& inst = inst_value.as_object();
                if (const auto it = inst.find("pseudo"); it != inst.end()) {
                    std::string mnemonic = boost::json::value_to<std::string>(it->value());
#endif
                    InstMetaData::PtrType meta = this->makeInstMetaData(mnemonic, inst);
                    Disassembler::PtrType dasm = std::make_shared<Disassembler>();
                    FormGeneric::PtrType form = std::make_shared<FormGeneric>(inst, meta);
                    build_(mnemonic, meta, dasm, form);
                }
            }
        }
    }

    void setDisassembler(const InstructionUniqueID uid, const DisassemblerIF::PtrType& dasm)
    {
        assert(dasm != nullptr);
        typename FactoryType::PtrType ifact = this->findIFact(uid);
        if (ifact == nullptr) {
            throw UnknownPseudoUID(uid);
        }
        ifact->setDisassembler(dasm);
    }

private:
    typename IFactoryIF<InstType, AnnotationType>::PtrType build_(const std::string& mnemonic,
                                                                  const InstMetaData::PtrType& meta,
                                                                  const DisassemblerIF::PtrType& dasm,
                                                                  const FormGeneric::PtrType& form)
    {
        typename FactoryType::PtrType ifact = this->findIFact(mnemonic);

        if (ifact == nullptr) {
            const InstructionUniqueID inst_uid = this->registerInst(mnemonic);
            typename AnnotationType::PtrType panno = this->findAnnotation(mnemonic);
            ifact.reset(new FactoryType(mnemonic, inst_uid, meta, dasm, form, panno));
            registry_[mnemonic] = ifact;
        }

        return ifact;
    }
};

} // namespace mavis

