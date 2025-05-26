#ifndef TCC_MAVIS_DTABLE
#define TCC_MAVIS_DTABLE

#include <mavis/Overlay.hpp>
#include "mavis/DTable.h" // Needed for CLION
#include "mavis/JSONUtils.hpp"

#ifdef USE_NLOHMANN_JSON
#include <nlohmann/json.hpp>
using json_object = nlohmann::json;
#else
#include <boost/json.hpp>
using json_object = boost::json::object;
#endif

namespace mavis
{

    template <typename InstType, typename AnnotationType, typename AnnotationTypeAllocator>
    void DTable<InstType, AnnotationType, AnnotationTypeAllocator>::parseInstInfo_(
        const std::string & jfile, const json_object & inst, const std::string & mnemonic,
        const MatchSet<Tag> & tags)
    {
        Opcode istencil = 0;
#ifdef USE_NLOHMANN_JSON
        if (inst.contains("stencil")) {
            istencil = std::stoll(inst["stencil"].get<std::string>(), nullptr, 16);
        }

        FieldNameListType flist;
        if (inst.contains("fixed")) {
            flist = inst["fixed"].get<FieldNameListType>();
        }

        FieldNameSetType ignore_set;
        if (inst.contains("ignore")) {
            ignore_set = inst["ignore"].get<FieldNameSetType>();
        }

        ExtractorIF::PtrType override_extractor = nullptr;
        if (inst.contains("xform")) {
            override_extractor = extractors_.getExtractor(inst["xform"].get<std::string>());
        }

        std::string factory_name = mnemonic;
        if (inst.contains("factory")) {
            factory_name = inst["factory"].get<std::string>();
        }

        std::string xpand_name;
        if (inst.contains("expand")) {
            xpand_name = inst["expand"].get<std::string>();
        }

        if (inst.contains("overlay")) {
            typename Overlay<InstType, AnnotationType>::PtrType olay =
                std::make_shared<Overlay<InstType, AnnotationType>>(mnemonic, inst["overlay"], inst, override_extractor);
#else
        if (const auto it = inst.find("stencil"); it != inst.end()) {
            istencil = strtoll(it->value().as_string().c_str(), nullptr, 16);
        }

        FieldNameListType flist;
        if (const auto it = inst.find("fixed"); it != inst.end()) {
            flist = boost::json::value_to<FieldNameListType>(it->value());
        }

        FieldNameSetType ignore_set;
        if (const auto it = inst.find("ignore"); it != inst.end()) {
            ignore_set = boost::json::value_to<FieldNameSetType>(it->value());
        }

        ExtractorIF::PtrType override_extractor = nullptr;
        if (const auto it = inst.find("xform"); it != inst.end()) {
            override_extractor = extractors_.getExtractor(boost::json::value_to<std::string>(it->value()));
        }

        std::string factory_name = mnemonic;
        if (const auto it = inst.find("factory"); it != inst.end()) {
            factory_name = boost::json::value_to<std::string>(it->value());
        }

        std::string xpand_name;
        if (const auto it = inst.find("expand"); it != inst.end()) {
            xpand_name = boost::json::value_to<std::string>(it->value());
        }

        if (const auto it = inst.find("overlay"); it != inst.end()) {
            typename Overlay<InstType, AnnotationType>::PtrType olay =
                std::make_shared<Overlay<InstType, AnnotationType>>(mnemonic, it->value().as_object(), inst, override_extractor);
#endif
            builder_->buildOverlay(olay, jfile);
            typename IFactory<InstType, AnnotationType>::PtrType ifact =
                builder_->findIFact(olay->getBaseMnemonic());
            if (ifact == nullptr) {
                throw BuildErrorOverlayBaseNotFound(olay->getMnemonic(), olay->getBaseMnemonic(), jfile);
            }
            ifact->addOverlay(olay);
        } else {
#ifdef USE_NLOHMANN_JSON
            const std::string form = inst["form"].get<std::string>();
#else
            const std::string form = boost::json::value_to<std::string>(inst.at("form"));
#endif
            const FormBase* form_wrap = forms_.findFormWrapper(form);
            if (form_wrap == nullptr) {
                throw BuildErrorUnknownForm(jfile, mnemonic, form);
            }

            InstMetaData::PtrType meta =
                builder_->makeInstMetaData(mnemonic, inst, !xpand_name.empty(), tags);
            try {
                typename IFactoryIF<InstType, AnnotationType>::PtrType ifact =
                    build_(form_wrap, mnemonic, istencil, flist, ignore_set, factory_name,
                           xpand_name, override_extractor, meta);

                StringListType alias_stencils;
#ifdef USE_NLOHMANN_JSON
                if (inst.contains("alias")) {
                    alias_stencils = inst["alias"].get<StringListType>();
#else
                if (const auto alias_it = inst.find("alias"); alias_it != inst.end()) {
                    alias_stencils = boost::json::value_to<StringListType>(alias_it->value());
#endif
                    for (const auto & astencil : alias_stencils) {
                        Opcode opc = std::stoll(astencil, nullptr, 16);
                        build_(form_wrap, mnemonic, opc, flist, ignore_set, factory_name,
                               xpand_name, override_extractor, meta, ifact);
                    }
                }
            } catch (const BuildErrorInstructionAlias & ex) {
                std::cerr << ex.what() << std::endl;
            }
        }
    }

    template <typename InstType, typename AnnotationType, typename AnnotationTypeAllocator>
    void DTable<InstType, AnnotationType, AnnotationTypeAllocator>::configure(
        const FileNameListType & isa_files, const MatchSet<Pattern> & inclusions,
        const MatchSet<Pattern> & exclusions)
    {
        struct parseInstInfoArgs
        {
            const std::string jfile;
            const json_object inst;
            const std::string mnemonic;
            const MatchSet<Tag> tags;

            parseInstInfoArgs(const std::string & jfile, const json_object & inst,
                              const std::string & mnemonic, const MatchSet<Tag> & tags)
                : jfile(jfile), inst(inst), mnemonic(mnemonic), tags(tags)
            {}
        };

        std::vector<parseInstInfoArgs> expansions;

        for (const auto & jfile : isa_files)
        {
            const auto json = parseJSONWithException<BadISAFile>(jfile);
#ifdef USE_NLOHMANN_JSON
            const auto& jobj = json;
#else
            const auto& jobj = json.as_array();
#endif

            for (const auto & inst_value : jobj)
            {
#ifdef USE_NLOHMANN_JSON
                const auto& inst = inst_value;
#else
                const auto& inst = inst_value.as_object();
#endif
                std::string mnemonic;
#ifdef USE_NLOHMANN_JSON
                if (inst.contains("mnemonic"))
                {
                    mnemonic = inst["mnemonic"].get<std::string>();
                    MatchSet<Tag> tags;
                    if (inst.contains("tags"))
                    {
                        tags = MatchSet<Tag>(inst["tags"].get<std::vector<std::string>>());
#else
                if (const auto it = inst.find("mnemonic"); it != inst.end())
                {
                    mnemonic = boost::json::value_to<std::string>(it->value());
                    MatchSet<Tag> tags;
                    if (const auto tag_it = inst.find("tags"); tag_it != inst.end())
                    {
                        tags = MatchSet<Tag>(boost::json::value_to<std::vector<std::string>>(tag_it->value()));
#endif

                    }

                    const bool is_expansion =
#ifdef USE_NLOHMANN_JSON
                        inst.contains("expand");
                    const bool is_overlay = inst.contains("overlay");
#else
                        inst.find("expand") != inst.end();
                    const bool is_overlay = inst.find("overlay") != inst.end();
#endif

                    if ((inclusions.isEmpty() && exclusions.isEmpty())
                        || (inclusions.isEmpty() && tags.isEmpty()))
                    {
                        if (!is_expansion && !is_overlay)
                        {
                            parseInstInfo_(jfile, inst, mnemonic, tags);
                        }
                        else
                        {
                            expansions.emplace_back(jfile, inst, mnemonic, tags);
                        }
                    }
                    else if (!tags.isEmpty())
                    {
                        bool included = inclusions.isEmpty() || tags.matchAnyAny(inclusions);
                        if (included)
                        {
                            bool excluded = !exclusions.isEmpty() && tags.matchAnyAny(exclusions);
                            if (!excluded)
                            {
                                if (!is_expansion)
                                {
                                    parseInstInfo_(jfile, inst, mnemonic, tags);
                                }
                                else
                                {
                                    expansions.emplace_back(jfile, inst, mnemonic, tags);
                                }
                            }
                        }
                    }
                }
#ifdef USE_NLOHMANN_JSON
                else if (inst.contains("pseudo"))
#else
                else if (inst.find("pseudo") != inst.end())
#endif
                {
                    continue;
                }
                else
                {
#ifdef USE_NLOHMANN_JSON
                    if (inst.contains("stencil"))
                    {
                        throw BuildErrorMissingMnemonic(jfile, inst["stencil"].get<std::string>());
#else
                    if (const auto stencil_it = inst.find("stencil"); stencil_it != inst.end())
                    {
                        throw BuildErrorMissingMnemonic(jfile, boost::json::value_to<std::string>(stencil_it->value()));
#endif
                    }
                    throw BuildErrorMissingMnemonic(jfile);
                }
            }
        }

        for (auto & exp : expansions)
        {
            parseInstInfo_(exp.jfile, exp.inst, exp.mnemonic, exp.tags);
        }
    }

    // Remaining functions are JSON-agnostic
    // buildLeaf_ and build_ are unchanged

    template <typename InstType, typename AnnotationType, typename AnnotationTypeAllocator>
    typename IFactoryIF<InstType, AnnotationType>::PtrType
    DTable<InstType, AnnotationType, AnnotationTypeAllocator>::buildLeaf_(
        const FormBase* form,
        const typename IFactoryIF<InstType, AnnotationType>::PtrType & currNode,
        const std::string & mnemonic, const Opcode istencil, const FieldNameListType & flist,
        const std::string & factory_name, const std::string & xpand_name,
        ExtractorIF::PtrType override_extractor, InstMetaData::PtrType & meta,
        const typename IFactoryIF<InstType, AnnotationType>::PtrType & shared_ifact)
    {
        if (currNode == nullptr)
        {
            std::cout << root_ << std::endl;
            assert(currNode != nullptr);
        }

        if (override_extractor == nullptr)
        {
            override_extractor = extractors_.getExtractor(form->getName());
        }

        std::shared_ptr<IFactorySpecialCaseComposite<InstType, AnnotationType>>
            parent = std::dynamic_pointer_cast<IFactorySpecialCaseComposite<InstType, AnnotationType>>(currNode);

        if (parent == nullptr)
        {
            throw BuildErrorOpcodeConflict(mnemonic, istencil);
        }
        if (!flist.empty())
        {
            parent->addSpecialCase(form, mnemonic, istencil, flist);
            meta->addFixedFields(flist);
        }

        typename IFactoryIF<InstType, AnnotationType>::PtrType ifact;
        if (shared_ifact == nullptr)
        {
            ifact = builder_->build(mnemonic, factory_name, xpand_name, istencil, meta);
        }
        else
        {
            ifact = shared_ifact;
        }

        if (parent->getNode(istencil) == nullptr)
        {
            parent->addIFactory(mnemonic, istencil, ifact, override_extractor);
        }
        else if (parent->getDefault() == nullptr)
        {
            parent->addDefaultIFactory(mnemonic, istencil, ifact, override_extractor);
        }
        else
        {
            throw BuildErrorInstructionAlias(istencil, mnemonic,
                                             parent->getNode(istencil)->getName());
        }

        return ifact;
    }

    template <typename InstType, typename AnnotationType, typename AnnotationTypeAllocator>
    typename IFactoryIF<InstType, AnnotationType>::PtrType
    DTable<InstType, AnnotationType, AnnotationTypeAllocator>::build_(
        const FormBase* form, const std::string & mnemonic, const Opcode istencil,
        const FieldNameListType & flist, const FieldNameSetType & ignore_set,
        const std::string & factory_name, const std::string & xpand_name,
        const ExtractorIF::PtrType & override_extractor, InstMetaData::PtrType & einfo,
        const typename IFactoryIF<InstType, AnnotationType>::PtrType shared_ifact)
    {
        assert(form != nullptr);
        typename IFactoryIF<InstType, AnnotationType>::PtrType currNode = root_;

        const FieldsType & fields = form->getOpcodeFields();
        const uint32_t n_fields = fields.size();
        assert(n_fields > 0);

        if (currNode->getNode(istencil) == nullptr)
        {
            currNode->addIFactory(
                istencil, typename IFactoryIF<InstType, AnnotationType>::PtrType(
                              new IFactoryDenseComposite<InstType, AnnotationType>(fields[0])));
        }
        currNode = currNode->getNode(istencil);
        assert(currNode->getField() != nullptr);
        if (!currNode->getField()->isEquivalent(fields[0]))
        {
            throw BuildErrorFieldsIncompatible(mnemonic, *currNode->getField(), fields[0]);
        }

        const uint32_t last_field = n_fields - 1;
        for (uint32_t i = 0; i < last_field; ++i)
        {
            if (ignore_set.find(fields[i].getName()) != ignore_set.end())
            {
                if (currNode->getDefault() == nullptr)
                {
                    currNode->addDefaultIFactory(
                        typename IFactoryIF<InstType, AnnotationType>::PtrType(
                            new IFactoryDenseComposite<InstType, AnnotationType>(fields[i + 1])));
                }
                currNode = currNode->getDefault();
            }
            else
            {
                if (currNode->getNode(istencil) == nullptr)
                {
                    currNode->addIFactory(
                        istencil,
                        typename IFactoryIF<InstType, AnnotationType>::PtrType(
                            new IFactoryDenseComposite<InstType, AnnotationType>(fields[i + 1])));
                }
                currNode = currNode->getNode(istencil);
            }

            assert(currNode->getField() != nullptr);
            if (!currNode->getField()->isEquivalent(fields[i + 1]))
            {
                std::cerr << "ERROR with field collision on tree:" << std::endl;
                currNode->print(std::cerr);
                throw BuildErrorFieldsIncompatible(mnemonic, *currNode->getField(), fields[i + 1]);
            }
        }

        if (ignore_set.find(fields[last_field].getName()) != ignore_set.end())
        {
            if (currNode->getDefault() == nullptr)
            {
                currNode->addDefaultIFactory(typename IFactoryIF<InstType, AnnotationType>::PtrType(
                    new IFactorySpecialCaseComposite<InstType, AnnotationType>()));
            }
            currNode = currNode->getDefault();
        }
        else
        {
            if (currNode->getNode(istencil) == nullptr)
            {
                currNode->addIFactory(
                    istencil, typename IFactoryIF<InstType, AnnotationType>::PtrType(
                                  new IFactorySpecialCaseComposite<InstType, AnnotationType>()));
            }
            currNode = currNode->getNode(istencil);
        }

        return buildLeaf_(form, currNode, mnemonic, istencil, flist, factory_name, xpand_name,
                          override_extractor, einfo, shared_ifact);
    }

} // namespace mavis

#endif // TCC_MAVIS_DTABLE

