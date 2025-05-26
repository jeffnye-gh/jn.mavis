#pragma once

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <set>

#ifdef USE_NLOHMANN_JSON
#include <nlohmann/json.hpp>
using json_value = nlohmann::json;
using json_object = nlohmann::json;
#else
#include <boost/json.hpp>
using json_value = boost::json::value;
using json_object = boost::json::object;
#endif

#include "FormRegistry.h"
#include "FormPseudo.h"
#include "IFactory.h"
#include "IFactoryBuilder.h"
#include "InstMetaData.h"
#include "InstMetaDataRegistry.hpp"
#include "ExtractorTraceInfo.h"
#include "ExtractorDirectInfo.h"
#include "ExtractorDirectImplementations.hpp"
#include "ExtractorRegistry.h"
#include "DecoderTypes.h"
#include "DecoderExceptions.h"
#include "Tag.hpp"
#include "Pattern.hpp"
#include "MatchSet.hpp"

namespace mavis
{

template <typename InstType, typename AnnotationType, typename AnnotationTypeAllocator>
class DTable
{
  public:
    typedef std::shared_ptr<DTable<InstType, AnnotationType, AnnotationTypeAllocator>> PtrType;

  private:
    typedef typename std::vector<std::string> FieldNameListType;

    template <typename ObjectType, uint32_t Size, bool CollectStats = false>
    class Cache
    {
      private:
        struct Line
        {
            uint32_t tag = 0;
            typename ObjectType::PtrType handle;
        };

        std::array<Line, Size> table_;
        typename ObjectType::PtrType not_found_;
        uint32_t hits_ = 0;
        uint32_t accesses_ = 0;
        uint32_t collisions_ = 0;

        uint32_t hash_(const Opcode icode) { return icode % Size; }

      public:
        ~Cache()
        {
            if constexpr (CollectStats)
            {
                std::ios_base::fmtflags cout_state(std::cout.flags());
                std::cout << "Cache<" << std::dec << Size << ">: " << hits_ << "/" << accesses_
                          << " (collisions: " << collisions_ << ")" << std::endl;
                std::cout.flags(cout_state);
            }
        }

        const typename ObjectType::PtrType &lookup(const Opcode icode)
        {
            if constexpr (CollectStats)
                ++accesses_;
            uint32_t hash = hash_(icode);
            if ((table_[hash].handle != nullptr) && (table_[hash].tag == icode))
            {
                if constexpr (CollectStats)
                    ++hits_;
                return table_[hash].handle;
            }
            else
            {
                if constexpr (CollectStats)
                    collisions_ += (table_[hash].handle != nullptr);
                return not_found_;
            }
        }

        void allocate(const Opcode icode, const typename ObjectType::PtrType &handle)
        {
            uint32_t hash = hash_(icode);
            table_[hash].tag = icode;
            table_[hash].handle = handle;
        }
    };

    constexpr static inline uint32_t CACHE_SIZE = 1023;
    using InstCache = Cache<InstType, CACHE_SIZE>;
    using IFactoryCache =
        Cache<typename IFactoryIF<InstType, AnnotationType>::IFactoryInfo, CACHE_SIZE>;

  public:
    explicit DTable(typename IFactoryBuilder<InstType, AnnotationType,
                                             AnnotationTypeAllocator>::PtrType builder)
        : builder_(builder),
          icache_(new InstCache()),
          ocache_(new IFactoryCache())
    {
        root_.reset(new IFactoryMatchListComposite<InstType, AnnotationType, 6>(
            PseudoForm<'*'>::getField(PseudoForm<'*'>::FAMILY),
            {
                [](uint32_t icode) { return (icode & 0x3ul) != 0x3ul; },
                [](uint32_t icode)
                { return ((icode & 0x3ul) == 3ul) && ((icode & 0x1cul) != 0x1cul); },
                [](uint32_t icode) { return (icode & 0x3ful) == 0x1ful; },
                [](uint32_t icode) { return (icode & 0x7ful) == 0x3ful; },
                [](uint32_t icode)
                { return ((icode & 0x7ful) == 0x7ful) && ((icode & 0x7000ul) != 0x7000ul); },
                [](uint32_t icode) { return (icode & 0x707ful) == 0x707ful; },
            }));
    }

    void configure(const FileNameListType & isa_files,
                   const MatchSet<Pattern> & inclusions = MatchSet<Pattern>(),
                   const MatchSet<Pattern> & exclusions = MatchSet<Pattern>());

    typename IFactoryIF<InstType, AnnotationType>::IFactoryInfo::PtrType
    getInfo(const Opcode icode)
    {
        const auto &ohandle = ocache_->lookup(icode);
        if (ohandle == nullptr)
        {
            const auto &new_ohandle = root_->getInfo(icode);
            if (new_ohandle != nullptr)
            {
                ocache_->allocate(icode, new_ohandle);
                return new_ohandle;
            }
            else
            {
                throw UnknownOpcode(icode);
            }
        }
        else
        {
            return ohandle;
        }
    }

    template <class InstTypeAllocator, typename... ArgTypes>
    typename InstType::PtrType makeInst(const Opcode icode, InstTypeAllocator &allocator,
                                        ArgTypes &&... args)
    {
        const typename InstType::PtrType &ihandle = icache_->lookup(icode);

        if (ihandle == nullptr)
        {
            const auto &info = getInfo(icode);
            if (info != nullptr)
            {
                const auto new_ihandle = allocator(info->opinfo, info->uinfo, args...);
                icache_->allocate(icode, new_ihandle);
                return allocator(*new_ihandle);
            }
            else
            {
                throw UnknownOpcode(icode);
            }
        }
        else
        {
            return allocator(*ihandle);
        }
    }

    template <typename TraceInfoType, class InstTypeAllocator, typename... ArgTypes>
    typename InstType::PtrType makeInstFromTrace(const TraceInfoType &tinfo,
                                                 InstTypeAllocator &allocator,
                                                 ArgTypes &&... args)
    {
        auto inst = makeInst(tinfo.getOpcode(), allocator, std::forward<ArgTypes>(args)...);

        if (std::string(inst->getMnemonic()) != tinfo.getMnemonic())
        {
            InstMetaData::PtrType einfo(new InstMetaData(InstMetaData::ISA::RV32I));
            auto ifact = builder_->build(tinfo.getMnemonic(), tinfo.getMnemonic(), "", 0, einfo);
            ExtractorIF::PtrType extractor(new ExtractorTraceInfo<TraceInfoType>(tinfo));
            const auto &info = ifact->getInfo(tinfo.getMnemonic(), tinfo.getOpcode(), extractor);
            inst = allocator(info->opinfo, info->uinfo, std::forward<ArgTypes>(args)...);
            icache_->allocate(tinfo.getOpcode(), inst);
        }

        return inst;
    }

    template <class InstTypeAllocator, typename... ArgTypes>
    typename InstType::PtrType makeInstDirectly(const ExtractorDirectInfoIF &ex_info,
                                                InstTypeAllocator &allocator,
                                                ArgTypes &&... args)
    {
        typename InstType::PtrType inst = nullptr;
        std::string mnemonic = ex_info.getMnemonic();
        const InstructionUniqueID uid = ex_info.getUID();
        typename IFactory<InstType, AnnotationType>::PtrType ifact = nullptr;

        if (uid != mavis::INVALID_UID)
        {
            mnemonic = builder_->findInstructionMnemonic(uid);
            ifact = builder_->findIFact(uid);
        }
        else
        {
            ifact = builder_->findIFact(mnemonic);
        }

        if (ifact == nullptr)
        {
            throw UnknownMnemonic(mnemonic);
        }
        else
        {
            const auto &info = ifact->getInfoBypassCache(mnemonic, ex_info.clone());
            inst = allocator(info->opinfo, info->uinfo, std::forward<ArgTypes>(args)...);
        }

        return inst;
    }

    void morphInst(typename InstType::PtrType inst, const ExtractorDirectInfoIF &ex_info) const
    {
        auto ifact = builder_->findIFact(ex_info.getMnemonic());
        if (ifact == nullptr)
        {
            throw UnknownMnemonic(ex_info.getMnemonic());
        }
        else
        {
            const auto &info = ifact->getInfoBypassCache(ex_info.getMnemonic(), ex_info.clone());
            inst->morph(info->opinfo, info->uinfo);
        }
    }

    void flushCaches()
    {
        icache_.reset(new InstCache());
        ocache_.reset(new IFactoryCache());
        root_->flushCaches();
    }

    void print(std::ostream &os) const { root_->print(os); }

  private:
    typename IFactoryIF<InstType, AnnotationType>::PtrType root_ = nullptr;
    typename IFactoryBuilder<InstType, AnnotationType, AnnotationTypeAllocator>::PtrType builder_;
    ExtractorRegistry extractors_;
    FormRegistry forms_;
    std::unique_ptr<InstCache> icache_;
    std::unique_ptr<IFactoryCache> ocache_;

    void parseInstInfo_(const std::string &jfile, const json_object &inst,
                        const std::string &mnemonic, const MatchSet<Tag> &tags);

    typename IFactoryIF<InstType, AnnotationType>::PtrType
    buildLeaf_(const FormBase *form,
               const typename IFactoryIF<InstType, AnnotationType>::PtrType &currNode,
               const std::string &mnemonic, Opcode istencil, const FieldNameListType &flist,
               const std::string &factory_name, const std::string &xpand_name,
               ExtractorIF::PtrType override_extractor, InstMetaData::PtrType &meta,
               const typename IFactoryIF<InstType, AnnotationType>::PtrType &shared_ifact);

    typename IFactoryIF<InstType, AnnotationType>::PtrType
    build_(const FormBase *form, const std::string &mnemonic, Opcode istencil,
           const FieldNameListType &flist, const FieldNameSetType &ignore_set,
           const std::string &factory_name, const std::string &xpand_name,
           const ExtractorIF::PtrType &override_extractor, InstMetaData::PtrType &einfo,
           typename IFactoryIF<InstType, AnnotationType>::PtrType shared_ifact = nullptr);

    template <typename FormType>
    void buildSpecial_(const std::string &mnemonic, Opcode istencil,
                       const FieldNameListType &flist, const FieldNameSetType &ignore_set,
                       const std::string &factory_name, const std::string &xpand_name,
                       const ExtractorIF::PtrType &override_extractor,
                       const InstMetaData::PtrType &einfo);
};

template <typename InstType, typename AnnotationType, typename AnnotationTypeAllocator>
inline std::ostream &
operator<<(std::ostream &os, const DTable<InstType, AnnotationType, AnnotationTypeAllocator> &dt)
{
    dt.print(os);
    return os;
}

} // namespace mavis

#include "impl/DTable.tcc"
#include "impl/DTableBuildSpecial.tcc"

