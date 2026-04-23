#pragma once
#include "comms_minimal.h"
#include <Windows.h>
#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include <unordered_map>

class PEDumper
{
public:
    struct DumpStats
    {
        uint32_t totalPages      = 0;
        uint32_t failedPages     = 0;
        uint32_t totalCodePages  = 0;
        uint32_t failedCodePages = 0;
        uint32_t int3Patched     = 0;
        uint32_t totalSections   = 0;
        uint32_t ff15Total       = 0;
        uint32_t ff15SysRange    = 0;
        uint32_t slotsCollected  = 0;
        uint32_t importsExact    = 0;
        uint32_t importsNear     = 0;
        uint32_t importModules   = 0;
        uint64_t imageSize       = 0;

        bool isHyperion() const { return ff15SysRange > 0; }

        float pageScore() const
        {
            return totalPages ? float(totalPages - failedPages) / float(totalPages) : 0.f;
        }
        float codeScore() const
        {
            return totalCodePages ? float(totalCodePages - failedCodePages) / float(totalCodePages) : 1.f;
        }
        float importScore() const
        {
            uint32_t total = importsExact + importsNear;
            if (total == 0) return 0.f;
            if (isHyperion())
                return float(importsExact) / float(total);
            return slotsCollected ? float(total) / float(slotsCollected) : 0.f;
        }
        float overall() const
        {
            float is = importScore();
            if (is > 1.f) is = 1.f;
            return 0.60f * pageScore() + 0.30f * codeScore() + 0.10f * is;
        }
    };

    explicit PEDumper(Driver& drv);

    bool Dump(uint64_t base, uint32_t oepRva, const std::string& outPath,
              bool patchInt3s = true, bool rebuildIAT = true, bool preTouch = false);

    const DumpStats& Stats() const { return m_stats; }

private:
    Driver&   m_drv;
    DumpStats m_stats;

    struct ImportSlot
    {
        uint32_t    rva;
        std::string mod;
        std::string func;
        uint16_t    ordinal;
    };
    std::vector<ImportSlot> m_importSlots;

    static constexpr uint64_t OFF_PEB_LDR         = 0x18;
    static constexpr uint64_t OFF_LDR_INLOAD_HEAD = 0x10;
    static constexpr uint64_t OFF_ENTRY_DLLBASE    = 0x30;
    static constexpr uint64_t OFF_ENTRY_IMAGESIZE  = 0x40;
    static constexpr uint64_t OFF_ENTRY_BASELEN    = 0x58;
    static constexpr uint64_t OFF_ENTRY_BASEBUF    = 0x60;

    struct ModInfo
    {
        uint64_t    base;
        uint32_t    size;
        std::string name;
    };

    struct ExportEntry
    {
        uint64_t    va;
        std::string name;
        uint16_t    ordinal;
    };

    struct ImportEntry
    {
        uint32_t    iatRva;
        std::string func;
        uint16_t    ordinal;
    };

    bool     TouchAllPages(uint64_t base, uint32_t size);
    bool     ReadFull(uint64_t base, std::vector<uint8_t>& out);
    bool     FixSections(std::vector<uint8_t>& pe);
    void     FixHeadersForIDA(std::vector<uint8_t>& pe, uint64_t base);
    void     PatchInt3s(std::vector<uint8_t>& pe);
    bool     RebuildIAT(std::vector<uint8_t>& pe, uint64_t base);
    uint32_t DetectRealOEP(const std::vector<uint8_t>& pe, uint64_t base);
    void     WriteIDAPythonScript(const std::string& outPath, uint64_t base) const;

    bool EnumModules(std::vector<ModInfo>& out);
    bool ReadExports(const ModInfo& mod, std::vector<ExportEntry>& out);
    uint64_t FollowTrampoline(uint64_t va, uint64_t moduleBase, uint32_t moduleSize, int maxDepth = 4);
    uint32_t RvaToOffset(const std::vector<uint8_t>& pe, uint32_t rva) const;
    uint32_t AlignUp(uint32_t val, uint32_t align) const { return (val + align - 1) & ~(align - 1); }
};
