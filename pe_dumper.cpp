#include "pe_dumper.h"
#include "cli.h"
#include <iostream>
#include <fstream>
#include <algorithm>
#include <cassert>
#include <cstring>
#include <unordered_set>
#include <iomanip>
#include <sstream>

static void printDumpQuality(const PEDumper::DumpStats& s);

PEDumper::PEDumper(Driver& drv) : m_drv(drv) {}

bool PEDumper::TouchAllPages(uint64_t base, uint32_t size)
{
    // shellcode: touch every 0x1000-byte page of [base, base+size) then spin on done flag
    //   mov rcx, base  /  mov rdx, size  /  xor rax, rax
    //   .loop: movzx r9d, [rcx+rax]  /  add rax, 0x1000  /  cmp rax, rdx  /  jb .loop
    //   mov rax, <done_flag_va>  /  mov byte [rax], 1  /  jmp $ (spin - context hijack restore)
    // layout:  [0] 48 B9 [base 8B]  [10] 48 BA [size 8B]  [20] 48 31 C0
    //          [23] 4C 0F B6 0C 01  [28] 48 05 00 10 00 00  [34] 48 3B C2
    //          [37] 72 F0  [39] 48 B8 [doneFlagVa 8B]  [49] C6 00 01  [52] EB FE
    static constexpr size_t SC_SZ = 54; // 53 instruction bytes + 1 done-flag byte
    uint8_t sc[SC_SZ] = {
        0x48, 0xB9, 0,0,0,0,0,0,0,0,   // [0]  mov rcx, base
        0x48, 0xBA, 0,0,0,0,0,0,0,0,   // [10] mov rdx, size
        0x48, 0x31, 0xC0,               // [20] xor rax, rax
        0x4C, 0x0F, 0xB6, 0x0C, 0x01,  // [23] movzx r9d, [rcx+rax]
        0x48, 0x05, 0x00, 0x10, 0x00, 0x00, // [28] add rax, 0x1000
        0x48, 0x3B, 0xC2,               // [34] cmp rax, rdx
        0x72, 0xF0,                     // [37] jb -16 (.loop)
        0x48, 0xB8, 0,0,0,0,0,0,0,0,   // [39] mov rax, doneFlagVa
        0xC6, 0x00, 0x01,               // [49] mov byte [rax], 1
        0xEB, 0xFE                      // [52] jmp $ (spin until context restored)
    };
    memcpy(sc + 2,  &base, 8);
    uint64_t sz64 = size;
    memcpy(sc + 12, &sz64, 8);

    IMAGE_DOS_HEADER dos{};
    IMAGE_NT_HEADERS64 nt{};
    m_drv.Read(base, &dos, sizeof(dos));
    m_drv.Read(base + dos.e_lfanew, &nt, sizeof(nt));

    std::vector<uint8_t> hdr(nt.OptionalHeader.SizeOfHeaders);
    m_drv.Read(base, hdr.data(), hdr.size());

    auto* ntBuf = reinterpret_cast<IMAGE_NT_HEADERS64*>(hdr.data() + dos.e_lfanew);
    auto* sec   = IMAGE_FIRST_SECTION(ntBuf);

    uint64_t             caveVa = 0;
    std::vector<uint8_t> savedBytes;

    for (int i = 0; i < ntBuf->FileHeader.NumberOfSections && !caveVa; i++)
    {
        if (!(sec[i].Characteristics & IMAGE_SCN_CNT_CODE)) continue;

        uint32_t rva = sec[i].VirtualAddress;
        uint32_t vsz = sec[i].Misc.VirtualSize;

        for (uint32_t off = 0; off + 0x1000 <= vsz && !caveVa; off += 0x1000)
        {
            std::vector<uint8_t> page(0x1000);
            if (!m_drv.Read(base + rva + off, page.data(), 0x1000)) continue;

            uint32_t run = 0, runStart = 0;
            for (uint32_t j = 0; j < 0x1000; j++)
            {
                uint8_t b = page[j];
                if (b == 0x90 || b == 0xCC)
                {
                    if (!run) runStart = j;
                    if (++run >= SC_SZ + 1)
                    {
                        caveVa = base + rva + off + runStart;
                        savedBytes.assign(page.begin() + runStart,
                                          page.begin() + runStart + SC_SZ + 1);
                        break;
                    }
                }
                else { run = 0; }
            }
        }
    }

    if (!caveVa)
    {
        UI::Warn("no code cave found");
        return false;
    }

    uint64_t doneFlagVa = caveVa + SC_SZ;
    memcpy(sc + 41, &doneFlagVa, 8);

    uint8_t zero = 0;
    m_drv.Write(doneFlagVa, &zero, 1);

    if (!m_drv.Write(caveVa, sc, SC_SZ))
    {
        UI::Warn("cave write failed " + UI::Hex(caveVa));
        return false;
    }
    UI::Sub("cave at " + UI::Hex(caveVa));

    // enumerate target threads sorted by creation time
    DWORD pid = m_drv.ProcessId;
    struct TInfo { DWORD tid; ULONGLONG createTime; };
    std::vector<TInfo> threads;
    {
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (hSnap != INVALID_HANDLE_VALUE)
        {
            THREADENTRY32 te{ sizeof(te) };
            if (Thread32First(hSnap, &te))
            {
                do {
                    if (te.th32OwnerProcessID != pid) continue;
                    HANDLE ht = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
                    if (!ht || ht == INVALID_HANDLE_VALUE) continue;
                    FILETIME ct, ex, kt, ut;
                    if (GetThreadTimes(ht, &ct, &ex, &kt, &ut))
                    {
                        ULONGLONG t = ((ULONGLONG)ct.dwHighDateTime << 32) | ct.dwLowDateTime;
                        threads.push_back({ te.th32ThreadID, t });
                    }
                    CloseHandle(ht);
                }
                while (Thread32Next(hSnap, &te));
            }
            CloseHandle(hSnap);
        }
    }
    std::sort(threads.begin(), threads.end(),
        [](const TInfo& a, const TInfo& b) { return a.createTime < b.createTime; });

    UI::Sub("found " + std::to_string(threads.size()) + " threads");

    bool ran = false;
    int tcount = (int)threads.size();
    int tstart = tcount > 16 ? tcount / 4 : 1;   // skip first quarter (init threads)
    int tend   = tcount > 16 ? tcount / 2 : min(tcount, 9); // use middle range only
    for (int i = tstart; i < tend && !ran; i++)
    {
        HANDLE ht = OpenThread(
            THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT,
            FALSE, threads[i].tid);
        if (!ht || ht == INVALID_HANDLE_VALUE) continue;

        if (SuspendThread(ht) == (DWORD)-1) { CloseHandle(ht); continue; }

        CONTEXT ctx{};
        ctx.ContextFlags = CONTEXT_ALL;
        if (!GetThreadContext(ht, &ctx))
        {
            ResumeThread(ht);
            CloseHandle(ht);
            continue;
        }

        CONTEXT savedCtx = ctx;
        ctx.Rip = caveVa;
        if (!SetThreadContext(ht, &ctx))
        {
            ResumeThread(ht);
            CloseHandle(ht);
            continue;
        }

        ResumeThread(ht);
        UI::Sub("TID " + std::to_string(threads[i].tid) + " hijacked");

        static constexpr int POLL_MS    = 25;
        static constexpr int TIMEOUT_MS = 5000;
        for (int elapsed = 0; elapsed < TIMEOUT_MS; elapsed += POLL_MS)
        {
            Sleep(POLL_MS);
            uint8_t flag = 0;
            m_drv.Read(doneFlagVa, &flag, 1);
            if (flag)
            {
                UI::Ok("pre-touch done in ~" + std::to_string(elapsed + POLL_MS) + "ms");
                ran = true;
                break;
            }
        }

        // restore thread context regardless of whether shellcode completed
        SuspendThread(ht);
        SetThreadContext(ht, &savedCtx);
        ResumeThread(ht);
        CloseHandle(ht);

        if (!ran)
            UI::Warn("TID " + std::to_string(threads[i].tid) + " timeout context restored");
    }

    if (!ran)
        UI::Warn("pre-touch skipped no threads completed");

    m_drv.Write(caveVa, savedBytes.data(), savedBytes.size());
    UI::Sub("cave restored");
    return ran;
}

bool PEDumper::Dump(uint64_t base, uint32_t oepRva, const std::string& outPath,
                    bool doPatchInt3s, bool doRebuildIAT, bool doPreTouch)
{
    if (doPreTouch)
    {
        UI::Info("pre-touching encrypted pages via APC...");
        IMAGE_DOS_HEADER dos{};
        IMAGE_NT_HEADERS64 nt{};
        m_drv.Read(base, &dos, sizeof(dos));
        m_drv.Read(base + dos.e_lfanew, &nt, sizeof(nt));
        TouchAllPages(base, nt.OptionalHeader.SizeOfImage);
        std::cout << "\n";
    }

    m_stats = {};
    m_importSlots.clear();

    {
        HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, m_drv.ProcessId);
        if (hProc)
        {
            DWORD exitCode = STILL_ACTIVE;
            GetExitCodeProcess(hProc, &exitCode);
            CloseHandle(hProc);
            if (exitCode != STILL_ACTIVE)
            {
                UI::Err("target process exited (code " + std::to_string(exitCode) +
                        "), Hyperion likely killed it");
                UI::Sub("re-run after Roblox has fully loaded in-game");
                return false;
            }
        }
    }

    std::vector<uint8_t> pe;

    if (!ReadFull(base, pe))   return false;
    if (!FixSections(pe))      return false;
    FixHeadersForIDA(pe, base);
    if (doPatchInt3s) PatchInt3s(pe);
    if (doRebuildIAT) RebuildIAT(pe, base);

    if (!oepRva)
        oepRva = DetectRealOEP(pe, base);

    if (oepRva)
    {
        auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(pe.data());
        auto* nt  = reinterpret_cast<IMAGE_NT_HEADERS64*>(pe.data() + dos->e_lfanew);
        nt->OptionalHeader.AddressOfEntryPoint = oepRva;
        UI::Ok("OEP -> RVA " + UI::Hex(oepRva));
    }

    std::ofstream f(outPath, std::ios::binary);
    if (!f) { UI::Err("failed to open output: " + outPath); return false; }
    f.write(reinterpret_cast<char*>(pe.data()), pe.size());
    UI::Ok("wrote " + UI::Hex(pe.size()) + " bytes");

    if (!m_importSlots.empty())
        WriteIDAPythonScript(outPath, base);

    printDumpQuality(m_stats);
    return true;
}

static void printDumpQuality(const PEDumper::DumpStats& s)
{
    auto bar = [](float pct, int w = 20) {
        int fill = int(pct * w + 0.5f);
        std::string b = "[";
        for (int i = 0; i < w; i++) b += (i < fill ? '=' : ' ');
        return b + "]";
    };
    auto pct = [](float v) {
        std::ostringstream ss;
        ss << std::fixed << std::setprecision(1) << (v * 100.f) << "%";
        return ss.str();
    };
    auto grade = [](float v) -> const char* {
        if (v >= 0.97f) return "PERFECT";
        if (v >= 0.90f) return "EXCELLENT";
        if (v >= 0.75f) return "GOOD";
        if (v >= 0.50f) return "FAIR";
        return "POOR";
    };

    float pg = s.pageScore(), cg = s.codeScore(), ig = s.importScore(), ov = s.overall();
    bool hyperion = s.isHyperion();
    uint32_t totalImports = s.importsExact + s.importsNear;

    std::cout << "\n";
    UI::Sep('=');
    UI::Info("dump quality");
    UI::Sep();
    std::cout << Ansi::BrBlack << "  pages   " << Ansi::BrCyan << bar(pg) << " "
              << Ansi::BrWhite << std::setw(6) << pct(pg)
              << Ansi::BrBlack << "  (" << s.totalPages - s.failedPages << "/" << s.totalPages << " pages)\n";
    std::cout << Ansi::BrBlack << "  code    " << Ansi::BrCyan << bar(cg) << " "
              << Ansi::BrWhite << std::setw(6) << pct(cg)
              << Ansi::BrBlack << "  (" << s.totalCodePages - s.failedCodePages << "/" << s.totalCodePages
              << " code pages, " << s.int3Patched << " INT3s removed)\n";

    if (hyperion)
    {
        std::cout << Ansi::BrBlack << "  imports " << Ansi::BrCyan << bar(ig) << " "
                  << Ansi::BrWhite << std::setw(6) << pct(ig) << " exact"
                  << Ansi::BrBlack << "  (" << totalImports << " imports / "
                  << s.importModules << " modules"
                  << (s.ff15SysRange ? ", " + std::to_string(s.ff15SysRange) + " in-range" : "")
                  << ", Hyperion IAT)\n";
    }
    else
    {
        std::cout << Ansi::BrBlack << "  imports " << Ansi::BrCyan << bar(ig) << " "
                  << Ansi::BrWhite << std::setw(6) << pct(ig)
                  << Ansi::BrBlack << "  (" << s.importsExact << " exact + " << s.importsNear << " approx / "
                  << s.importModules << " modules)\n";
    }

    UI::Sep();
    const char* clr = (ov >= 0.90f) ? Ansi::BrGreen : (ov >= 0.75f ? Ansi::BrYellow : Ansi::BrRed);
    std::cout << Ansi::BrBlack << "  overall " << clr << bar(ov) << " "
              << Ansi::BrWhite << std::setw(6) << pct(ov) << "  "
              << clr << grade(ov) << Ansi::Reset << "\n";
    UI::Sep('=');
    std::cout << "\n";
}

void PEDumper::FixHeadersForIDA(std::vector<uint8_t>& pe, uint64_t base)
{
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(pe.data());
    auto* nt  = reinterpret_cast<IMAGE_NT_HEADERS64*>(pe.data() + dos->e_lfanew);

    // set imagebase to actual load address so IDA doesn't rebase
    nt->OptionalHeader.ImageBase = base;

    // clear ASLR flags - image is already at its final address
    nt->OptionalHeader.DllCharacteristics &=
        ~(IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE | IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA);

    // clear stale directories that confuse analysis tools
    auto clearDir = [&](int idx) {
        nt->OptionalHeader.DataDirectory[idx] = { 0, 0 };
    };
    clearDir(IMAGE_DIRECTORY_ENTRY_BASERELOC);    // image is already relocated
    clearDir(IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT); // stale bind data
    clearDir(IMAGE_DIRECTORY_ENTRY_SECURITY);     // stale authenticode sig
    clearDir(IMAGE_DIRECTORY_ENTRY_DEBUG);        // stale debug info

    // zero checksum - tools that verify it against file content would fail anyway
    nt->OptionalHeader.CheckSum = 0;

    UI::Ok("PE headers patched for IDA (base=" + UI::Hex(base) + ", ASLR cleared, stale dirs zeroed)");
}

void PEDumper::WriteIDAPythonScript(const std::string& outPath, uint64_t base) const
{
    std::string scriptPath = outPath + ".py";
    std::ofstream f(scriptPath);
    if (!f)
    {
        UI::Warn("failed to write IDAPython script: " + scriptPath);
        return;
    }

    f << "import idc, ida_name, idaapi\n\n";
    f << "DUMP_BASE = 0x" << std::hex << base << std::dec << "\n\n";
    f << "# maps slot RVA -> (\"module.dll\", \"FunctionName\", ordinal)\n";
    f << "IMPORTS = {\n";
    for (auto& s : m_importSlots)
    {
        std::string funcName = s.func;
        if (!funcName.empty() && funcName[0] == '~')
            funcName = funcName.substr(1); // strip approx prefix

        f << "    0x" << std::hex << s.rva << std::dec
          << ": (\"" << s.mod << "\", \""
          << (funcName.empty() ? "Ordinal_" + std::to_string(s.ordinal) : funcName)
          << "\", " << s.ordinal << "),\n";
    }
    f << "}\n\n";

    f << R"(def apply_imports():
    base = idaapi.get_imagebase()
    applied = 0
    for rva, (mod, func, ordinal) in IMPORTS.items():
        ea = base + rva
        imp_name = f"__imp_{func}"
        if ida_name.set_name(ea, imp_name, ida_name.SN_FORCE | ida_name.SN_NOWARN):
            applied += 1
    print(f"[pedumper] named {applied}/{len(IMPORTS)} import slots")

def apply_comments():
    base = idaapi.get_imagebase()
    for rva, (mod, func, ordinal) in IMPORTS.items():
        ea = base + rva
        idc.set_cmt(ea, f"{mod}!{func}", 0)

apply_imports()
apply_comments()
print("[pedumper] done, run apply_imports() again if IDA reanalyzed")
)";

    UI::Ok("IDAPython script -> " + scriptPath +
           " (" + std::to_string(m_importSlots.size()) + " slots)");
}

bool PEDumper::ReadFull(uint64_t base, std::vector<uint8_t>& out)
{
    IMAGE_DOS_HEADER dos{};
    if (!m_drv.Read(base, &dos, sizeof(dos)) || dos.e_magic != IMAGE_DOS_SIGNATURE)
    {
        UI::Err("bad DOS header at " + UI::Hex(base));
        return false;
    }

    IMAGE_NT_HEADERS64 nt{};
    if (!m_drv.Read(base + dos.e_lfanew, &nt, sizeof(nt)) || nt.Signature != IMAGE_NT_SIGNATURE)
    {
        UI::Err("bad NT header");
        return false;
    }

    if (nt.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
    {
        UI::Err("only x64 targets supported");
        return false;
    }

    uint32_t imageSize = nt.OptionalHeader.SizeOfImage;
    out.assign(imageSize, 0);

    if (!m_drv.Read(base, out.data(), nt.OptionalHeader.SizeOfHeaders))
    {
        UI::Err("failed to read PE headers");
        return false;
    }

    // must derive section table from the buffer - IMAGE_FIRST_SECTION(&nt) points into stack garbage
    auto* ntBuf  = reinterpret_cast<IMAGE_NT_HEADERS64*>(out.data() + dos.e_lfanew);
    auto* sec    = IMAGE_FIRST_SECTION(ntBuf);
    uint16_t numSections = ntBuf->FileHeader.NumberOfSections;

    static constexpr uint32_t PAGE_SZ = 0x1000;

    m_stats.imageSize    = imageSize;
    m_stats.totalSections = numSections;

    for (int i = 0; i < numSections; i++)
    {
        uint32_t rva  = sec[i].VirtualAddress;
        uint32_t size = sec[i].Misc.VirtualSize;
        if (!rva || !size || rva + size > imageSize) continue;

        bool isCode = !!(sec[i].Characteristics & IMAGE_SCN_CNT_CODE);

        for (uint32_t off = 0; off < size; off += PAGE_SZ)
        {
            uint32_t chunk = (off + PAGE_SZ <= size) ? PAGE_SZ : (size - off);
            m_stats.totalPages++;
            if (isCode) m_stats.totalCodePages++;

            if (!m_drv.Read(base + rva + off, out.data() + rva + off, chunk))
            {
                m_stats.failedPages++;
                if (isCode)
                {
                    m_stats.failedCodePages++;
                    memset(out.data() + rva + off, 0x90, chunk);
                }
            }
        }
    }

    UI::Ok("read " + UI::Hex(imageSize) + " bytes  (" +
           std::to_string(m_stats.failedPages) + "/" + std::to_string(m_stats.totalPages) + " pages failed, " +
           std::to_string(m_stats.failedCodePages) + "/" + std::to_string(m_stats.totalCodePages) + " code pages failed)");
    return true;
}

bool PEDumper::FixSections(std::vector<uint8_t>& pe)
{
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(pe.data());
    auto* nt  = reinterpret_cast<IMAGE_NT_HEADERS64*>(pe.data() + dos->e_lfanew);
    auto* sec = IMAGE_FIRST_SECTION(nt);

    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++)
    {
        sec[i].PointerToRawData = sec[i].VirtualAddress;
        sec[i].SizeOfRawData    = sec[i].Misc.VirtualSize;
    }

    UI::Ok("fixed " + std::to_string(nt->FileHeader.NumberOfSections) + " section raw offsets");
    return true;
}

void PEDumper::PatchInt3s(std::vector<uint8_t>& pe)
{
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(pe.data());
    auto* nt  = reinterpret_cast<IMAGE_NT_HEADERS64*>(pe.data() + dos->e_lfanew);
    auto* sec = IMAGE_FIRST_SECTION(nt);

    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++)
    {
        if (!(sec[i].Characteristics & IMAGE_SCN_CNT_CODE)) continue;

        uint32_t off = sec[i].PointerToRawData;
        uint32_t sz  = sec[i].SizeOfRawData;
        if (!off || !sz || off + sz > pe.size()) continue;

        uint8_t* p = pe.data() + off;
        for (uint32_t j = 0; j < sz; j++)
        {
            if (p[j] == 0xCC)
            {
                p[j] = 0x90;
                m_stats.int3Patched++;
            }
        }
    }

    UI::Ok("patched " + std::to_string(m_stats.int3Patched) + " INT3(s) -> NOP");
}

uint32_t PEDumper::RvaToOffset(const std::vector<uint8_t>& pe, uint32_t rva) const
{
    auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(pe.data());
    auto* nt  = reinterpret_cast<const IMAGE_NT_HEADERS64*>(pe.data() + dos->e_lfanew);
    auto* sec = IMAGE_FIRST_SECTION(nt);

    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++)
    {
        uint32_t start = sec[i].VirtualAddress;
        uint32_t end   = start + sec[i].SizeOfRawData;
        if (rva >= start && rva < end)
            return sec[i].PointerToRawData + (rva - start);
    }
    return 0;
}

bool PEDumper::EnumModules(std::vector<ModInfo>& out)
{
    uint64_t peb = m_drv.GetPeb();
    if (!peb) { UI::Err("GetPeb() returned 0"); return false; }

    uint64_t ldrPtr = m_drv.Read<uint64_t>(peb + OFF_PEB_LDR);
    if (!ldrPtr) { UI::Err("PEB.Ldr is null"); return false; }

    uint64_t listHead = ldrPtr + OFF_LDR_INLOAD_HEAD;
    uint64_t cur      = m_drv.Read<uint64_t>(listHead);

    while (cur && cur != listHead)
    {
        uint64_t dllBase  = m_drv.Read<uint64_t>(cur + OFF_ENTRY_DLLBASE);
        uint32_t imgSize  = m_drv.Read<uint32_t>(cur + OFF_ENTRY_IMAGESIZE);
        uint16_t nameLen  = m_drv.Read<uint16_t>(cur + OFF_ENTRY_BASELEN);
        uint64_t nameBuf  = m_drv.Read<uint64_t>(cur + OFF_ENTRY_BASEBUF);

        if (dllBase && imgSize && nameLen && nameBuf)
        {
            std::wstring wname(nameLen / sizeof(wchar_t), L'\0');
            m_drv.Read(nameBuf, wname.data(), nameLen);

            std::string name(wname.size(), '\0');
            std::transform(wname.begin(), wname.end(), name.begin(),
                [](wchar_t c) { return static_cast<char>(::tolower(c & 0xFF)); });

            out.push_back({ dllBase, imgSize, name });
        }

        cur = m_drv.Read<uint64_t>(cur); // InLoadOrderLinks.Flink
    }

    UI::Ok("enumerated " + std::to_string(out.size()) + " modules");
    return !out.empty();
}

bool PEDumper::ReadExports(const ModInfo& mod, std::vector<ExportEntry>& out)
{
    if (!mod.base || mod.size < sizeof(IMAGE_DOS_HEADER) || mod.size > 0x40000000)
        return false;

    IMAGE_DOS_HEADER dos{};
    if (!m_drv.Read(mod.base, &dos, sizeof(dos)) || dos.e_magic != IMAGE_DOS_SIGNATURE)
        return false;

    if (dos.e_lfanew < 0x40 || dos.e_lfanew > 0x1000)
        return false;

    IMAGE_NT_HEADERS64 nt{};
    if (!m_drv.Read(mod.base + dos.e_lfanew, &nt, sizeof(nt)) || nt.Signature != IMAGE_NT_SIGNATURE)
        return false;

    if (nt.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
        return false;

    auto& expDataDir = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!expDataDir.VirtualAddress || !expDataDir.Size) return false;
    if (expDataDir.VirtualAddress + expDataDir.Size > mod.size) return false;

    IMAGE_EXPORT_DIRECTORY exp{};
    if (!m_drv.Read(mod.base + expDataDir.VirtualAddress, &exp, sizeof(exp)))
        return false;

    uint32_t numFuncs = exp.NumberOfFunctions;
    uint32_t numNames = exp.NumberOfNames;
    if (numFuncs == 0 || numFuncs > 16384) return false;
    if (numNames > numFuncs)               return false;

    if (!exp.AddressOfFunctions    || exp.AddressOfFunctions    + numFuncs * 4 > mod.size) return false;
    if (numNames && (!exp.AddressOfNames || exp.AddressOfNames  + numNames * 4 > mod.size)) return false;
    if (numNames && (!exp.AddressOfNameOrdinals || exp.AddressOfNameOrdinals + numNames * 2 > mod.size)) return false;

    std::vector<uint32_t> funcRvas(numFuncs, 0);
    std::vector<uint32_t> nameRvas(numNames, 0);
    std::vector<uint16_t> nameOrds(numNames, 0);

    if (!m_drv.Read(mod.base + exp.AddressOfFunctions, funcRvas.data(), numFuncs * sizeof(uint32_t)))
        return false;

    if (numNames)
    {
        m_drv.Read(mod.base + exp.AddressOfNames,        nameRvas.data(), numNames * sizeof(uint32_t));
        m_drv.Read(mod.base + exp.AddressOfNameOrdinals, nameOrds.data(), numNames * sizeof(uint16_t));
    }

    std::unordered_map<uint16_t, std::string> ordIdxToName;
    ordIdxToName.reserve(numNames);
    for (uint32_t i = 0; i < numNames; i++)
    {
        if (!nameRvas[i] || nameRvas[i] > mod.size) continue;
        if (nameOrds[i] >= numFuncs) continue;
        char buf[256]{};
        m_drv.Read(mod.base + nameRvas[i], buf, sizeof(buf) - 1);
        if (buf[0] == '\0') continue;
        ordIdxToName[nameOrds[i]] = buf;
    }

    out.reserve(numFuncs);
    for (uint32_t i = 0; i < numFuncs; i++)
    {
        uint32_t rva = funcRvas[i];
        if (!rva || rva > mod.size) continue;

        // skip forwarders
        if (rva >= expDataDir.VirtualAddress && rva < expDataDir.VirtualAddress + expDataDir.Size)
            continue;

        ExportEntry e;
        e.va      = mod.base + rva;
        e.ordinal = static_cast<uint16_t>(exp.Base + i);
        if (ordIdxToName.count(i)) e.name = ordIdxToName[i];
        out.push_back(e);
    }

    return !out.empty();
}

uint64_t PEDumper::FollowTrampoline(uint64_t va, uint64_t moduleBase, uint32_t moduleSize, int maxDepth)
{
    if (maxDepth <= 0 || !va) return 0;

    if (va < moduleBase || va >= moduleBase + moduleSize)
        return va;

    uint8_t buf[16]{};
    if (!m_drv.Read(va, buf, sizeof(buf)))
        return 0;

    if (buf[0] == 0xFF && buf[1] == 0x25)
    {
        int32_t  disp    = *reinterpret_cast<int32_t*>(buf + 2);
        uint64_t ptrAddr = va + 6 + disp;
        uint64_t target  = m_drv.Read<uint64_t>(ptrAddr);
        return FollowTrampoline(target, moduleBase, moduleSize, maxDepth - 1);
    }

    if (buf[0] == 0x48 && buf[1] == 0xFF && buf[2] == 0x25)
    {
        int32_t  disp    = *reinterpret_cast<int32_t*>(buf + 3);
        uint64_t ptrAddr = va + 7 + disp;
        uint64_t target  = m_drv.Read<uint64_t>(ptrAddr);
        return FollowTrampoline(target, moduleBase, moduleSize, maxDepth - 1);
    }

    if (buf[0] == 0xE9)
    {
        int32_t  rel    = *reinterpret_cast<int32_t*>(buf + 1);
        uint64_t target = va + 5 + rel;
        return FollowTrampoline(target, moduleBase, moduleSize, maxDepth - 1);
    }

    if (buf[0] == 0xEB)
    {
        int8_t   rel    = static_cast<int8_t>(buf[1]);
        uint64_t target = va + 2 + rel;
        return FollowTrampoline(target, moduleBase, moduleSize, maxDepth - 1);
    }

    if (buf[0] == 0x48 && buf[1] == 0xB8 && buf[10] == 0xFF && buf[11] == 0xE0)
    {
        uint64_t target = *reinterpret_cast<uint64_t*>(buf + 2);
        return FollowTrampoline(target, moduleBase, moduleSize, maxDepth - 1);
    }

    return 0;
}

uint32_t PEDumper::DetectRealOEP(const std::vector<uint8_t>& pe, uint64_t base)
{
    auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(pe.data());
    auto* nt  = reinterpret_cast<const IMAGE_NT_HEADERS64*>(pe.data() + dos->e_lfanew);

    uint32_t epRva     = nt->OptionalHeader.AddressOfEntryPoint;
    uint32_t imageSize = nt->OptionalHeader.SizeOfImage;
    if (!epRva) return 0;

    auto* sec = IMAGE_FIRST_SECTION(nt);
    bool inTempest = false;
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++)
    {
        const char* name = reinterpret_cast<const char*>(sec[i].Name);
        if (strncmp(name, "tempest", 7) == 0)
        {
            uint32_t s = sec[i].VirtualAddress;
            uint32_t e = s + sec[i].Misc.VirtualSize;
            if (epRva >= s && epRva < e) { inTempest = true; break; }
        }
    }
    if (!inTempest) return 0;

    uint32_t epOff = RvaToOffset(pe, epRva);
    if (!epOff || epOff + 32 > pe.size()) return 0;
    const uint8_t* b = pe.data() + epOff;

    uint64_t targetVa = 0;

    // 48 B8 [imm64] FF E0   =>  mov rax, imm64 / jmp rax
    if (b[0] == 0x48 && b[1] == 0xB8 && b[10] == 0xFF && b[11] == 0xE0)
        memcpy(&targetVa, b + 2, 8);
    // 68 [lo32] C7 44 24 04 [hi32] C3   =>  push lo; mov [rsp+4], hi; ret
    else if (b[0] == 0x68 && b[5] == 0xC7 && b[6] == 0x44 && b[7] == 0x24 && b[8] == 0x04 && b[13] == 0xC3)
    {
        uint32_t lo, hi;
        memcpy(&lo, b + 1, 4);
        memcpy(&hi, b + 9, 4);
        targetVa = (static_cast<uint64_t>(hi) << 32) | lo;
    }
    // E9 [rel32]   =>  jmp rel32
    else if (b[0] == 0xE9)
    {
        int32_t rel;
        memcpy(&rel, b + 1, 4);
        targetVa = (base + epRva) + 5 + static_cast<uint64_t>(static_cast<int64_t>(rel));
    }
    // FF 25 [disp32]   =>  jmp [rip+disp32]
    else if (b[0] == 0xFF && b[1] == 0x25)
    {
        int32_t disp;
        memcpy(&disp, b + 2, 4);
        uint64_t ptrVa = (base + epRva) + 6 + static_cast<uint64_t>(static_cast<int64_t>(disp));
        if (ptrVa > base && ptrVa - base < imageSize)
        {
            uint32_t ptrOff = RvaToOffset(pe, static_cast<uint32_t>(ptrVa - base));
            if (ptrOff && ptrOff + 8 <= pe.size())
                memcpy(&targetVa, pe.data() + ptrOff, 8);
        }
    }

    if (targetVa && targetVa > base && targetVa < base + imageSize)
    {
        uint32_t rva = static_cast<uint32_t>(targetVa - base);
        UI::Ok("OEP auto-detected: RVA " + UI::Hex(rva) + " (tempest stub target)");
        return rva;
    }

    // strategy 2: find WinMain by locating the function that calls GetCommandLineA/W
    // works for Hyperion where the tempest stub jumps to Windows CRT, not directly to OEP
    uint32_t cmdLineSlotRva = 0;
    for (auto& slot : m_importSlots)
    {
        std::string fn = slot.func;
        if (!fn.empty() && fn[0] == '~') fn = fn.substr(1);
        if (fn == "GetCommandLineA" || fn == "GetCommandLineW")
        {
            cmdLineSlotRva = slot.rva;
            break;
        }
    }

    if (!cmdLineSlotRva)
    {
        UI::Warn("OEP detection: GetCommandLineA/W not in resolved imports, skipping scan");
        return 0;
    }

    // find the first code section to scan
    auto* dos2 = reinterpret_cast<const IMAGE_DOS_HEADER*>(pe.data());
    auto* nt2  = reinterpret_cast<const IMAGE_NT_HEADERS64*>(pe.data() + dos2->e_lfanew);
    auto* sec2 = IMAGE_FIRST_SECTION(nt2);

    uint32_t textOff = 0, textEnd = 0;
    for (int i = 0; i < nt2->FileHeader.NumberOfSections; i++)
    {
        if (sec2[i].Characteristics & IMAGE_SCN_CNT_CODE)
        {
            textOff = sec2[i].PointerToRawData;
            textEnd = sec2[i].PointerToRawData + sec2[i].SizeOfRawData;
            break;
        }
    }

    if (!textOff || textEnd <= textOff) return 0;

    const uint8_t* buf2 = pe.data();
    uint32_t       hits = 0;
    uint32_t       oepRva = 0;

    for (uint32_t i = textOff; i + 6 <= textEnd; i++)
    {
        if (buf2[i] != 0xFF || buf2[i + 1] != 0x15) continue;
        int32_t disp;
        memcpy(&disp, buf2 + i + 2, 4);
        uint32_t instrRva = i; // offset == rva after FixSections
        uint32_t refRva   = instrRva + 6 + static_cast<uint32_t>(static_cast<int64_t>(disp));
        if (refRva != cmdLineSlotRva) continue;

        // walk backwards up to 4KB to find function start (INT3/NOP/zero padding boundary)
        uint32_t limit = (i > 0x1000) ? i - 0x1000 : textOff;
        uint32_t fnOff = i;
        for (uint32_t j = i; j > limit + 4; j--)
        {
            uint8_t p0 = buf2[j], p1 = buf2[j-1], p2 = buf2[j-2], p3 = buf2[j-3];
            bool isPad = (p0 == 0xCC || p0 == 0x90 || p0 == 0x00) &&
                         (p1 == 0xCC || p1 == 0x90 || p1 == 0x00) &&
                         (p2 == 0xCC || p2 == 0x90 || p2 == 0x00) &&
                         (p3 == 0xCC || p3 == 0x90 || p3 == 0x00);
            if (isPad)
            {
                uint32_t after = j + 1;
                while (after < i && (buf2[after] == 0xCC || buf2[after] == 0x90 || buf2[after] == 0x00))
                    after++;
                fnOff = (after + 15) & ~15u; // snap to 16-byte alignment
                break;
            }
        }

        hits++;
        oepRva = fnOff;
        UI::Ok("OEP auto-detected: RVA " + UI::Hex(oepRva) + " (GetCommandLine scan, hit " + std::to_string(hits) + ")");

        if (hits == 1) break; // take the first match - WinMain calls it first
    }

    return oepRva;
}

bool PEDumper::RebuildIAT(std::vector<uint8_t>& pe, uint64_t base)
{
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(pe.data());
    auto* nt  = reinterpret_cast<IMAGE_NT_HEADERS64*>(pe.data() + dos->e_lfanew);

    std::vector<ModInfo> mods;
    if (!EnumModules(mods)) return false;

    std::unordered_map<uint64_t, std::vector<ExportEntry>> exportCache;

    {
        int total = static_cast<int>(mods.size());
        for (int i = 0; i < total; i++)
        {
            auto& mod = mods[i];
            UI::Progress(i, total, mod.name);
            if (!exportCache.count(mod.base))
                ReadExports(mod, exportCache[mod.base]);
        }
        UI::Progress(total, total, "done");
    }

    struct Resolved { std::string mod, func; uint16_t ord; bool approximate; };
    std::unordered_map<uint64_t, Resolved> vaMap;
    vaMap.reserve(65536);
    for (auto& mod : mods)
        for (auto& e : exportCache[mod.base])
            vaMap[e.va] = { mod.name, e.name, e.ordinal, false };

    std::vector<std::pair<uint64_t, Resolved>> sortedExports(vaMap.begin(), vaMap.end());
    std::sort(sortedExports.begin(), sortedExports.end(),
        [](auto& a, auto& b) { return a.first < b.first; });

    auto nearestExport = [&](uint64_t va) -> const Resolved*
    {
        if (sortedExports.empty()) return nullptr;
        auto it = std::lower_bound(sortedExports.begin(), sortedExports.end(),
            std::make_pair(va, Resolved{}),
            [](auto& a, auto& b) { return a.first < b.first; });
        if (it != sortedExports.begin()) --it;
        if (va >= it->first && va - it->first <= 256) return &it->second;
        return nullptr;
    };

    UI::Ok("export map built (" + std::to_string(vaMap.size()) + " entries)");

    struct IATSlot { uint32_t rva; };
    std::vector<IATSlot> slots;

    auto& iatDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT];
    auto& impDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

    auto collectRange = [&](uint32_t rva, uint32_t size)
    {
        uint32_t off = RvaToOffset(pe, rva);
        if (!off || off + size > pe.size()) return;
        for (uint32_t j = 0; j + 8 <= size; j += 8)
            slots.push_back({ rva + j });
    };

    enum class ScanMode { Directory, Descriptors, BruteForce };
    ScanMode mode = ScanMode::BruteForce;

    if (iatDir.VirtualAddress && iatDir.Size)
    {
        mode = ScanMode::Directory;
        collectRange(iatDir.VirtualAddress, iatDir.Size);
    }
    else if (impDir.VirtualAddress && impDir.Size)
    {
        mode = ScanMode::Descriptors;
        uint32_t off = RvaToOffset(pe, impDir.VirtualAddress);
        if (off)
        {
            auto* desc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(pe.data() + off);
            while (desc->FirstThunk && off + sizeof(*desc) <= pe.size())
            {
                uint32_t thunkOff = RvaToOffset(pe, desc->FirstThunk);
                if (thunkOff)
                {
                    auto* thunk = reinterpret_cast<uint64_t*>(pe.data() + thunkOff);
                    uint32_t cnt = 0;
                    while (thunk[cnt]) cnt++;
                    collectRange(desc->FirstThunk, (cnt + 1) * 8);
                }
                desc++;
            }
        }
    }

    struct GroupedImport
    {
        std::string              modName;
        std::vector<ImportEntry> entries;
    };
    std::map<std::string, GroupedImport> groups;

    auto resolveSlots = [&]()
    {
        groups.clear();
        for (auto& slot : slots)
        {
            uint32_t off = RvaToOffset(pe, slot.rva);
            if (!off || off + 8 > pe.size()) continue;

            uint64_t va = *reinterpret_cast<uint64_t*>(pe.data() + off);
            if (!va) continue;

            auto tryAdd = [&](const Resolved& r, uint32_t iatRva)
            {
                auto& g = groups[r.mod];
                g.modName = r.mod;
                g.entries.push_back({ iatRva, r.func, r.ord });
            };

            auto it = vaMap.find(va);
            if (it != vaMap.end()) { tryAdd(it->second, slot.rva); continue; }

            uint64_t resolved = FollowTrampoline(va, base, nt->OptionalHeader.SizeOfImage);
            if (resolved)
            {
                it = vaMap.find(resolved);
                if (it != vaMap.end()) { tryAdd(it->second, slot.rva); continue; }
            }

            const Resolved* nr = nearestExport(va);
            if (!nr && resolved) nr = nearestExport(resolved);
            if (nr)
            {
                Resolved approx = *nr;
                approx.approximate = true;
                if (!approx.func.empty()) approx.func = "~" + approx.func;
                tryAdd(approx, slot.rva);
            }
        }
    };

    if (!slots.empty())
    {
        const char* modeStr = (mode == ScanMode::Directory) ? "IAT data directory" : "import descriptor walk";
        UI::Info(std::string("trying ") + modeStr + " (" + std::to_string(slots.size()) + " slots)");
        m_stats.slotsCollected = static_cast<uint32_t>(slots.size());
        resolveSlots();

        if (groups.empty())
        {
            UI::Warn("directory slots didn't resolve, likely stub-redirected IAT");
            int shown = 0;
            for (auto& slot : slots)
            {
                if (shown++ >= 4) break;
                uint32_t off = RvaToOffset(pe, slot.rva);
                if (!off || off + 8 > pe.size()) continue;
                uint64_t va = *reinterpret_cast<uint64_t*>(pe.data() + off);
                UI::Sub("slot " + UI::Hex(slot.rva) + " -> " + UI::Hex(va));
            }
            slots.clear();
        }
    }

    if (groups.empty())
    {
        bool hasHyperion = false;
        {
            auto* chkSec = IMAGE_FIRST_SECTION(nt);
            for (int i = 0; i < nt->FileHeader.NumberOfSections; i++)
            {
                const char* n = reinterpret_cast<const char*>(chkSec[i].Name);
                if (strncmp(n, ".byfron", 7) == 0 || strncmp(n, "tempest", 7) == 0)
                { hasHyperion = true; break; }
            }
        }

        if (hasHyperion)
            UI::Warn("Hyperion/Byfron detected, IAT intentionally wiped at load time");

        UI::Info("scanning full image for FF15/48FF25 patterns (Vulkan method)...");

        uint32_t diagTotal = 0, diagValidPtr = 0, diagNonZero = 0, diagInRange = 0;

        struct ModRange { uint64_t lo, hi; };
        std::vector<ModRange> modRanges;
        modRanges.reserve(mods.size());
        for (auto& m : mods)
        {
            if (m.base == base) continue;
            modRanges.push_back({ m.base, m.base + m.size });
        }
        std::sort(modRanges.begin(), modRanges.end(),
            [](const ModRange& a, const ModRange& b) { return a.lo < b.lo; });

        auto inAnyMod = [&](uint64_t va) -> bool
        {
            if (modRanges.empty()) return false;
            auto it = std::upper_bound(modRanges.begin(), modRanges.end(), va,
                [](uint64_t v, const ModRange& r) { return v < r.lo; });
            if (it == modRanges.begin()) return false;
            --it;
            return va < it->hi;
        };

        uint64_t selfLo = base;
        uint64_t selfHi = base + nt->OptionalHeader.SizeOfImage;

        static constexpr uint64_t USER_HI = 0x00007FFFFFFFFFFFULL;

        struct Pattern { uint8_t b0, b1, b2; uint32_t dispOff; uint32_t instrLen; };
        static constexpr Pattern patterns[] = {
            { 0xFF, 0x15, 0x00, 2, 6 },  // CALL [RIP+d32]
            { 0x48, 0xFF, 0x25, 3, 7 },  // REX JMP [RIP+d32]
            { 0x48, 0x8B, 0x05, 3, 7 },  // MOV RAX,[RIP+d32]
            { 0x48, 0x8B, 0x0D, 3, 7 },  // MOV RCX,[RIP+d32]
            { 0x48, 0x8B, 0x15, 3, 7 },  // MOV RDX,[RIP+d32]
            { 0x48, 0x8B, 0x1D, 3, 7 },  // MOV RBX,[RIP+d32]
            { 0x48, 0x8B, 0x2D, 3, 7 },  // MOV RBP,[RIP+d32]
            { 0x48, 0x8B, 0x35, 3, 7 },  // MOV RSI,[RIP+d32]
            { 0x48, 0x8B, 0x3D, 3, 7 },  // MOV RDI,[RIP+d32]
            { 0x4C, 0x8B, 0x05, 3, 7 },  // MOV R8,[RIP+d32]
            { 0x4C, 0x8B, 0x0D, 3, 7 },  // MOV R9,[RIP+d32]
            { 0x4C, 0x8B, 0x15, 3, 7 },  // MOV R10,[RIP+d32]
            { 0x4C, 0x8B, 0x1D, 3, 7 },  // MOV R11,[RIP+d32]
            { 0x4C, 0x8B, 0x25, 3, 7 },  // MOV R12,[RIP+d32]
            { 0x4C, 0x8B, 0x2D, 3, 7 },  // MOV R13,[RIP+d32]
            { 0x4C, 0x8B, 0x35, 3, 7 },  // MOV R14,[RIP+d32]
            { 0x4C, 0x8B, 0x3D, 3, 7 },  // MOV R15,[RIP+d32]
            { 0x48, 0x89, 0x05, 3, 7 },  // MOV [RIP+d32],RAX
            { 0x48, 0x89, 0x0D, 3, 7 },  // MOV [RIP+d32],RCX
            { 0x48, 0x89, 0x15, 3, 7 },  // MOV [RIP+d32],RDX
            { 0x48, 0x89, 0x1D, 3, 7 },  // MOV [RIP+d32],RBX
            { 0x4C, 0x89, 0x05, 3, 7 },  // MOV [RIP+d32],R8
            { 0x4C, 0x89, 0x0D, 3, 7 },  // MOV [RIP+d32],R9
            { 0x4C, 0x89, 0x15, 3, 7 },  // MOV [RIP+d32],R10
            { 0x4C, 0x89, 0x1D, 3, 7 },  // MOV [RIP+d32],R11
        };

        std::unordered_set<uint32_t> seenSlots;

        const uint8_t* buf = pe.data();
        const uint32_t  sz  = static_cast<uint32_t>(pe.size());

        for (uint32_t i = 0; i + 7 < sz; i++)
        {
            for (auto& pat : patterns)
            {
                if (buf[i] != pat.b0 || buf[i+1] != pat.b1 || buf[i+2] != pat.b2) continue;
                if (i + pat.instrLen > sz) continue;

                diagTotal++;

                // offset == rva after FixSections
                uint32_t instrRva = i;
                int32_t  disp     = *reinterpret_cast<const int32_t*>(buf + i + pat.dispOff);
                uint32_t ptrRva   = instrRva + pat.instrLen + static_cast<uint32_t>(disp);
                uint32_t ptrOff   = RvaToOffset(pe, ptrRva);
                if (!ptrOff || ptrOff + 8 > sz) continue;

                diagValidPtr++;

                uint64_t fnVa = *reinterpret_cast<const uint64_t*>(buf + ptrOff);
                if (!fnVa) continue;
                diagNonZero++;

                if (fnVa > USER_HI) continue;
                if (fnVa >= selfLo && fnVa < selfHi) continue;
                if (!inAnyMod(fnVa)) continue;
                diagInRange++;

                uint64_t resolved = fnVa;
                bool found = vaMap.count(resolved) > 0;
                if (!found)
                {
                    resolved = FollowTrampoline(fnVa, base, nt->OptionalHeader.SizeOfImage);
                    found = resolved && vaMap.count(resolved) > 0;
                }
                if (!found)
                {
                    const Resolved* nr2 = nearestExport(fnVa);
                    if (!nr2 && resolved) nr2 = nearestExport(resolved);
                    if (!nr2) continue;
                }

                if (seenSlots.insert(ptrRva).second)
                    slots.push_back({ ptrRva });

                break;
            }
        }

        m_stats.ff15Total    = diagTotal;
        m_stats.ff15SysRange = diagInRange;

        UI::Sub("FF15/MOV patterns: " + std::to_string(diagTotal) +
                "  valid ptr: " + std::to_string(diagValidPtr) +
                "  non-zero: " + std::to_string(diagNonZero) +
                "  in mod range: " + std::to_string(diagInRange) +
                "  collected: " + std::to_string(slots.size()));

        {
            UI::Info("scanning full image for cached import pointers...");
            uint32_t dataHits = 0, dataBefore = static_cast<uint32_t>(slots.size());

            struct SecRange { uint32_t start, end; bool isCode; };
            std::vector<SecRange> secRanges;
            {
                auto* scanSec = IMAGE_FIRST_SECTION(nt);
                for (int si = 0; si < nt->FileHeader.NumberOfSections; si++)
                {
                    uint32_t flags = scanSec[si].Characteristics;
                    if (!(flags & IMAGE_SCN_MEM_READ)) continue;
                    uint32_t start = scanSec[si].VirtualAddress;
                    uint32_t end   = start + scanSec[si].Misc.VirtualSize;
                    bool isCode    = !!(flags & IMAGE_SCN_CNT_CODE);
                    secRanges.push_back({ start, end, isCode });
                }
            }

            for (uint32_t j = 0; j + 8 <= sz; j += 8)
            {
                uint64_t val = *reinterpret_cast<const uint64_t*>(buf + j);
                if (val > USER_HI) continue;
                if (val >= selfLo && val < selfHi) continue;
                if (!inAnyMod(val)) continue;
                if (seenSlots.count(j)) continue;

                bool inCode = false;
                bool inAnySection = false;
                for (auto& sr : secRanges)
                {
                    if (j >= sr.start && j < sr.end)
                    {
                        inAnySection = true;
                        inCode = sr.isCode;
                        break;
                    }
                }
                if (!inAnySection) continue;

                uint64_t res2 = val;
                bool exactHit = vaMap.count(res2) > 0;
                if (!exactHit)
                {
                    res2     = FollowTrampoline(val, base, nt->OptionalHeader.SizeOfImage);
                    exactHit = res2 && vaMap.count(res2) > 0;
                }
                if (!exactHit)
                {
                    if (inCode) continue;
                    const Resolved* nr3 = nearestExport(val);
                    if (!nr3 && res2) nr3 = nearestExport(res2);
                    if (!nr3) continue;
                }

                seenSlots.insert(j);
                slots.push_back({ j });
                dataHits++;
            }

            uint32_t dataAdded = static_cast<uint32_t>(slots.size()) - dataBefore;
            UI::Sub("full-image scan hits: " + std::to_string(dataHits) +
                    "  resolvable: " + std::to_string(dataAdded));
        }

        if (slots.empty())
        {
            if (hasHyperion)
            {
                UI::Err("Hyperion custom IAT not resolved");
                UI::Sub("if high page fail count: code pages are still encrypted");
                UI::Sub("try dumping after full game init");
            }
            else
            {
                UI::Err("no resolvable import pointers found");
            }
            return false;
        }

        UI::Ok("found " + std::to_string(slots.size()) + " unique IAT slot(s)");
        m_stats.slotsCollected = static_cast<uint32_t>(slots.size());
        resolveSlots();
    }

    if (groups.empty()) { UI::Err("zero imports resolved after all strategies"); return false; }

    for (auto& [k, g] : groups)
        for (auto& e : g.entries)
        {
            if (!e.func.empty() && e.func[0] == '~') m_stats.importsNear++;
            else                                      m_stats.importsExact++;
            m_importSlots.push_back({ e.iatRva, g.modName, e.func, e.ordinal });
        }
    m_stats.importModules = static_cast<uint32_t>(groups.size());

    UI::Ok("resolved imports from " + std::to_string(groups.size()) + " module(s)");
    for (auto& [k, g] : groups)
    {
        uint32_t ex = 0, ap = 0;
        for (auto& e : g.entries) { if (!e.func.empty() && e.func[0] == '~') ap++; else ex++; }
        std::string detail = std::to_string(ex) + " exact";
        if (ap) detail += " + " + std::to_string(ap) + " approx";
        UI::Sub(k + ": " + detail);
    }

    uint32_t numMods   = static_cast<uint32_t>(groups.size());
    uint32_t descBytes = (numMods + 1) * sizeof(IMAGE_IMPORT_DESCRIPTOR);

    uint32_t intBytes = 0;
    for (auto& [k, g] : groups)
        intBytes += static_cast<uint32_t>((g.entries.size() + 1) * sizeof(uint64_t));

    uint32_t nameBytes = 0;
    for (auto& [k, g] : groups)
    {
        for (auto& e : g.entries)
            if (!e.func.empty())
                nameBytes += static_cast<uint32_t>(sizeof(uint16_t) + e.func.size() + 1);
        nameBytes += static_cast<uint32_t>(g.modName.size() + 1);
    }

    uint32_t secAlign  = nt->OptionalHeader.SectionAlignment;
    uint32_t rawTotal  = AlignUp(descBytes + intBytes + nameBytes, secAlign);

    auto* sec          = IMAGE_FIRST_SECTION(nt);
    uint32_t lastSecEnd = 0;
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++)
    {
        uint32_t end = sec[i].VirtualAddress + AlignUp(sec[i].Misc.VirtualSize, secAlign);
        lastSecEnd   = max(lastSecEnd, end);
    }
    uint32_t newSecRva = AlignUp(lastSecEnd, secAlign);

    if (nt->FileHeader.NumberOfSections >= 96)
    {
        std::cerr << "[!] section table full, can't add .idat\n";
        return false;
    }

    std::vector<uint8_t> secBuf(rawTotal, 0);

    uint32_t intCursor  = descBytes;
    uint32_t nameCursor = descBytes + intBytes;

    uint32_t descIdx = 0;
    for (auto& [k, g] : groups)
    {
        auto* d = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(secBuf.data() + descIdx * sizeof(IMAGE_IMPORT_DESCRIPTOR));

        d->OriginalFirstThunk = newSecRva + intCursor;
        d->FirstThunk = g.entries[0].iatRva;

        auto* intArr = reinterpret_cast<uint64_t*>(secBuf.data() + intCursor);
        uint32_t ei = 0;
        for (auto& e : g.entries)
        {
            if (!e.func.empty())
            {
                auto* ibn = reinterpret_cast<uint16_t*>(secBuf.data() + nameCursor);
                *ibn = e.ordinal; // hint
                memcpy(secBuf.data() + nameCursor + sizeof(uint16_t), e.func.c_str(), e.func.size() + 1);
                intArr[ei] = static_cast<uint64_t>(newSecRva + nameCursor);
                nameCursor += static_cast<uint32_t>(sizeof(uint16_t) + e.func.size() + 1);
            }
            else
            {
                intArr[ei] = (static_cast<uint64_t>(1) << 63) | e.ordinal; // ordinal flag
            }
            ei++;
        }
        intCursor += static_cast<uint32_t>((g.entries.size() + 1) * sizeof(uint64_t));

        memcpy(secBuf.data() + nameCursor, g.modName.c_str(), g.modName.size() + 1);
        d->Name = newSecRva + nameCursor;
        nameCursor += static_cast<uint32_t>(g.modName.size() + 1);

        descIdx++;
    }

    pe.resize(newSecRva + rawTotal, 0);
    memcpy(pe.data() + newSecRva, secBuf.data(), secBuf.size());

    // re-derive after resize (buffer may have moved)
    dos = reinterpret_cast<IMAGE_DOS_HEADER*>(pe.data());
    nt  = reinterpret_cast<IMAGE_NT_HEADERS64*>(pe.data() + dos->e_lfanew);
    sec = IMAGE_FIRST_SECTION(nt);

    uint16_t& numSec = nt->FileHeader.NumberOfSections;
    IMAGE_SECTION_HEADER& newHdr = sec[numSec];
    memset(&newHdr, 0, sizeof(newHdr));
    memcpy(newHdr.Name, ".idat\0\0\0", 8);
    newHdr.Misc.VirtualSize    = rawTotal;
    newHdr.VirtualAddress      = newSecRva;
    newHdr.SizeOfRawData       = rawTotal;
    newHdr.PointerToRawData    = newSecRva;
    newHdr.Characteristics     = IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA;
    numSec++;

    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = newSecRva;
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size =
        (numMods + 1) * sizeof(IMAGE_IMPORT_DESCRIPTOR);

    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT] = { 0, 0 };
    nt->OptionalHeader.SizeOfImage = AlignUp(newSecRva + rawTotal, secAlign);

    UI::Ok(".idat appended at RVA " + UI::Hex(newSecRva));
    return true;
}
