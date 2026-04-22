#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include <cstdint>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <iostream>
#include <algorithm>

// ANSI via ENABLE_VIRTUAL_TERMINAL_PROCESSING (Win10 1607+)
namespace Ansi
{
    constexpr const char* Reset   = "\x1b[0m";
    constexpr const char* Bold    = "\x1b[1m";
    constexpr const char* Dim     = "\x1b[2m";

    constexpr const char* Black   = "\x1b[30m";
    constexpr const char* Red     = "\x1b[31m";
    constexpr const char* Green   = "\x1b[32m";
    constexpr const char* Yellow  = "\x1b[33m";
    constexpr const char* Blue    = "\x1b[34m";
    constexpr const char* Magenta = "\x1b[35m";
    constexpr const char* Cyan    = "\x1b[36m";
    constexpr const char* White   = "\x1b[37m";

    constexpr const char* BrBlack   = "\x1b[90m";
    constexpr const char* BrRed     = "\x1b[91m";
    constexpr const char* BrGreen   = "\x1b[92m";
    constexpr const char* BrYellow  = "\x1b[93m";
    constexpr const char* BrBlue    = "\x1b[94m";
    constexpr const char* BrMagenta = "\x1b[95m";
    constexpr const char* BrCyan    = "\x1b[96m";
    constexpr const char* BrWhite   = "\x1b[97m";

    inline void Enable()
    {
        HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
        DWORD mode = 0;
        GetConsoleMode(h, &mode);
        SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
    }

    inline void ClearLine()  { std::cout << "\x1b[2K\r"; }
    inline void CursorUp(int n = 1) { std::cout << "\x1b[" << n << "A"; }
}

namespace UI
{
    // -----------------------------------------------------------------------
    // tag helpers
    // -----------------------------------------------------------------------
    inline void Ok(const std::string& msg)
    {
        std::cout << Ansi::BrGreen << "  [+] " << Ansi::White << msg << Ansi::Reset << "\n";
    }
    inline void Warn(const std::string& msg)
    {
        std::cout << Ansi::BrYellow << "  [!] " << Ansi::White << msg << Ansi::Reset << "\n";
    }
    inline void Err(const std::string& msg)
    {
        std::cout << Ansi::BrRed << "  [-] " << Ansi::White << msg << Ansi::Reset << "\n";
    }
    inline void Info(const std::string& msg)
    {
        std::cout << Ansi::BrCyan << "  [*] " << Ansi::White << msg << Ansi::Reset << "\n";
    }
    inline void Sub(const std::string& msg)
    {
        std::cout << Ansi::BrBlack << "   |  " << Ansi::Reset << msg << "\n";
    }

    // progress bar - call repeatedly, prints on same line
    // usage: for (int i = 0; i <= total; i++) { Progress(i, total, label); }
    inline void Progress(int cur, int total, const std::string& label, int barW = 36)
    {
        float pct  = total > 0 ? (float)cur / total : 1.0f;
        int   fill = static_cast<int>(pct * barW);

        // truncate label so total line width stays predictable (avoids leftover chars on \r)
        std::string lbl = label.size() > 28 ? label.substr(0, 28) : label;
        lbl.resize(28, ' '); // pad to fixed width so overwrite is clean

        std::cout << "\r" << Ansi::BrBlack << "  [" << Ansi::BrCyan;
        for (int i = 0; i < barW; i++)
            std::cout << (i < fill ? '=' : (i == fill ? '>' : ' '));
        std::cout << Ansi::BrBlack << "] "
                  << Ansi::BrWhite << std::setw(3) << (int)(pct * 100) << "% "
                  << Ansi::BrBlack << lbl
                  << Ansi::Reset << std::flush;

        if (cur >= total) std::cout << "\n";
    }

    inline void Sep(char c = '-', int w = 60)
    {
        std::cout << Ansi::BrBlack;
        for (int i = 0; i < w; i++) std::cout << c;
        std::cout << Ansi::Reset << "\n";
    }

    inline void Banner()
    {
        std::cout << "\n";
        std::cout << Ansi::BrCyan << Ansi::Bold;
        std::cout << "  ██████╗ ██╗   ██╗███╗   ███╗██████╗ \n";
        std::cout << "  ██╔══██╗██║   ██║████╗ ████║██╔══██╗\n";
        std::cout << "  ██║  ██║██║   ██║██╔████╔██║██████╔╝\n";
        std::cout << "  ██║  ██║██║   ██║██║╚██╔╝██║██╔═══╝ \n";
        std::cout << "  ██████╔╝╚██████╔╝██║ ╚═╝ ██║██║     \n";
        std::cout << "  ╚═════╝  ╚═════╝ ╚═╝     ╚═╝╚═╝     \n";
        std::cout << Ansi::Reset;
        std::cout << Ansi::BrBlack << "  kernel-assisted PE dumper\n" << Ansi::Reset;
        std::cout << "\n";
    }

    // -----------------------------------------------------------------------
    // hex formatting
    // -----------------------------------------------------------------------
    inline std::string Hex(uint64_t v, int w = 0)
    {
        std::ostringstream ss;
        ss << "0x" << std::uppercase << std::hex;
        if (w) ss << std::setw(w) << std::setfill('0');
        ss << v;
        return ss.str();
    }

    // -----------------------------------------------------------------------
    // prompt
    // -----------------------------------------------------------------------
    inline std::string Prompt(const std::string& label, const std::string& defaultVal = "")
    {
        std::cout << Ansi::BrYellow << "  > " << Ansi::White << label;
        if (!defaultVal.empty())
            std::cout << Ansi::BrBlack << " [" << defaultVal << "]";
        std::cout << Ansi::BrYellow << ": " << Ansi::BrWhite;
        std::string input;
        std::getline(std::cin, input);
        std::cout << Ansi::Reset;
        return input.empty() ? defaultVal : input;
    }

    inline bool YesNo(const std::string& label, bool def = true)
    {
        std::string d = def ? "Y/n" : "y/N";
        std::string r = Prompt(label, d);
        if (r == "Y/n" || r == "y/N") return def;
        return r == "y" || r == "Y" || r == "yes" || r == "Yes";
    }

    // -----------------------------------------------------------------------
    // process list picker
    // -----------------------------------------------------------------------
    struct ProcEntry
    {
        uint32_t    pid;
        std::string name;
    };

    inline std::vector<ProcEntry> ListProcesses(const std::string& filter = "")
    {
        std::vector<ProcEntry> out;
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE) return out;

        PROCESSENTRY32 e;
        e.dwSize = sizeof(e);
        if (Process32First(snap, &e))
        {
            do
            {
                size_t len = wcslen(e.szExeFile);
                std::string name(len, '\0');
                std::transform(e.szExeFile, e.szExeFile + len, name.begin(),
                    [](wchar_t c) { return static_cast<char>(c & 0xFF); });
                if (filter.empty() ||
                    name.find(filter) != std::string::npos)
                {
                    out.push_back({ e.th32ProcessID, name });
                }
            } while (Process32Next(snap, &e));
        }
        CloseHandle(snap);
        return out;
    }

    // show a filterable process list, return selected name or empty
    inline std::string PickProcess()
    {
        while (true)
        {
            std::string filter = Prompt("filter process name (empty = show all)");
            auto procs = ListProcesses(filter);

            if (procs.empty())
            {
                Warn("no matching processes");
                continue;
            }

            std::cout << "\n";
            Sep();
            std::cout << Ansi::BrBlack << "  "
                      << std::left << std::setw(8)  << "PID"
                      << std::setw(36) << "Name"
                      << Ansi::Reset << "\n";
            Sep();

            int idx = 1;
            for (auto& p : procs)
            {
                std::cout << Ansi::BrBlack  << "  [" << std::setw(2) << idx << "] "
                          << Ansi::BrCyan   << std::left << std::setw(8) << p.pid
                          << Ansi::BrWhite  << p.name
                          << Ansi::Reset    << "\n";
                idx++;
            }
            Sep();
            std::cout << "\n";

            std::string sel = Prompt("select # or type name");
            if (sel.empty()) continue;

            // numeric index
            bool isNum = std::all_of(sel.begin(), sel.end(), ::isdigit);
            if (isNum)
            {
                int n = std::stoi(sel);
                if (n >= 1 && n <= (int)procs.size())
                    return procs[n - 1].name;
                Warn("out of range");
                continue;
            }

            // direct name match
            for (auto& p : procs)
                if (p.name == sel) return p.name;

            Warn("no match, try again");
        }
    }

    // -----------------------------------------------------------------------
    // presets
    // -----------------------------------------------------------------------
    enum class Preset { None, Roblox };

    inline Preset PickPreset()
    {
        std::cout << "\n";
        std::cout << Ansi::BrBlack << "  [1] " << Ansi::BrCyan << "Roblox"
                  << Ansi::BrBlack << "  (RobloxPlayerBeta.exe)\n";
        std::cout << Ansi::BrBlack << "  [2] " << Ansi::BrWhite << "manual\n";
        std::cout << "\n" << Ansi::Reset;

        std::string sel = Prompt("preset");
        if (sel == "1" || sel == "roblox" || sel == "Roblox" || sel == "r")
            return Preset::Roblox;
        return Preset::None;
    }

    // -----------------------------------------------------------------------
    // config struct shown to user
    // -----------------------------------------------------------------------
    struct DumpConfig
    {
        std::string procName;
        std::string outPath;
        uint32_t    oepRva       = 0;
        bool        preTouch     = true;
        bool        patchInt3s   = true;
        bool        rebuildIAT   = true;
    };

    inline void PrintConfig(const DumpConfig& cfg)
    {
        Sep();
        std::cout << Ansi::BrBlack << "  target    " << Ansi::BrWhite << cfg.procName << "\n";
        std::cout << Ansi::BrBlack << "  output    " << Ansi::BrWhite << cfg.outPath  << "\n";
        std::cout << Ansi::BrBlack << "  OEP RVA   " << Ansi::BrYellow
                  << (cfg.oepRva ? Hex(cfg.oepRva) : "auto") << "\n";
        std::cout << Ansi::BrBlack << "  pre-touch " << (cfg.preTouch  ? Ansi::BrGreen  : Ansi::BrRed)
                  << (cfg.preTouch  ? "on" : "off") << "\n";
        std::cout << Ansi::BrBlack << "  INT3 NOP  " << (cfg.patchInt3s ? Ansi::BrGreen  : Ansi::BrRed)
                  << (cfg.patchInt3s ? "on" : "off") << "\n";
        std::cout << Ansi::BrBlack << "  IAT fix   " << (cfg.rebuildIAT ? Ansi::BrGreen  : Ansi::BrRed)
                  << (cfg.rebuildIAT ? "on" : "off") << "\n";
        std::cout << Ansi::Reset;
        Sep();
        std::cout << "\n";
    }
}
