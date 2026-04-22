#include "comms_minimal.h"
#include "pe_dumper.h"
#include "cli.h"
#include <iostream>
#include <string>
#include <algorithm>

static bool IsElevated()
{
    BOOL elevated = FALSE;
    HANDLE token  = nullptr;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
    {
        TOKEN_ELEVATION te{};
        DWORD sz = sizeof(te);
        if (GetTokenInformation(token, TokenElevation, &te, sizeof(te), &sz))
            elevated = te.TokenIsElevated;
        CloseHandle(token);
    }
    return elevated != FALSE;
}

static bool VerifyDriver(Driver& drv)
{
    Driver probe;
    probe.Setup(CreateFileA("\\\\.\\WinNotify",
        GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr));

    if (probe.GetProcessBase() == 0 && GetLastError() != 0)
        return false;

    DWORD err = GetLastError();
    return err == 0 || err == ERROR_INSUFFICIENT_BUFFER || err == ERROR_MORE_DATA
           || err == ERROR_SUCCESS;
}

static bool OpenDriver(Driver& drv)
{
    auto tryOpen = []() -> HANDLE {
        return CreateFileA("\\\\.\\WinNotify",
            GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    };

    HANDLE h = tryOpen();
    if (h == INVALID_HANDLE_VALUE && GetLastError() == ERROR_FILE_NOT_FOUND)
    {
        UI::Info("device not found - loading WinNotify driver...");

        char exePath[MAX_PATH]{};
        GetModuleFileNameA(nullptr, exePath, MAX_PATH);
        std::string drvPath = exePath;
        auto slash = drvPath.find_last_of("\\/");
        if (slash != std::string::npos)
            drvPath = drvPath.substr(0, slash + 1);
        drvPath += "signeddrv.sys";
        UI::Sub("driver path: " + drvPath);

        SC_HANDLE scm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE | SC_MANAGER_CONNECT);
        if (!scm)
        {
            UI::Err("OpenSCManager failed (err " + std::to_string(GetLastError()) + ")");
            return false;
        }

        SC_HANDLE svc = OpenServiceA(scm, "WinNotify", SERVICE_START | SERVICE_QUERY_STATUS);
        if (!svc)
        {
            DWORD openErr = GetLastError();
            if (openErr != ERROR_SERVICE_DOES_NOT_EXIST)
            {
                CloseServiceHandle(scm);
                UI::Err("OpenService failed (err " + std::to_string(openErr) + ")");
                return false;
            }

            UI::Sub("service not found - registering...");
            svc = CreateServiceA(scm, "WinNotify", "WinNotify",
                SERVICE_START | SERVICE_QUERY_STATUS,
                SERVICE_KERNEL_DRIVER,
                SERVICE_DEMAND_START,
                SERVICE_ERROR_NORMAL,
                drvPath.c_str(),
                nullptr, nullptr, nullptr, nullptr, nullptr);

            if (!svc)
            {
                CloseServiceHandle(scm);
                UI::Err("CreateService failed (err " + std::to_string(GetLastError()) + ")");
                return false;
            }
            UI::Ok("service registered");
        }

        bool started = StartServiceA(svc, 0, nullptr) != FALSE;
        DWORD startErr = GetLastError();

        CloseServiceHandle(svc);
        CloseServiceHandle(scm);

        if (!started && startErr != ERROR_SERVICE_ALREADY_RUNNING)
        {
            UI::Err("StartService failed (err " + std::to_string(startErr) + ")");
            return false;
        }

        UI::Ok("driver started");
        Sleep(500);
        h = tryOpen();
    }

    if (h == INVALID_HANDLE_VALUE)
    {
        UI::Err("failed to open driver handle (err " + std::to_string(GetLastError()) + ")");
        return false;
    }

    UI::Ok("WinNotify device open");
    drv.Setup(h);
    return true;
}

static bool AttachToTarget(Driver& drv, const std::string& procName)
{
    std::wstring wname(procName.begin(), procName.end());

    if (!drv.Target(wname.c_str()))
    {
        UI::Err("process not found: " + procName);
        return false;
    }

    UI::Ok("found " + procName + "  PID " + std::to_string(drv.ProcessId));

    drv.UpdateCr3();
    uint64_t cr3 = drv.GetCr3();
    if (cr3 == 0)
    {
        UI::Err("CR3 bruteforce failed - driver may not be responding to IOCTLs");
        UI::Sub("confirm driver is loaded and process is not heavily protected at this stage");
        return false;
    }
    UI::Sub("CR3   " + UI::Hex(cr3));

    uint64_t base = drv.GetProcessBase();
    if (!base)
    {
        UI::Err("GetProcessBase() failed");
        return false;
    }
    UI::Sub("base  " + UI::Hex(base));

    uint64_t peb = drv.GetPeb();
    if (!peb)
    {
        UI::Err("GetPeb() failed - driver IOCTLs may not be working correctly");
        return false;
    }
    UI::Sub("PEB   " + UI::Hex(peb));

    if (peb > 0x7FFFFFFFFFFF)
    {
        UI::Err("PEB address looks wrong (" + UI::Hex(peb) + ") - driver may be returning garbage");
        return false;
    }

    return true;
}

int main()
{
    Ansi::Enable();
    UI::Banner();

    if (!IsElevated())
    {
        UI::Warn("not running as administrator");
        UI::Sub("kernel driver IOCTLs will likely fail without elevation");
        UI::Sub("re-run as admin or the dump will be empty/incorrect");
        std::cout << "\n";
    }
    else
    {
        UI::Ok("running elevated");
    }
    std::cout << "\n";

    UI::Info("opening driver...");
    Driver drv;
    if (!OpenDriver(drv))
        return 1;
    UI::Ok("driver handle open  (\\\\.\\WinNotify)");
    std::cout << "\n";

    UI::Info("select preset");
    UI::DumpConfig cfg;
    auto preset = UI::PickPreset();

    if (preset == UI::Preset::Roblox)
    {
        cfg.procName   = "RobloxPlayerBeta.exe";
        cfg.outPath    = "roblox_dump.exe";
        cfg.oepRva     = 0;
        cfg.preTouch   = true;
        cfg.patchInt3s = true;
        cfg.rebuildIAT = true;

        UI::Ok("Roblox preset loaded");
        cfg.outPath = UI::Prompt("output file", cfg.outPath);
        std::cout << "\n";
    }
    else
    {
        UI::Info("select target process");
        std::cout << "\n";
        cfg.procName = UI::PickProcess();
        std::cout << "\n";

        cfg.outPath = UI::Prompt("output file", "dump.exe");

        std::string oepStr = UI::Prompt("OEP RVA hex (empty = keep as-is)");
        if (!oepStr.empty())
        {
            try { cfg.oepRva = static_cast<uint32_t>(std::stoul(oepStr, nullptr, 16)); }
            catch (...) { UI::Warn("invalid hex, OEP unchanged"); }
        }

        std::cout << "\n";
        cfg.preTouch   = UI::YesNo("APC page pre-touch (force Hyperion VEH decryption)", true);
        cfg.patchInt3s = UI::YesNo("patch INT3s (0xCC -> NOP)", true);
        cfg.rebuildIAT = UI::YesNo("rebuild IAT", true);
        std::cout << "\n";
    }

    UI::Info("dump config");
    UI::PrintConfig(cfg);

    if (!UI::YesNo("proceed with dump", true))
    {
        UI::Warn("aborted");
        return 0;
    }
    std::cout << "\n";

    UI::Sep();
    UI::Info("attaching...");
    if (!AttachToTarget(drv, cfg.procName))
        return 1;
    std::cout << "\n";

    UI::Info("dumping...");
    UI::Sep();
    std::cout << "\n";

    PEDumper dumper(drv);
    bool ok = dumper.Dump(drv.GetProcessBase(), cfg.oepRva, cfg.outPath,
                          cfg.patchInt3s, cfg.rebuildIAT, cfg.preTouch);

    std::cout << "\n";
    UI::Sep();
    if (ok)
        UI::Ok("done  ->  " + cfg.outPath);
    else
        UI::Err("dump failed");
    std::cout << "\n";

    return ok ? 0 : 1;
}
