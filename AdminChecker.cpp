/*
 * AdminChecker.cpp
 * Admin Privilege Checker with multi-language support, auto-check, auto-log.
 *
 * Compile (MSVC x64):
 *   build.bat
 */

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif
#ifndef WINVER
#define WINVER 0x0601
#endif
#ifndef NTDDI_VERSION
#define NTDDI_VERSION 0x06010000
#endif
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif

#include <windows.h>
#include <shellapi.h>
#include <sddl.h>
#include <lm.h>
#include <shlobj.h>
#include <stdio.h>
#include <string>
#include <vector>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "comctl32.lib")

#ifndef KEY_SET_VALUES
#define KEY_SET_VALUES 0x0002
#endif

// ============================================================================
// Language strings
// ============================================================================
struct LangPack {
    // Window
    const wchar_t* title;
    const wchar_t* btnCheck;
    const wchar_t* btnLog;
    const wchar_t* btnSettings;
    const wchar_t* btnAbout;
    const wchar_t* btnExit;

    // Status
    const wchar_t* statusAdmin;
    const wchar_t* statusStandard;
    const wchar_t* clickToCheck;
    const wchar_t* computer;
    const wchar_t* user;
    const wchar_t* summary;
    const wchar_t* summaryOf;
    const wchar_t* passed;
    const wchar_t* missingTitle;
    const wchar_t* missingNone;

    // Table
    const wchar_t* colMethod;
    const wchar_t* colResult;
    const wchar_t* colDetail;
    const wchar_t* resultPass;
    const wchar_t* resultFail;

    // Missing items
    const wchar_t* missToken;
    const wchar_t* missHKLM;
    const wchar_t* missSysDir;
    const wchar_t* missIntegrity;

    // Check names & details
    const wchar_t* chk1Name; const wchar_t* chk1Pass; const wchar_t* chk1Fail;
    const wchar_t* chk2Name; const wchar_t* chk2Full; const wchar_t* chk2Limited; const wchar_t* chk2Default;
    const wchar_t* chk3Name; const wchar_t* chk3Pass; const wchar_t* chk3Fail;
    const wchar_t* chk4Name; const wchar_t* chk4Pass; const wchar_t* chk4Fail;
    const wchar_t* chk5Name; const wchar_t* chk5Admin; const wchar_t* chk5User; const wchar_t* chk5Guest;
    const wchar_t* chk6Name; const wchar_t* chk6Pass; const wchar_t* chk6Fail;
    const wchar_t* chk7Name; const wchar_t* chk7Pass; const wchar_t* chk7Fail;
    const wchar_t* chk8Name; const wchar_t* chk8High; const wchar_t* chk8Medium; const wchar_t* chk8Low; const wchar_t* chk8Untrusted;

    // Log
    const wchar_t* logOK;
    const wchar_t* logOKMsg;
    const wchar_t* logErr;
    const wchar_t* logRunFirst;
    const wchar_t* logAutoSuccess;
    const wchar_t* logAutoFail;

    // Settings
    const wchar_t* settingsTitle;
    const wchar_t* settLang;
    const wchar_t* settLangCN;
    const wchar_t* settLangEN;
    const wchar_t* settAutoCheck;
    const wchar_t* settYes;
    const wchar_t* settNo;
    const wchar_t* settAutoLog;
    const wchar_t* settLogPath;
    const wchar_t* settSave;
    const wchar_t* settCancel;
    const wchar_t* settSaved;

    // About
    const wchar_t* aboutTitle;
    const wchar_t* aboutText;

    // Errors
    const wchar_t* errCannotOpen;
    const wchar_t* errCannotCreate;
    const wchar_t* errGetTokenFail;
    const wchar_t* errGetGroupFail;
    const wchar_t* errCreateSIDFail;
    const wchar_t* errNotAvail;
    const wchar_t* errIntegrity;
    const wchar_t* errNoAdminSID;
    const wchar_t* errCheckFail;

    // Log format labels
    const wchar_t* logStatusAdmin;
    const wchar_t* logStatusStd;
};

static LangPack g_cn = {
    // Window
    L"Admin 权限检测工具",              // title
    L"开始检测",                        // btnCheck
    L"写入日志",                        // btnLog
    L"设置",                            // btnSettings
    L"关于",                            // btnAbout
    L"退出",                            // btnExit

    // Status
    L"状态: 以管理员身份运行 (已提权)",  // statusAdmin
    L"状态: 标准用户运行 (未提权)",       // statusStandard
    L"点击 [开始检测] 进行检测",          // clickToCheck
    L"计算机",                           // computer
    L"用户",                             // user
    L"汇总",                             // summary
    L"项检测通过",                        // summaryOf
    L"项",                               // passed
    L"缺少以下管理员权限:",              // missingTitle
    L"  (无 — 你拥有完整的管理员权限)",    // missingNone

    // Table
    L"检测方法",                         // colMethod
    L"结果",                             // colResult
    L"详细信息",                          // colDetail
    L"通过",                             // resultPass
    L"未通过",                           // resultFail

    // Missing items
    L"  - 令牌不在管理员组中\n",          // missToken
    L"  - 无法写入 HKLM 注册表\n",        // missHKLM
    L"  - 无法在 System32 目录创建文件\n", // missSysDir
    L"  - 进程完整性级别为中等 (非高)\n",  // missIntegrity

    // Check names & details
    L"令牌管理员组",                      // chk1Name
    L"令牌包含管理员 SID",               // chk1Pass
    L"令牌不包含管理员 SID",             // chk1Fail
    L"令牌提权类型",                      // chk2Name
    L"完全提权",                          // chk2Full
    L"受限令牌",                          // chk2Limited
    L"默认 (UAC 未启用或内置管理员)",     // chk2Default
    L"提权标志",                          // chk3Name
    L"已提权",                            // chk3Pass
    L"未提权",                            // chk3Fail
    L"管理员 SID 匹配",                  // chk4Name
    L"在令牌组中找到管理员 SID",          // chk4Pass
    L"在令牌组中未找到管理员 SID",        // chk4Fail
    L"用户特权级别",                      // chk5Name
    L"管理员 (级别 3)",                   // chk5Admin
    L"普通用户 (级别 2)",                 // chk5User
    L"来宾 (级别 1)",                     // chk5Guest
    L"HKLM 写入测试",                    // chk6Name
    L"可写入 HKLM (管理员)",             // chk6Pass
    L"写入 HKLM 被拒绝 (非管理员)",      // chk6Fail
    L"系统目录写入",                      // chk7Name
    L"可在 System32 创建文件 (管理员)",   // chk7Pass
    L"无法在 System32 创建文件 (非管理员)", // chk7Fail
    L"完整性级别",                        // chk8Name
    L"高 — 管理员",                       // chk8High
    L"中等 — 标准用户",                   // chk8Medium
    L"低",                                // chk8Low
    L"不受信任",                          // chk8Untrusted

    // Log
    L"日志写入",                          // logOK
    L"检测结果已成功追加到日志。",         // logOKMsg
    L"日志错误",                          // logErr
    L"请先运行检测。",                    // logRunFirst
    L"自动日志写入成功",                  // logAutoSuccess
    L"自动日志写入失败",                  // logAutoFail

    // Settings
    L"设置",                              // settingsTitle
    L"界面语言",                          // settLang
    L"简体中文",                          // settLangCN
    L"English",                          // settLangEN
    L"启动时自动检测",                    // settAutoCheck
    L"是",                                // settYes
    L"否",                                // settNo
    L"检测后自动写入日志",                // settAutoLog
    L"日志网络路径",                      // settLogPath
    L"保存",                              // settSave
    L"取消",                              // settCancel
    L"设置已保存，重启后生效。",          // settSaved

    // About
    L"关于",                              // aboutTitle
    L"Admin 权限检测工具 v2.0\n\n"
    L"使用 7 种方法检测当前进程的管理员权限状态。\n"
    L"程序本身不请求提权运行。\n\n"
    L"对比方式:\n"
    L"  1. 直接双击运行 (标准用户)\n"
    L"  2. 右键 → 以管理员身份运行 (提权)\n"
    L"  对比两次结果即可看到权限差异。\n\n"
    L"配置文件: AdminChecker.ini",

    // Errors
    L"无法打开进程令牌",                  // errCannotOpen
    L"无法创建文件",                      // errCannotCreate
    L"GetTokenInformation 失败",          // errGetTokenFail
    L"无法获取令牌组信息",                // errGetGroupFail
    L"无法创建管理员 SID",               // errCreateSIDFail
    L"不可用",                            // errNotAvail
    L"无法获取完整性级别",                // errIntegrity
    L"无法创建管理员 SID",               // errNoAdminSID
    L"检测失败",                          // errCheckFail

    // Log format
    L"管理员",                            // logStatusAdmin
    L"标准用户",                          // logStatusStd
};

static LangPack g_en = {
    L"Admin Privilege Checker",
    L"Run Check", L"Write Log", L"Settings", L"About", L"Exit",

    L"STATUS: Running as ADMINISTRATOR (elevated)",
    L"STATUS: Running as STANDARD USER (not elevated)",
    L"Click [Run Check] to start",
    L"Computer", L"User", L"Summary", L"checks passed", L"",
    L"Missing privileges without admin:",
    L"  (none — you have full admin privileges)",

    L"Method", L"Result", L"Detail", L"PASS", L"FAIL",

    L"  - Token not in Administrators group\n",
    L"  - Cannot write to HKLM registry\n",
    L"  - Cannot create files in System32\n",
    L"  - Process integrity level is Medium (not High)\n",

    L"IsUserAnAdmin()", L"Token contains Admin SID", L"Token does NOT contain Admin SID",
    L"TokenElevationType", L"Fully elevated", L"Limited (restricted)", L"Default (UAC off or built-in admin)",
    L"TokenElevation", L"Elevated", L"Not elevated",
    L"Admin SID Match", L"Admin SID found in token groups", L"Admin SID NOT found in token groups",
    L"NetUserGetInfo", L"Admin (priv=3)", L"User (priv=2)", L"Guest (priv=1)",
    L"HKLM Write Test", L"Can write HKLM (admin)", L"HKLM write denied (not admin)",
    L"System Dir Write", L"Can create files in System32 (admin)", L"Cannot create files in System32 (not admin)",
    L"Integrity Level", L"High — Admin", L"Medium — Standard User", L"Low", L"Untrusted",

    L"Log", L"Results appended to log successfully.", L"Log Error",
    L"Run the check first.", L"Auto-log succeeded", L"Auto-log failed",

    L"Settings",
    L"Language", L"Chinese", L"English",
    L"Auto-check on startup", L"Yes", L"No",
    L"Auto-log after check", L"Log network path",
    L"Save", L"Cancel", L"Settings saved. Restart to apply.",

    L"About",
    L"Admin Privilege Checker v2.0\n\n"
    L"Detects admin privileges using 7 methods.\n"
    L"The program does NOT request elevation itself.\n\n"
    L"Compare by running:\n"
    L"  1. Double-click (standard user)\n"
    L"  2. Right-click -> Run as admin (elevated)\n"
    L"  Compare results to see the difference.\n\n"
    L"Config file: AdminChecker.ini",

    L"Cannot open process token",
    L"Cannot create file",
    L"GetTokenInformation failed",
    L"Cannot get token groups",
    L"Cannot create Admin SID",
    L"N/A",
    L"Cannot get integrity level",
    L"Cannot create Admin SID",
    L"Check failed",

    L"ADMIN", L"STANDARD",
};

// ============================================================================
// Config
// ============================================================================
static const wchar_t* INI_FILE = L"AdminChecker.ini";
static int g_lang = 0;           // 0=CN, 1=EN
static int g_autoCheck = 1;      // 1=auto check on startup
static int g_autoLog = 1;        // 1=auto log after check
static wchar_t g_logPath[MAX_PATH] = L"\\\\172.30.220.250\\itclass\\record\\ip.log";

static void LoadConfig() {
    wchar_t iniPath[MAX_PATH];
    GetModuleFileNameW(NULL, iniPath, MAX_PATH);
    // Replace exe name with ini name
    wchar_t* p = wcsrchr(iniPath, L'\\');
    if (p) { p++; wcscpy_s(p, MAX_PATH - (p - iniPath), INI_FILE); }
    else { wcscpy_s(iniPath, MAX_PATH, INI_FILE); }

    g_lang = GetPrivateProfileIntW(L"Settings", L"Language", 0, iniPath);
    g_autoCheck = GetPrivateProfileIntW(L"Settings", L"AutoCheck", 1, iniPath);
    g_autoLog = GetPrivateProfileIntW(L"Settings", L"AutoLog", 1, iniPath);
    GetPrivateProfileStringW(L"Settings", L"LogPath",
        L"\\\\172.30.220.250\\itclass\\record\\ip.log",
        g_logPath, MAX_PATH, iniPath);
}

static void SaveConfig() {
    wchar_t iniPath[MAX_PATH];
    GetModuleFileNameW(NULL, iniPath, MAX_PATH);
    wchar_t* p = wcsrchr(iniPath, L'\\');
    if (p) { p++; wcscpy_s(p, MAX_PATH - (p - iniPath), INI_FILE); }
    else { wcscpy_s(iniPath, MAX_PATH, INI_FILE); }

    wchar_t buf[16];
    wsprintfW(buf, L"%d", g_lang);
    WritePrivateProfileStringW(L"Settings", L"Language", buf, iniPath);
    wsprintfW(buf, L"%d", g_autoCheck);
    WritePrivateProfileStringW(L"Settings", L"AutoCheck", buf, iniPath);
    wsprintfW(buf, L"%d", g_autoLog);
    WritePrivateProfileStringW(L"Settings", L"AutoLog", buf, iniPath);
    WritePrivateProfileStringW(L"Settings", L"LogPath", g_logPath, iniPath);
}

static LangPack* L() { return g_lang == 0 ? &g_cn : &g_en; }

// ============================================================================
// Constants & state
// ============================================================================
static const wchar_t* WINDOW_CLASS = L"AdminCheckerWnd";
static const int WIN_W = 800;
static const int WIN_H = 660;

enum {
    ID_BTN_CHECK = 1001, ID_BTN_LOG = 1002, ID_BTN_SETTINGS = 1003,
    ID_BTN_ABOUT = 1004, ID_BTN_EXIT = 1005,
    // Settings dialog
    ID_SET_LANG = 2001, ID_SET_AUTOCHECK = 2002, ID_SET_AUTOLOG = 2003,
    ID_SET_LOGPATH = 2004, ID_SET_SAVE = 2005, ID_SET_CANCEL = 2006,
    ID_SET_LBL_LANG = 2010, ID_SET_LBL_AUTOCHECK = 2011,
    ID_SET_LBL_AUTOLOG = 2012, ID_SET_LBL_LOGPATH = 2013,
};

static const COLORREF CLR_GREEN  = RGB(34, 139, 34);
static const COLORREF CLR_RED    = RGB(200, 30, 30);
static const COLORREF CLR_YELLOW = RGB(180, 140, 0);
static const COLORREF CLR_GRAY   = RGB(100, 100, 100);
static const COLORREF CLR_WHITE  = RGB(255, 255, 255);
static const COLORREF CLR_BG     = RGB(245, 245, 250);
static const COLORREF CLR_HEADER = RGB(50, 60, 80);

struct CheckResult {
    int nameIdx;      // index into name/detail lookup
    bool passed;
    bool available;
    int detailIdx;    // which detail string to show
};

static HINSTANCE g_hInst = NULL;
static HWND g_hWndMain = NULL;
static HFONT g_hFontNormal = NULL, g_hFontBold = NULL, g_hFontTitle = NULL;
static HBRUSH g_hBrushBg = NULL;

static std::vector<CheckResult> g_results;
static bool g_isAdmin = false;
static wchar_t g_userName[256] = {0};
static wchar_t g_domainName[256] = {0};

// Detail index enum
enum {
    DET_CHK1_PASS, DET_CHK1_FAIL,
    DET_CHK2_FULL, DET_CHK2_LIMITED, DET_CHK2_DEFAULT,
    DET_CHK3_PASS, DET_CHK3_FAIL,
    DET_CHK4_PASS, DET_CHK4_FAIL,
    DET_CHK5_ADMIN, DET_CHK5_USER, DET_CHK5_GUEST,
    DET_CHK6_PASS, DET_CHK6_FAIL,
    DET_CHK7_PASS, DET_CHK7_FAIL,
    DET_CHK8_HIGH, DET_CHK8_MEDIUM, DET_CHK8_LOW, DET_CHK8_UNTRUSTED,
    DET_ERR_TOKEN, DET_ERR_FAIL, DET_ERR_NA,
};

static const wchar_t* GetDetail(int idx) {
    LangPack* l = L();
    switch (idx) {
    case DET_CHK1_PASS: return l->chk1Pass;
    case DET_CHK1_FAIL: return l->chk1Fail;
    case DET_CHK2_FULL: return l->chk2Full;
    case DET_CHK2_LIMITED: return l->chk2Limited;
    case DET_CHK2_DEFAULT: return l->chk2Default;
    case DET_CHK3_PASS: return l->chk3Pass;
    case DET_CHK3_FAIL: return l->chk3Fail;
    case DET_CHK4_PASS: return l->chk4Pass;
    case DET_CHK4_FAIL: return l->chk4Fail;
    case DET_CHK5_ADMIN: return l->chk5Admin;
    case DET_CHK5_USER: return l->chk5User;
    case DET_CHK5_GUEST: return l->chk5Guest;
    case DET_CHK6_PASS: return l->chk6Pass;
    case DET_CHK6_FAIL: return l->chk6Fail;
    case DET_CHK7_PASS: return l->chk7Pass;
    case DET_CHK7_FAIL: return l->chk7Fail;
    case DET_CHK8_HIGH: return l->chk8High;
    case DET_CHK8_MEDIUM: return l->chk8Medium;
    case DET_CHK8_LOW: return l->chk8Low;
    case DET_CHK8_UNTRUSTED: return l->chk8Untrusted;
    case DET_ERR_TOKEN: return l->errCannotOpen;
    case DET_ERR_FAIL: return l->errCheckFail;
    case DET_ERR_NA: return l->errNotAvail;
    default: return L"?";
    }
}

static const wchar_t* GetCheckName(int idx) {
    LangPack* l = L();
    switch (idx) {
    case 0: return l->chk1Name;
    case 1: return l->chk2Name;
    case 2: return l->chk3Name;
    case 3: return l->chk4Name;
    case 4: return l->chk5Name;
    case 5: return l->chk6Name;
    case 6: return l->chk7Name;
    case 7: return l->chk8Name;
    default: return L"?";
    }
}

// ============================================================================
// Utility
// ============================================================================
static std::string WideToGB2312(const std::wstring& wide) {
    if (wide.empty()) return "";
    int len = WideCharToMultiByte(936, 0, wide.c_str(), (int)wide.size(), NULL, 0, NULL, NULL);
    if (len <= 0) return "";
    std::string result(len, 0);
    WideCharToMultiByte(936, 0, wide.c_str(), (int)wide.size(), &result[0], len, NULL, NULL);
    return result;
}

static std::wstring GetTimeStr() {
    wchar_t buf[64];
    SYSTEMTIME st;
    GetLocalTime(&st);
    wsprintfW(buf, L"%04d-%02d-%02d %02d:%02d:%02d",
              st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    return buf;
}

static std::wstring GetComputerNameStr() {
    wchar_t buf[256] = {0};
    DWORD size = 256;
    ::GetComputerNameW(buf, &size);
    return buf;
}

static std::wstring GetLastErrorStr() {
    DWORD err = GetLastError();
    wchar_t* buf = NULL;
    FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
                   NULL, err, 0, (LPWSTR)&buf, 0, NULL);
    std::wstring result = buf ? buf : L"Unknown";
    if (buf) LocalFree(buf);
    return result;
}

// ============================================================================
// Checks
// ============================================================================
static void RunAllChecks() {
    g_results.clear();
    LangPack* l = L();

    // Get user info
    DWORD uLen = 256, dLen = 256;
    GetUserNameW(g_userName, &uLen);
    HANDLE hToken = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        DWORD needed = 0;
        GetTokenInformation(hToken, TokenUser, NULL, 0, &needed);
        if (needed > 0) {
            std::vector<BYTE> buf(needed);
            if (GetTokenInformation(hToken, TokenUser, buf.data(), needed, &needed)) {
                PTOKEN_USER pUser = (PTOKEN_USER)buf.data();
                SID_NAME_USE snu;
                LookupAccountSidW(NULL, pUser->User.Sid, g_userName, &uLen, g_domainName, &dLen, &snu);
            }
        }
        CloseHandle(hToken);
    }

    // Check 1: CheckTokenMembership
    {
        CheckResult r = {0};
        r.nameIdx = 0;
        PSID pSID = NULL;
        SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
        if (AllocateAndInitializeSid(&ntAuth, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                     DOMAIN_ALIAS_RID_ADMINS, 0,0,0,0,0,0, &pSID)) {
            BOOL isMember = FALSE;
            r.available = true;
            r.passed = CheckTokenMembership(NULL, pSID, &isMember) && isMember;
            r.detailIdx = r.passed ? DET_CHK1_PASS : DET_CHK1_FAIL;
            FreeSid(pSID);
        } else {
            r.available = false;
            r.detailIdx = DET_ERR_NA;
        }
        g_results.push_back(r);
    }

    // Check 2: TokenElevationType
    {
        CheckResult r = {0};
        r.nameIdx = 1;
        hToken = NULL;
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
            TOKEN_ELEVATION_TYPE elevType = TokenElevationTypeDefault;
            DWORD retLen = 0;
            r.available = true;
            if (GetTokenInformation(hToken, TokenElevationType, &elevType, sizeof(elevType), &retLen)) {
                if (elevType == TokenElevationTypeFull) {
                    r.passed = true; r.detailIdx = DET_CHK2_FULL;
                } else if (elevType == TokenElevationTypeLimited) {
                    r.passed = false; r.detailIdx = DET_CHK2_LIMITED;
                } else {
                    r.passed = false; r.detailIdx = DET_CHK2_DEFAULT;
                }
            } else {
                r.detailIdx = DET_ERR_FAIL;
            }
            CloseHandle(hToken);
        } else {
            r.available = false;
            r.detailIdx = DET_ERR_TOKEN;
        }
        g_results.push_back(r);
    }

    // Check 3: TokenElevation BOOL
    {
        CheckResult r = {0};
        r.nameIdx = 2;
        hToken = NULL;
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
            TOKEN_ELEVATION elev = {0};
            DWORD retLen = 0;
            r.available = true;
            if (GetTokenInformation(hToken, TokenElevation, &elev, sizeof(elev), &retLen)) {
                r.passed = (elev.TokenIsElevated != 0);
                r.detailIdx = r.passed ? DET_CHK3_PASS : DET_CHK3_FAIL;
            } else {
                r.detailIdx = DET_ERR_FAIL;
            }
            CloseHandle(hToken);
        } else {
            r.available = false;
            r.detailIdx = DET_ERR_TOKEN;
        }
        g_results.push_back(r);
    }

    // Check 4: Admin SID in token groups
    {
        CheckResult r = {0};
        r.nameIdx = 3;
        hToken = NULL;
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
            DWORD needed = 0;
            GetTokenInformation(hToken, TokenGroups, NULL, 0, &needed);
            if (needed > 0) {
                std::vector<BYTE> buf(needed);
                if (GetTokenInformation(hToken, TokenGroups, buf.data(), needed, &needed)) {
                    PTOKEN_GROUPS pGroups = (PTOKEN_GROUPS)buf.data();
                    PSID pSID = NULL;
                    SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
                    if (AllocateAndInitializeSid(&ntAuth, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                                 DOMAIN_ALIAS_RID_ADMINS, 0,0,0,0,0,0, &pSID)) {
                        r.available = true;
                        bool found = false;
                        for (DWORD i = 0; i < pGroups->GroupCount; i++) {
                            if (EqualSid(pGroups->Groups[i].Sid, pSID)) { found = true; break; }
                        }
                        r.passed = found;
                        r.detailIdx = found ? DET_CHK4_PASS : DET_CHK4_FAIL;
                        FreeSid(pSID);
                    } else {
                        r.detailIdx = DET_ERR_NA;
                    }
                } else { r.detailIdx = DET_ERR_FAIL; }
            } else { r.detailIdx = DET_ERR_FAIL; }
            CloseHandle(hToken);
        } else {
            r.available = false;
            r.detailIdx = DET_ERR_TOKEN;
        }
        g_results.push_back(r);
    }

    // Check 5: NetUserGetInfo
    {
        CheckResult r = {0};
        r.nameIdx = 4;
        wchar_t userName[256] = {0};
        DWORD sz = 256;
        GetUserNameW(userName, &sz);
        LPBYTE buf = NULL;
        DWORD rc = NetUserGetInfo(NULL, userName, 3, &buf);
        if (rc == NERR_Success && buf) {
            PUSER_INFO_3 ui = (PUSER_INFO_3)buf;
            r.available = true;
            if (ui->usri3_priv == 3) { r.passed = true; r.detailIdx = DET_CHK5_ADMIN; }
            else if (ui->usri3_priv == 2) { r.passed = false; r.detailIdx = DET_CHK5_USER; }
            else { r.passed = false; r.detailIdx = DET_CHK5_GUEST; }
            NetApiBufferFree(buf);
        } else {
            r.available = false;
            r.passed = false;
            r.detailIdx = DET_ERR_NA;
        }
        g_results.push_back(r);
    }

    // Check 6: HKLM write
    {
        CheckResult r = {0};
        r.nameIdx = 5;
        HKEY hKey = NULL;
        LONG rc = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE", 0, KEY_SET_VALUES, &hKey);
        if (rc == ERROR_SUCCESS) {
            DWORD val = 1;
            rc = RegSetValueExW(hKey, L"_AdminCheckerTest", 0, REG_DWORD, (BYTE*)&val, sizeof(val));
            r.available = true;
            if (rc == ERROR_SUCCESS) {
                r.passed = true; r.detailIdx = DET_CHK6_PASS;
                RegDeleteValueW(hKey, L"_AdminCheckerTest");
            } else {
                r.passed = false; r.detailIdx = DET_CHK6_FAIL;
            }
            RegCloseKey(hKey);
        } else {
            r.available = true;
            r.passed = false;
            r.detailIdx = DET_CHK6_FAIL;
        }
        g_results.push_back(r);
    }

    // Check 7: System32 write
    {
        CheckResult r = {0};
        r.nameIdx = 6;
        wchar_t sysDir[MAX_PATH] = {0};
        GetSystemDirectoryW(sysDir, MAX_PATH);
        std::wstring testPath = std::wstring(sysDir) + L"\\_admin_test.tmp";
        HANDLE hFile = CreateFileW(testPath.c_str(), GENERIC_WRITE, 0, NULL,
                                   CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY, NULL);
        r.available = true;
        if (hFile != INVALID_HANDLE_VALUE) {
            CloseHandle(hFile);
            DeleteFileW(testPath.c_str());
            r.passed = true; r.detailIdx = DET_CHK7_PASS;
        } else {
            r.passed = false; r.detailIdx = DET_CHK7_FAIL;
        }
        g_results.push_back(r);
    }

    // Check 8: Integrity level
    {
        CheckResult r = {0};
        r.nameIdx = 7;
        hToken = NULL;
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
            DWORD needed = 0;
            GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &needed);
            if (needed > 0) {
                std::vector<BYTE> buf(needed);
                if (GetTokenInformation(hToken, TokenIntegrityLevel, buf.data(), needed, &needed)) {
                    PTOKEN_MANDATORY_LABEL pLabel = (PTOKEN_MANDATORY_LABEL)buf.data();
                    DWORD level = *GetSidSubAuthority(pLabel->Label.Sid,
                        *GetSidSubAuthorityCount(pLabel->Label.Sid) - 1);
                    r.available = true;
                    if (level >= SECURITY_MANDATORY_HIGH_RID) {
                        r.passed = true; r.detailIdx = DET_CHK8_HIGH;
                    } else if (level >= SECURITY_MANDATORY_MEDIUM_RID) {
                        r.passed = false; r.detailIdx = DET_CHK8_MEDIUM;
                    } else if (level >= SECURITY_MANDATORY_LOW_RID) {
                        r.passed = false; r.detailIdx = DET_CHK8_LOW;
                    } else {
                        r.passed = false; r.detailIdx = DET_CHK8_UNTRUSTED;
                    }
                } else { r.detailIdx = DET_ERR_FAIL; }
            } else { r.detailIdx = DET_ERR_FAIL; }
            CloseHandle(hToken);
        } else {
            r.available = false;
            r.detailIdx = DET_ERR_TOKEN;
        }
        g_results.push_back(r);
    }

    // Determine overall status
    int passCount = 0;
    for (const auto& r : g_results) { if (r.passed) passCount++; }
    g_isAdmin = (passCount > (int)g_results.size() / 2);

    InvalidateRect(g_hWndMain, NULL, TRUE);
}

// ============================================================================
// Log
// ============================================================================
static bool WriteLog(HWND hWnd, bool showError) {
    LangPack* l = L();

    std::wstring line;
    line += L"[" + GetTimeStr() + L"]";
    line += L" | " + GetComputerNameStr();
    line += L" | " + std::wstring(g_domainName) + L"\\" + std::wstring(g_userName);
    line += L" | " + std::wstring(g_isAdmin ? l->logStatusAdmin : l->logStatusStd);

    for (int i = 0; i < (int)g_results.size(); i++) {
        line += L" | " + std::wstring(GetCheckName(i)) + L":";
        line += g_results[i].passed ? l->resultPass : l->resultFail;
    }

    line += L" || ";
    for (int i = 0; i < (int)g_results.size(); i++) {
        wchar_t num[8];
        wsprintfW(num, L"%d.", i + 1);
        line += std::wstring(num) + std::wstring(GetCheckName(i)) + L"=";
        line += g_results[i].passed ? L"Y" : L"N";
        if (!g_results[i].available) line += L"(N/A)";
        line += L"; ";
    }

    std::string output = WideToGB2312(line) + "\r\n";

    HANDLE hFile = CreateFileW(g_logPath, GENERIC_WRITE,
                               FILE_SHARE_READ | FILE_SHARE_WRITE,
                               NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        if (showError) {
            wchar_t msg[512];
            wsprintfW(msg, L"%s\n%s\n\nError: %s", l->errCannotOpen, g_logPath, GetLastErrorStr().c_str());
            MessageBoxW(hWnd, msg, l->logErr, MB_ICONERROR);
        }
        return false;
    }

    SetFilePointer(hFile, 0, NULL, FILE_END);
    DWORD written = 0;
    WriteFile(hFile, output.c_str(), (DWORD)output.size(), &written, NULL);
    CloseHandle(hFile);
    return true;
}

// ============================================================================
// Paint
// ============================================================================
static void PaintResults(HWND hWnd) {
    PAINTSTRUCT ps;
    HDC hdc = BeginPaint(hWnd, &ps);
    LangPack* l = L();

    RECT rc;
    GetClientRect(hWnd, &rc);
    HDC mem = CreateCompatibleDC(hdc);
    HBITMAP bmp = CreateCompatibleBitmap(hdc, rc.right, rc.bottom);
    SelectObject(mem, bmp);
    FillRect(mem, &rc, g_hBrushBg);
    SetBkMode(mem, TRANSPARENT);

    int y = 10;

    // Title bar
    RECT rcT = {20, y, rc.right - 20, y + 38};
    FillRect(mem, &rcT, CreateSolidBrush(CLR_HEADER));
    SelectObject(mem, g_hFontTitle);
    SetTextColor(mem, CLR_WHITE);
    DrawTextW(mem, l->title, -1, &rcT, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    y += 48;

    // User info
    SelectObject(mem, g_hFontBold);
    SetTextColor(mem, CLR_HEADER);
    wchar_t userInfo[512];
    wsprintfW(userInfo, L"  %s: %s    |    %s: %s\\%s",
              l->computer, GetComputerNameStr().c_str(),
              l->user, g_domainName, g_userName);
    TextOutW(mem, 20, y, userInfo, (int)wcslen(userInfo));
    y += 28;

    // Status or placeholder
    if (g_results.empty()) {
        SelectObject(mem, g_hFontTitle);
        SetTextColor(mem, CLR_GRAY);
        TextOutW(mem, 20, y, l->clickToCheck, (int)wcslen(l->clickToCheck));
        y += 35;
    } else {
        RECT rcS = {20, y, rc.right - 20, y + 34};
        FillRect(mem, &rcS, CreateSolidBrush(g_isAdmin ? CLR_GREEN : CLR_RED));
        SelectObject(mem, g_hFontTitle);
        SetTextColor(mem, CLR_WHITE);
        DrawTextW(mem, g_isAdmin ? l->statusAdmin : l->statusStandard, -1,
                  &rcS, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
        y += 44;
    }

    // Results table
    if (!g_results.empty()) {
        int col1 = 20, col2 = 200, col3 = 310, col4 = 420;

        // Header
        RECT rcH = {20, y, rc.right - 20, y + 24};
        FillRect(mem, &rcH, CreateSolidBrush(RGB(220, 225, 235)));
        SelectObject(mem, g_hFontBold);
        SetTextColor(mem, CLR_HEADER);
        TextOutW(mem, col1, y + 3, l->colMethod, (int)wcslen(l->colMethod));
        TextOutW(mem, col2, y + 3, l->colResult, (int)wcslen(l->colResult));
        TextOutW(mem, col3, y + 3, l->colDetail, (int)wcslen(l->colDetail));
        y += 26;

        // Rows
        SelectObject(mem, g_hFontNormal);
        for (int i = 0; i < (int)g_results.size(); i++) {
            const CheckResult& r = g_results[i];
            if (i % 2 == 1) {
                RECT rcR = {20, y, rc.right - 20, y + 22};
                FillRect(mem, &rcR, CreateSolidBrush(RGB(240, 242, 248)));
            }

            wchar_t num[4];
            wsprintfW(num, L"%d", i + 1);
            SetTextColor(mem, CLR_GRAY);
            TextOutW(mem, col1, y + 2, num, (int)wcslen(num));

            SetTextColor(mem, CLR_HEADER);
            const wchar_t* name = GetCheckName(i);
            TextOutW(mem, col1 + 20, y + 2, name, (int)wcslen(name));

            SetTextColor(mem, r.passed ? CLR_GREEN : CLR_RED);
            const wchar_t* res = r.passed ? l->resultPass : l->resultFail;
            TextOutW(mem, col2, y + 2, res, (int)wcslen(res));

            SetTextColor(mem, r.passed ? CLR_GREEN : CLR_RED);
            const wchar_t* det = GetDetail(r.detailIdx);
            TextOutW(mem, col3, y + 2, det, (int)wcslen(det));

            y += 22;
        }

        y += 8;

        // Summary
        int passCount = 0;
        for (const auto& r : g_results) { if (r.passed) passCount++; }
        SelectObject(mem, g_hFontBold);
        SetTextColor(mem, CLR_HEADER);
        wchar_t summary[256];
        wsprintfW(summary, L"  %s: %d / %d %s",
                  l->summary, passCount, (int)g_results.size(), l->summaryOf);
        TextOutW(mem, 20, y, summary, (int)wcslen(summary));
        y += 28;

        // Missing privileges
        RECT rcMT = {20, y, rc.right - 20, y + 22};
        FillRect(mem, &rcMT, CreateSolidBrush(RGB(200, 210, 230)));
        SetTextColor(mem, CLR_HEADER);
        TextOutW(mem, 25, y + 2, l->missingTitle, (int)wcslen(l->missingTitle));
        y += 26;

        SelectObject(mem, g_hFontNormal);
        std::wstring missing;
        if (!g_results.empty() && !g_results[0].passed) missing += l->missToken;
        if (g_results.size() > 5 && !g_results[5].passed) missing += l->missHKLM;
        if (g_results.size() > 6 && !g_results[6].passed) missing += l->missSysDir;
        if (g_results.size() > 7 && !g_results[7].passed) missing += l->missIntegrity;

        if (missing.empty()) {
            missing = l->missingNone;
            SetTextColor(mem, CLR_GREEN);
        } else {
            SetTextColor(mem, CLR_YELLOW);
        }
        RECT rcM = {20, y, rc.right - 20, y + 90};
        DrawTextW(mem, missing.c_str(), -1, &rcM, DT_LEFT | DT_WORDBREAK);
    }

    BitBlt(hdc, 0, 0, rc.right, rc.bottom, mem, 0, 0, SRCCOPY);
    DeleteObject(bmp);
    DeleteDC(mem);
    EndPaint(hWnd, &ps);
}

// ============================================================================
// Settings dialog
// ============================================================================
static INT_PTR CALLBACK SettingsDlgProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam) {
    LangPack* l = L();
    switch (msg) {
    case WM_INITDIALOG: {
        // Language
        SendDlgItemMessageW(hDlg, ID_SET_LANG, CB_ADDSTRING, 0, (LPARAM)l->settLangCN);
        SendDlgItemMessageW(hDlg, ID_SET_LANG, CB_ADDSTRING, 0, (LPARAM)l->settLangEN);
        SendDlgItemMessageW(hDlg, ID_SET_LANG, CB_SETCURSEL, g_lang, 0);

        // Auto-check
        SendDlgItemMessageW(hDlg, ID_SET_AUTOCHECK, CB_ADDSTRING, 0, (LPARAM)l->settYes);
        SendDlgItemMessageW(hDlg, ID_SET_AUTOCHECK, CB_ADDSTRING, 0, (LPARAM)l->settNo);
        SendDlgItemMessageW(hDlg, ID_SET_AUTOCHECK, CB_SETCURSEL, g_autoCheck ? 0 : 1, 0);

        // Auto-log
        SendDlgItemMessageW(hDlg, ID_SET_AUTOLOG, CB_ADDSTRING, 0, (LPARAM)l->settYes);
        SendDlgItemMessageW(hDlg, ID_SET_AUTOLOG, CB_ADDSTRING, 0, (LPARAM)l->settNo);
        SendDlgItemMessageW(hDlg, ID_SET_AUTOLOG, CB_SETCURSEL, g_autoLog ? 0 : 1, 0);

        // Log path
        SetDlgItemTextW(hDlg, ID_SET_LOGPATH, g_logPath);

        // Set labels
        SetDlgItemTextW(hDlg, ID_SET_LBL_LANG, l->settLang);
        SetDlgItemTextW(hDlg, ID_SET_LBL_AUTOCHECK, l->settAutoCheck);
        SetDlgItemTextW(hDlg, ID_SET_LBL_AUTOLOG, l->settAutoLog);
        SetDlgItemTextW(hDlg, ID_SET_LBL_LOGPATH, l->settLogPath);
        SetDlgItemTextW(hDlg, ID_SET_SAVE, l->settSave);
        SetDlgItemTextW(hDlg, ID_SET_CANCEL, l->settCancel);
        SetWindowTextW(hDlg, l->settingsTitle);
        return TRUE;
    }
    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case ID_SET_SAVE:
            g_lang = (int)SendDlgItemMessageW(hDlg, ID_SET_LANG, CB_GETCURSEL, 0, 0);
            g_autoCheck = (int)SendDlgItemMessageW(hDlg, ID_SET_AUTOCHECK, CB_GETCURSEL, 0, 0) == 0 ? 1 : 0;
            g_autoLog = (int)SendDlgItemMessageW(hDlg, ID_SET_AUTOLOG, CB_GETCURSEL, 0, 0) == 0 ? 1 : 0;
            GetDlgItemTextW(hDlg, ID_SET_LOGPATH, g_logPath, MAX_PATH);
            SaveConfig();
            MessageBoxW(hDlg, L()->settSaved, L()->settingsTitle, MB_ICONINFORMATION);
            EndDialog(hDlg, 1);
            return TRUE;
        case ID_SET_CANCEL:
            EndDialog(hDlg, 0);
            return TRUE;
        }
        break;
    }
    return FALSE;
}

// ============================================================================
// Window procedure
// ============================================================================
static LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    LangPack* l = L();
    switch (msg) {
    case WM_CREATE: {
        g_hFontNormal = CreateFontW(16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Segoe UI");
        g_hFontBold = CreateFontW(16, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Segoe UI");
        g_hFontTitle = CreateFontW(18, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Segoe UI");
        g_hBrushBg = CreateSolidBrush(CLR_BG);

        int btnY = WIN_H - 60;
        int x = 20;
        auto MakeBtn = [&](const wchar_t* text, int id, int w) -> HWND {
            HWND hBtn = CreateWindowW(L"BUTTON", text,
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                x, btnY, w, 32, hWnd, (HMENU)(INT_PTR)id, g_hInst, NULL);
            SendMessageW(hBtn, WM_SETFONT, (WPARAM)g_hFontBold, TRUE);
            x += w + 10;
            return hBtn;
        };

        MakeBtn(l->btnCheck, ID_BTN_CHECK, 110);
        MakeBtn(l->btnLog, ID_BTN_LOG, 110);
        MakeBtn(l->btnSettings, ID_BTN_SETTINGS, 80);
        MakeBtn(l->btnAbout, ID_BTN_ABOUT, 80);
        MakeBtn(l->btnExit, ID_BTN_EXIT, 80);

        // Auto-check on startup
        if (g_autoCheck) {
            PostMessageW(hWnd, WM_COMMAND, ID_BTN_CHECK, 0);
        }
        return 0;
    }

    case WM_PAINT:
        PaintResults(hWnd);
        return 0;

    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case ID_BTN_CHECK:
            RunAllChecks();
            if (g_autoLog && !g_results.empty()) {
                if (WriteLog(hWnd, false)) {
                    // silent success
                }
            }
            break;
        case ID_BTN_LOG:
            if (g_results.empty()) {
                MessageBoxW(hWnd, l->logRunFirst, l->logErr, MB_ICONINFORMATION);
            } else {
                if (WriteLog(hWnd, true)) {
                    MessageBoxW(hWnd, l->logOKMsg, l->logOK, MB_ICONINFORMATION);
                }
            }
            break;
        case ID_BTN_SETTINGS:
            DialogBoxW(g_hInst, MAKEINTRESOURCEW(100), hWnd, SettingsDlgProc);
            break;
        case ID_BTN_ABOUT:
            MessageBoxW(hWnd, l->aboutText, l->aboutTitle, MB_ICONINFORMATION);
            break;
        case ID_BTN_EXIT:
            PostMessageW(hWnd, WM_CLOSE, 0, 0);
            break;
        }
        return 0;

    case WM_GETMINMAXINFO: {
        MINMAXINFO* mmi = (MINMAXINFO*)lParam;
        mmi->ptMinTrackSize.x = WIN_W;
        mmi->ptMinTrackSize.y = WIN_H;
        mmi->ptMaxTrackSize.x = WIN_W;
        mmi->ptMaxTrackSize.y = WIN_H;
        return 0;
    }

    case WM_DESTROY:
        if (g_hFontNormal) DeleteObject(g_hFontNormal);
        if (g_hFontBold) DeleteObject(g_hFontBold);
        if (g_hFontTitle) DeleteObject(g_hFontTitle);
        if (g_hBrushBg) DeleteObject(g_hBrushBg);
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

// ============================================================================
// Entry point
// ============================================================================
int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, LPWSTR, int nShow) {
    g_hInst = hInstance;
    LoadConfig();

    WNDCLASSEXW wc = {0};
    wc.cbSize = sizeof(wc);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.hCursor = LoadCursorW(NULL, IDC_ARROW);
    wc.hbrBackground = g_hBrushBg;
    wc.lpszClassName = WINDOW_CLASS;
    wc.hIcon = LoadIconW(NULL, IDI_SHIELD);
    RegisterClassExW(&wc);

    int sx = GetSystemMetrics(SM_CXSCREEN);
    int sy = GetSystemMetrics(SM_CYSCREEN);

    g_hWndMain = CreateWindowExW(0, WINDOW_CLASS, L()->title,
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        (sx - WIN_W) / 2, (sy - WIN_H) / 2, WIN_W, WIN_H,
        NULL, NULL, hInstance, NULL);

    if (!g_hWndMain) return 1;
    ShowWindow(g_hWndMain, nShow);
    UpdateWindow(g_hWndMain);

    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return (int)msg.wParam;
}

// ============================================================================
// Resource script (embedded as string, compiled with rc.exe)
// This defines the settings dialog layout.
// ============================================================================
