/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/

import "pe"

rule DebuggerCheck__PEB : AntiDebug DebuggerCheck {
    meta:
        id = "77QNNKU0Oy7Bq1Wry7hPDh"
        fingerprint = "v1_sha256_4bfc1e405d9ddc1eb402677de0e295c2c5d665327c21ff54c8307390caa5b62d"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "NA"
        category = "INFO"
        reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"
        weight = 1
        Author = "naxonez"

    strings:
        $ ="IsDebugged"
    condition:
        any of them
}

rule DebuggerCheck__GlobalFlags : AntiDebug DebuggerCheck {
    meta:
        id = "5D6FtXuP1WtRNQwPY88KQL"
        fingerprint = "v1_sha256_8c6a03689a07a40ec57e9f3229ce825a01e02905acea3597dd04950306bb97a0"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "NA"
        category = "INFO"
        reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"
        weight = 1
        Author = "naxonez"

    strings:
        $ ="NtGlobalFlags"
    condition:
        any of them
}

rule DebuggerCheck__QueryInfo : AntiDebug DebuggerCheck {
    meta:
        id = "7bTibgVtXZCSQKytM2Fv5Z"
        fingerprint = "v1_sha256_7f7b006f93172f7826a9c6fbea805fc2ee3fb5c7f0e5fbb75e97189585f462cf"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "NA"
        category = "INFO"
        reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"
        weight = 1
        Author = "naxonez"

    strings:
        $ ="QueryInformationProcess"
    condition:
        any of them
}

rule DebuggerCheck__RemoteAPI : AntiDebug DebuggerCheck {
    meta:
        id = "512lyxEzIcuh3qmn8OSCJl"
        fingerprint = "v1_sha256_e92162c66f778c35b3e3d32b84b20c23b54407ac705610135063c30524e55ba6"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "NA"
        category = "INFO"
        reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"
        weight = 1
        Author = "naxonez"

    strings:
        $ ="CheckRemoteDebuggerPresent"
    condition:
        any of them
}

rule DebuggerHiding__Thread : AntiDebug DebuggerHiding {
    meta:
        id = "3KOCeRpNialjuQnXbzvuWe"
        fingerprint = "v1_sha256_254cbd1a7ece355bef8f6146ce2f99b2855236708a80a23fd2134e2b7d3a0bcc"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "NA"
        category = "INFO"
        reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"
        Author = "naxonez"
        weight = 1

    strings:
        $ ="SetInformationThread"
    condition:
        any of them
}

rule DebuggerHiding__Active : AntiDebug DebuggerHiding {
    meta:
        id = "43k29YxVoVkeZIS7nK3ruF"
        fingerprint = "v1_sha256_8573fee375b8b7cd68c71a9aa9d1cc3e4f5ee077a20da73cc855d457fe3d36f6"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "NA"
        category = "INFO"
        reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"
        weight = 1
        Author = "naxonez"

    strings:
        $ ="DebugActiveProcess"
    condition:
        any of them
}




rule DebuggerException__ConsoleCtrl : AntiDebug DebuggerException {
    meta:
        id = "2kWcSZjjb0TfOkWYIQVjWX"
        fingerprint = "v1_sha256_59a53ee8ee6aaed551e75a3582d6d7525168766d3c6d976df802f29df78ec5f2"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "NA"
        category = "INFO"
        reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"
        weight = 1
        Author = "naxonez"

    strings:
        $ ="GenerateConsoleCtrlEvent"
    condition:
        any of them
}

rule DebuggerException__SetConsoleCtrl : AntiDebug DebuggerException {
    meta:
        id = "tbnbiNQudqgbavqPmAvnZ"
        fingerprint = "v1_sha256_d086f93d7f4623dba5d96a592ec60b6ebf0e459a00b73757b0e8d78529f4a0c5"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "NA"
        category = "INFO"
        reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"
        weight = 1
        Author = "naxonez"

    strings:
        $ ="SetConsoleCtrlHandler"
    condition:
        any of them
}

rule ThreadControl__Context : AntiDebug ThreadControl {
    meta:
        id = "6fPJAm7HPApJeerfn9GmrF"
        fingerprint = "v1_sha256_c1df3bdda12ace8d3b52e099dfbea13b1ea697c6c960ef8f9715bf2ad36299ce"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "NA"
        category = "INFO"
        reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"
        weight = 1
        Author = "naxonez"

    strings:
        $ ="SetThreadContext"
    condition:
        any of them
}

rule DebuggerCheck__DrWatson : AntiDebug DebuggerCheck {
    meta:
        id = "7VdAowYHcUWysAdsrVyxNI"
        fingerprint = "v1_sha256_b89b7aeaae0c6f449528efa7c501d3f0e156f45abf23fdad58189066888879a2"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "NA"
        category = "INFO"
        reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"
        weight = 1
        Author = "naxonez"

    strings:
        $ ="__invoke__watson"
    condition:
        any of them
}

rule SEH__v3 : AntiDebug SEH {
    meta:
        id = "2pBaUrzSLiAOtYSeAJT2z6"
        fingerprint = "v1_sha256_f561b01d0333a1c41ef0aff9fb4e21d3c658a3e1e58085f04e2253bc877598ec"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "NA"
        category = "INFO"
        reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"
        weight = 1
        Author = "naxonez"

    strings:
        $ = "____except__handler3"
        $ = "____local__unwind3"
    condition:
        any of them
}

rule SEH__v4 : AntiDebug SEH {
    // VS 8.0+
    meta:
        id = "7EtQodul8pfVf6XNu3ohDE"
        fingerprint = "v1_sha256_d8d1165b7038b72cebd6c881fb17f833b59657a040c1bf753817ede1a37f0acf"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "NA"
        category = "INFO"
        reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"
        weight = 1
        Author = "naxonez"

    strings:
        $ = "____except__handler4"
        $ = "____local__unwind4"
        $ = "__XcptFilter"
    condition:
        any of them
}

rule SEH__vba : AntiDebug SEH {
    meta:
        id = "3917I6lAZK7bWAidyNDaSp"
        fingerprint = "v1_sha256_64b3f4c95103bb4544c7a977d189174ae55a514f6fc2b096f0cf779bcdadb30f"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "NA"
        category = "INFO"
        reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"
        weight = 1
        Author = "naxonez"

    strings:
        $ = "vbaExceptHandler"
    condition:
        any of them
}

rule SEH__vectored : AntiDebug SEH {
    meta:
        id = "6CWwxEjsUERpYkTSfRULsT"
        fingerprint = "v1_sha256_20b1b348a461d36521a83c8db7f12f3985d85d46c80503d25371405e851339f5"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "NA"
        category = "INFO"
        reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"
        weight = 1
        Author = "naxonez"

    strings:
        $ = "AddVectoredExceptionHandler"
        $ = "RemoveVectoredExceptionHandler"
    condition:
        any of them
}
rule Check_Debugger
{
    meta:
        id = "7RImiGFnsJzLSQjQWyMh81"
        fingerprint = "v1_sha256_40ea29c3e45363b559c64e9e6b13fad01ea2f2d5e01cb7604b6af5af8eabbe3d"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "NA"
        category = "INFO"
        Author = "Nick Hoffman"
        Description = "Looks for both isDebuggerPresent and CheckRemoteDebuggerPresent"
        Sample = "de1af0e97e94859d372be7fcf3a5daa5"

    condition:
        pe.imports("kernel32.dll","CheckRemoteDebuggerPresent") and
        pe.imports("kernel32.dll","IsDebuggerPresent")
}
rule Check_OutputDebugStringA_iat
{

    meta:
        id = "3WciSp4cQNvXwUUnQJ1yQW"
        fingerprint = "v1_sha256_0f47c247ff140dc1bcc757f00f98a1210e88987a7544af5a638bbf60162cc6b5"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "NA"
        category = "INFO"
        Author = "http://twitter.com/j0sm1"
        Description = "Detect in IAT OutputDebugstringA"
        Date = "20/04/2015"

    condition:
        pe.imports("kernel32.dll","OutputDebugStringA")
}
rule Check_FindWindowA_iat {

    meta:
        id = "1BTXcWRnsNJBEoUp99nrqh"
        fingerprint = "v1_sha256_65a38f2258d6f216cafb19bdc636a311ce4511bbea5078d942c709656871d145"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "NA"
        category = "INFO"
        Author = "http://twitter.com/j0sm1"
        Description = "it's checked if FindWindowA() is imported"
        Date = "20/04/2015"
        Reference = "http://www.codeproject.com/Articles/30815/An-Anti-Reverse-Engineering-Guide#OllyFindWindow"

    strings:
        $ollydbg = "OLLYDBG"
        $windbg = "WinDbgFrameClass"

    condition:
        pe.imports("user32.dll","FindWindowA") and ($ollydbg or $windbg)
}

rule DebuggerCheck__MemoryWorkingSet : AntiDebug DebuggerCheck {
    meta:
        id = "1gMncVOTx41wsD9zMJVnbT"
        fingerprint = "v1_sha256_00855abffaddadc925e637eb7796cdf582223d2faeb6784b3d4eee2f34968dad"
        version = "1.0"
        date = "2015-06"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Fernando Mercês"
        description = "Anti-debug process memory working set size check"
        category = "INFO"
        reference = "http://www.gironsec.com/blog/2015/06/anti-debugger-trick-quicky/"

    condition:
        pe.imports("kernel32.dll", "K32GetProcessMemoryInfo") and
        pe.imports("kernel32.dll", "GetCurrentProcess")
}

rule Debugging_API {
    meta:
        id = "2VJZGiPgVJCUKmXceqbvQZ"
        fingerprint = "v1_sha256_76ba4ffe1a57de230bfde007b1afe38c1f45706e3279b7eb1ba19569f0a3810f"
        version = "0.2"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "x0r"
        description = "Checks if being debugged"
        category = "INFO"

    strings:
        $d1 = "Kernel32.dll" nocase
        $c1 = "CheckRemoteDebuggerPresent"
        $c2 = "IsDebuggerPresent"
        $c3 = "OutputDebugString"
        $c4 = "ContinueDebugEvent"
        $c5 = "DebugActiveProcess"
    condition:
        $d1 and 1 of ($c*)
}
rule anti_dbgtools {
    meta:
        id = "7cKnpiutwO0ff9qfODjqKW"
        fingerprint = "v1_sha256_739c42ff6e8f8fb7b6d3c4d4c86a039aa1eb081d52d3b2d0fcd146dd64d8b651"
        version = "0.1"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "x0r"
        description = "Checks for the presence of known debug tools"
        category = "INFO"

    strings:
        $f1 = "procexp.exe" nocase
        $f2 = "procmon.exe" nocase
        $f3 = "processmonitor.exe" nocase
        $f4 = "wireshark.exe" nocase
        $f5 = "fiddler.exe" nocase
        $f6 = "windbg.exe" nocase
        $f7 = "ollydbg.exe" nocase
        $f8 = "winhex.exe" nocase
        $f9 = "processhacker.exe" nocase
        $f10 = "hiew32.exe" nocase
        $c11 = "\\\\.\\NTICE"
        $c12 = "\\\\.\\SICE"
        $c13 = "\\\\.\\Syser"
        $c14 = "\\\\.\\SyserBoot"
        $c15 = "\\\\.\\SyserDbgMsg"
    condition:
        any of them
}
