rule mal_syscall_hwsyscalls: TESTING MALWARE OBFUSCATOR TA0002 T1106 {
    meta:
        id = "523uXsBBEeUqL0c2GRWHbE"
        fingerprint = "v1_sha256_0d9f8ab90b6612088766a7a8b25ca0d1a064d705d43b0e29f0cacaeee462789d"
        version = "1.0"
        date = "2023-02-28"
        modified = "2023-02-28"
        status = "TESTING"
        sharing = "TLP:WHITE"
        source = "THIEBAUT.DEV"
        author = "Maxime THIEBAUT (@0xThiebaut)"
        description = "Detects suspicious strings related to the HWSyscalls PoC by Mor Davidovich"
        category = "MALWARE"
        malware = "OBFUSCATOR"
        mitre_att = "T1106"
        reference = "https://github.com/Dec0ne/HWSyscalls/blob/ff832ed11a95092478eeebb3422fc35c7be7df31/Src/HWSyscalls.cpp"
        hash = "b27ee235a1caeeeecfc4c7023e894d08c1cbffcb86b4f315974217def617a0c7"
        first_imported = "2023-02-28"

    strings:
        // Common data
        $FindRetGadget_Module_1         = "KERNEL32.DLL"            fullword ascii 
        $FindRetGadget_Module_2         = "kernelbase.dll"          fullword ascii
        $FindRetGadget_bMask            = "\x48\x83\xC4\x68\xC3"    fullword ascii
        $SetMainBreakpoint_Module       = "KERNEL32.DLL"            fullword wide
        $SetMainBreakpoint_Symbol_1     = "GetThreadContext"        fullword ascii
        $SetMainBreakpoint_Symbol_2     = "SetThreadContext"        fullword ascii
        $SetMainBreakpoint_ContextFlags = {C7 84 24 ?? 00 00 00 10 00 10 00} // mov DWORD PTR [rsp+0x??],0x100010
        // Debug data 
        $FindRetGadget_FindInModule_1   = "RET_GADGET in kernel32"          fullword nocase
        $FindRetGadget_FindInModule_2   = "RET_GADGET in kernelbase"        fullword nocase
        $HWSyscallExceptionHandler_1    = "HWSYSCALLS DEBUG"                fullword nocase
        $HWSyscallExceptionHandler_2    = "PrepareSyscall Breakpoint Hit"   fullword nocase
        $HWSyscallExceptionHandler_3    = "RET_GADGET (%#llx)"              fullword nocase
        $HWSyscallExceptionHandler_4    = "Halos Gate"                      fullword nocase
        $HWSyscallExceptionHandler_5    = "PrepareSyscall"                  fullword nocase
        $HWSyscallExceptionHandlerOp_1  = "mov r10, rcx"                    fullword nocase
        $HWSyscallExceptionHandlerOp_2  = "mov rax, 0x%X"                   fullword nocase        
        $InitHWSyscalls_FindRetGadget_1 = "ADD RSP,68;RET"                  fullword nocase
        $InitHWSyscalls_FindRetGadget_2 = "gadget in kernel32 or kernelbase"            fullword nocase
        $InitHWSyscalls_FindRetGadget_3 = "InitHWSyscalls failed"                       fullword nocase
    condition:
        // Common data
        (
            $FindRetGadget_bMask
            and any of ($FindRetGadget_Module_*)
            and all of ($SetMainBreakpoint_*)
        )
        // Debug data
        or any of ($FindRetGadget_FindInModule_*)
        or any of ($InitHWSyscalls_*)
        or any of ($HWSyscallExceptionHandler_*)
        or all of ($HWSyscallExceptionHandlerOp_*)
}
