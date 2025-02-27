rule win_asyncrat_auto {

    meta:
        id = "4YTPo8tVe8mU0iJNPf1Mll"
        fingerprint = "v1_sha256_3c690e6c4aabf0a3bbe6d35e23c8b6dc92a76dc82a8ee3c7b71a7188a5267e9e"
        version = "1"
        date = "2020-10-14"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "autogenerated rule brought to you by yara-signator"
        category = "INFO"
        tool = "yara-signator v0.5.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.asyncrat"
        malpedia_rule_date = "20201014"
        malpedia_hash = "a7e3bd57eaf12bf3ea29a863c041091ba3af9ac9"
        malpedia_version = "20201014"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 03c0 01ff 03b701ff03cb 01ff 03cc 01ff 03cb }
            // n = 7, score = 100
            //   03c0                 | add                 eax, eax
            //   01ff                 | add                 edi, edi
            //   03b701ff03cb         | add                 esi, dword ptr [edi - 0x34fc00ff]
            //   01ff                 | add                 edi, edi
            //   03cc                 | add                 ecx, esp
            //   01ff                 | add                 edi, edi
            //   03cb                 | add                 ecx, ebx

        $sequence_1 = { 03bd01ff03cc 01ff 03e7 01ff 01e5 02e6 01ff }
            // n = 7, score = 100
            //   03bd01ff03cc         | add                 edi, dword ptr [ebp - 0x33fc00ff]
            //   01ff                 | add                 edi, edi
            //   03e7                 | add                 esp, edi
            //   01ff                 | add                 edi, edi
            //   01e5                 | add                 ebp, esp
            //   02e6                 | add                 ah, dh
            //   01ff                 | add                 edi, edi

        $sequence_2 = { 01ff 03e3 01ff 03e1 01ff }
            // n = 5, score = 100
            //   01ff                 | add                 edi, edi
            //   03e3                 | add                 esp, ebx
            //   01ff                 | add                 edi, edi
            //   03e1                 | add                 esp, ecx
            //   01ff                 | add                 edi, edi

        $sequence_3 = { 019c016e018201 8601 f1 019301e001fd }
            // n = 4, score = 100
            //   019c016e018201       | add                 dword ptr [ecx + eax + 0x182016e], ebx
            //   8601                 | xchg                byte ptr [ecx], al
            //   f1                   | int1                
            //   019301e001fd         | add                 dword ptr [ebx - 0x2fe1fff], edx

        $sequence_4 = { f8 01ff 018501d601f9 01ff }
            // n = 4, score = 100
            //   f8                   | clc                 
            //   01ff                 | add                 edi, edi
            //   018501d601f9         | add                 dword ptr [ebp - 0x6fe29ff], eax
            //   01ff                 | add                 edi, edi

        $sequence_5 = { 018101cf01f0 01ff 018801d101f1 01ff }
            // n = 4, score = 100
            //   018101cf01f0         | add                 dword ptr [ecx - 0xffe30ff], eax
            //   01ff                 | add                 edi, edi
            //   018801d101f1         | add                 dword ptr [eax - 0xefe2eff], ecx
            //   01ff                 | add                 edi, edi

        $sequence_6 = { 01ff 018501d301f3 01ff 018c01d601f501 }
            // n = 4, score = 100
            //   01ff                 | add                 edi, edi
            //   018501d301f3         | add                 dword ptr [ebp - 0xcfe2cff], eax
            //   01ff                 | add                 edi, edi
            //   018c01d601f501       | add                 dword ptr [ecx + eax + 0x1f501d6], ecx

        $sequence_7 = { 018e01d801f8 01ff 018b01d601f7 01ff }
            // n = 4, score = 100
            //   018e01d801f8         | add                 dword ptr [esi - 0x7fe27ff], ecx
            //   01ff                 | add                 edi, edi
            //   018b01d601f7         | add                 dword ptr [ebx - 0x8fe29ff], ecx
            //   01ff                 | add                 edi, edi

        $sequence_8 = { 03e3 01ff 03e3 01ff 03e2 01ff 03e2 }
            // n = 7, score = 100
            //   03e3                 | add                 esp, ebx
            //   01ff                 | add                 edi, edi
            //   03e3                 | add                 esp, ebx
            //   01ff                 | add                 edi, edi
            //   03e2                 | add                 esp, edx
            //   01ff                 | add                 edi, edi
            //   03e2                 | add                 esp, edx

        $sequence_9 = { db01 ff03 da01 ff03 }
            // n = 4, score = 100
            //   db01                 | fild                dword ptr [ecx]
            //   ff03                 | inc                 dword ptr [ebx]
            //   da01                 | fiadd               dword ptr [ecx]
            //   ff03                 | inc                 dword ptr [ebx]

    condition:
        7 of them and filesize < 2605056
}
