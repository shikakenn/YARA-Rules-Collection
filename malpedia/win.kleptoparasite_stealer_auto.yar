rule win_kleptoparasite_stealer_auto {

    meta:
        id = "3KaGZo2jQhj9M3XieSha1b"
        fingerprint = "v1_sha256_7be717d94b9f90fe9083718b4b3c9a144ee692fe8b9cfc6de9546fc76b8ff287"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.kleptoparasite_stealer."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.kleptoparasite_stealer"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 7405 8901 895104 8be5 5d c3 3b0d???????? }
            // n = 7, score = 300
            //   7405                 | je                  7
            //   8901                 | mov                 dword ptr [ecx], eax
            //   895104               | mov                 dword ptr [ecx + 4], edx
            //   8be5                 | mov                 esp, ebp
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   3b0d????????         |                     

        $sequence_1 = { 8901 895104 8be5 5d c3 3b0d???????? 7502 }
            // n = 7, score = 300
            //   8901                 | mov                 dword ptr [ecx], eax
            //   895104               | mov                 dword ptr [ecx + 4], edx
            //   8be5                 | mov                 esp, ebp
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   3b0d????????         |                     
            //   7502                 | jne                 4

        $sequence_2 = { cc 55 8bec 56 e8???????? 8b7508 6a02 }
            // n = 7, score = 300
            //   cc                   | int3                
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   56                   | push                esi
            //   e8????????           |                     
            //   8b7508               | mov                 esi, dword ptr [ebp + 8]
            //   6a02                 | push                2

        $sequence_3 = { cc 55 8bec 56 e8???????? 8b7508 }
            // n = 6, score = 300
            //   cc                   | int3                
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   56                   | push                esi
            //   e8????????           |                     
            //   8b7508               | mov                 esi, dword ptr [ebp + 8]

        $sequence_4 = { 895104 8be5 5d c3 3b0d???????? 7502 f3c3 }
            // n = 7, score = 300
            //   895104               | mov                 dword ptr [ecx + 4], edx
            //   8be5                 | mov                 esp, ebp
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   3b0d????????         |                     
            //   7502                 | jne                 4
            //   f3c3                 | ret                 

        $sequence_5 = { e8???????? cc 55 8bec 56 e8???????? 8b7508 }
            // n = 7, score = 300
            //   e8????????           |                     
            //   cc                   | int3                
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   56                   | push                esi
            //   e8????????           |                     
            //   8b7508               | mov                 esi, dword ptr [ebp + 8]

        $sequence_6 = { b8???????? c3 e9???????? 55 8bec 56 e8???????? }
            // n = 7, score = 300
            //   b8????????           |                     
            //   c3                   | ret                 
            //   e9????????           |                     
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   56                   | push                esi
            //   e8????????           |                     

        $sequence_7 = { 895104 8be5 5d c3 3b0d???????? }
            // n = 5, score = 300
            //   895104               | mov                 dword ptr [ecx + 4], edx
            //   8be5                 | mov                 esp, ebp
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   3b0d????????         |                     

        $sequence_8 = { c3 e9???????? 55 8bec 56 e8???????? 8bf0 }
            // n = 7, score = 300
            //   c3                   | ret                 
            //   e9????????           |                     
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   56                   | push                esi
            //   e8????????           |                     
            //   8bf0                 | mov                 esi, eax

        $sequence_9 = { 8901 895104 8be5 5d c3 3b0d???????? }
            // n = 6, score = 300
            //   8901                 | mov                 dword ptr [ecx], eax
            //   895104               | mov                 dword ptr [ecx + 4], edx
            //   8be5                 | mov                 esp, ebp
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   3b0d????????         |                     

    condition:
        7 of them and filesize < 3006464
}
