rule win_nimgrabber_auto {

    meta:
        id = "JAAyXGtWLgneTfysPDP1c"
        fingerprint = "v1_sha256_d297cfdaadbf9a62a41740c1e9e183f352f7bffa358a9fd4217b0060da18e6ef"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.nimgrabber."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.nimgrabber"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 7c79 8b4500 85c0 0f8457040000 8b10 39da 0f862d040000 }
            // n = 7, score = 200
            //   7c79                 | jl                  0x7b
            //   8b4500               | mov                 eax, dword ptr [ebp]
            //   85c0                 | test                eax, eax
            //   0f8457040000         | je                  0x45d
            //   8b10                 | mov                 edx, dword ptr [eax]
            //   39da                 | cmp                 edx, ebx
            //   0f862d040000         | jbe                 0x433

        $sequence_1 = { e9???????? 8b4c2434 c70424???????? 89442438 894c2404 e8???????? 8b442438 }
            // n = 7, score = 200
            //   e9????????           |                     
            //   8b4c2434             | mov                 ecx, dword ptr [esp + 0x34]
            //   c70424????????       |                     
            //   89442438             | mov                 dword ptr [esp + 0x38], eax
            //   894c2404             | mov                 dword ptr [esp + 4], ecx
            //   e8????????           |                     
            //   8b442438             | mov                 eax, dword ptr [esp + 0x38]

        $sequence_2 = { 891c24 ffd0 83ec2c 83f8ff 0f94c3 e9???????? 8bbc2498000000 }
            // n = 7, score = 200
            //   891c24               | mov                 dword ptr [esp], ebx
            //   ffd0                 | call                eax
            //   83ec2c               | sub                 esp, 0x2c
            //   83f8ff               | cmp                 eax, -1
            //   0f94c3               | sete                bl
            //   e9????????           |                     
            //   8bbc2498000000       | mov                 edi, dword ptr [esp + 0x98]

        $sequence_3 = { e8???????? 8b15???????? 89c3 8d7310 85d2 0f84ab010000 01f5 }
            // n = 7, score = 200
            //   e8????????           |                     
            //   8b15????????         |                     
            //   89c3                 | mov                 ebx, eax
            //   8d7310               | lea                 esi, [ebx + 0x10]
            //   85d2                 | test                edx, edx
            //   0f84ab010000         | je                  0x1b1
            //   01f5                 | add                 ebp, esi

        $sequence_4 = { 0f49fa 85c9 0f84c8000000 89ce 8b4904 89f2 89c8 }
            // n = 7, score = 200
            //   0f49fa               | cmovns              edi, edx
            //   85c9                 | test                ecx, ecx
            //   0f84c8000000         | je                  0xce
            //   89ce                 | mov                 esi, ecx
            //   8b4904               | mov                 ecx, dword ptr [ecx + 4]
            //   89f2                 | mov                 edx, esi
            //   89c8                 | mov                 eax, ecx

        $sequence_5 = { 894c2404 c70424???????? e8???????? c7470400000000 ba???????? 89f9 c7442408b0000000 }
            // n = 7, score = 200
            //   894c2404             | mov                 dword ptr [esp + 4], ecx
            //   c70424????????       |                     
            //   e8????????           |                     
            //   c7470400000000       | mov                 dword ptr [edi + 4], 0
            //   ba????????           |                     
            //   89f9                 | mov                 ecx, edi
            //   c7442408b0000000     | mov                 dword ptr [esp + 8], 0xb0

        $sequence_6 = { 0f8f2b0c0000 31c0 8b742474 85f6 781e 83fe5f 0f845e1a0000 }
            // n = 7, score = 200
            //   0f8f2b0c0000         | jg                  0xc31
            //   31c0                 | xor                 eax, eax
            //   8b742474             | mov                 esi, dword ptr [esp + 0x74]
            //   85f6                 | test                esi, esi
            //   781e                 | js                  0x20
            //   83fe5f               | cmp                 esi, 0x5f
            //   0f845e1a0000         | je                  0x1a64

        $sequence_7 = { 56 89ce 53 83ec2c 8b19 89542410 85db }
            // n = 7, score = 200
            //   56                   | push                esi
            //   89ce                 | mov                 esi, ecx
            //   53                   | push                ebx
            //   83ec2c               | sub                 esp, 0x2c
            //   8b19                 | mov                 ebx, dword ptr [ecx]
            //   89542410             | mov                 dword ptr [esp + 0x10], edx
            //   85db                 | test                ebx, ebx

        $sequence_8 = { 83ec24 8b742430 8b7c2434 c744240429000000 c70424???????? e8???????? 8d4c241c }
            // n = 7, score = 200
            //   83ec24               | sub                 esp, 0x24
            //   8b742430             | mov                 esi, dword ptr [esp + 0x30]
            //   8b7c2434             | mov                 edi, dword ptr [esp + 0x34]
            //   c744240429000000     | mov                 dword ptr [esp + 4], 0x29
            //   c70424????????       |                     
            //   e8????????           |                     
            //   8d4c241c             | lea                 ecx, [esp + 0x1c]

        $sequence_9 = { 89442404 8b442424 890424 e8???????? e9???????? 83e801 893424 }
            // n = 7, score = 200
            //   89442404             | mov                 dword ptr [esp + 4], eax
            //   8b442424             | mov                 eax, dword ptr [esp + 0x24]
            //   890424               | mov                 dword ptr [esp], eax
            //   e8????????           |                     
            //   e9????????           |                     
            //   83e801               | sub                 eax, 1
            //   893424               | mov                 dword ptr [esp], esi

    condition:
        7 of them and filesize < 1238016
}
