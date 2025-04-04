rule win_purplewave_auto {

    meta:
        id = "6Z4VqA7tL87Iei96D2xp9j"
        fingerprint = "v1_sha256_ec1dbe620cafbb0b6c5ed6f89052ebc62f770f57ab87864e785a226f41ace5e3"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.purplewave."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.purplewave"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 7c37 8a16 8bc7 80fa39 7f2e 0fbe07 8d4f01 }
            // n = 7, score = 400
            //   7c37                 | jl                  0x39
            //   8a16                 | mov                 dl, byte ptr [esi]
            //   8bc7                 | mov                 eax, edi
            //   80fa39               | cmp                 dl, 0x39
            //   7f2e                 | jg                  0x30
            //   0fbe07               | movsx               eax, byte ptr [edi]
            //   8d4f01               | lea                 ecx, [edi + 1]

        $sequence_1 = { 8b0495201e4900 885c012e 8b0495201e4900 804c012d04 46 ebb0 ff15???????? }
            // n = 7, score = 400
            //   8b0495201e4900       | mov                 eax, dword ptr [edx*4 + 0x491e20]
            //   885c012e             | mov                 byte ptr [ecx + eax + 0x2e], bl
            //   8b0495201e4900       | mov                 eax, dword ptr [edx*4 + 0x491e20]
            //   804c012d04           | or                  byte ptr [ecx + eax + 0x2d], 4
            //   46                   | inc                 esi
            //   ebb0                 | jmp                 0xffffffb2
            //   ff15????????         |                     

        $sequence_2 = { e8???????? 6a13 e8???????? 8bf0 59 6a17 c7063519ef54 }
            // n = 7, score = 400
            //   e8????????           |                     
            //   6a13                 | push                0x13
            //   e8????????           |                     
            //   8bf0                 | mov                 esi, eax
            //   59                   | pop                 ecx
            //   6a17                 | push                0x17
            //   c7063519ef54         | mov                 dword ptr [esi], 0x54ef1935

        $sequence_3 = { 85c0 754c 8b45ec 85c0 7445 33c9 6a02 }
            // n = 7, score = 400
            //   85c0                 | test                eax, eax
            //   754c                 | jne                 0x4e
            //   8b45ec               | mov                 eax, dword ptr [ebp - 0x14]
            //   85c0                 | test                eax, eax
            //   7445                 | je                  0x47
            //   33c9                 | xor                 ecx, ecx
            //   6a02                 | push                2

        $sequence_4 = { e8???????? 50 8d8d08ffffff e8???????? 81cb00000100 ffb52cffffff 8d8508ffffff }
            // n = 7, score = 400
            //   e8????????           |                     
            //   50                   | push                eax
            //   8d8d08ffffff         | lea                 ecx, [ebp - 0xf8]
            //   e8????????           |                     
            //   81cb00000100         | or                  ebx, 0x10000
            //   ffb52cffffff         | push                dword ptr [ebp - 0xd4]
            //   8d8508ffffff         | lea                 eax, [ebp - 0xf8]

        $sequence_5 = { 8bcc 68???????? 8937 e8???????? 8bcf e8???????? 84c0 }
            // n = 7, score = 400
            //   8bcc                 | mov                 ecx, esp
            //   68????????           |                     
            //   8937                 | mov                 dword ptr [edi], esi
            //   e8????????           |                     
            //   8bcf                 | mov                 ecx, edi
            //   e8????????           |                     
            //   84c0                 | test                al, al

        $sequence_6 = { 8903 894624 e8???????? c20800 6a64 b8???????? e8???????? }
            // n = 7, score = 400
            //   8903                 | mov                 dword ptr [ebx], eax
            //   894624               | mov                 dword ptr [esi + 0x24], eax
            //   e8????????           |                     
            //   c20800               | ret                 8
            //   6a64                 | push                0x64
            //   b8????????           |                     
            //   e8????????           |                     

        $sequence_7 = { 6a02 8955ec 8b0485201e4900 5f 894df4 c644032b0a 8b5d08 }
            // n = 7, score = 400
            //   6a02                 | push                2
            //   8955ec               | mov                 dword ptr [ebp - 0x14], edx
            //   8b0485201e4900       | mov                 eax, dword ptr [eax*4 + 0x491e20]
            //   5f                   | pop                 edi
            //   894df4               | mov                 dword ptr [ebp - 0xc], ecx
            //   c644032b0a           | mov                 byte ptr [ebx + eax + 0x2b], 0xa
            //   8b5d08               | mov                 ebx, dword ptr [ebp + 8]

        $sequence_8 = { 50 e8???????? 83c40c 8d4d88 e8???????? 8d0477 }
            // n = 6, score = 400
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   8d4d88               | lea                 ecx, [ebp - 0x78]
            //   e8????????           |                     
            //   8d0477               | lea                 eax, [edi + esi*2]

        $sequence_9 = { 8bc3 e8???????? c20c00 807f4900 740d 8d4f10 51 }
            // n = 7, score = 400
            //   8bc3                 | mov                 eax, ebx
            //   e8????????           |                     
            //   c20c00               | ret                 0xc
            //   807f4900             | cmp                 byte ptr [edi + 0x49], 0
            //   740d                 | je                  0xf
            //   8d4f10               | lea                 ecx, [edi + 0x10]
            //   51                   | push                ecx

    condition:
        7 of them and filesize < 1400832
}
