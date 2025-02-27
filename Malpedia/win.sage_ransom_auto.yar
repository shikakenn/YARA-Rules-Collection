rule win_sage_ransom_auto {

    meta:
        id = "2xYeKYbPIymLdwyKMNZDNQ"
        fingerprint = "v1_sha256_aa9c344ed40cd82065b24d270c712730728bf75ebcabdbfdec5a88ea8d283ad2"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.sage_ransom."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.sage_ransom"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 50 8d4c2430 51 e8???????? 8b542438 6a00 }
            // n = 6, score = 300
            //   50                   | push                eax
            //   8d4c2430             | lea                 ecx, [esp + 0x30]
            //   51                   | push                ecx
            //   e8????????           |                     
            //   8b542438             | mov                 edx, dword ptr [esp + 0x38]
            //   6a00                 | push                0

        $sequence_1 = { 8da42400000000 8b442418 50 ffd7 8b742414 85f6 }
            // n = 6, score = 300
            //   8da42400000000       | lea                 esp, [esp]
            //   8b442418             | mov                 eax, dword ptr [esp + 0x18]
            //   50                   | push                eax
            //   ffd7                 | call                edi
            //   8b742414             | mov                 esi, dword ptr [esp + 0x14]
            //   85f6                 | test                esi, esi

        $sequence_2 = { 8d0c24 51 50 ff15???????? 833c2402 7564 }
            // n = 6, score = 300
            //   8d0c24               | lea                 ecx, [esp]
            //   51                   | push                ecx
            //   50                   | push                eax
            //   ff15????????         |                     
            //   833c2402             | cmp                 dword ptr [esp], 2
            //   7564                 | jne                 0x66

        $sequence_3 = { 8b503c 01542430 8b4840 014c2434 8b5044 }
            // n = 5, score = 300
            //   8b503c               | mov                 edx, dword ptr [eax + 0x3c]
            //   01542430             | add                 dword ptr [esp + 0x30], edx
            //   8b4840               | mov                 ecx, dword ptr [eax + 0x40]
            //   014c2434             | add                 dword ptr [esp + 0x34], ecx
            //   8b5044               | mov                 edx, dword ptr [eax + 0x44]

        $sequence_4 = { 56 57 8b7b04 03f9 8bf1 }
            // n = 5, score = 300
            //   56                   | push                esi
            //   57                   | push                edi
            //   8b7b04               | mov                 edi, dword ptr [ebx + 4]
            //   03f9                 | add                 edi, ecx
            //   8bf1                 | mov                 esi, ecx

        $sequence_5 = { 85c0 7907 83c8ff 83c408 c3 833c2441 }
            // n = 6, score = 300
            //   85c0                 | test                eax, eax
            //   7907                 | jns                 9
            //   83c8ff               | or                  eax, 0xffffffff
            //   83c408               | add                 esp, 8
            //   c3                   | ret                 
            //   833c2441             | cmp                 dword ptr [esp], 0x41

        $sequence_6 = { 8b442410 56 57 8bfa }
            // n = 4, score = 300
            //   8b442410             | mov                 eax, dword ptr [esp + 0x10]
            //   56                   | push                esi
            //   57                   | push                edi
            //   8bfa                 | mov                 edi, edx

        $sequence_7 = { 90 6aff 56 ffd3 8d4c2410 }
            // n = 5, score = 300
            //   90                   | nop                 
            //   6aff                 | push                -1
            //   56                   | push                esi
            //   ffd3                 | call                ebx
            //   8d4c2410             | lea                 ecx, [esp + 0x10]

        $sequence_8 = { 014114 8b4318 014118 8b431c }
            // n = 4, score = 200
            //   014114               | add                 dword ptr [ecx + 0x14], eax
            //   8b4318               | mov                 eax, dword ptr [ebx + 0x18]
            //   014118               | add                 dword ptr [ecx + 0x18], eax
            //   8b431c               | mov                 eax, dword ptr [ebx + 0x1c]

        $sequence_9 = { 014110 8b4314 014114 8b4318 }
            // n = 4, score = 200
            //   014110               | add                 dword ptr [ecx + 0x10], eax
            //   8b4314               | mov                 eax, dword ptr [ebx + 0x14]
            //   014114               | add                 dword ptr [ecx + 0x14], eax
            //   8b4318               | mov                 eax, dword ptr [ebx + 0x18]

        $sequence_10 = { 014108 8b430c 01410c 8b4310 }
            // n = 4, score = 200
            //   014108               | add                 dword ptr [ecx + 8], eax
            //   8b430c               | mov                 eax, dword ptr [ebx + 0xc]
            //   01410c               | add                 dword ptr [ecx + 0xc], eax
            //   8b4310               | mov                 eax, dword ptr [ebx + 0x10]

        $sequence_11 = { 891c24 89442404 e8???????? 891c24 e8???????? e9???????? 83bd54fffffff6 }
            // n = 7, score = 200
            //   891c24               | mov                 dword ptr [esp], ebx
            //   89442404             | mov                 dword ptr [esp + 4], eax
            //   e8????????           |                     
            //   891c24               | mov                 dword ptr [esp], ebx
            //   e8????????           |                     
            //   e9????????           |                     
            //   83bd54fffffff6       | cmp                 dword ptr [ebp - 0xac], -0xa

        $sequence_12 = { 013c13 83c102 46 ebd3 }
            // n = 4, score = 200
            //   013c13               | add                 dword ptr [ebx + edx], edi
            //   83c102               | add                 ecx, 2
            //   46                   | inc                 esi
            //   ebd3                 | jmp                 0xffffffd5

        $sequence_13 = { 0101 8b4304 014104 8b4308 014108 }
            // n = 5, score = 200
            //   0101                 | add                 dword ptr [ecx], eax
            //   8b4304               | mov                 eax, dword ptr [ebx + 4]
            //   014104               | add                 dword ptr [ecx + 4], eax
            //   8b4308               | mov                 eax, dword ptr [ebx + 8]
            //   014108               | add                 dword ptr [ecx + 8], eax

        $sequence_14 = { 01410c 8b4310 014110 8b4314 }
            // n = 4, score = 200
            //   01410c               | add                 dword ptr [ecx + 0xc], eax
            //   8b4310               | mov                 eax, dword ptr [ebx + 0x10]
            //   014110               | add                 dword ptr [ecx + 0x10], eax
            //   8b4314               | mov                 eax, dword ptr [ebx + 0x14]

        $sequence_15 = { 0119 117104 83c110 83c210 }
            // n = 4, score = 200
            //   0119                 | add                 dword ptr [ecx], ebx
            //   117104               | adc                 dword ptr [ecx + 4], esi
            //   83c110               | add                 ecx, 0x10
            //   83c210               | add                 edx, 0x10

    condition:
        7 of them and filesize < 335872
}
