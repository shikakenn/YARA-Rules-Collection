rule win_nosu_auto {

    meta:
        id = "511TKvOUWMJdJptH1KyXBA"
        fingerprint = "v1_sha256_63b3125b2fa7b440ce66614e4988544ad3a96e52c6fcd77e2718549a9b26e496"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.nosu."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.nosu"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 56 c605????????01 ff15???????? ff35???????? ff15???????? }
            // n = 5, score = 200
            //   56                   | push                esi
            //   c605????????01       |                     
            //   ff15????????         |                     
            //   ff35????????         |                     
            //   ff15????????         |                     

        $sequence_1 = { eb1e 8d4714 50 8d5710 8d4c2418 e8???????? 8bf0 }
            // n = 7, score = 200
            //   eb1e                 | jmp                 0x20
            //   8d4714               | lea                 eax, [edi + 0x14]
            //   50                   | push                eax
            //   8d5710               | lea                 edx, [edi + 0x10]
            //   8d4c2418             | lea                 ecx, [esp + 0x18]
            //   e8????????           |                     
            //   8bf0                 | mov                 esi, eax

        $sequence_2 = { 8d87d8000000 50 e8???????? 8b542420 8d87480d0000 83c40c 8bcf }
            // n = 7, score = 200
            //   8d87d8000000         | lea                 eax, [edi + 0xd8]
            //   50                   | push                eax
            //   e8????????           |                     
            //   8b542420             | mov                 edx, dword ptr [esp + 0x20]
            //   8d87480d0000         | lea                 eax, [edi + 0xd48]
            //   83c40c               | add                 esp, 0xc
            //   8bcf                 | mov                 ecx, edi

        $sequence_3 = { 55 50 57 55 6a00 6a00 8d8680000000 }
            // n = 7, score = 200
            //   55                   | push                ebp
            //   50                   | push                eax
            //   57                   | push                edi
            //   55                   | push                ebp
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   8d8680000000         | lea                 eax, [esi + 0x80]

        $sequence_4 = { 8bc8 8954243c e8???????? 83c120 83ef01 75f3 8d86f8030000 }
            // n = 7, score = 200
            //   8bc8                 | mov                 ecx, eax
            //   8954243c             | mov                 dword ptr [esp + 0x3c], edx
            //   e8????????           |                     
            //   83c120               | add                 ecx, 0x20
            //   83ef01               | sub                 edi, 1
            //   75f3                 | jne                 0xfffffff5
            //   8d86f8030000         | lea                 eax, [esi + 0x3f8]

        $sequence_5 = { 663902 74f8 52 51 8d85f8fbffff 50 ff15???????? }
            // n = 7, score = 200
            //   663902               | cmp                 word ptr [edx], ax
            //   74f8                 | je                  0xfffffffa
            //   52                   | push                edx
            //   51                   | push                ecx
            //   8d85f8fbffff         | lea                 eax, [ebp - 0x408]
            //   50                   | push                eax
            //   ff15????????         |                     

        $sequence_6 = { 744c 6800020000 ff74242c 8d442438 50 ff15???????? 8d442430 }
            // n = 7, score = 200
            //   744c                 | je                  0x4e
            //   6800020000           | push                0x200
            //   ff74242c             | push                dword ptr [esp + 0x2c]
            //   8d442438             | lea                 eax, [esp + 0x38]
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8d442430             | lea                 eax, [esp + 0x30]

        $sequence_7 = { c20400 53 8bda 8bd1 56 57 8b3a }
            // n = 7, score = 200
            //   c20400               | ret                 4
            //   53                   | push                ebx
            //   8bda                 | mov                 ebx, edx
            //   8bd1                 | mov                 edx, ecx
            //   56                   | push                esi
            //   57                   | push                edi
            //   8b3a                 | mov                 edi, dword ptr [edx]

        $sequence_8 = { 8d5508 6a02 894508 e8???????? 85c0 59 0f95c0 }
            // n = 7, score = 200
            //   8d5508               | lea                 edx, [ebp + 8]
            //   6a02                 | push                2
            //   894508               | mov                 dword ptr [ebp + 8], eax
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   59                   | pop                 ecx
            //   0f95c0               | setne               al

        $sequence_9 = { 50 56 ff15???????? 8bd0 8bce e8???????? 59 }
            // n = 7, score = 200
            //   50                   | push                eax
            //   56                   | push                esi
            //   ff15????????         |                     
            //   8bd0                 | mov                 edx, eax
            //   8bce                 | mov                 ecx, esi
            //   e8????????           |                     
            //   59                   | pop                 ecx

    condition:
        7 of them and filesize < 513024
}
