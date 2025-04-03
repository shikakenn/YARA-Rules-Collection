rule win_maoloa_auto {

    meta:
        id = "68IgOTfgRjcANCfh5Pn3Mi"
        fingerprint = "v1_sha256_db1d30099f88e9731a955a855e8ff6fe8bdddafcf359d763b17d4e94ad2fc492"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.maoloa."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.maoloa"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { e8???????? 8be5 5d c3 bf00afffff 8d8dc8fbffff e8???????? }
            // n = 7, score = 100
            //   e8????????           |                     
            //   8be5                 | mov                 esp, ebp
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   bf00afffff           | mov                 edi, 0xffffaf00
            //   8d8dc8fbffff         | lea                 ecx, [ebp - 0x438]
            //   e8????????           |                     

        $sequence_1 = { 50 56 6a01 6a00 68???????? ffb598e3ffff ff15???????? }
            // n = 7, score = 100
            //   50                   | push                eax
            //   56                   | push                esi
            //   6a01                 | push                1
            //   6a00                 | push                0
            //   68????????           |                     
            //   ffb598e3ffff         | push                dword ptr [ebp - 0x1c68]
            //   ff15????????         |                     

        $sequence_2 = { 33c3 d1e9 83f007 8bde 8b9c8310100000 8bc2 335cbdbc }
            // n = 7, score = 100
            //   33c3                 | xor                 eax, ebx
            //   d1e9                 | shr                 ecx, 1
            //   83f007               | xor                 eax, 7
            //   8bde                 | mov                 ebx, esi
            //   8b9c8310100000       | mov                 ebx, dword ptr [ebx + eax*4 + 0x1010]
            //   8bc2                 | mov                 eax, edx
            //   335cbdbc             | xor                 ebx, dword ptr [ebp + edi*4 - 0x44]

        $sequence_3 = { 0f8eddfeffff 8b44244c 8d4c2458 68???????? 03c1 50 ff15???????? }
            // n = 7, score = 100
            //   0f8eddfeffff         | jle                 0xfffffee3
            //   8b44244c             | mov                 eax, dword ptr [esp + 0x4c]
            //   8d4c2458             | lea                 ecx, [esp + 0x58]
            //   68????????           |                     
            //   03c1                 | add                 eax, ecx
            //   50                   | push                eax
            //   ff15????????         |                     

        $sequence_4 = { 8b4de8 8b0485d8ed4200 f644082840 7409 803f1a 7504 }
            // n = 6, score = 100
            //   8b4de8               | mov                 ecx, dword ptr [ebp - 0x18]
            //   8b0485d8ed4200       | mov                 eax, dword ptr [eax*4 + 0x42edd8]
            //   f644082840           | test                byte ptr [eax + ecx + 0x28], 0x40
            //   7409                 | je                  0xb
            //   803f1a               | cmp                 byte ptr [edi], 0x1a
            //   7504                 | jne                 6

        $sequence_5 = { 8bd7 8d4d90 e8???????? 8bf0 6a6c 8d4590 }
            // n = 6, score = 100
            //   8bd7                 | mov                 edx, edi
            //   8d4d90               | lea                 ecx, [ebp - 0x70]
            //   e8????????           |                     
            //   8bf0                 | mov                 esi, eax
            //   6a6c                 | push                0x6c
            //   8d4590               | lea                 eax, [ebp - 0x70]

        $sequence_6 = { 8d45f0 50 e8???????? 83c404 85c0 7502 8937 }
            // n = 7, score = 100
            //   8d45f0               | lea                 eax, [ebp - 0x10]
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   85c0                 | test                eax, eax
            //   7502                 | jne                 4
            //   8937                 | mov                 dword ptr [edi], esi

        $sequence_7 = { 50 8d8570ffffff 50 e8???????? 83c40c 8d8d70ffffff 33d2 }
            // n = 7, score = 100
            //   50                   | push                eax
            //   8d8570ffffff         | lea                 eax, [ebp - 0x90]
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   8d8d70ffffff         | lea                 ecx, [ebp - 0x90]
            //   33d2                 | xor                 edx, edx

        $sequence_8 = { 8bd7 e8???????? 85c0 0f898e020000 ba01000000 8bce e8???????? }
            // n = 7, score = 100
            //   8bd7                 | mov                 edx, edi
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   0f898e020000         | jns                 0x294
            //   ba01000000           | mov                 edx, 1
            //   8bce                 | mov                 ecx, esi
            //   e8????????           |                     

        $sequence_9 = { 3bc1 0f47c1 a3???????? c705????????000000c0 c705????????000000c0 c705????????80000088 8d8594e3ffff }
            // n = 7, score = 100
            //   3bc1                 | cmp                 eax, ecx
            //   0f47c1               | cmova               eax, ecx
            //   a3????????           |                     
            //   c705????????000000c0     |     
            //   c705????????000000c0     |     
            //   c705????????80000088     |     
            //   8d8594e3ffff         | lea                 eax, [ebp - 0x1c6c]

    condition:
        7 of them and filesize < 586752
}
