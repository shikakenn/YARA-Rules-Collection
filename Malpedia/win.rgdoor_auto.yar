rule win_rgdoor_auto {

    meta:
        id = "63TNZ1jDaRiZIgq1z37iLR"
        fingerprint = "v1_sha256_e436d1f0b319cc823655f3b279c99c1561f88f885f295d5e38aafb91490652b3"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.rgdoor."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.rgdoor"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 740a e9???????? 418bfe eb05 bf02000000 418bd6 4533c9 }
            // n = 7, score = 100
            //   740a                 | dec                 eax
            //   e9????????           |                     
            //   418bfe               | mov                 ecx, dword ptr [edi]
            //   eb05                 | jmp                 0x1df
            //   bf02000000           | dec                 eax
            //   418bd6               | mov                 ecx, edi
            //   4533c9               | movzx               eax, byte ptr [esi]

        $sequence_1 = { 488d0dc59d0200 ff15???????? ff15???????? 33c0 }
            // n = 4, score = 100
            //   488d0dc59d0200       | dec                 eax
            //   ff15????????         |                     
            //   ff15????????         |                     
            //   33c0                 | mov                 dword ptr [ebp + 0x78], eax

        $sequence_2 = { 41c644070889 498b04d0 418064073880 498b04d0 }
            // n = 4, score = 100
            //   41c644070889         | inc                 ecx
            //   498b04d0             | inc                 ecx
            //   418064073880         | movzx               edx, byte ptr [eax]
            //   498b04d0             | inc                 ecx

        $sequence_3 = { 488d4d98 e8???????? 90 498d4d04 488d150b8c0200 e8???????? 488bd8 }
            // n = 7, score = 100
            //   488d4d98             | je                  0x226
            //   e8????????           |                     
            //   90                   | dec                 esp
            //   498d4d04             | lea                 esi, [ebx + eax*2]
            //   488d150b8c0200       | inc                 ecx
            //   e8????????           |                     
            //   488bd8               | mov                 esi, eax

        $sequence_4 = { 43881410 49ffc0 3bcb 0f8c42ffffff }
            // n = 4, score = 100
            //   43881410             | inc                 ecx
            //   49ffc0               | and                 edx, esi
            //   3bcb                 | je                  0x15c
            //   0f8c42ffffff         | jmp                 0x68

        $sequence_5 = { c64405c000 48ffc0 4883f803 7cf0 440fb66dc2 440fb67dc1 }
            // n = 6, score = 100
            //   c64405c000           | dec                 eax
            //   48ffc0               | lea                 edx, [esi + 3]
            //   4883f803             | dec                 esp
            //   7cf0                 | mov                 ebp, eax
            //   440fb66dc2           | inc                 esp
            //   440fb67dc1           | mov                 eax, dword ptr [ebp - 0x74]

        $sequence_6 = { 488d05b9a40100 740f 3908 740e 4883c010 4883780800 }
            // n = 6, score = 100
            //   488d05b9a40100       | and                 ecx, 0x1f
            //   740f                 | dec                 eax
            //   3908                 | sar                 eax, 5
            //   740e                 | dec                 eax
            //   4883c010             | imul                edx, ecx, 0x58
            //   4883780800           | dec                 eax

        $sequence_7 = { 488d05b97cfeff 4a8b84e8503f0300 400f95c7 03f6 42897c3048 e9???????? 397de8 }
            // n = 7, score = 100
            //   488d05b97cfeff       | inc                 eax
            //   4a8b84e8503f0300     | push                ebx
            //   400f95c7             | dec                 eax
            //   03f6                 | sub                 esp, 0x20
            //   42897c3048           | mov                 ebx, ecx
            //   e9????????           |                     
            //   397de8               | je                  0x33a

        $sequence_8 = { 48897c2420 4156 4883ec20 4c8bc2 4863f1 33c0 4885d2 }
            // n = 7, score = 100
            //   48897c2420           | cmp                 esi, ebp
            //   4156                 | jne                 0xbef
            //   4883ec20             | jmp                 0xb75
            //   4c8bc2               | dec                 eax
            //   4863f1               | lea                 edx, [0x28a07]
            //   33c0                 | dec                 eax
            //   4885d2               | lea                 ecx, [ebp - 0x10]

        $sequence_9 = { 41b803010000 488bd6 e8???????? 4889842490000000 4885c0 0f8435010000 381e }
            // n = 7, score = 100
            //   41b803010000         | dec                 eax
            //   488bd6               | lea                 eax, [0xfffe3576]
            //   e8????????           |                     
            //   4889842490000000     | jmp                 0x11a3
            //   4885c0               | xor                 edx, edx
            //   0f8435010000         | mov                 dword ptr [edx + 0x10], eax
            //   381e                 | test                dword ptr [edx + 0x14], eax

    condition:
        7 of them and filesize < 475136
}
