rule win_mirai_auto {

    meta:
        id = "6tgpe0G3m9GjZqZ7sUOr3G"
        fingerprint = "v1_sha256_4b520e473aaa65894d4224b9e87eda17dce7091dc19025c78727d13bc484a535"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.mirai."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.mirai"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { c1e608 0bf5 c1e608 0bf7 8bbc24c0000000 3304bd30a55c00 8bbc24b0000000 }
            // n = 7, score = 100
            //   c1e608               | shl                 esi, 8
            //   0bf5                 | or                  esi, ebp
            //   c1e608               | shl                 esi, 8
            //   0bf7                 | or                  esi, edi
            //   8bbc24c0000000       | mov                 edi, dword ptr [esp + 0xc0]
            //   3304bd30a55c00       | xor                 eax, dword ptr [edi*4 + 0x5ca530]
            //   8bbc24b0000000       | mov                 edi, dword ptr [esp + 0xb0]

        $sequence_1 = { c1e810 0fb6c0 331c8588b65c00 8b442418 c1e808 0fb6c0 331c8588b25c00 }
            // n = 7, score = 100
            //   c1e810               | shr                 eax, 0x10
            //   0fb6c0               | movzx               eax, al
            //   331c8588b65c00       | xor                 ebx, dword ptr [eax*4 + 0x5cb688]
            //   8b442418             | mov                 eax, dword ptr [esp + 0x18]
            //   c1e808               | shr                 eax, 8
            //   0fb6c0               | movzx               eax, al
            //   331c8588b25c00       | xor                 ebx, dword ptr [eax*4 + 0x5cb288]

        $sequence_2 = { d3e2 8b4df4 0fb60401 0bc2 8b4dec c1f903 8b55f4 }
            // n = 7, score = 100
            //   d3e2                 | shl                 edx, cl
            //   8b4df4               | mov                 ecx, dword ptr [ebp - 0xc]
            //   0fb60401             | movzx               eax, byte ptr [ecx + eax]
            //   0bc2                 | or                  eax, edx
            //   8b4dec               | mov                 ecx, dword ptr [ebp - 0x14]
            //   c1f903               | sar                 ecx, 3
            //   8b55f4               | mov                 edx, dword ptr [ebp - 0xc]

        $sequence_3 = { 85c0 7540 ff15???????? 50 68???????? 6a52 68???????? }
            // n = 7, score = 100
            //   85c0                 | test                eax, eax
            //   7540                 | jne                 0x42
            //   ff15????????         |                     
            //   50                   | push                eax
            //   68????????           |                     
            //   6a52                 | push                0x52
            //   68????????           |                     

        $sequence_4 = { c60100 41 c60100 0fb6475f 8802 0fb6475e 42 }
            // n = 7, score = 100
            //   c60100               | mov                 byte ptr [ecx], 0
            //   41                   | inc                 ecx
            //   c60100               | mov                 byte ptr [ecx], 0
            //   0fb6475f             | movzx               eax, byte ptr [edi + 0x5f]
            //   8802                 | mov                 byte ptr [edx], al
            //   0fb6475e             | movzx               eax, byte ptr [edi + 0x5e]
            //   42                   | inc                 edx

        $sequence_5 = { 8d4d9c e8???????? 68???????? ff750c 68???????? ff7508 68???????? }
            // n = 7, score = 100
            //   8d4d9c               | lea                 ecx, [ebp - 0x64]
            //   e8????????           |                     
            //   68????????           |                     
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   68????????           |                     
            //   ff7508               | push                dword ptr [ebp + 8]
            //   68????????           |                     

        $sequence_6 = { e8???????? 8b4c241c 8b11 52 e8???????? 8bf0 83c410 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   8b4c241c             | mov                 ecx, dword ptr [esp + 0x1c]
            //   8b11                 | mov                 edx, dword ptr [ecx]
            //   52                   | push                edx
            //   e8????????           |                     
            //   8bf0                 | mov                 esi, eax
            //   83c410               | add                 esp, 0x10

        $sequence_7 = { e8???????? 59 59 8365fc00 ff7514 8d459c 50 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx
            //   8365fc00             | and                 dword ptr [ebp - 4], 0
            //   ff7514               | push                dword ptr [ebp + 0x14]
            //   8d459c               | lea                 eax, [ebp - 0x64]
            //   50                   | push                eax

        $sequence_8 = { c3 5b 5f 5e b801000000 5d 83c408 }
            // n = 7, score = 100
            //   c3                   | ret                 
            //   5b                   | pop                 ebx
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   b801000000           | mov                 eax, 1
            //   5d                   | pop                 ebp
            //   83c408               | add                 esp, 8

        $sequence_9 = { 8bf0 85f6 7511 6829010000 68???????? 6a41 e9???????? }
            // n = 7, score = 100
            //   8bf0                 | mov                 esi, eax
            //   85f6                 | test                esi, esi
            //   7511                 | jne                 0x13
            //   6829010000           | push                0x129
            //   68????????           |                     
            //   6a41                 | push                0x41
            //   e9????????           |                     

    condition:
        7 of them and filesize < 7086080
}
