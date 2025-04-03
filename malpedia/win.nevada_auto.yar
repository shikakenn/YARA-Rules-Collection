rule win_nevada_auto {

    meta:
        id = "1ATAxRH1UhJw06bUQkHIlt"
        fingerprint = "v1_sha256_e8b202252b082c203b7b36b32325aea4ef97f49142f8ff76e8fa7afc9a175f74"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.nevada."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.nevada"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { e9???????? 90 4881c4b8000000 5b 5f 5e 5d }
            // n = 7, score = 100
            //   e9????????           |                     
            //   90                   | movups              xmm0, xmmword ptr [ebp - 0x48]
            //   4881c4b8000000       | movups              xmmword ptr [ebp + 0x410], xmm0
            //   5b                   | dec                 eax
            //   5f                   | mov                 dword ptr [ebp + 0x408], edx
            //   5e                   | dec                 eax
            //   5d                   | mov                 eax, dword ptr [ebp + 0x418]

        $sequence_1 = { e8???????? 4c8bad10060000 4c3bad08060000 751d c6852206000000 488d8d00060000 4c89ea }
            // n = 7, score = 100
            //   e8????????           |                     
            //   4c8bad10060000       | nop                 
            //   4c3bad08060000       | dec                 eax
            //   751d                 | add                 esp, 0x38
            //   c6852206000000       | pop                 ebx
            //   488d8d00060000       | pop                 edi
            //   4c89ea               | dec                 eax

        $sequence_2 = { 7413 488b4c3320 4801d2 41b802000000 e8???????? 488b8cfb18020000 4885c9 }
            // n = 7, score = 100
            //   7413                 | add                 esp, 0xf8
            //   488b4c3320           | pop                 ebx
            //   4801d2               | je                  0x25d
            //   41b802000000         | dec                 eax
            //   e8????????           |                     
            //   488b8cfb18020000     | mov                 ecx, dword ptr [esi + 0x10]
            //   4885c9               | inc                 ecx

        $sequence_3 = { 488d9d70060000 4c8db5e0040000 4c8da508050000 662e0f1f840000000000 90 4c896c2438 4c897c2430 }
            // n = 7, score = 100
            //   488d9d70060000       | pop                 esi
            //   4c8db5e0040000       | dec                 eax
            //   4c8da508050000       | lea                 ecx, [ebp - 0x20]
            //   662e0f1f840000000000     | dec    eax
            //   90                   | cmp                 dword ptr [ebp - 0x20], 0
            //   4c896c2438           | je                  0x51d
            //   4c897c2430           | dec                 eax

        $sequence_4 = { 4c89ee 48f7d6 4801c6 6689b722030000 4a8d0c6d00000000 4c01e9 4889ca }
            // n = 7, score = 100
            //   4c89ee               | jmp                 9
            //   48f7d6               | dec                 eax
            //   4801c6               | add                 edx, 1
            //   6689b722030000       | dec                 ecx
            //   4a8d0c6d00000000     | mov                 ebx, edx
            //   4c01e9               | dec                 ecx
            //   4889ca               | cmp                 ebx, 0x14

        $sequence_5 = { 4c8bac2490000000 4b8d0c2e 4883c1ff 4839d1 0f8362020000 4d8d46ff 4c8b942488000000 }
            // n = 7, score = 100
            //   4c8bac2490000000     | cmp                 eax, ebx
            //   4b8d0c2e             | jne                 0x8d1
            //   4883c1ff             | dec                 ecx
            //   4839d1               | mov                 ebp, esi
            //   0f8362020000         | dec                 ecx
            //   4d8d46ff             | lea                 eax, [esi + 8]
            //   4c8b942488000000     | dec                 esp

        $sequence_6 = { 75dc 0fb744244e 6685c0 74e2 6683f82e 75cc 66837c245000 }
            // n = 7, score = 100
            //   75dc                 | test                eax, eax
            //   0fb744244e           | je                  0xb0
            //   6685c0               | jne                 0x86
            //   74e2                 | jmp                 0x99
            //   6683f82e             | dec                 eax
            //   75cc                 | shl                 eax, 0x20
            //   66837c245000         | dec                 eax

        $sequence_7 = { 660febea f30f7f6e58 660fdbcb 660fdfd8 660febd9 f30f7f5e68 4889f0 }
            // n = 7, score = 100
            //   660febea             | push                edi
            //   f30f7f6e58           | push                ebp
            //   660fdbcb             | push                ebx
            //   660fdfd8             | dec                 eax
            //   660febd9             | sub                 esp, 0x68
            //   f30f7f5e68           | dec                 ebp
            //   4889f0               | mov                 esp, eax

        $sequence_8 = { 4889c1 e8???????? 4885c0 0f846a0a0000 4889c1 e8???????? 4889c3 }
            // n = 7, score = 100
            //   4889c1               | dec                 eax
            //   e8????????           |                     
            //   4885c0               | mov                 dword ptr [ebp + 0x198], eax
            //   0f846a0a0000         | dec                 eax
            //   4889c1               | mov                 eax, dword ptr [esi + 0x10]
            //   e8????????           |                     
            //   4889c3               | dec                 eax

        $sequence_9 = { 84db 780a 4983c101 31c0 89de }
            // n = 5, score = 100
            //   84db                 | dec                 eax
            //   780a                 | mov                 eax, dword ptr [ecx + eax*8]
            //   4983c101             | setle               cl
            //   31c0                 | dec                 eax
            //   89de                 | mov                 esi, dword ptr [eax + 0x58]

    condition:
        7 of them and filesize < 1063936
}
