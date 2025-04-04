rule win_tinyfluff_auto {

    meta:
        id = "HQRNxJAL9dhcZbbnRuG9T"
        fingerprint = "v1_sha256_e68e7d6c227d4701d78eb91cd8fa16d542e11d322177ea0064fd63e81ec16ac3"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.tinyfluff."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.tinyfluff"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 52 51 e8???????? 83c408 8b54247c 33c0 }
            // n = 6, score = 200
            //   52                   | push                edx
            //   51                   | push                ecx
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   8b54247c             | mov                 edx, dword ptr [esp + 0x7c]
            //   33c0                 | xor                 eax, eax

        $sequence_1 = { 8a5de3 8b049550704100 885c012e 8b049550704100 804c012d04 46 }
            // n = 6, score = 200
            //   8a5de3               | mov                 bl, byte ptr [ebp - 0x1d]
            //   8b049550704100       | mov                 eax, dword ptr [edx*4 + 0x417050]
            //   885c012e             | mov                 byte ptr [ecx + eax + 0x2e], bl
            //   8b049550704100       | mov                 eax, dword ptr [edx*4 + 0x417050]
            //   804c012d04           | or                  byte ptr [ecx + eax + 0x2d], 4
            //   46                   | inc                 esi

        $sequence_2 = { 8b04bd50704100 f644032801 7444 837c0318ff 743d e8???????? }
            // n = 6, score = 200
            //   8b04bd50704100       | mov                 eax, dword ptr [edi*4 + 0x417050]
            //   f644032801           | test                byte ptr [ebx + eax + 0x28], 1
            //   7444                 | je                  0x46
            //   837c0318ff           | cmp                 dword ptr [ebx + eax + 0x18], -1
            //   743d                 | je                  0x3f
            //   e8????????           |                     

        $sequence_3 = { 0f876d010000 52 51 e8???????? 83c408 33c0 }
            // n = 6, score = 200
            //   0f876d010000         | ja                  0x173
            //   52                   | push                edx
            //   51                   | push                ecx
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   33c0                 | xor                 eax, eax

        $sequence_4 = { 83e03f 6bc838 894de0 8b049d50704100 }
            // n = 4, score = 200
            //   83e03f               | and                 eax, 0x3f
            //   6bc838               | imul                ecx, eax, 0x38
            //   894de0               | mov                 dword ptr [ebp - 0x20], ecx
            //   8b049d50704100       | mov                 eax, dword ptr [ebx*4 + 0x417050]

        $sequence_5 = { 6af6 ff15???????? 8b04bd50704100 834c0318ff 33c0 eb16 }
            // n = 6, score = 200
            //   6af6                 | push                -0xa
            //   ff15????????         |                     
            //   8b04bd50704100       | mov                 eax, dword ptr [edi*4 + 0x417050]
            //   834c0318ff           | or                  dword ptr [ebx + eax + 0x18], 0xffffffff
            //   33c0                 | xor                 eax, eax
            //   eb16                 | jmp                 0x18

        $sequence_6 = { 8b4c2450 8d145502000000 8bc1 81fa00100000 }
            // n = 4, score = 200
            //   8b4c2450             | mov                 ecx, dword ptr [esp + 0x50]
            //   8d145502000000       | lea                 edx, [edx*2 + 2]
            //   8bc1                 | mov                 eax, ecx
            //   81fa00100000         | cmp                 edx, 0x1000

        $sequence_7 = { 57 8d3c85506d4100 8b07 83ceff 3bc6 742b }
            // n = 6, score = 200
            //   57                   | push                edi
            //   8d3c85506d4100       | lea                 edi, [eax*4 + 0x416d50]
            //   8b07                 | mov                 eax, dword ptr [edi]
            //   83ceff               | or                  esi, 0xffffffff
            //   3bc6                 | cmp                 eax, esi
            //   742b                 | je                  0x2d

        $sequence_8 = { e8???????? 8b404c 83b8a800000000 750e 8b04bd50704100 807c302900 }
            // n = 6, score = 200
            //   e8????????           |                     
            //   8b404c               | mov                 eax, dword ptr [eax + 0x4c]
            //   83b8a800000000       | cmp                 dword ptr [eax + 0xa8], 0
            //   750e                 | jne                 0x10
            //   8b04bd50704100       | mov                 eax, dword ptr [edi*4 + 0x417050]
            //   807c302900           | cmp                 byte ptr [eax + esi + 0x29], 0

        $sequence_9 = { 8b4c2468 8d145502000000 8bc1 81fa00100000 7214 8b49fc }
            // n = 6, score = 200
            //   8b4c2468             | mov                 ecx, dword ptr [esp + 0x68]
            //   8d145502000000       | lea                 edx, [edx*2 + 2]
            //   8bc1                 | mov                 eax, ecx
            //   81fa00100000         | cmp                 edx, 0x1000
            //   7214                 | jb                  0x16
            //   8b49fc               | mov                 ecx, dword ptr [ecx - 4]

    condition:
        7 of them and filesize < 245760
}
