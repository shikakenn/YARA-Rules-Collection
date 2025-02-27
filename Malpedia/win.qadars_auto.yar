rule win_qadars_auto {

    meta:
        id = "aB19qUnwboxKJsoFlYr12"
        fingerprint = "v1_sha256_1b2a593b94764cfdb9793ab67d53c7287007841a19e7fe336bf33e3d401fbe52"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.qadars."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.qadars"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 33c0 eb05 8b11 8b0482 8bce 83e11f }
            // n = 6, score = 700
            //   33c0                 | xor                 eax, eax
            //   eb05                 | jmp                 7
            //   8b11                 | mov                 edx, dword ptr [ecx]
            //   8b0482               | mov                 eax, dword ptr [edx + eax*4]
            //   8bce                 | mov                 ecx, esi
            //   83e11f               | and                 ecx, 0x1f

        $sequence_1 = { 891481 40 3b4608 72f2 8b06 50 e8???????? }
            // n = 7, score = 700
            //   891481               | mov                 dword ptr [ecx + eax*4], edx
            //   40                   | inc                 eax
            //   3b4608               | cmp                 eax, dword ptr [esi + 8]
            //   72f2                 | jb                  0xfffffff4
            //   8b06                 | mov                 eax, dword ptr [esi]
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_2 = { 75f8 8b07 50 e8???????? 57 e8???????? 83c408 }
            // n = 7, score = 700
            //   75f8                 | jne                 0xfffffffa
            //   8b07                 | mov                 eax, dword ptr [edi]
            //   50                   | push                eax
            //   e8????????           |                     
            //   57                   | push                edi
            //   e8????????           |                     
            //   83c408               | add                 esp, 8

        $sequence_3 = { 57 c1e805 83e11f 33ff }
            // n = 4, score = 700
            //   57                   | push                edi
            //   c1e805               | shr                 eax, 5
            //   83e11f               | and                 ecx, 0x1f
            //   33ff                 | xor                 edi, edi

        $sequence_4 = { 5e 5b c3 85f6 7427 8b4604 85c0 }
            // n = 7, score = 700
            //   5e                   | pop                 esi
            //   5b                   | pop                 ebx
            //   c3                   | ret                 
            //   85f6                 | test                esi, esi
            //   7427                 | je                  0x29
            //   8b4604               | mov                 eax, dword ptr [esi + 4]
            //   85c0                 | test                eax, eax

        $sequence_5 = { 8b4114 2b410c 5f 03c6 03450c }
            // n = 5, score = 700
            //   8b4114               | mov                 eax, dword ptr [ecx + 0x14]
            //   2b410c               | sub                 eax, dword ptr [ecx + 0xc]
            //   5f                   | pop                 edi
            //   03c6                 | add                 eax, esi
            //   03450c               | add                 eax, dword ptr [ebp + 0xc]

        $sequence_6 = { 837e0c00 7405 015e0c eb31 85f6 742d }
            // n = 6, score = 700
            //   837e0c00             | cmp                 dword ptr [esi + 0xc], 0
            //   7405                 | je                  7
            //   015e0c               | add                 dword ptr [esi + 0xc], ebx
            //   eb31                 | jmp                 0x33
            //   85f6                 | test                esi, esi
            //   742d                 | je                  0x2f

        $sequence_7 = { 0fb64d0c 8345fc03 8bd1 c1ea02 0fb6841578ffffff 0fb6550d 8807 }
            // n = 7, score = 700
            //   0fb64d0c             | movzx               ecx, byte ptr [ebp + 0xc]
            //   8345fc03             | add                 dword ptr [ebp - 4], 3
            //   8bd1                 | mov                 edx, ecx
            //   c1ea02               | shr                 edx, 2
            //   0fb6841578ffffff     | movzx               eax, byte ptr [ebp + edx - 0x88]
            //   0fb6550d             | movzx               edx, byte ptr [ebp + 0xd]
            //   8807                 | mov                 byte ptr [edi], al

        $sequence_8 = { 6a00 8d4df4 51 6a04 8d55f8 }
            // n = 5, score = 600
            //   6a00                 | push                0
            //   8d4df4               | lea                 ecx, [ebp - 0xc]
            //   51                   | push                ecx
            //   6a04                 | push                4
            //   8d55f8               | lea                 edx, [ebp - 8]

        $sequence_9 = { 6a01 6a08 ff15???????? 83c408 }
            // n = 4, score = 300
            //   6a01                 | push                1
            //   6a08                 | push                8
            //   ff15????????         |                     
            //   83c408               | add                 esp, 8

        $sequence_10 = { 6a01 8b55fc 52 ff15???????? 83c408 }
            // n = 5, score = 300
            //   6a01                 | push                1
            //   8b55fc               | mov                 edx, dword ptr [ebp - 4]
            //   52                   | push                edx
            //   ff15????????         |                     
            //   83c408               | add                 esp, 8

        $sequence_11 = { 83c40c 6805010000 8d8df8feffff 51 }
            // n = 4, score = 300
            //   83c40c               | add                 esp, 0xc
            //   6805010000           | push                0x105
            //   8d8df8feffff         | lea                 ecx, [ebp - 0x108]
            //   51                   | push                ecx

        $sequence_12 = { 51 8b55f0 52 ff15???????? 83c40c }
            // n = 5, score = 300
            //   51                   | push                ecx
            //   8b55f0               | mov                 edx, dword ptr [ebp - 0x10]
            //   52                   | push                edx
            //   ff15????????         |                     
            //   83c40c               | add                 esp, 0xc

        $sequence_13 = { 83c408 83c001 8985c8fcffff 8d95f0feffff 8995c4fcffff }
            // n = 5, score = 100
            //   83c408               | add                 esp, 8
            //   83c001               | add                 eax, 1
            //   8985c8fcffff         | mov                 dword ptr [ebp - 0x338], eax
            //   8d95f0feffff         | lea                 edx, [ebp - 0x110]
            //   8995c4fcffff         | mov                 dword ptr [ebp - 0x33c], edx

        $sequence_14 = { 83c408 83f801 0f85a5000000 6a00 }
            // n = 4, score = 100
            //   83c408               | add                 esp, 8
            //   83f801               | cmp                 eax, 1
            //   0f85a5000000         | jne                 0xab
            //   6a00                 | push                0

        $sequence_15 = { 83c408 83c8ff e9???????? eb1d 8b4d10 }
            // n = 5, score = 100
            //   83c408               | add                 esp, 8
            //   83c8ff               | or                  eax, 0xffffffff
            //   e9????????           |                     
            //   eb1d                 | jmp                 0x1f
            //   8b4d10               | mov                 ecx, dword ptr [ebp + 0x10]

    condition:
        7 of them and filesize < 630784
}
