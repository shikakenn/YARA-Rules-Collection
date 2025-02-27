rule win_helauto_auto {

    meta:
        id = "2e9HVNuRzLILhXoEFVHly1"
        fingerprint = "v1_sha256_8c0415faca54a4465c0b97b35f2aed1c836ec68c9df037f6186699e53a26046b"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.helauto."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.helauto"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 8bf8 59 8bc6 6a0a 33d2 59 }
            // n = 6, score = 100
            //   8bf8                 | mov                 edi, eax
            //   59                   | pop                 ecx
            //   8bc6                 | mov                 eax, esi
            //   6a0a                 | push                0xa
            //   33d2                 | xor                 edx, edx
            //   59                   | pop                 ecx

        $sequence_1 = { aa 8d8528feffff c7855cffffff01010000 50 66899d60ffffff }
            // n = 5, score = 100
            //   aa                   | stosb               byte ptr es:[edi], al
            //   8d8528feffff         | lea                 eax, [ebp - 0x1d8]
            //   c7855cffffff01010000     | mov    dword ptr [ebp - 0xa4], 0x101
            //   50                   | push                eax
            //   66899d60ffffff       | mov                 word ptr [ebp - 0xa0], bx

        $sequence_2 = { 8dbd9de5ffff c6859ce5ffff30 f3ab 66ab aa }
            // n = 5, score = 100
            //   8dbd9de5ffff         | lea                 edi, [ebp - 0x1a63]
            //   c6859ce5ffff30       | mov                 byte ptr [ebp - 0x1a64], 0x30
            //   f3ab                 | rep stosd           dword ptr es:[edi], eax
            //   66ab                 | stosw               word ptr es:[edi], ax
            //   aa                   | stosb               byte ptr es:[edi], al

        $sequence_3 = { 8b4510 69c0f4010000 50 8945ec }
            // n = 4, score = 100
            //   8b4510               | mov                 eax, dword ptr [ebp + 0x10]
            //   69c0f4010000         | imul                eax, eax, 0x1f4
            //   50                   | push                eax
            //   8945ec               | mov                 dword ptr [ebp - 0x14], eax

        $sequence_4 = { 6a44 8d85a8feffff 53 50 }
            // n = 4, score = 100
            //   6a44                 | push                0x44
            //   8d85a8feffff         | lea                 eax, [ebp - 0x158]
            //   53                   | push                ebx
            //   50                   | push                eax

        $sequence_5 = { 3b4510 75ad 395dfc 7409 }
            // n = 4, score = 100
            //   3b4510               | cmp                 eax, dword ptr [ebp + 0x10]
            //   75ad                 | jne                 0xffffffaf
            //   395dfc               | cmp                 dword ptr [ebp - 4], ebx
            //   7409                 | je                  0xb

        $sequence_6 = { ff75fc ff15???????? 3bc3 0f8448070000 8d45b8 }
            // n = 5, score = 100
            //   ff75fc               | push                dword ptr [ebp - 4]
            //   ff15????????         |                     
            //   3bc3                 | cmp                 eax, ebx
            //   0f8448070000         | je                  0x74e
            //   8d45b8               | lea                 eax, [ebp - 0x48]

        $sequence_7 = { 50 8d8598f7ffff 68ff030000 50 }
            // n = 4, score = 100
            //   50                   | push                eax
            //   8d8598f7ffff         | lea                 eax, [ebp - 0x868]
            //   68ff030000           | push                0x3ff
            //   50                   | push                eax

        $sequence_8 = { e8???????? 8b45d4 83c40c 898568ffffff 8b45d0 6a1f }
            // n = 6, score = 100
            //   e8????????           |                     
            //   8b45d4               | mov                 eax, dword ptr [ebp - 0x2c]
            //   83c40c               | add                 esp, 0xc
            //   898568ffffff         | mov                 dword ptr [ebp - 0x98], eax
            //   8b45d0               | mov                 eax, dword ptr [ebp - 0x30]
            //   6a1f                 | push                0x1f

        $sequence_9 = { a3???????? 50 ff15???????? e9???????? 8b442408 48 7509 }
            // n = 7, score = 100
            //   a3????????           |                     
            //   50                   | push                eax
            //   ff15????????         |                     
            //   e9????????           |                     
            //   8b442408             | mov                 eax, dword ptr [esp + 8]
            //   48                   | dec                 eax
            //   7509                 | jne                 0xb

    condition:
        7 of them and filesize < 57344
}
