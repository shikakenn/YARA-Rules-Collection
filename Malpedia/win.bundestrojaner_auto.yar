rule win_bundestrojaner_auto {

    meta:
        id = "3RjQWMNX0O5nNnQEjq3dmB"
        fingerprint = "v1_sha256_4726f6c288ba39b565a7c1ba35f099303564bb770df1743f44ad4cd587b35c16"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.bundestrojaner."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.bundestrojaner"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { e8???????? 8bf0 85f6 75d3 57 ff15???????? }
            // n = 6, score = 100
            //   e8????????           |                     
            //   8bf0                 | mov                 esi, eax
            //   85f6                 | test                esi, esi
            //   75d3                 | jne                 0xffffffd5
            //   57                   | push                edi
            //   ff15????????         |                     

        $sequence_1 = { 84c9 0f8486010000 84c0 0f84e6000000 8b4e24 8b11 ff5204 }
            // n = 7, score = 100
            //   84c9                 | test                cl, cl
            //   0f8486010000         | je                  0x18c
            //   84c0                 | test                al, al
            //   0f84e6000000         | je                  0xec
            //   8b4e24               | mov                 ecx, dword ptr [esi + 0x24]
            //   8b11                 | mov                 edx, dword ptr [ecx]
            //   ff5204               | call                dword ptr [edx + 4]

        $sequence_2 = { 7d02 8bc2 8b542414 03ca 8b5620 3bca 7e0e }
            // n = 7, score = 100
            //   7d02                 | jge                 4
            //   8bc2                 | mov                 eax, edx
            //   8b542414             | mov                 edx, dword ptr [esp + 0x14]
            //   03ca                 | add                 ecx, edx
            //   8b5620               | mov                 edx, dword ptr [esi + 0x20]
            //   3bca                 | cmp                 ecx, edx
            //   7e0e                 | jle                 0x10

        $sequence_3 = { 8d149d00000000 2bc3 7914 8bc1 2bc2 8b5cbc44 8b0428 }
            // n = 7, score = 100
            //   8d149d00000000       | lea                 edx, [ebx*4]
            //   2bc3                 | sub                 eax, ebx
            //   7914                 | jns                 0x16
            //   8bc1                 | mov                 eax, ecx
            //   2bc2                 | sub                 eax, edx
            //   8b5cbc44             | mov                 ebx, dword ptr [esp + edi*4 + 0x44]
            //   8b0428               | mov                 eax, dword ptr [eax + ebp]

        $sequence_4 = { 0210 3f 2102 1008 2102 105121 0210 }
            // n = 7, score = 100
            //   0210                 | add                 dl, byte ptr [eax]
            //   3f                   | aas                 
            //   2102                 | and                 dword ptr [edx], eax
            //   1008                 | adc                 byte ptr [eax], cl
            //   2102                 | and                 dword ptr [edx], eax
            //   105121               | adc                 byte ptr [ecx + 0x21], dl
            //   0210                 | add                 dl, byte ptr [eax]

        $sequence_5 = { 8b5614 895118 8b06 ff10 83c404 8b442414 33db }
            // n = 7, score = 100
            //   8b5614               | mov                 edx, dword ptr [esi + 0x14]
            //   895118               | mov                 dword ptr [ecx + 0x18], edx
            //   8b06                 | mov                 eax, dword ptr [esi]
            //   ff10                 | call                dword ptr [eax]
            //   83c404               | add                 esp, 4
            //   8b442414             | mov                 eax, dword ptr [esp + 0x14]
            //   33db                 | xor                 ebx, ebx

        $sequence_6 = { 03c8 8b4614 3bc5 894c242c 0f8e21020000 8b442420 8b4e3c }
            // n = 7, score = 100
            //   03c8                 | add                 ecx, eax
            //   8b4614               | mov                 eax, dword ptr [esi + 0x14]
            //   3bc5                 | cmp                 eax, ebp
            //   894c242c             | mov                 dword ptr [esp + 0x2c], ecx
            //   0f8e21020000         | jle                 0x227
            //   8b442420             | mov                 eax, dword ptr [esp + 0x20]
            //   8b4e3c               | mov                 ecx, dword ptr [esi + 0x3c]

        $sequence_7 = { d9442454 d81d???????? d9442454 dfe0 f6c441 7406 dc0d???????? }
            // n = 7, score = 100
            //   d9442454             | fld                 dword ptr [esp + 0x54]
            //   d81d????????         |                     
            //   d9442454             | fld                 dword ptr [esp + 0x54]
            //   dfe0                 | fnstsw              ax
            //   f6c441               | test                ah, 0x41
            //   7406                 | je                  8
            //   dc0d????????         |                     

        $sequence_8 = { 8b4c2418 52 8b542424 53 52 8b542420 50 }
            // n = 7, score = 100
            //   8b4c2418             | mov                 ecx, dword ptr [esp + 0x18]
            //   52                   | push                edx
            //   8b542424             | mov                 edx, dword ptr [esp + 0x24]
            //   53                   | push                ebx
            //   52                   | push                edx
            //   8b542420             | mov                 edx, dword ptr [esp + 0x20]
            //   50                   | push                eax

        $sequence_9 = { 8b56f8 33c3 8b1c8d187b0410 33c3 33c9 33c2 33d2 }
            // n = 7, score = 100
            //   8b56f8               | mov                 edx, dword ptr [esi - 8]
            //   33c3                 | xor                 eax, ebx
            //   8b1c8d187b0410       | mov                 ebx, dword ptr [ecx*4 + 0x10047b18]
            //   33c3                 | xor                 eax, ebx
            //   33c9                 | xor                 ecx, ecx
            //   33c2                 | xor                 eax, edx
            //   33d2                 | xor                 edx, edx

    condition:
        7 of them and filesize < 729088
}
