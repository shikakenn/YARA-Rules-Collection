rule win_casper_auto {

    meta:
        id = "4rniP4sX7SGlUNdPCrAfo6"
        fingerprint = "v1_sha256_44b510f3119535b0c0c8064d1c39533cfa6df7cf823ef2fa1ba3402aaa98bcc5"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.casper."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.casper"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 8d4d10 51 57 8d4d08 51 56 ff7514 }
            // n = 7, score = 100
            //   8d4d10               | lea                 ecx, [ebp + 0x10]
            //   51                   | push                ecx
            //   57                   | push                edi
            //   8d4d08               | lea                 ecx, [ebp + 8]
            //   51                   | push                ecx
            //   56                   | push                esi
            //   ff7514               | push                dword ptr [ebp + 0x14]

        $sequence_1 = { 8945f4 885dfc 895df8 e8???????? 8a07 3c41 7c09 }
            // n = 7, score = 100
            //   8945f4               | mov                 dword ptr [ebp - 0xc], eax
            //   885dfc               | mov                 byte ptr [ebp - 4], bl
            //   895df8               | mov                 dword ptr [ebp - 8], ebx
            //   e8????????           |                     
            //   8a07                 | mov                 al, byte ptr [edi]
            //   3c41                 | cmp                 al, 0x41
            //   7c09                 | jl                  0xb

        $sequence_2 = { 6a2c e8???????? 59 3bc3 7409 8bf0 e8???????? }
            // n = 7, score = 100
            //   6a2c                 | push                0x2c
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   3bc3                 | cmp                 eax, ebx
            //   7409                 | je                  0xb
            //   8bf0                 | mov                 esi, eax
            //   e8????????           |                     

        $sequence_3 = { ff7508 e8???????? 85c0 7431 391e 762d 8d7e04 }
            // n = 7, score = 100
            //   ff7508               | push                dword ptr [ebp + 8]
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   7431                 | je                  0x33
            //   391e                 | cmp                 dword ptr [esi], ebx
            //   762d                 | jbe                 0x2f
            //   8d7e04               | lea                 edi, [esi + 4]

        $sequence_4 = { 13f9 e8???????? 3bd7 770f 7205 3b45e4 7308 }
            // n = 7, score = 100
            //   13f9                 | adc                 edi, ecx
            //   e8????????           |                     
            //   3bd7                 | cmp                 edx, edi
            //   770f                 | ja                  0x11
            //   7205                 | jb                  7
            //   3b45e4               | cmp                 eax, dword ptr [ebp - 0x1c]
            //   7308                 | jae                 0xa

        $sequence_5 = { e8???????? 59 3bf8 72e5 6a3d 8bc3 e8???????? }
            // n = 7, score = 100
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   3bf8                 | cmp                 edi, eax
            //   72e5                 | jb                  0xffffffe7
            //   6a3d                 | push                0x3d
            //   8bc3                 | mov                 eax, ebx
            //   e8????????           |                     

        $sequence_6 = { 8a8040a14200 8845f4 ff75f4 8bc6 e8???????? 0fb64701 0fb64f02 }
            // n = 7, score = 100
            //   8a8040a14200         | mov                 al, byte ptr [eax + 0x42a140]
            //   8845f4               | mov                 byte ptr [ebp - 0xc], al
            //   ff75f4               | push                dword ptr [ebp - 0xc]
            //   8bc6                 | mov                 eax, esi
            //   e8????????           |                     
            //   0fb64701             | movzx               eax, byte ptr [edi + 1]
            //   0fb64f02             | movzx               ecx, byte ptr [edi + 2]

        $sequence_7 = { 50 6a00 ff75fc e8???????? 85c0 740a ff75fc }
            // n = 7, score = 100
            //   50                   | push                eax
            //   6a00                 | push                0
            //   ff75fc               | push                dword ptr [ebp - 4]
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   740a                 | je                  0xc
            //   ff75fc               | push                dword ptr [ebp - 4]

        $sequence_8 = { 8d143b 8945fc 8945f8 3bd1 7746 3bc8 7303 }
            // n = 7, score = 100
            //   8d143b               | lea                 edx, [ebx + edi]
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   8945f8               | mov                 dword ptr [ebp - 8], eax
            //   3bd1                 | cmp                 edx, ecx
            //   7746                 | ja                  0x48
            //   3bc8                 | cmp                 ecx, eax
            //   7303                 | jae                 5

        $sequence_9 = { 6a28 c6431001 e8???????? 8bf8 33c0 59 3bf8 }
            // n = 7, score = 100
            //   6a28                 | push                0x28
            //   c6431001             | mov                 byte ptr [ebx + 0x10], 1
            //   e8????????           |                     
            //   8bf8                 | mov                 edi, eax
            //   33c0                 | xor                 eax, eax
            //   59                   | pop                 ecx
            //   3bf8                 | cmp                 edi, eax

    condition:
        7 of them and filesize < 434176
}
