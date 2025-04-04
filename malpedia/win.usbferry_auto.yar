rule win_usbferry_auto {

    meta:
        id = "1t0ACs70PS9ZYVTi8kc7nX"
        fingerprint = "v1_sha256_246be59259afe1548e2a4d266237ef3554d233c2ef89881c3d19b399601a13ef"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.usbferry."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.usbferry"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { ff7210 8982f8000000 8b92fc000000 e8???????? 8b15???????? }
            // n = 5, score = 200
            //   ff7210               | push                dword ptr [edx + 0x10]
            //   8982f8000000         | mov                 dword ptr [edx + 0xf8], eax
            //   8b92fc000000         | mov                 edx, dword ptr [edx + 0xfc]
            //   e8????????           |                     
            //   8b15????????         |                     

        $sequence_1 = { 8b5df0 8b5514 8b4510 3bc8 }
            // n = 4, score = 200
            //   8b5df0               | mov                 ebx, dword ptr [ebp - 0x10]
            //   8b5514               | mov                 edx, dword ptr [ebp + 0x14]
            //   8b4510               | mov                 eax, dword ptr [ebp + 0x10]
            //   3bc8                 | cmp                 ecx, eax

        $sequence_2 = { 3bf0 7d1e 2bc6 50 6a30 53 894510 }
            // n = 7, score = 200
            //   3bf0                 | cmp                 esi, eax
            //   7d1e                 | jge                 0x20
            //   2bc6                 | sub                 eax, esi
            //   50                   | push                eax
            //   6a30                 | push                0x30
            //   53                   | push                ebx
            //   894510               | mov                 dword ptr [ebp + 0x10], eax

        $sequence_3 = { e8???????? 83c40c e8???????? 8d4d0c }
            // n = 4, score = 200
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   e8????????           |                     
            //   8d4d0c               | lea                 ecx, [ebp + 0xc]

        $sequence_4 = { 83c40c 8b45cc e9???????? 8b55e0 52 ff15???????? }
            // n = 6, score = 200
            //   83c40c               | add                 esp, 0xc
            //   8b45cc               | mov                 eax, dword ptr [ebp - 0x34]
            //   e9????????           |                     
            //   8b55e0               | mov                 edx, dword ptr [ebp - 0x20]
            //   52                   | push                edx
            //   ff15????????         |                     

        $sequence_5 = { 8d95a8feffff 83c2ff 899594f5ffff 8b8594f5ffff 8a4801 888da2f5ffff 838594f5ffff01 }
            // n = 7, score = 200
            //   8d95a8feffff         | lea                 edx, [ebp - 0x158]
            //   83c2ff               | add                 edx, -1
            //   899594f5ffff         | mov                 dword ptr [ebp - 0xa6c], edx
            //   8b8594f5ffff         | mov                 eax, dword ptr [ebp - 0xa6c]
            //   8a4801               | mov                 cl, byte ptr [eax + 1]
            //   888da2f5ffff         | mov                 byte ptr [ebp - 0xa5e], cl
            //   838594f5ffff01       | add                 dword ptr [ebp - 0xa6c], 1

        $sequence_6 = { 8d8db0f7ffff 51 e8???????? 83c40c }
            // n = 4, score = 200
            //   8d8db0f7ffff         | lea                 ecx, [ebp - 0x850]
            //   51                   | push                ecx
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc

        $sequence_7 = { 899588f5ffff 8b8598f5ffff 8a08 888da1f5ffff 838598f5ffff01 80bda1f5ffff00 75e2 }
            // n = 7, score = 200
            //   899588f5ffff         | mov                 dword ptr [ebp - 0xa78], edx
            //   8b8598f5ffff         | mov                 eax, dword ptr [ebp - 0xa68]
            //   8a08                 | mov                 cl, byte ptr [eax]
            //   888da1f5ffff         | mov                 byte ptr [ebp - 0xa5f], cl
            //   838598f5ffff01       | add                 dword ptr [ebp - 0xa68], 1
            //   80bda1f5ffff00       | cmp                 byte ptr [ebp - 0xa5f], 0
            //   75e2                 | jne                 0xffffffe4

        $sequence_8 = { c7404441342411 c7404cdbd5c0fe c740604fcda240 c740640f690ebc c74068b065f747 c7406c4a06d5fe }
            // n = 6, score = 200
            //   c7404441342411       | mov                 dword ptr [eax + 0x44], 0x11243441
            //   c7404cdbd5c0fe       | mov                 dword ptr [eax + 0x4c], 0xfec0d5db
            //   c740604fcda240       | mov                 dword ptr [eax + 0x60], 0x40a2cd4f
            //   c740640f690ebc       | mov                 dword ptr [eax + 0x64], 0xbc0e690f
            //   c74068b065f747       | mov                 dword ptr [eax + 0x68], 0x47f765b0
            //   c7406c4a06d5fe       | mov                 dword ptr [eax + 0x6c], 0xfed5064a

        $sequence_9 = { 59 85c0 752e 6a09 }
            // n = 4, score = 200
            //   59                   | pop                 ecx
            //   85c0                 | test                eax, eax
            //   752e                 | jne                 0x30
            //   6a09                 | push                9

        $sequence_10 = { f20f101d???????? 0f28ca 56 57 33ff }
            // n = 5, score = 200
            //   f20f101d????????     |                     
            //   0f28ca               | movaps              xmm1, xmm2
            //   56                   | push                esi
            //   57                   | push                edi
            //   33ff                 | xor                 edi, edi

        $sequence_11 = { 0f83ae000000 c64405e000 40 83f820 7cef }
            // n = 5, score = 200
            //   0f83ae000000         | jae                 0xb4
            //   c64405e000           | mov                 byte ptr [ebp + eax - 0x20], 0
            //   40                   | inc                 eax
            //   83f820               | cmp                 eax, 0x20
            //   7cef                 | jl                  0xfffffff1

        $sequence_12 = { 51 6a00 8b5510 52 8b45e0 50 }
            // n = 6, score = 200
            //   51                   | push                ecx
            //   6a00                 | push                0
            //   8b5510               | mov                 edx, dword ptr [ebp + 0x10]
            //   52                   | push                edx
            //   8b45e0               | mov                 eax, dword ptr [ebp - 0x20]
            //   50                   | push                eax

        $sequence_13 = { 7504 33c0 eb54 85c9 740e }
            // n = 5, score = 200
            //   7504                 | jne                 6
            //   33c0                 | xor                 eax, eax
            //   eb54                 | jmp                 0x56
            //   85c9                 | test                ecx, ecx
            //   740e                 | je                  0x10

        $sequence_14 = { 6aff 8b8da0f7ffff 51 ff15???????? 8b95a0f7ffff }
            // n = 5, score = 200
            //   6aff                 | push                -1
            //   8b8da0f7ffff         | mov                 ecx, dword ptr [ebp - 0x860]
            //   51                   | push                ecx
            //   ff15????????         |                     
            //   8b95a0f7ffff         | mov                 edx, dword ptr [ebp - 0x860]

        $sequence_15 = { 8a02 8845df 8345d801 807ddf00 75ee 8b4dd8 }
            // n = 6, score = 200
            //   8a02                 | mov                 al, byte ptr [edx]
            //   8845df               | mov                 byte ptr [ebp - 0x21], al
            //   8345d801             | add                 dword ptr [ebp - 0x28], 1
            //   807ddf00             | cmp                 byte ptr [ebp - 0x21], 0
            //   75ee                 | jne                 0xfffffff0
            //   8b4dd8               | mov                 ecx, dword ptr [ebp - 0x28]

    condition:
        7 of them and filesize < 638976
}
