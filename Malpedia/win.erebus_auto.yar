rule win_erebus_auto {

    meta:
        id = "tOiXw5ppsv3gWWJqrQFqg"
        fingerprint = "v1_sha256_f2c3fac68e77b34a8cb144aa7557b3180cfb2d2c5f88070b47f30c977edf0360"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.erebus."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.erebus"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 75e4 33c0 8b54242c 33c9 85c0 8bfb 0f4ff9 }
            // n = 7, score = 100
            //   75e4                 | jne                 0xffffffe6
            //   33c0                 | xor                 eax, eax
            //   8b54242c             | mov                 edx, dword ptr [esp + 0x2c]
            //   33c9                 | xor                 ecx, ecx
            //   85c0                 | test                eax, eax
            //   8bfb                 | mov                 edi, ebx
            //   0f4ff9               | cmovg               edi, ecx

        $sequence_1 = { 55 56 57 8b7308 8b430c 895c241c 85f6 }
            // n = 7, score = 100
            //   55                   | push                ebp
            //   56                   | push                esi
            //   57                   | push                edi
            //   8b7308               | mov                 esi, dword ptr [ebx + 8]
            //   8b430c               | mov                 eax, dword ptr [ebx + 0xc]
            //   895c241c             | mov                 dword ptr [esp + 0x1c], ebx
            //   85f6                 | test                esi, esi

        $sequence_2 = { 33c0 c744243007000000 8d146b c744242c00000000 668944241c 663902 }
            // n = 6, score = 100
            //   33c0                 | xor                 eax, eax
            //   c744243007000000     | mov                 dword ptr [esp + 0x30], 7
            //   8d146b               | lea                 edx, [ebx + ebp*2]
            //   c744242c00000000     | mov                 dword ptr [esp + 0x2c], 0
            //   668944241c           | mov                 word ptr [esp + 0x1c], ax
            //   663902               | cmp                 word ptr [edx], ax

        $sequence_3 = { 8b0f 8b4704 2bc1 55 83e0fc 50 51 }
            // n = 7, score = 100
            //   8b0f                 | mov                 ecx, dword ptr [edi]
            //   8b4704               | mov                 eax, dword ptr [edi + 4]
            //   2bc1                 | sub                 eax, ecx
            //   55                   | push                ebp
            //   83e0fc               | and                 eax, 0xfffffffc
            //   50                   | push                eax
            //   51                   | push                ecx

        $sequence_4 = { 03ff 8b0485b86f5200 894c1830 8b45f0 8b5de8 3b450c }
            // n = 6, score = 100
            //   03ff                 | add                 edi, edi
            //   8b0485b86f5200       | mov                 eax, dword ptr [eax*4 + 0x526fb8]
            //   894c1830             | mov                 dword ptr [eax + ebx + 0x30], ecx
            //   8b45f0               | mov                 eax, dword ptr [ebp - 0x10]
            //   8b5de8               | mov                 ebx, dword ptr [ebp - 0x18]
            //   3b450c               | cmp                 eax, dword ptr [ebp + 0xc]

        $sequence_5 = { 8da42400000000 833d????????00 750f e8???????? c705????????c0474400 b902000000 c7442430043a5000 }
            // n = 7, score = 100
            //   8da42400000000       | lea                 esp, [esp]
            //   833d????????00       |                     
            //   750f                 | jne                 0x11
            //   e8????????           |                     
            //   c705????????c0474400     |     
            //   b902000000           | mov                 ecx, 2
            //   c7442430043a5000     | mov                 dword ptr [esp + 0x30], 0x503a04

        $sequence_6 = { 68???????? 8d4dd8 e8???????? 50 6a00 8d45a8 }
            // n = 6, score = 100
            //   68????????           |                     
            //   8d4dd8               | lea                 ecx, [ebp - 0x28]
            //   e8????????           |                     
            //   50                   | push                eax
            //   6a00                 | push                0
            //   8d45a8               | lea                 eax, [ebp - 0x58]

        $sequence_7 = { c744245c00000000 e8???????? 8b54242c 33c0 8b5c2430 8bca 8bfb }
            // n = 7, score = 100
            //   c744245c00000000     | mov                 dword ptr [esp + 0x5c], 0
            //   e8????????           |                     
            //   8b54242c             | mov                 edx, dword ptr [esp + 0x2c]
            //   33c0                 | xor                 eax, eax
            //   8b5c2430             | mov                 ebx, dword ptr [esp + 0x30]
            //   8bca                 | mov                 ecx, edx
            //   8bfb                 | mov                 edi, ebx

        $sequence_8 = { 0bd7 890cc5d07a5200 8914c5d47a5200 40 3d00010000 7cb2 0f57c0 }
            // n = 7, score = 100
            //   0bd7                 | or                  edx, edi
            //   890cc5d07a5200       | mov                 dword ptr [eax*8 + 0x527ad0], ecx
            //   8914c5d47a5200       | mov                 dword ptr [eax*8 + 0x527ad4], edx
            //   40                   | inc                 eax
            //   3d00010000           | cmp                 eax, 0x100
            //   7cb2                 | jl                  0xffffffb4
            //   0f57c0               | xorps               xmm0, xmm0

        $sequence_9 = { 7405 2bea 896b10 8b4c2440 64890d00000000 59 }
            // n = 6, score = 100
            //   7405                 | je                  7
            //   2bea                 | sub                 ebp, edx
            //   896b10               | mov                 dword ptr [ebx + 0x10], ebp
            //   8b4c2440             | mov                 ecx, dword ptr [esp + 0x40]
            //   64890d00000000       | mov                 dword ptr fs:[0], ecx
            //   59                   | pop                 ecx

    condition:
        7 of them and filesize < 2564096
}
