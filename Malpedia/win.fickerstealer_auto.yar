rule win_fickerstealer_auto {

    meta:
        id = "11C5CShc5YjJRC6TBjSaW0"
        fingerprint = "v1_sha256_0126c62412dad879a43e44f06017fe0625a540d4c54a2a3f5410236702fb1a45"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.fickerstealer."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.fickerstealer"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { ff500c 83c40c 84c0 0f85fe000000 8b45f0 8945cc 8975d0 }
            // n = 7, score = 200
            //   ff500c               | call                dword ptr [eax + 0xc]
            //   83c40c               | add                 esp, 0xc
            //   84c0                 | test                al, al
            //   0f85fe000000         | jne                 0x104
            //   8b45f0               | mov                 eax, dword ptr [ebp - 0x10]
            //   8945cc               | mov                 dword ptr [ebp - 0x34], eax
            //   8975d0               | mov                 dword ptr [ebp - 0x30], esi

        $sequence_1 = { ebb7 e8???????? 89c1 8945ec 6a02 58 31d2 }
            // n = 7, score = 200
            //   ebb7                 | jmp                 0xffffffb9
            //   e8????????           |                     
            //   89c1                 | mov                 ecx, eax
            //   8945ec               | mov                 dword ptr [ebp - 0x14], eax
            //   6a02                 | push                2
            //   58                   | pop                 eax
            //   31d2                 | xor                 edx, edx

        $sequence_2 = { f20f104c2420 31d2 895c2470 890c24 894c2474 898424f0000000 8b442428 }
            // n = 7, score = 200
            //   f20f104c2420         | movsd               xmm1, qword ptr [esp + 0x20]
            //   31d2                 | xor                 edx, edx
            //   895c2470             | mov                 dword ptr [esp + 0x70], ebx
            //   890c24               | mov                 dword ptr [esp], ecx
            //   894c2474             | mov                 dword ptr [esp + 0x74], ecx
            //   898424f0000000       | mov                 dword ptr [esp + 0xf0], eax
            //   8b442428             | mov                 eax, dword ptr [esp + 0x28]

        $sequence_3 = { 8b4508 c7400cffffff7f 834808ff 834804ff 8308ff 5d c3 }
            // n = 7, score = 200
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   c7400cffffff7f       | mov                 dword ptr [eax + 0xc], 0x7fffffff
            //   834808ff             | or                  dword ptr [eax + 8], 0xffffffff
            //   834804ff             | or                  dword ptr [eax + 4], 0xffffffff
            //   8308ff               | or                  dword ptr [eax], 0xffffffff
            //   5d                   | pop                 ebp
            //   c3                   | ret                 

        $sequence_4 = { 31cb 234c2404 21df 231c24 31f8 89fa 8b7c2408 }
            // n = 7, score = 200
            //   31cb                 | xor                 ebx, ecx
            //   234c2404             | and                 ecx, dword ptr [esp + 4]
            //   21df                 | and                 edi, ebx
            //   231c24               | and                 ebx, dword ptr [esp]
            //   31f8                 | xor                 eax, edi
            //   89fa                 | mov                 edx, edi
            //   8b7c2408             | mov                 edi, dword ptr [esp + 8]

        $sequence_5 = { f20f114e0c 895614 eb12 8365e400 8d4de4 e8???????? 8b45f0 }
            // n = 7, score = 200
            //   f20f114e0c           | movsd               qword ptr [esi + 0xc], xmm1
            //   895614               | mov                 dword ptr [esi + 0x14], edx
            //   eb12                 | jmp                 0x14
            //   8365e400             | and                 dword ptr [ebp - 0x1c], 0
            //   8d4de4               | lea                 ecx, [ebp - 0x1c]
            //   e8????????           |                     
            //   8b45f0               | mov                 eax, dword ptr [ebp - 0x10]

        $sequence_6 = { d3e8 31db 80c518 43 21d8 c1e008 09d0 }
            // n = 7, score = 200
            //   d3e8                 | shr                 eax, cl
            //   31db                 | xor                 ebx, ebx
            //   80c518               | add                 ch, 0x18
            //   43                   | inc                 ebx
            //   21d8                 | and                 eax, ebx
            //   c1e008               | shl                 eax, 8
            //   09d0                 | or                  eax, edx

        $sequence_7 = { 56 83ec10 8b7d0c 8b4514 8b4d10 8b7508 8b5d18 }
            // n = 7, score = 200
            //   56                   | push                esi
            //   83ec10               | sub                 esp, 0x10
            //   8b7d0c               | mov                 edi, dword ptr [ebp + 0xc]
            //   8b4514               | mov                 eax, dword ptr [ebp + 0x14]
            //   8b4d10               | mov                 ecx, dword ptr [ebp + 0x10]
            //   8b7508               | mov                 esi, dword ptr [ebp + 8]
            //   8b5d18               | mov                 ebx, dword ptr [ebp + 0x18]

        $sequence_8 = { f20f114610 f20f114e08 f20f1116 56 e8???????? 59 83c418 }
            // n = 7, score = 200
            //   f20f114610           | movsd               qword ptr [esi + 0x10], xmm0
            //   f20f114e08           | movsd               qword ptr [esi + 8], xmm1
            //   f20f1116             | movsd               qword ptr [esi], xmm2
            //   56                   | push                esi
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   83c418               | add                 esp, 0x18

        $sequence_9 = { c1e00f 09f8 c1e107 0fb6f9 8b4de8 09f8 89df }
            // n = 7, score = 200
            //   c1e00f               | shl                 eax, 0xf
            //   09f8                 | or                  eax, edi
            //   c1e107               | shl                 ecx, 7
            //   0fb6f9               | movzx               edi, cl
            //   8b4de8               | mov                 ecx, dword ptr [ebp - 0x18]
            //   09f8                 | or                  eax, edi
            //   89df                 | mov                 edi, ebx

    condition:
        7 of them and filesize < 598016
}
