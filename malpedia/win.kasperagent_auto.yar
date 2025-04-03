rule win_kasperagent_auto {

    meta:
        id = "5o14rcitG1ura6W664RFw9"
        fingerprint = "v1_sha256_64254218e6067b681b9ff76df50b8965f4daccd1f710c2911946f314fae43e64"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.kasperagent."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.kasperagent"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 8b442420 2b442418 8b4c2428 2bc7 40 99 2bc2 }
            // n = 7, score = 200
            //   8b442420             | mov                 eax, dword ptr [esp + 0x20]
            //   2b442418             | sub                 eax, dword ptr [esp + 0x18]
            //   8b4c2428             | mov                 ecx, dword ptr [esp + 0x28]
            //   2bc7                 | sub                 eax, edi
            //   40                   | inc                 eax
            //   99                   | cdq                 
            //   2bc2                 | sub                 eax, edx

        $sequence_1 = { c3 e9???????? 6860020000 b8???????? e8???????? 8b4508 8b35???????? }
            // n = 7, score = 200
            //   c3                   | ret                 
            //   e9????????           |                     
            //   6860020000           | push                0x260
            //   b8????????           |                     
            //   e8????????           |                     
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   8b35????????         |                     

        $sequence_2 = { 3b5c2410 72c3 8b742414 8b7c241c 5d 5b 2bc1 }
            // n = 7, score = 200
            //   3b5c2410             | cmp                 ebx, dword ptr [esp + 0x10]
            //   72c3                 | jb                  0xffffffc5
            //   8b742414             | mov                 esi, dword ptr [esp + 0x14]
            //   8b7c241c             | mov                 edi, dword ptr [esp + 0x1c]
            //   5d                   | pop                 ebp
            //   5b                   | pop                 ebx
            //   2bc1                 | sub                 eax, ecx

        $sequence_3 = { 8b0f 8bc7 5f c6040e00 5e 5d 5b }
            // n = 7, score = 200
            //   8b0f                 | mov                 ecx, dword ptr [edi]
            //   8bc7                 | mov                 eax, edi
            //   5f                   | pop                 edi
            //   c6040e00             | mov                 byte ptr [esi + ecx], 0
            //   5e                   | pop                 esi
            //   5d                   | pop                 ebp
            //   5b                   | pop                 ebx

        $sequence_4 = { 750d 8b46f8 50 56 e8???????? 83c408 85c0 }
            // n = 7, score = 200
            //   750d                 | jne                 0xf
            //   8b46f8               | mov                 eax, dword ptr [esi - 8]
            //   50                   | push                eax
            //   56                   | push                esi
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   85c0                 | test                eax, eax

        $sequence_5 = { 8b4c2414 8b01 3b70f8 7fa9 }
            // n = 4, score = 200
            //   8b4c2414             | mov                 ecx, dword ptr [esp + 0x14]
            //   8b01                 | mov                 eax, dword ptr [ecx]
            //   3b70f8               | cmp                 esi, dword ptr [eax - 8]
            //   7fa9                 | jg                  0xffffffab

        $sequence_6 = { e8???????? 8b4500 ff442414 b92d000000 66890c78 8d7c3f02 }
            // n = 6, score = 200
            //   e8????????           |                     
            //   8b4500               | mov                 eax, dword ptr [ebp]
            //   ff442414             | inc                 dword ptr [esp + 0x14]
            //   b92d000000           | mov                 ecx, 0x2d
            //   66890c78             | mov                 word ptr [eax + edi*2], cx
            //   8d7c3f02             | lea                 edi, [edi + edi + 2]

        $sequence_7 = { 668b28 668929 83c102 83c002 47 3bce }
            // n = 6, score = 200
            //   668b28               | mov                 bp, word ptr [eax]
            //   668929               | mov                 word ptr [ecx], bp
            //   83c102               | add                 ecx, 2
            //   83c002               | add                 eax, 2
            //   47                   | inc                 edi
            //   3bce                 | cmp                 ecx, esi

        $sequence_8 = { ffd0 c645fc01 8b45d8 83c0f0 }
            // n = 4, score = 200
            //   ffd0                 | call                eax
            //   c645fc01             | mov                 byte ptr [ebp - 4], 1
            //   8b45d8               | mov                 eax, dword ptr [ebp - 0x28]
            //   83c0f0               | add                 eax, -0x10

        $sequence_9 = { 2bc1 33d2 d1f8 2bf0 668911 8bce 781a }
            // n = 7, score = 200
            //   2bc1                 | sub                 eax, ecx
            //   33d2                 | xor                 edx, edx
            //   d1f8                 | sar                 eax, 1
            //   2bf0                 | sub                 esi, eax
            //   668911               | mov                 word ptr [ecx], dx
            //   8bce                 | mov                 ecx, esi
            //   781a                 | js                  0x1c

    condition:
        7 of them and filesize < 1605632
}
