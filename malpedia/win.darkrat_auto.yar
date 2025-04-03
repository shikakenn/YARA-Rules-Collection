rule win_darkrat_auto {

    meta:
        id = "3lueuQxraDN2Oym5B58ZNy"
        fingerprint = "v1_sha256_e8461586b168e71b04b888d3fef9b643bcbbe5ebaeef3515951b1dcd9d78d8ef"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.darkrat."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.darkrat"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 8b75b8 8b4314 0f43d6 8b7b10 2bc7 8b4dc8 }
            // n = 6, score = 200
            //   8b75b8               | mov                 esi, dword ptr [ebp - 0x48]
            //   8b4314               | mov                 eax, dword ptr [ebx + 0x14]
            //   0f43d6               | cmovae              edx, esi
            //   8b7b10               | mov                 edi, dword ptr [ebx + 0x10]
            //   2bc7                 | sub                 eax, edi
            //   8b4dc8               | mov                 ecx, dword ptr [ebp - 0x38]

        $sequence_1 = { 85c0 7446 8bd0 b805000000 2bd6 8a0e 8d7601 }
            // n = 7, score = 200
            //   85c0                 | test                eax, eax
            //   7446                 | je                  0x48
            //   8bd0                 | mov                 edx, eax
            //   b805000000           | mov                 eax, 5
            //   2bd6                 | sub                 edx, esi
            //   8a0e                 | mov                 cl, byte ptr [esi]
            //   8d7601               | lea                 esi, [esi + 1]

        $sequence_2 = { 83f801 751f 6a0a 68???????? 8bcb e8???????? }
            // n = 6, score = 200
            //   83f801               | cmp                 eax, 1
            //   751f                 | jne                 0x21
            //   6a0a                 | push                0xa
            //   68????????           |                     
            //   8bcb                 | mov                 ecx, ebx
            //   e8????????           |                     

        $sequence_3 = { 3bf2 0f8211010000 2bf2 8d45d8 b901000000 3bf1 0f42ce }
            // n = 7, score = 200
            //   3bf2                 | cmp                 esi, edx
            //   0f8211010000         | jb                  0x117
            //   2bf2                 | sub                 esi, edx
            //   8d45d8               | lea                 eax, [ebp - 0x28]
            //   b901000000           | mov                 ecx, 1
            //   3bf1                 | cmp                 esi, ecx
            //   0f42ce               | cmovb               ecx, esi

        $sequence_4 = { 85c0 7413 8b4904 8b00 8b4c3938 }
            // n = 5, score = 200
            //   85c0                 | test                eax, eax
            //   7413                 | je                  0x15
            //   8b4904               | mov                 ecx, dword ptr [ecx + 4]
            //   8b00                 | mov                 eax, dword ptr [eax]
            //   8b4c3938             | mov                 ecx, dword ptr [ecx + edi + 0x38]

        $sequence_5 = { ff15???????? 85c0 7445 8bc6 }
            // n = 4, score = 200
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7445                 | je                  0x47
            //   8bc6                 | mov                 eax, esi

        $sequence_6 = { 57 50 8975fc e8???????? 8bd0 }
            // n = 5, score = 200
            //   57                   | push                edi
            //   50                   | push                eax
            //   8975fc               | mov                 dword ptr [ebp - 4], esi
            //   e8????????           |                     
            //   8bd0                 | mov                 edx, eax

        $sequence_7 = { e8???????? 8b551c 83fa10 72bd 8b4d08 42 8bc1 }
            // n = 7, score = 200
            //   e8????????           |                     
            //   8b551c               | mov                 edx, dword ptr [ebp + 0x1c]
            //   83fa10               | cmp                 edx, 0x10
            //   72bd                 | jb                  0xffffffbf
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   42                   | inc                 edx
            //   8bc1                 | mov                 eax, ecx

        $sequence_8 = { 6a00 8945ec ff15???????? 8bd8 85db 7462 }
            // n = 6, score = 200
            //   6a00                 | push                0
            //   8945ec               | mov                 dword ptr [ebp - 0x14], eax
            //   ff15????????         |                     
            //   8bd8                 | mov                 ebx, eax
            //   85db                 | test                ebx, ebx
            //   7462                 | je                  0x64

        $sequence_9 = { 8b8d68ffffff 8bc2 2bc1 57 3bf8 7731 8d040f }
            // n = 7, score = 200
            //   8b8d68ffffff         | mov                 ecx, dword ptr [ebp - 0x98]
            //   8bc2                 | mov                 eax, edx
            //   2bc1                 | sub                 eax, ecx
            //   57                   | push                edi
            //   3bf8                 | cmp                 edi, eax
            //   7731                 | ja                  0x33
            //   8d040f               | lea                 eax, [edi + ecx]

    condition:
        7 of them and filesize < 884736
}
