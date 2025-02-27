rule win_graftor_auto {

    meta:
        id = "797TMZteEIF1KGg2FiUFPQ"
        fingerprint = "v1_sha256_fb4376621aa16704d8aafacb83eec317def5e2f740ec5d73dd897b4e00fd49ae"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.graftor."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.graftor"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { c684246003000090 e8???????? 8d8c24e8010000 51 8d4c2440 51 8d9424c4000000 }
            // n = 7, score = 100
            //   c684246003000090     | mov                 byte ptr [esp + 0x360], 0x90
            //   e8????????           |                     
            //   8d8c24e8010000       | lea                 ecx, [esp + 0x1e8]
            //   51                   | push                ecx
            //   8d4c2440             | lea                 ecx, [esp + 0x40]
            //   51                   | push                ecx
            //   8d9424c4000000       | lea                 edx, [esp + 0xc4]

        $sequence_1 = { 81fee8d94e00 59 7cee 5e c3 8bff 55 }
            // n = 7, score = 100
            //   81fee8d94e00         | cmp                 esi, 0x4ed9e8
            //   59                   | pop                 ecx
            //   7cee                 | jl                  0xfffffff0
            //   5e                   | pop                 esi
            //   c3                   | ret                 
            //   8bff                 | mov                 edi, edi
            //   55                   | push                ebp

        $sequence_2 = { 6a30 ff750c 6a00 ff7508 ffd0 5d }
            // n = 6, score = 100
            //   6a30                 | push                0x30
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   6a00                 | push                0
            //   ff7508               | push                dword ptr [ebp + 8]
            //   ffd0                 | call                eax
            //   5d                   | pop                 ebp

        $sequence_3 = { a5 a5 a5 7205 8b4004 eb03 83c004 }
            // n = 7, score = 100
            //   a5                   | movsd               dword ptr es:[edi], dword ptr [esi]
            //   a5                   | movsd               dword ptr es:[edi], dword ptr [esi]
            //   a5                   | movsd               dword ptr es:[edi], dword ptr [esi]
            //   7205                 | jb                  7
            //   8b4004               | mov                 eax, dword ptr [eax + 4]
            //   eb03                 | jmp                 5
            //   83c004               | add                 eax, 4

        $sequence_4 = { ff15???????? 57 85c0 750c ff15???????? 32c0 5f }
            // n = 7, score = 100
            //   ff15????????         |                     
            //   57                   | push                edi
            //   85c0                 | test                eax, eax
            //   750c                 | jne                 0xe
            //   ff15????????         |                     
            //   32c0                 | xor                 al, al
            //   5f                   | pop                 edi

        $sequence_5 = { 732c ff75f0 8b4508 8b00 ff75ec 8945e4 8d45e4 }
            // n = 7, score = 100
            //   732c                 | jae                 0x2e
            //   ff75f0               | push                dword ptr [ebp - 0x10]
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   8b00                 | mov                 eax, dword ptr [eax]
            //   ff75ec               | push                dword ptr [ebp - 0x14]
            //   8945e4               | mov                 dword ptr [ebp - 0x1c], eax
            //   8d45e4               | lea                 eax, [ebp - 0x1c]

        $sequence_6 = { 57 50 51 57 68e9fd0000 ffd3 8945c8 }
            // n = 7, score = 100
            //   57                   | push                edi
            //   50                   | push                eax
            //   51                   | push                ecx
            //   57                   | push                edi
            //   68e9fd0000           | push                0xfde9
            //   ffd3                 | call                ebx
            //   8945c8               | mov                 dword ptr [ebp - 0x38], eax

        $sequence_7 = { c20400 55 8bec 8b450c 8d4802 668b10 40 }
            // n = 7, score = 100
            //   c20400               | ret                 4
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   8d4802               | lea                 ecx, [eax + 2]
            //   668b10               | mov                 dx, word ptr [eax]
            //   40                   | inc                 eax

        $sequence_8 = { 6a00 6a01 ff15???????? 85c0 7406 8935???????? c605????????01 }
            // n = 7, score = 100
            //   6a00                 | push                0
            //   6a01                 | push                1
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7406                 | je                  8
            //   8935????????         |                     
            //   c605????????01       |                     

        $sequence_9 = { 57 e8???????? 8bc7 e8???????? 84c0 750b 68d8db4c00 }
            // n = 7, score = 100
            //   57                   | push                edi
            //   e8????????           |                     
            //   8bc7                 | mov                 eax, edi
            //   e8????????           |                     
            //   84c0                 | test                al, al
            //   750b                 | jne                 0xd
            //   68d8db4c00           | push                0x4cdbd8

    condition:
        7 of them and filesize < 294912
}
