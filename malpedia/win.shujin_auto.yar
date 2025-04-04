rule win_shujin_auto {

    meta:
        id = "4DZAHfZydmwIKBdwNo1EWY"
        fingerprint = "v1_sha256_9e7c36d5a8e7a7e0db70030a2edbd679a6e8a68faaf57024a99c72983d6e53eb"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.shujin."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.shujin"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 23d8 333c9de8994000 0fb6590b 23d0 333c95e8a14000 8b510a 897906 }
            // n = 7, score = 100
            //   23d8                 | and                 ebx, eax
            //   333c9de8994000       | xor                 edi, dword ptr [ebx*4 + 0x4099e8]
            //   0fb6590b             | movzx               ebx, byte ptr [ecx + 0xb]
            //   23d0                 | and                 edx, eax
            //   333c95e8a14000       | xor                 edi, dword ptr [edx*4 + 0x40a1e8]
            //   8b510a               | mov                 edx, dword ptr [ecx + 0xa]
            //   897906               | mov                 dword ptr [ecx + 6], edi

        $sequence_1 = { 8b5df8 c1eb18 333c9de8954000 8b5dfc 23d8 333c9de8a14000 }
            // n = 6, score = 100
            //   8b5df8               | mov                 ebx, dword ptr [ebp - 8]
            //   c1eb18               | shr                 ebx, 0x18
            //   333c9de8954000       | xor                 edi, dword ptr [ebx*4 + 0x4095e8]
            //   8b5dfc               | mov                 ebx, dword ptr [ebp - 4]
            //   23d8                 | and                 ebx, eax
            //   333c9de8a14000       | xor                 edi, dword ptr [ebx*4 + 0x40a1e8]

        $sequence_2 = { 33d2 6bc003 85c0 7664 48 f7f7 }
            // n = 6, score = 100
            //   33d2                 | xor                 edx, edx
            //   6bc003               | imul                eax, eax, 3
            //   85c0                 | test                eax, eax
            //   7664                 | jbe                 0x66
            //   48                   | dec                 eax
            //   f7f7                 | div                 edi

        $sequence_3 = { 53 8b1d???????? 40 8bf0 6a02 8d7e7e 57 }
            // n = 7, score = 100
            //   53                   | push                ebx
            //   8b1d????????         |                     
            //   40                   | inc                 eax
            //   8bf0                 | mov                 esi, eax
            //   6a02                 | push                2
            //   8d7e7e               | lea                 edi, [esi + 0x7e]
            //   57                   | push                edi

        $sequence_4 = { f8 660fb3d9 30d1 8b4e08 e8???????? 60 53 }
            // n = 7, score = 100
            //   f8                   | clc                 
            //   660fb3d9             | btr                 cx, bx
            //   30d1                 | xor                 cl, dl
            //   8b4e08               | mov                 ecx, dword ptr [esi + 8]
            //   e8????????           |                     
            //   60                   | pushal              
            //   53                   | push                ebx

        $sequence_5 = { ffd3 8db7f4030000 e8???????? 8d85fcfeffff 50 }
            // n = 5, score = 100
            //   ffd3                 | call                ebx
            //   8db7f4030000         | lea                 esi, [edi + 0x3f4]
            //   e8????????           |                     
            //   8d85fcfeffff         | lea                 eax, [ebp - 0x104]
            //   50                   | push                eax

        $sequence_6 = { 53 8b1d???????? 57 8bf8 eb07 57 ffd3 }
            // n = 7, score = 100
            //   53                   | push                ebx
            //   8b1d????????         |                     
            //   57                   | push                edi
            //   8bf8                 | mov                 edi, eax
            //   eb07                 | jmp                 9
            //   57                   | push                edi
            //   ffd3                 | call                ebx

        $sequence_7 = { 8a06 3c41 7430 3c42 742c 56 }
            // n = 6, score = 100
            //   8a06                 | mov                 al, byte ptr [esi]
            //   3c41                 | cmp                 al, 0x41
            //   7430                 | je                  0x32
            //   3c42                 | cmp                 al, 0x42
            //   742c                 | je                  0x2e
            //   56                   | push                esi

        $sequence_8 = { e8???????? 52 ff742404 c745d843686563 ff3424 c6442404f2 }
            // n = 6, score = 100
            //   e8????????           |                     
            //   52                   | push                edx
            //   ff742404             | push                dword ptr [esp + 4]
            //   c745d843686563       | mov                 dword ptr [ebp - 0x28], 0x63656843
            //   ff3424               | push                dword ptr [esp]
            //   c6442404f2           | mov                 byte ptr [esp + 4], 0xf2

        $sequence_9 = { 56 8d45dc e8???????? 8d45ec 50 ff7620 ff15???????? }
            // n = 7, score = 100
            //   56                   | push                esi
            //   8d45dc               | lea                 eax, [ebp - 0x24]
            //   e8????????           |                     
            //   8d45ec               | lea                 eax, [ebp - 0x14]
            //   50                   | push                eax
            //   ff7620               | push                dword ptr [esi + 0x20]
            //   ff15????????         |                     

    condition:
        7 of them and filesize < 172032
}
