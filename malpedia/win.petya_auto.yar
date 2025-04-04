rule win_petya_auto {

    meta:
        id = "4MrmYBh9ZVhAAkgCbkQQ8a"
        fingerprint = "v1_sha256_126f559636a52e8bbed5a94164c0b2da83f722a29115c2b51cd7bbb82a77ed47"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.petya."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.petya"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 03c7 53 50 e8???????? 83c40c 8d5750 }
            // n = 6, score = 600
            //   03c7                 | add                 eax, edi
            //   53                   | push                ebx
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   8d5750               | lea                 edx, [edi + 0x50]

        $sequence_1 = { 75f5 46 3bf2 53 0f42f2 6a04 56 }
            // n = 7, score = 600
            //   75f5                 | jne                 0xfffffff7
            //   46                   | inc                 esi
            //   3bf2                 | cmp                 esi, edx
            //   53                   | push                ebx
            //   0f42f2               | cmovb               esi, edx
            //   6a04                 | push                4
            //   56                   | push                esi

        $sequence_2 = { 0f42f2 6a04 56 e8???????? 8bd8 }
            // n = 5, score = 600
            //   0f42f2               | cmovb               esi, edx
            //   6a04                 | push                4
            //   56                   | push                esi
            //   e8????????           |                     
            //   8bd8                 | mov                 ebx, eax

        $sequence_3 = { 8b4c2420 33fe 8bf0 33da 0facc80e 33d2 c1e612 }
            // n = 7, score = 600
            //   8b4c2420             | mov                 ecx, dword ptr [esp + 0x20]
            //   33fe                 | xor                 edi, esi
            //   8bf0                 | mov                 esi, eax
            //   33da                 | xor                 ebx, edx
            //   0facc80e             | shrd                eax, ecx, 0xe
            //   33d2                 | xor                 edx, edx
            //   c1e612               | shl                 esi, 0x12

        $sequence_4 = { a1???????? 85c0 743a 53 56 8b35???????? 33c9 }
            // n = 7, score = 600
            //   a1????????           |                     
            //   85c0                 | test                eax, eax
            //   743a                 | je                  0x3c
            //   53                   | push                ebx
            //   56                   | push                esi
            //   8b35????????         |                     
            //   33c9                 | xor                 ecx, ecx

        $sequence_5 = { c1e017 33ff 0bf9 c1eb09 8b4c2424 }
            // n = 5, score = 600
            //   c1e017               | shl                 eax, 0x17
            //   33ff                 | xor                 edi, edi
            //   0bf9                 | or                  edi, ecx
            //   c1eb09               | shr                 ebx, 9
            //   8b4c2424             | mov                 ecx, dword ptr [esp + 0x24]

        $sequence_6 = { c1eb09 0bd8 8b44241c 8bf0 0facc812 c1e60e }
            // n = 6, score = 600
            //   c1eb09               | shr                 ebx, 9
            //   0bd8                 | or                  ebx, eax
            //   8b44241c             | mov                 eax, dword ptr [esp + 0x1c]
            //   8bf0                 | mov                 esi, eax
            //   0facc812             | shrd                eax, ecx, 0x12
            //   c1e60e               | shl                 esi, 0xe

        $sequence_7 = { 8bf8 85f6 7505 e8???????? 8bc7 5f }
            // n = 6, score = 600
            //   8bf8                 | mov                 edi, eax
            //   85f6                 | test                esi, esi
            //   7505                 | jne                 7
            //   e8????????           |                     
            //   8bc7                 | mov                 eax, edi
            //   5f                   | pop                 edi

        $sequence_8 = { 33d2 0facc812 0bd0 c1e912 0bf1 }
            // n = 5, score = 600
            //   33d2                 | xor                 edx, edx
            //   0facc812             | shrd                eax, ecx, 0x12
            //   0bd0                 | or                  edx, eax
            //   c1e912               | shr                 ecx, 0x12
            //   0bf1                 | or                  esi, ecx

        $sequence_9 = { 6a00 50 e8???????? ff7618 8d857cfeffff }
            // n = 5, score = 600
            //   6a00                 | push                0
            //   50                   | push                eax
            //   e8????????           |                     
            //   ff7618               | push                dword ptr [esi + 0x18]
            //   8d857cfeffff         | lea                 eax, [ebp - 0x184]

    condition:
        7 of them and filesize < 229376
}
