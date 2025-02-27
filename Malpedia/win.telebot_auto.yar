rule win_telebot_auto {

    meta:
        id = "7S5LL5aLi66nT2X7bGF49C"
        fingerprint = "v1_sha256_9fb4b3d66890ed58f3a3d59d018f251f86a856f3ab96889528177b8a2474637f"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.telebot."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.telebot"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 891c24 89442404 e8???????? 807c244f00 0f8449020000 80bc244f10000000 0f843b020000 }
            // n = 7, score = 100
            //   891c24               | mov                 dword ptr [esp], ebx
            //   89442404             | mov                 dword ptr [esp + 4], eax
            //   e8????????           |                     
            //   807c244f00           | cmp                 byte ptr [esp + 0x4f], 0
            //   0f8449020000         | je                  0x24f
            //   80bc244f10000000     | cmp                 byte ptr [esp + 0x104f], 0
            //   0f843b020000         | je                  0x241

        $sequence_1 = { 807c244300 0f85a8000000 8b8424a4000000 89e9 8d149d00000000 895c2430 }
            // n = 6, score = 100
            //   807c244300           | cmp                 byte ptr [esp + 0x43], 0
            //   0f85a8000000         | jne                 0xae
            //   8b8424a4000000       | mov                 eax, dword ptr [esp + 0xa4]
            //   89e9                 | mov                 ecx, ebp
            //   8d149d00000000       | lea                 edx, [ebx*4]
            //   895c2430             | mov                 dword ptr [esp + 0x30], ebx

        $sequence_2 = { 8b5328 8b4b24 85c9 7472 c7442408cc1b0000 c744240401000000 891424 }
            // n = 7, score = 100
            //   8b5328               | mov                 edx, dword ptr [ebx + 0x28]
            //   8b4b24               | mov                 ecx, dword ptr [ebx + 0x24]
            //   85c9                 | test                ecx, ecx
            //   7472                 | je                  0x74
            //   c7442408cc1b0000     | mov                 dword ptr [esp + 8], 0x1bcc
            //   c744240401000000     | mov                 dword ptr [esp + 4], 1
            //   891424               | mov                 dword ptr [esp], edx

        $sequence_3 = { 8b4320 8b33 890424 ffd7 83ec04 8974240c c744240801000000 }
            // n = 7, score = 100
            //   8b4320               | mov                 eax, dword ptr [ebx + 0x20]
            //   8b33                 | mov                 esi, dword ptr [ebx]
            //   890424               | mov                 dword ptr [esp], eax
            //   ffd7                 | call                edi
            //   83ec04               | sub                 esp, 4
            //   8974240c             | mov                 dword ptr [esp + 0xc], esi
            //   c744240801000000     | mov                 dword ptr [esp + 8], 1

        $sequence_4 = { 83e0f8 83e107 897c2408 89463c d3e2 83f807 }
            // n = 6, score = 100
            //   83e0f8               | and                 eax, 0xfffffff8
            //   83e107               | and                 ecx, 7
            //   897c2408             | mov                 dword ptr [esp + 8], edi
            //   89463c               | mov                 dword ptr [esi + 0x3c], eax
            //   d3e2                 | shl                 edx, cl
            //   83f807               | cmp                 eax, 7

        $sequence_5 = { e8???????? 85c0 89c6 745e }
            // n = 4, score = 100
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   89c6                 | mov                 esi, eax
            //   745e                 | je                  0x60

        $sequence_6 = { 0fb74102 0fb64901 d3ea 29cf 0fb6cb 85c9 745e }
            // n = 7, score = 100
            //   0fb74102             | movzx               eax, word ptr [ecx + 2]
            //   0fb64901             | movzx               ecx, byte ptr [ecx + 1]
            //   d3ea                 | shr                 edx, cl
            //   29cf                 | sub                 edi, ecx
            //   0fb6cb               | movzx               ecx, bl
            //   85c9                 | test                ecx, ecx
            //   745e                 | je                  0x60

        $sequence_7 = { b801000000 d3e0 89d5 8954243c 8d40ff 89442440 21f0 }
            // n = 7, score = 100
            //   b801000000           | mov                 eax, 1
            //   d3e0                 | shl                 eax, cl
            //   89d5                 | mov                 ebp, edx
            //   8954243c             | mov                 dword ptr [esp + 0x3c], edx
            //   8d40ff               | lea                 eax, [eax - 1]
            //   89442440             | mov                 dword ptr [esp + 0x40], eax
            //   21f0                 | and                 eax, esi

        $sequence_8 = { c7442404???????? 890424 ff15???????? 8b6b08 3b6b0c 89442418 a1???????? }
            // n = 7, score = 100
            //   c7442404????????     |                     
            //   890424               | mov                 dword ptr [esp], eax
            //   ff15????????         |                     
            //   8b6b08               | mov                 ebp, dword ptr [ebx + 8]
            //   3b6b0c               | cmp                 ebp, dword ptr [ebx + 0xc]
            //   89442418             | mov                 dword ptr [esp + 0x18], eax
            //   a1????????           |                     

        $sequence_9 = { 8b06 89f3 85c0 7411 890424 }
            // n = 5, score = 100
            //   8b06                 | mov                 eax, dword ptr [esi]
            //   89f3                 | mov                 ebx, esi
            //   85c0                 | test                eax, eax
            //   7411                 | je                  0x13
            //   890424               | mov                 dword ptr [esp], eax

    condition:
        7 of them and filesize < 393216
}
