rule win_bumblebee_auto {

    meta:
        id = "sihP6HOOHElDXUL7X6mZ9"
        fingerprint = "v1_sha256_1740917da778479acf746acdc75f2beb6821c321be8f136bbd653a625bc1c0f8"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.bumblebee."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.bumblebee"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 0f849b010000 be80030000 488d4c2470 448bc6 }
            // n = 4, score = 3100
            //   0f849b010000         | dec                 eax
            //   be80030000           | cmp                 ecx, 1
            //   488d4c2470           | dec                 eax
            //   448bc6               | mov                 ecx, dword ptr [edx]

        $sequence_1 = { 488b4108 488bd9 4183c9ff 4889442428 }
            // n = 4, score = 3100
            //   488b4108             | lea                 ecx, [0xdfc60]
            //   488bd9               | dec                 eax
            //   4183c9ff             | cmp                 eax, 0x1c
            //   4889442428           | ja                  0x28a

        $sequence_2 = { ff15???????? 90 33c0 488b5c2448 }
            // n = 4, score = 3100
            //   ff15????????         |                     
            //   90                   | lea                 eax, [edx - 0x37]
            //   33c0                 | mov                 dword ptr [esp + 0x20], 0x78
            //   488b5c2448           | dec                 esp

        $sequence_3 = { 4881ec20040000 488b05???????? 4833c4 48898518030000 4c8bf1 }
            // n = 5, score = 3100
            //   4881ec20040000       | mov                 ebp, esp
            //   488b05????????       |                     
            //   4833c4               | dec                 ecx
            //   48898518030000       | add                 ebp, esi
            //   4c8bf1               | inc                 ecx

        $sequence_4 = { b8c0000000 4803fe ba64860000 66395304 8d4810 0f44c1 }
            // n = 6, score = 3100
            //   b8c0000000           | lea                 eax, [0x2280b]
            //   4803fe               | dec                 eax
            //   ba64860000           | mov                 dword ptr [esp + 0x28], eax
            //   66395304             | dec                 eax
            //   8d4810               | mov                 dword ptr [esp + 0x20], ebx
            //   0f44c1               | je                  0x225

        $sequence_5 = { 498bce ffd0 85c0 0f8895000000 8b7b28 b8c0000000 4803fe }
            // n = 7, score = 3100
            //   498bce               | dec                 eax
            //   ffd0                 | mov                 dword ptr [ebp + 0xb10], 0x16
            //   85c0                 | dec                 eax
            //   0f8895000000         | lea                 eax, [0x1a25f4]
            //   8b7b28               | dec                 eax
            //   b8c0000000           | mov                 dword ptr [ebp + 0xb18], eax
            //   4803fe               | dec                 eax

        $sequence_6 = { 488bd8 c744243802000000 488d442450 4889442430 4c8bc6 488d842498000000 488bd5 }
            // n = 7, score = 3100
            //   488bd8               | inc                 ebp
            //   c744243802000000     | xor                 eax, eax
            //   488d442450           | dec                 eax
            //   4889442430           | mov                 esi, edx
            //   4c8bc6               | dec                 esp
            //   488d842498000000     | mov                 esi, ecx
            //   488bd5               | dec                 esp

        $sequence_7 = { 4885d2 7411 4883c208 4883c108 }
            // n = 4, score = 3100
            //   4885d2               | dec                 ecx
            //   7411                 | shr                 ecx, 0x1a
            //   4883c208             | inc                 ebp
            //   4883c108             | mov                 edx, eax

        $sequence_8 = { 48833b00 480f453b 488bcb e8???????? 488bc7 488b8d18030000 4833cc }
            // n = 7, score = 3100
            //   48833b00             | inc                 edx
            //   480f453b             | dec                 eax
            //   488bcb               | sub                 eax, edx
            //   e8????????           |                     
            //   488bc7               | dec                 eax
            //   488b8d18030000       | cmp                 eax, 1
            //   4833cc               | jae                 0x164

        $sequence_9 = { 33db 4d8bf0 4c8bea 48895d48 8bf1 48895dc8 33d2 }
            // n = 7, score = 3100
            //   33db                 | dec                 eax
            //   4d8bf0               | mov                 ecx, edi
            //   4c8bea               | mov                 dword ptr [esp + 0x20], 0xb3
            //   48895d48             | inc                 esp
            //   8bf1                 | mov                 eax, edx
            //   48895dc8             | dec                 esp
            //   33d2                 | lea                 ecx, [0xff460]

    condition:
        7 of them and filesize < 4825088
}
