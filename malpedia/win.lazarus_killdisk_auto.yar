rule win_lazarus_killdisk_auto {

    meta:
        id = "448CLKxJwafu5t2C6pfJIQ"
        fingerprint = "v1_sha256_b26134f5ee9a86ea9f8f0c2251fd193e47e701ab49921be548b684d8807f003c"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.lazarus_killdisk."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.lazarus_killdisk"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 8d95f8feffff 52 e8???????? 8b4dfc ff0d???????? 33cd 83c410 }
            // n = 7, score = 200
            //   8d95f8feffff         | lea                 edx, [ebp - 0x108]
            //   52                   | push                edx
            //   e8????????           |                     
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   ff0d????????         |                     
            //   33cd                 | xor                 ecx, ebp
            //   83c410               | add                 esp, 0x10

        $sequence_1 = { 6800040000 68???????? 56 ffd7 4b 75ea }
            // n = 6, score = 200
            //   6800040000           | push                0x400
            //   68????????           |                     
            //   56                   | push                esi
            //   ffd7                 | call                edi
            //   4b                   | dec                 ebx
            //   75ea                 | jne                 0xffffffec

        $sequence_2 = { 56 57 e8???????? 8b1d???????? 33ff 6803010000 }
            // n = 6, score = 200
            //   56                   | push                esi
            //   57                   | push                edi
            //   e8????????           |                     
            //   8b1d????????         |                     
            //   33ff                 | xor                 edi, edi
            //   6803010000           | push                0x103

        $sequence_3 = { 83d2ff 56 8945ec 8955f0 ff15???????? }
            // n = 5, score = 200
            //   83d2ff               | adc                 edx, -1
            //   56                   | push                esi
            //   8945ec               | mov                 dword ptr [ebp - 0x14], eax
            //   8955f0               | mov                 dword ptr [ebp - 0x10], edx
            //   ff15????????         |                     

        $sequence_4 = { ffd7 46 fe442410 d1eb 759b }
            // n = 5, score = 200
            //   ffd7                 | call                edi
            //   46                   | inc                 esi
            //   fe442410             | inc                 byte ptr [esp + 0x10]
            //   d1eb                 | shr                 ebx, 1
            //   759b                 | jne                 0xffffff9d

        $sequence_5 = { e8???????? 8d842468010000 83c410 8d5001 }
            // n = 4, score = 200
            //   e8????????           |                     
            //   8d842468010000       | lea                 eax, [esp + 0x168]
            //   83c410               | add                 esp, 0x10
            //   8d5001               | lea                 edx, [eax + 1]

        $sequence_6 = { 8d75a6 8b06 8b4e08 8b560c 8945e8 8b4604 8945ec }
            // n = 7, score = 200
            //   8d75a6               | lea                 esi, [ebp - 0x5a]
            //   8b06                 | mov                 eax, dword ptr [esi]
            //   8b4e08               | mov                 ecx, dword ptr [esi + 8]
            //   8b560c               | mov                 edx, dword ptr [esi + 0xc]
            //   8945e8               | mov                 dword ptr [ebp - 0x18], eax
            //   8b4604               | mov                 eax, dword ptr [esi + 4]
            //   8945ec               | mov                 dword ptr [ebp - 0x14], eax

        $sequence_7 = { 57 ff15???????? 46 83fe20 7cc0 }
            // n = 5, score = 200
            //   57                   | push                edi
            //   ff15????????         |                     
            //   46                   | inc                 esi
            //   83fe20               | cmp                 esi, 0x20
            //   7cc0                 | jl                  0xffffffc2

        $sequence_8 = { 57 8945f0 89b5e4fdffff ffd3 3b45f0 }
            // n = 5, score = 200
            //   57                   | push                edi
            //   8945f0               | mov                 dword ptr [ebp - 0x10], eax
            //   89b5e4fdffff         | mov                 dword ptr [ebp - 0x21c], esi
            //   ffd3                 | call                ebx
            //   3b45f0               | cmp                 eax, dword ptr [ebp - 0x10]

        $sequence_9 = { 8945fc 53 56 57 6824010000 8d85c4feffff 6a00 }
            // n = 7, score = 200
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   53                   | push                ebx
            //   56                   | push                esi
            //   57                   | push                edi
            //   6824010000           | push                0x124
            //   8d85c4feffff         | lea                 eax, [ebp - 0x13c]
            //   6a00                 | push                0

    condition:
        7 of them and filesize < 209920
}
