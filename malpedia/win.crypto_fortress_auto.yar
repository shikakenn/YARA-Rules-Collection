rule win_crypto_fortress_auto {

    meta:
        id = "3nPJ5qboSX2WEB1zdu0myR"
        fingerprint = "v1_sha256_7ca8cfbcda8442ad971ad2acb852f7382cff13447a653716ebcb2d4ba6db0aed"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.crypto_fortress."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.crypto_fortress"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 341b aa 2c03 aa 2cf9 aa 2c00 }
            // n = 7, score = 100
            //   341b                 | xor                 al, 0x1b
            //   aa                   | stosb               byte ptr es:[edi], al
            //   2c03                 | sub                 al, 3
            //   aa                   | stosb               byte ptr es:[edi], al
            //   2cf9                 | sub                 al, 0xf9
            //   aa                   | stosb               byte ptr es:[edi], al
            //   2c00                 | sub                 al, 0

        $sequence_1 = { 0433 aa 04fc aa 3411 }
            // n = 5, score = 100
            //   0433                 | add                 al, 0x33
            //   aa                   | stosb               byte ptr es:[edi], al
            //   04fc                 | add                 al, 0xfc
            //   aa                   | stosb               byte ptr es:[edi], al
            //   3411                 | xor                 al, 0x11

        $sequence_2 = { e8???????? 8bd8 68???????? e8???????? 50 53 }
            // n = 6, score = 100
            //   e8????????           |                     
            //   8bd8                 | mov                 ebx, eax
            //   68????????           |                     
            //   e8????????           |                     
            //   50                   | push                eax
            //   53                   | push                ebx

        $sequence_3 = { 8d3dccec4000 33c0 0450 aa }
            // n = 4, score = 100
            //   8d3dccec4000         | lea                 edi, [0x40eccc]
            //   33c0                 | xor                 eax, eax
            //   0450                 | add                 al, 0x50
            //   aa                   | stosb               byte ptr es:[edi], al

        $sequence_4 = { 33c0 0442 aa 2ce1 }
            // n = 4, score = 100
            //   33c0                 | xor                 eax, eax
            //   0442                 | add                 al, 0x42
            //   aa                   | stosb               byte ptr es:[edi], al
            //   2ce1                 | sub                 al, 0xe1

        $sequence_5 = { 83c308 8345fc08 c78548ffffff9c000000 8d8548ffffff 50 e8???????? }
            // n = 6, score = 100
            //   83c308               | add                 ebx, 8
            //   8345fc08             | add                 dword ptr [ebp - 4], 8
            //   c78548ffffff9c000000     | mov    dword ptr [ebp - 0xb8], 0x9c
            //   8d8548ffffff         | lea                 eax, [ebp - 0xb8]
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_6 = { 8345fc04 e8???????? 8803 83c301 8345fc01 8b45fc 5b }
            // n = 7, score = 100
            //   8345fc04             | add                 dword ptr [ebp - 4], 4
            //   e8????????           |                     
            //   8803                 | mov                 byte ptr [ebx], al
            //   83c301               | add                 ebx, 1
            //   8345fc01             | add                 dword ptr [ebp - 4], 1
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   5b                   | pop                 ebx

        $sequence_7 = { a3???????? 68???????? ff35???????? e8???????? 85c0 0f84a9030000 }
            // n = 6, score = 100
            //   a3????????           |                     
            //   68????????           |                     
            //   ff35????????         |                     
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   0f84a9030000         | je                  0x3af

        $sequence_8 = { 3dffff0000 0f84040e0000 a3???????? e8???????? }
            // n = 4, score = 100
            //   3dffff0000           | cmp                 eax, 0xffff
            //   0f84040e0000         | je                  0xe0a
            //   a3????????           |                     
            //   e8????????           |                     

        $sequence_9 = { 68???????? ff35???????? e8???????? 85c0 0f842b010000 a3???????? }
            // n = 6, score = 100
            //   68????????           |                     
            //   ff35????????         |                     
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   0f842b010000         | je                  0x131
            //   a3????????           |                     

    condition:
        7 of them and filesize < 188416
}
