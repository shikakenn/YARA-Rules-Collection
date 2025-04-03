rule win_lightwork_auto {

    meta:
        id = "32nuzHXyTBkgPEZGa9pNa3"
        fingerprint = "v1_sha256_27c40b18d2800b0d83c68dd39a56494e6158b954f55a7dafaeb8933b3fe805f1"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.lightwork."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.lightwork"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 885003 90 5d c3 55 89e5 8b4508 }
            // n = 7, score = 100
            //   885003               | mov                 byte ptr [eax + 3], dl
            //   90                   | nop                 
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   55                   | push                ebp
            //   89e5                 | mov                 ebp, esp
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]

        $sequence_1 = { 8b4014 83f801 7e25 8b4508 8b00 8d90ff000000 }
            // n = 6, score = 100
            //   8b4014               | mov                 eax, dword ptr [eax + 0x14]
            //   83f801               | cmp                 eax, 1
            //   7e25                 | jle                 0x27
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   8b00                 | mov                 eax, dword ptr [eax]
            //   8d90ff000000         | lea                 edx, [eax + 0xff]

        $sequence_2 = { 55 89e5 8b4508 8b4004 83c001 0fb610 8b4508 }
            // n = 7, score = 100
            //   55                   | push                ebp
            //   89e5                 | mov                 ebp, esp
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   8b4004               | mov                 eax, dword ptr [eax + 4]
            //   83c001               | add                 eax, 1
            //   0fb610               | movzx               edx, byte ptr [eax]
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]

        $sequence_3 = { 8b4508 0fb6400d 8845f7 8b4508 0fb6400c 84c0 740a }
            // n = 7, score = 100
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   0fb6400d             | movzx               eax, byte ptr [eax + 0xd]
            //   8845f7               | mov                 byte ptr [ebp - 9], al
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   0fb6400c             | movzx               eax, byte ptr [eax + 0xc]
            //   84c0                 | test                al, al
            //   740a                 | je                  0xc

        $sequence_4 = { 8855e4 8845e0 837d0800 750f c7042410000000 e8???????? 894508 }
            // n = 7, score = 100
            //   8855e4               | mov                 byte ptr [ebp - 0x1c], dl
            //   8845e0               | mov                 byte ptr [ebp - 0x20], al
            //   837d0800             | cmp                 dword ptr [ebp + 8], 0
            //   750f                 | jne                 0x11
            //   c7042410000000       | mov                 dword ptr [esp], 0x10
            //   e8????????           |                     
            //   894508               | mov                 dword ptr [ebp + 8], eax

        $sequence_5 = { 01d0 8b4008 39450c 7f04 c645f701 }
            // n = 5, score = 100
            //   01d0                 | add                 eax, edx
            //   8b4008               | mov                 eax, dword ptr [eax + 8]
            //   39450c               | cmp                 dword ptr [ebp + 0xc], eax
            //   7f04                 | jg                  6
            //   c645f701             | mov                 byte ptr [ebp - 9], 1

        $sequence_6 = { 891424 e8???????? 83451802 8b4508 8d500f 8b4518 8944240c }
            // n = 7, score = 100
            //   891424               | mov                 dword ptr [esp], edx
            //   e8????????           |                     
            //   83451802             | add                 dword ptr [ebp + 0x18], 2
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   8d500f               | lea                 edx, [eax + 0xf]
            //   8b4518               | mov                 eax, dword ptr [ebp + 0x18]
            //   8944240c             | mov                 dword ptr [esp + 0xc], eax

        $sequence_7 = { 8b00 8b4014 83c00b 8945f0 }
            // n = 4, score = 100
            //   8b00                 | mov                 eax, dword ptr [eax]
            //   8b4014               | mov                 eax, dword ptr [eax + 0x14]
            //   83c00b               | add                 eax, 0xb
            //   8945f0               | mov                 dword ptr [ebp - 0x10], eax

        $sequence_8 = { 01d0 6bd03c 8b4508 8b00 01d0 2d00fd4b02 8b5dfc }
            // n = 7, score = 100
            //   01d0                 | add                 eax, edx
            //   6bd03c               | imul                edx, eax, 0x3c
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   8b00                 | mov                 eax, dword ptr [eax]
            //   01d0                 | add                 eax, edx
            //   2d00fd4b02           | sub                 eax, 0x24bfd00
            //   8b5dfc               | mov                 ebx, dword ptr [ebp - 4]

        $sequence_9 = { 8065fffc 8b450c 0045ff 8b4508 0fb655ff 8810 }
            // n = 6, score = 100
            //   8065fffc             | and                 byte ptr [ebp - 1], 0xfc
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   0045ff               | add                 byte ptr [ebp - 1], al
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   0fb655ff             | movzx               edx, byte ptr [ebp - 1]
            //   8810                 | mov                 byte ptr [eax], dl

    condition:
        7 of them and filesize < 1132544
}
