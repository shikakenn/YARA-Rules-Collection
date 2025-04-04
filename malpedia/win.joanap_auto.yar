rule win_joanap_auto {

    meta:
        id = "15sBQQLaGx4wgrIQu0b5xP"
        fingerprint = "v1_sha256_6fdacc4c6daa9a4be9b126a90beb146cca04ff56d03b259a90c3b1977b1b6f5e"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.joanap."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.joanap"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 8bd0 81e20f000080 7905 4a 83caf0 42 8a92fc002d00 }
            // n = 7, score = 100
            //   8bd0                 | mov                 edx, eax
            //   81e20f000080         | and                 edx, 0x8000000f
            //   7905                 | jns                 7
            //   4a                   | dec                 edx
            //   83caf0               | or                  edx, 0xfffffff0
            //   42                   | inc                 edx
            //   8a92fc002d00         | mov                 dl, byte ptr [edx + 0x2d00fc]

        $sequence_1 = { 56 57 8d4c2468 e8???????? a1???????? 6a10 6a10 }
            // n = 7, score = 100
            //   56                   | push                esi
            //   57                   | push                edi
            //   8d4c2468             | lea                 ecx, [esp + 0x68]
            //   e8????????           |                     
            //   a1????????           |                     
            //   6a10                 | push                0x10
            //   6a10                 | push                0x10

        $sequence_2 = { 8b7e0c 8b74246c 894e40 897e44 895648 c6464c00 }
            // n = 6, score = 100
            //   8b7e0c               | mov                 edi, dword ptr [esi + 0xc]
            //   8b74246c             | mov                 esi, dword ptr [esp + 0x6c]
            //   894e40               | mov                 dword ptr [esi + 0x40], ecx
            //   897e44               | mov                 dword ptr [esi + 0x44], edi
            //   895648               | mov                 dword ptr [esi + 0x48], edx
            //   c6464c00             | mov                 byte ptr [esi + 0x4c], 0

        $sequence_3 = { b941000000 8dbc243c010000 6a00 6a0f f3a5 c744241400000000 c744241c28010000 }
            // n = 7, score = 100
            //   b941000000           | mov                 ecx, 0x41
            //   8dbc243c010000       | lea                 edi, [esp + 0x13c]
            //   6a00                 | push                0
            //   6a0f                 | push                0xf
            //   f3a5                 | rep movsd           dword ptr es:[edi], dword ptr [esi]
            //   c744241400000000     | mov                 dword ptr [esp + 0x14], 0
            //   c744241c28010000     | mov                 dword ptr [esp + 0x1c], 0x128

        $sequence_4 = { 668b4024 51 55 6689842440080000 e8???????? 83c414 83f8ff }
            // n = 7, score = 100
            //   668b4024             | mov                 ax, word ptr [eax + 0x24]
            //   51                   | push                ecx
            //   55                   | push                ebp
            //   6689842440080000     | mov                 word ptr [esp + 0x840], ax
            //   e8????????           |                     
            //   83c414               | add                 esp, 0x14
            //   83f8ff               | cmp                 eax, -1

        $sequence_5 = { 5e 81c400010000 c3 6a00 6a00 6a00 681f000f00 }
            // n = 7, score = 100
            //   5e                   | pop                 esi
            //   81c400010000         | add                 esp, 0x100
            //   c3                   | ret                 
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   681f000f00           | push                0xf001f

        $sequence_6 = { 75f1 33f6 68???????? 8935???????? ff15???????? 8b842494000000 }
            // n = 6, score = 100
            //   75f1                 | jne                 0xfffffff3
            //   33f6                 | xor                 esi, esi
            //   68????????           |                     
            //   8935????????         |                     
            //   ff15????????         |                     
            //   8b842494000000       | mov                 eax, dword ptr [esp + 0x94]

        $sequence_7 = { 51 ff15???????? 85c0 7471 397c2410 }
            // n = 5, score = 100
            //   51                   | push                ecx
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7471                 | je                  0x73
            //   397c2410             | cmp                 dword ptr [esp + 0x10], edi

        $sequence_8 = { 52 e8???????? 83ec14 8b0d???????? b0ff }
            // n = 5, score = 100
            //   52                   | push                edx
            //   e8????????           |                     
            //   83ec14               | sub                 esp, 0x14
            //   8b0d????????         |                     
            //   b0ff                 | mov                 al, 0xff

        $sequence_9 = { 8d842494000000 6880000000 50 6800040000 68???????? 6a02 e8???????? }
            // n = 7, score = 100
            //   8d842494000000       | lea                 eax, [esp + 0x94]
            //   6880000000           | push                0x80
            //   50                   | push                eax
            //   6800040000           | push                0x400
            //   68????????           |                     
            //   6a02                 | push                2
            //   e8????????           |                     

    condition:
        7 of them and filesize < 270336
}
