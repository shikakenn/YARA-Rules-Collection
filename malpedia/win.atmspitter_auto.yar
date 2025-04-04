rule win_atmspitter_auto {

    meta:
        id = "1X8FUpRPF2vcd0u8Gl6yk8"
        fingerprint = "v1_sha256_0ed0ab3302f4e8054faec9b20c1025a14f4da75cd75a5c59684b771cac871b40"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.atmspitter."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.atmspitter"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 33c0 40 5f 5e c3 8324f5f0cb400000 }
            // n = 6, score = 200
            //   33c0                 | xor                 eax, eax
            //   40                   | inc                 eax
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   c3                   | ret                 
            //   8324f5f0cb400000     | and                 dword ptr [esi*8 + 0x40cbf0], 0

        $sequence_1 = { 8bc1 c1f805 8bf1 83e61f 8d3c8560da4000 8b07 c1e606 }
            // n = 7, score = 200
            //   8bc1                 | mov                 eax, ecx
            //   c1f805               | sar                 eax, 5
            //   8bf1                 | mov                 esi, ecx
            //   83e61f               | and                 esi, 0x1f
            //   8d3c8560da4000       | lea                 edi, [eax*4 + 0x40da60]
            //   8b07                 | mov                 eax, dword ptr [edi]
            //   c1e606               | shl                 esi, 6

        $sequence_2 = { 8d4c2420 8d8424c8000000 51 89442438 c744243400100000 ff15???????? }
            // n = 6, score = 200
            //   8d4c2420             | lea                 ecx, [esp + 0x20]
            //   8d8424c8000000       | lea                 eax, [esp + 0xc8]
            //   51                   | push                ecx
            //   89442438             | mov                 dword ptr [esp + 0x38], eax
            //   c744243400100000     | mov                 dword ptr [esp + 0x34], 0x1000
            //   ff15????????         |                     

        $sequence_3 = { 897b04 c7430801000000 e8???????? 6a06 89430c 8d4310 8d8984c84000 }
            // n = 7, score = 200
            //   897b04               | mov                 dword ptr [ebx + 4], edi
            //   c7430801000000       | mov                 dword ptr [ebx + 8], 1
            //   e8????????           |                     
            //   6a06                 | push                6
            //   89430c               | mov                 dword ptr [ebx + 0xc], eax
            //   8d4310               | lea                 eax, [ebx + 0x10]
            //   8d8984c84000         | lea                 ecx, [ecx + 0x40c884]

        $sequence_4 = { 5d c3 8b5c2420 33c0 89442450 89442454 89442458 }
            // n = 7, score = 200
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   8b5c2420             | mov                 ebx, dword ptr [esp + 0x20]
            //   33c0                 | xor                 eax, eax
            //   89442450             | mov                 dword ptr [esp + 0x50], eax
            //   89442454             | mov                 dword ptr [esp + 0x54], eax
            //   89442458             | mov                 dword ptr [esp + 0x58], eax

        $sequence_5 = { 8bc8 83e01f c1f905 c1e006 03048d60da4000 eb02 8bc2 }
            // n = 7, score = 200
            //   8bc8                 | mov                 ecx, eax
            //   83e01f               | and                 eax, 0x1f
            //   c1f905               | sar                 ecx, 5
            //   c1e006               | shl                 eax, 6
            //   03048d60da4000       | add                 eax, dword ptr [ecx*4 + 0x40da60]
            //   eb02                 | jmp                 4
            //   8bc2                 | mov                 eax, edx

        $sequence_6 = { 0f854a020000 66837c245207 0f853e020000 8d942480000000 52 ff15???????? 3d09030000 }
            // n = 7, score = 200
            //   0f854a020000         | jne                 0x250
            //   66837c245207         | cmp                 word ptr [esp + 0x52], 7
            //   0f853e020000         | jne                 0x244
            //   8d942480000000       | lea                 edx, [esp + 0x80]
            //   52                   | push                edx
            //   ff15????????         |                     
            //   3d09030000           | cmp                 eax, 0x309

        $sequence_7 = { a3???????? a1???????? c705????????4b3a4000 8935???????? }
            // n = 4, score = 200
            //   a3????????           |                     
            //   a1????????           |                     
            //   c705????????4b3a4000     |     
            //   8935????????         |                     

        $sequence_8 = { 7402 ffd0 8345e404 ebe6 c745e060914000 817de064914000 7311 }
            // n = 7, score = 200
            //   7402                 | je                  4
            //   ffd0                 | call                eax
            //   8345e404             | add                 dword ptr [ebp - 0x1c], 4
            //   ebe6                 | jmp                 0xffffffe8
            //   c745e060914000       | mov                 dword ptr [ebp - 0x20], 0x409160
            //   817de064914000       | cmp                 dword ptr [ebp - 0x20], 0x409164
            //   7311                 | jae                 0x13

        $sequence_9 = { e8???????? 83c404 8d442420 50 895c2424 c744242857000000 ff15???????? }
            // n = 7, score = 200
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   8d442420             | lea                 eax, [esp + 0x20]
            //   50                   | push                eax
            //   895c2424             | mov                 dword ptr [esp + 0x24], ebx
            //   c744242857000000     | mov                 dword ptr [esp + 0x28], 0x57
            //   ff15????????         |                     

    condition:
        7 of them and filesize < 147456
}
