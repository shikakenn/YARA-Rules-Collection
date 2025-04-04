rule win_jimmy_auto {

    meta:
        id = "15s6T5RMpHpCzJDQYmeDGl"
        fingerprint = "v1_sha256_1b3730a9d32503c4a70a6daa21a4c8b83fd1ef93162a202906ad5585e6f013b5"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.jimmy."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.jimmy"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 0345e4 8945f0 8b45fc 2b45e4 8945fc 8b451c }
            // n = 6, score = 400
            //   0345e4               | add                 eax, dword ptr [ebp - 0x1c]
            //   8945f0               | mov                 dword ptr [ebp - 0x10], eax
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   2b45e4               | sub                 eax, dword ptr [ebp - 0x1c]
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   8b451c               | mov                 eax, dword ptr [ebp + 0x1c]

        $sequence_1 = { 8b45fc 40 8945fc ebe6 8b45fc c9 c3 }
            // n = 7, score = 400
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   40                   | inc                 eax
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   ebe6                 | jmp                 0xffffffe8
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   c9                   | leave               
            //   c3                   | ret                 

        $sequence_2 = { 40 898584fbffff 8b8584fbffff 3b8588fbffff 0f83bc000000 6a08 }
            // n = 6, score = 400
            //   40                   | inc                 eax
            //   898584fbffff         | mov                 dword ptr [ebp - 0x47c], eax
            //   8b8584fbffff         | mov                 eax, dword ptr [ebp - 0x47c]
            //   3b8588fbffff         | cmp                 eax, dword ptr [ebp - 0x478]
            //   0f83bc000000         | jae                 0xc2
            //   6a08                 | push                8

        $sequence_3 = { 6a01 ff7508 e8???????? 59 59 f7d8 }
            // n = 6, score = 400
            //   6a01                 | push                1
            //   ff7508               | push                dword ptr [ebp + 8]
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx
            //   f7d8                 | neg                 eax

        $sequence_4 = { 8365f800 8d45f8 50 6a00 ff7508 a1???????? ffb030010000 }
            // n = 7, score = 400
            //   8365f800             | and                 dword ptr [ebp - 8], 0
            //   8d45f8               | lea                 eax, [ebp - 8]
            //   50                   | push                eax
            //   6a00                 | push                0
            //   ff7508               | push                dword ptr [ebp + 8]
            //   a1????????           |                     
            //   ffb030010000         | push                dword ptr [eax + 0x130]

        $sequence_5 = { 751a 8b4508 ff7024 e8???????? 59 8b4508 }
            // n = 6, score = 400
            //   751a                 | jne                 0x1c
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   ff7024               | push                dword ptr [eax + 0x24]
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]

        $sequence_6 = { 8b45f4 0fb700 8b4dfc 0fb709 3bc1 7514 33c0 }
            // n = 7, score = 400
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]
            //   0fb700               | movzx               eax, word ptr [eax]
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   0fb709               | movzx               ecx, word ptr [ecx]
            //   3bc1                 | cmp                 eax, ecx
            //   7514                 | jne                 0x16
            //   33c0                 | xor                 eax, eax

        $sequence_7 = { 8b45f0 2b45f4 50 ff75f4 ff75fc e8???????? 83c40c }
            // n = 7, score = 400
            //   8b45f0               | mov                 eax, dword ptr [ebp - 0x10]
            //   2b45f4               | sub                 eax, dword ptr [ebp - 0xc]
            //   50                   | push                eax
            //   ff75f4               | push                dword ptr [ebp - 0xc]
            //   ff75fc               | push                dword ptr [ebp - 4]
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc

        $sequence_8 = { 8945f8 837df800 7449 837d1000 7408 }
            // n = 5, score = 400
            //   8945f8               | mov                 dword ptr [ebp - 8], eax
            //   837df800             | cmp                 dword ptr [ebp - 8], 0
            //   7449                 | je                  0x4b
            //   837d1000             | cmp                 dword ptr [ebp + 0x10], 0
            //   7408                 | je                  0xa

        $sequence_9 = { 7406 837df400 7507 32c0 e9???????? 8b45f0 05f8000000 }
            // n = 7, score = 400
            //   7406                 | je                  8
            //   837df400             | cmp                 dword ptr [ebp - 0xc], 0
            //   7507                 | jne                 9
            //   32c0                 | xor                 al, al
            //   e9????????           |                     
            //   8b45f0               | mov                 eax, dword ptr [ebp - 0x10]
            //   05f8000000           | add                 eax, 0xf8

    condition:
        7 of them and filesize < 188416
}
