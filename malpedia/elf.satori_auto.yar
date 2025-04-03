rule elf_satori_auto {

    meta:
        id = "7e0HDToZ1PHDLPuF6q6miA"
        fingerprint = "v1_sha256_971903fb2922c6e0d29023431fedc1f613a69ac9544f2c3e1cb57d7bab55e6a5"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects elf.satori."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/elf.satori"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 50 e8???????? c704241f000000 e8???????? c7042420000000 e8???????? c7042420000000 }
            // n = 7, score = 100
            //   50                   | push                eax
            //   e8????????           |                     
            //   c704241f000000       | mov                 dword ptr [esp], 0x1f
            //   e8????????           |                     
            //   c7042420000000       | mov                 dword ptr [esp], 0x20
            //   e8????????           |                     
            //   c7042420000000       | mov                 dword ptr [esp], 0x20

        $sequence_1 = { ffb51c040000 e8???????? 83c420 6800400000 6a02 }
            // n = 5, score = 100
            //   ffb51c040000         | push                dword ptr [ebp + 0x41c]
            //   e8????????           |                     
            //   83c420               | add                 esp, 0x20
            //   6800400000           | push                0x4000
            //   6a02                 | push                2

        $sequence_2 = { 53 89cb 83ec0c 85c9 8b542420 }
            // n = 5, score = 100
            //   53                   | push                ebx
            //   89cb                 | mov                 ebx, ecx
            //   83ec0c               | sub                 esp, 0xc
            //   85c9                 | test                ecx, ecx
            //   8b542420             | mov                 edx, dword ptr [esp + 0x20]

        $sequence_3 = { c784245809000000000000 fc 8dbc2438090000 31c0 ab ab }
            // n = 6, score = 100
            //   c784245809000000000000     | mov    dword ptr [esp + 0x958], 0
            //   fc                   | cld                 
            //   8dbc2438090000       | lea                 edi, [esp + 0x938]
            //   31c0                 | xor                 eax, eax
            //   ab                   | stosd               dword ptr es:[edi], eax
            //   ab                   | stosd               dword ptr es:[edi], eax

        $sequence_4 = { a1???????? 83f8ff 7431 83ec0c 50 e8???????? c705????????ffffffff }
            // n = 7, score = 100
            //   a1????????           |                     
            //   83f8ff               | cmp                 eax, -1
            //   7431                 | je                  0x33
            //   83ec0c               | sub                 esp, 0xc
            //   50                   | push                eax
            //   e8????????           |                     
            //   c705????????ffffffff     |     

        $sequence_5 = { 7d02 89c2 c784243805000000000000 c78424340500000a000000 83ec0c }
            // n = 5, score = 100
            //   7d02                 | jge                 4
            //   89c2                 | mov                 edx, eax
            //   c784243805000000000000     | mov    dword ptr [esp + 0x538], 0
            //   c78424340500000a000000     | mov    dword ptr [esp + 0x534], 0xa
            //   83ec0c               | sub                 esp, 0xc

        $sequence_6 = { 888335040000 19c0 83e003 05a4000000 894304 89d8 }
            // n = 6, score = 100
            //   888335040000         | mov                 byte ptr [ebx + 0x435], al
            //   19c0                 | sbb                 eax, eax
            //   83e003               | and                 eax, 3
            //   05a4000000           | add                 eax, 0xa4
            //   894304               | mov                 dword ptr [ebx + 4], eax
            //   89d8                 | mov                 eax, ebx

        $sequence_7 = { c685360400000b e9???????? 50 6800020000 6a00 8d8c2444060000 }
            // n = 6, score = 100
            //   c685360400000b       | mov                 byte ptr [ebp + 0x436], 0xb
            //   e9????????           |                     
            //   50                   | push                eax
            //   6800020000           | push                0x200
            //   6a00                 | push                0
            //   8d8c2444060000       | lea                 ecx, [esp + 0x644]

        $sequence_8 = { 89ea b803000000 e8???????? 85c0 89442440 }
            // n = 5, score = 100
            //   89ea                 | mov                 edx, ebp
            //   b803000000           | mov                 eax, 3
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   89442440             | mov                 dword ptr [esp + 0x40], eax

        $sequence_9 = { 8884242e220000 8a84242d220000 c684242d22000030 8884242f220000 83ec0c 6a03 }
            // n = 6, score = 100
            //   8884242e220000       | mov                 byte ptr [esp + 0x222e], al
            //   8a84242d220000       | mov                 al, byte ptr [esp + 0x222d]
            //   c684242d22000030     | mov                 byte ptr [esp + 0x222d], 0x30
            //   8884242f220000       | mov                 byte ptr [esp + 0x222f], al
            //   83ec0c               | sub                 esp, 0xc
            //   6a03                 | push                3

    condition:
        7 of them and filesize < 122880
}
