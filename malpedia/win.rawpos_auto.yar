rule win_rawpos_auto {

    meta:
        id = "5ImnootTQeylUofSC7OywE"
        fingerprint = "v1_sha256_56a2b8fbb4e25a898a4bc87c65b7d85dae5bb8a6be93f75773ea8a26525a9a96"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.rawpos."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.rawpos"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 83e82d 741d 83e828 7440 83e803 7446 eb4c }
            // n = 7, score = 100
            //   83e82d               | sub                 eax, 0x2d
            //   741d                 | je                  0x1f
            //   83e828               | sub                 eax, 0x28
            //   7440                 | je                  0x42
            //   83e803               | sub                 eax, 3
            //   7446                 | je                  0x48
            //   eb4c                 | jmp                 0x4e

        $sequence_1 = { e9???????? ff45ec 8b55ec 3b55f8 7ede e9???????? c745ec01000000 }
            // n = 7, score = 100
            //   e9????????           |                     
            //   ff45ec               | inc                 dword ptr [ebp - 0x14]
            //   8b55ec               | mov                 edx, dword ptr [ebp - 0x14]
            //   3b55f8               | cmp                 edx, dword ptr [ebp - 8]
            //   7ede                 | jle                 0xffffffe0
            //   e9????????           |                     
            //   c745ec01000000       | mov                 dword ptr [ebp - 0x14], 1

        $sequence_2 = { 23c8 33d2 894d0c 8955cc 8955d0 8b45d0 }
            // n = 6, score = 100
            //   23c8                 | and                 ecx, eax
            //   33d2                 | xor                 edx, edx
            //   894d0c               | mov                 dword ptr [ebp + 0xc], ecx
            //   8955cc               | mov                 dword ptr [ebp - 0x34], edx
            //   8955d0               | mov                 dword ptr [ebp - 0x30], edx
            //   8b45d0               | mov                 eax, dword ptr [ebp - 0x30]

        $sequence_3 = { 8bca 894dcc 8bd1 035514 8955d0 8955ec 668b5608 }
            // n = 7, score = 100
            //   8bca                 | mov                 ecx, edx
            //   894dcc               | mov                 dword ptr [ebp - 0x34], ecx
            //   8bd1                 | mov                 edx, ecx
            //   035514               | add                 edx, dword ptr [ebp + 0x14]
            //   8955d0               | mov                 dword ptr [ebp - 0x30], edx
            //   8955ec               | mov                 dword ptr [ebp - 0x14], edx
            //   668b5608             | mov                 dx, word ptr [esi + 8]

        $sequence_4 = { 59 8b55e0 8b4d14 2b5508 33c0 8911 eb56 }
            // n = 7, score = 100
            //   59                   | pop                 ecx
            //   8b55e0               | mov                 edx, dword ptr [ebp - 0x20]
            //   8b4d14               | mov                 ecx, dword ptr [ebp + 0x14]
            //   2b5508               | sub                 edx, dword ptr [ebp + 8]
            //   33c0                 | xor                 eax, eax
            //   8911                 | mov                 dword ptr [ecx], edx
            //   eb56                 | jmp                 0x58

        $sequence_5 = { 83c410 6a00 8d4df4 51 8d856845feff 50 e8???????? }
            // n = 7, score = 100
            //   83c410               | add                 esp, 0x10
            //   6a00                 | push                0
            //   8d4df4               | lea                 ecx, [ebp - 0xc]
            //   51                   | push                ecx
            //   8d856845feff         | lea                 eax, [ebp - 0x1ba98]
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_6 = { ff550c 83c408 837dfc00 7505 83c8ff eb03 8b45fc }
            // n = 7, score = 100
            //   ff550c               | call                dword ptr [ebp + 0xc]
            //   83c408               | add                 esp, 8
            //   837dfc00             | cmp                 dword ptr [ebp - 4], 0
            //   7505                 | jne                 7
            //   83c8ff               | or                  eax, 0xffffffff
            //   eb03                 | jmp                 5
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]

        $sequence_7 = { f6833523430004 7405 48 3bd0 76ee }
            // n = 5, score = 100
            //   f6833523430004       | test                byte ptr [ebx + 0x432335], 4
            //   7405                 | je                  7
            //   48                   | dec                 eax
            //   3bd0                 | cmp                 edx, eax
            //   76ee                 | jbe                 0xfffffff0

        $sequence_8 = { 7507 be0a000000 eb12 83fe01 0f8ce6000000 83fe24 0f8fdd000000 }
            // n = 7, score = 100
            //   7507                 | jne                 9
            //   be0a000000           | mov                 esi, 0xa
            //   eb12                 | jmp                 0x14
            //   83fe01               | cmp                 esi, 1
            //   0f8ce6000000         | jl                  0xec
            //   83fe24               | cmp                 esi, 0x24
            //   0f8fdd000000         | jg                  0xe3

        $sequence_9 = { 8bd0 83e207 8911 8816 }
            // n = 4, score = 100
            //   8bd0                 | mov                 edx, eax
            //   83e207               | and                 edx, 7
            //   8911                 | mov                 dword ptr [ecx], edx
            //   8816                 | mov                 byte ptr [esi], dl

    condition:
        7 of them and filesize < 466944
}
