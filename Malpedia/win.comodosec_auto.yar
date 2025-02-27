rule win_comodosec_auto {

    meta:
        id = "5EPgcTKTKmjmZuz999b80S"
        fingerprint = "v1_sha256_e597b78121a52d60a573b56f0e35aaefc17a26eca761f19f63e0fd1655712254"
        version = "1"
        date = "2020-10-14"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "autogenerated rule brought to you by yara-signator"
        category = "INFO"
        tool = "yara-signator v0.5.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.comodosec"
        malpedia_rule_date = "20201014"
        malpedia_hash = "a7e3bd57eaf12bf3ea29a863c041091ba3af9ac9"
        malpedia_version = "20201014"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 8b5590 8d4594 e8???????? 8d4594 8b15???????? 8b12 e8???????? }
            // n = 7, score = 200
            //   8b5590               | mov                 edx, dword ptr [ebp - 0x70]
            //   8d4594               | lea                 eax, [ebp - 0x6c]
            //   e8????????           |                     
            //   8d4594               | lea                 eax, [ebp - 0x6c]
            //   8b15????????         |                     
            //   8b12                 | mov                 edx, dword ptr [edx]
            //   e8????????           |                     

        $sequence_1 = { 8d45ec e8???????? 8b55ec 8b45f4 e8???????? 8b45f4 8b45f8 }
            // n = 7, score = 200
            //   8d45ec               | lea                 eax, [ebp - 0x14]
            //   e8????????           |                     
            //   8b55ec               | mov                 edx, dword ptr [ebp - 0x14]
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]
            //   e8????????           |                     
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]

        $sequence_2 = { 46 f6430c02 740c 8b4508 50 8bc3 }
            // n = 6, score = 200
            //   46                   | inc                 esi
            //   f6430c02             | test                byte ptr [ebx + 0xc], 2
            //   740c                 | je                  0xe
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   50                   | push                eax
            //   8bc3                 | mov                 eax, ebx

        $sequence_3 = { 53 e8???????? 8bd8 83fbff 0f8489000000 }
            // n = 5, score = 200
            //   53                   | push                ebx
            //   e8????????           |                     
            //   8bd8                 | mov                 ebx, eax
            //   83fbff               | cmp                 ebx, -1
            //   0f8489000000         | je                  0x8f

        $sequence_4 = { 8d458c ba03000000 e8???????? 8b458c e8???????? 50 }
            // n = 6, score = 200
            //   8d458c               | lea                 eax, [ebp - 0x74]
            //   ba03000000           | mov                 edx, 3
            //   e8????????           |                     
            //   8b458c               | mov                 eax, dword ptr [ebp - 0x74]
            //   e8????????           |                     
            //   50                   | push                eax

        $sequence_5 = { e8???????? 8b859cfdffff e8???????? 8d85a8fdffff 50 53 e8???????? }
            // n = 7, score = 200
            //   e8????????           |                     
            //   8b859cfdffff         | mov                 eax, dword ptr [ebp - 0x264]
            //   e8????????           |                     
            //   8d85a8fdffff         | lea                 eax, [ebp - 0x258]
            //   50                   | push                eax
            //   53                   | push                ebx
            //   e8????????           |                     

        $sequence_6 = { 8b858cfdffff e8???????? 59 eb3c ff75fc 68???????? 8d8580fdffff }
            // n = 7, score = 200
            //   8b858cfdffff         | mov                 eax, dword ptr [ebp - 0x274]
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   eb3c                 | jmp                 0x3e
            //   ff75fc               | push                dword ptr [ebp - 4]
            //   68????????           |                     
            //   8d8580fdffff         | lea                 eax, [ebp - 0x280]

        $sequence_7 = { 50 e8???????? 8b45f4 e8???????? 8bd8 53 e8???????? }
            // n = 7, score = 200
            //   50                   | push                eax
            //   e8????????           |                     
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]
            //   e8????????           |                     
            //   8bd8                 | mov                 ebx, eax
            //   53                   | push                ebx
            //   e8????????           |                     

        $sequence_8 = { 8b45f8 e8???????? 48 50 33c9 }
            // n = 5, score = 200
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]
            //   e8????????           |                     
            //   48                   | dec                 eax
            //   50                   | push                eax
            //   33c9                 | xor                 ecx, ecx

        $sequence_9 = { 8b55d0 8d45fc e8???????? a1???????? 803800 7436 8d45c8 }
            // n = 7, score = 200
            //   8b55d0               | mov                 edx, dword ptr [ebp - 0x30]
            //   8d45fc               | lea                 eax, [ebp - 4]
            //   e8????????           |                     
            //   a1????????           |                     
            //   803800               | cmp                 byte ptr [eax], 0
            //   7436                 | je                  0x38
            //   8d45c8               | lea                 eax, [ebp - 0x38]

    condition:
        7 of them and filesize < 262144
}
