rule win_3cx_backdoor_auto {

    meta:
        id = "6BGOPzc2pkc4odS2ugvosZ"
        fingerprint = "v1_sha256_92678e8f023e2e18a272c55dabf9fa5b49a39a58d01ec45cd8edb3c746fea107"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.3cx_backdoor."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.3cx_backdoor"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 49b8ffffffffffffff0f 4c8bf1 493bc0 0f849f010000 488b4910 }
            // n = 5, score = 100
            //   49b8ffffffffffffff0f     | mov    dword ptr [ebp - 0x20], edi
            //   4c8bf1               | dec                 eax
            //   493bc0               | lea                 ecx, [esp + 0x48]
            //   0f849f010000         | nop                 
            //   488b4910             | inc                 ebp

        $sequence_1 = { 418502 418b01 7409 440fabc0 418901 eba6 }
            // n = 6, score = 100
            //   418502               | cmp                 esp, 0x10
            //   418b01               | jb                  0xba6
            //   7409                 | nop                 dword ptr [eax]
            //   440fabc0             | nop                 dword ptr [eax + eax]
            //   418901               | dec                 eax
            //   eba6                 | mov                 ebx, ecx

        $sequence_2 = { 7575 488b7608 4c8b7608 4c3b7610 7443 33c0 }
            // n = 6, score = 100
            //   7575                 | jae                 0x5d5
            //   488b7608             | dec                 esp
            //   4c8b7608             | lea                 eax, [ecx + edi]
            //   4c3b7610             | dec                 ecx
            //   7443                 | mov                 ecx, eax
            //   33c0                 | dec                 eax

        $sequence_3 = { 488b8dc0010000 488bc1 4881fa00100000 0f82a30d0000 4883c227 488b49f8 }
            // n = 6, score = 100
            //   488b8dc0010000       | mov                 byte ptr [eax + ecx], dl
            //   488bc1               | mov                 byte ptr [eax + ecx + 1], 0
            //   4881fa00100000       | jmp                 0xc8
            //   0f82a30d0000         | inc                 esp
            //   4883c227             | movzx               ecx, dl
            //   488b49f8             | dec                 eax

        $sequence_4 = { 482bc1 4883c0f8 4883f81f 0f8792090000 e8???????? 4c897580 48c745880f000000 }
            // n = 7, score = 100
            //   482bc1               | mov                 dword ptr [esp + 0x58], edx
            //   4883c0f8             | inc                 ecx
            //   4883f81f             | push                edi
            //   0f8792090000         | dec                 eax
            //   e8????????           |                     
            //   4c897580             | lea                 ebp, [esp - 0x220]
            //   48c745880f000000     | dec                 eax

        $sequence_5 = { c60601 498b4660 48894608 0fb655c8 488d4dd0 e8???????? 488bc6 }
            // n = 7, score = 100
            //   c60601               | jmp                 ecx
            //   498b4660             | cmp                 eax, 0x57
            //   48894608             | jne                 0x479
            //   0fb655c8             | inc                 esp
            //   488d4dd0             | lea                 eax, [ebx + 7]
            //   e8????????           |                     
            //   488bc6               | dec                 ecx

        $sequence_6 = { 4180fa2d 7502 f7db 4584c9 7529 488b07 48ffc8 }
            // n = 7, score = 100
            //   4180fa2d             | dec                 eax
            //   7502                 | mov                 ecx, dword ptr [eax + 8]
            //   f7db                 | dec                 eax
            //   4584c9               | mov                 dword ptr [edx + 8], ecx
            //   7529                 | mov                 byte ptr [eax], 0
            //   488b07               | dec                 eax
            //   48ffc8               | mov                 dword ptr [eax + 8], ebx

        $sequence_7 = { 4883fa1f 7305 48ffc2 eb06 33d2 4983c104 }
            // n = 6, score = 100
            //   4883fa1f             | dec                 eax
            //   7305                 | add                 edx, 0x27
            //   48ffc2               | dec                 eax
            //   eb06                 | mov                 ecx, dword ptr [ecx - 8]
            //   33d2                 | dec                 eax
            //   4983c104             | sub                 eax, ecx

        $sequence_8 = { 89442448 ffc8 8bf8 410fb68c80023f0300 410fb6b480033f0300 488d1c8d00000000 8d040e }
            // n = 7, score = 100
            //   89442448             | mov                 dword ptr [esp + 0x20], eax
            //   ffc8                 | mov                 edx, 0xfff
            //   8bf8                 | dec                 eax
            //   410fb68c80023f0300     | lea    ecx, [ebp + 0x1e0]
            //   410fb6b480033f0300     | je    0x172
            //   488d1c8d00000000     | dec                 eax
            //   8d040e               | mov                 edx, dword ptr [esp + 0x20]

        $sequence_9 = { e8???????? 90 e8???????? 90 488bd3 488d8d80000000 e8???????? }
            // n = 7, score = 100
            //   e8????????           |                     
            //   90                   | lea                 eax, [esi + ecx]
            //   e8????????           |                     
            //   90                   | dec                 esp
            //   488bd3               | mov                 eax, ebx
            //   488d8d80000000       | dec                 eax
            //   e8????????           |                     

    condition:
        7 of them and filesize < 585728
}
