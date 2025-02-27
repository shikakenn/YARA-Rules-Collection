rule win_transbox_auto {

    meta:
        id = "4Jxx3CZYJHVfaINzLbRg4l"
        fingerprint = "v1_sha256_e0417344b856e4de18adbd11a563963b1ed47459f0027440ad36de04e1848468"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.transbox."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.transbox"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { e8???????? 8bda 8bf1 ff15???????? 898520fbffff 85f6 741a }
            // n = 7, score = 100
            //   e8????????           |                     
            //   8bda                 | mov                 ebx, edx
            //   8bf1                 | mov                 esi, ecx
            //   ff15????????         |                     
            //   898520fbffff         | mov                 dword ptr [ebp - 0x4e0], eax
            //   85f6                 | test                esi, esi
            //   741a                 | je                  0x1c

        $sequence_1 = { 33c9 83c414 85c0 0f9fc1 8bc1 8b4dfc 33cd }
            // n = 7, score = 100
            //   33c9                 | xor                 ecx, ecx
            //   83c414               | add                 esp, 0x14
            //   85c0                 | test                eax, eax
            //   0f9fc1               | setg                cl
            //   8bc1                 | mov                 eax, ecx
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   33cd                 | xor                 ecx, ebp

        $sequence_2 = { 898738010000 85c0 745d 8d856cffffff 50 53 }
            // n = 6, score = 100
            //   898738010000         | mov                 dword ptr [edi + 0x138], eax
            //   85c0                 | test                eax, eax
            //   745d                 | je                  0x5f
            //   8d856cffffff         | lea                 eax, [ebp - 0x94]
            //   50                   | push                eax
            //   53                   | push                ebx

        $sequence_3 = { 8bbdb0fdffff 8bc7 8bb5acfdffff 2bc6 99 f7f9 85c0 }
            // n = 7, score = 100
            //   8bbdb0fdffff         | mov                 edi, dword ptr [ebp - 0x250]
            //   8bc7                 | mov                 eax, edi
            //   8bb5acfdffff         | mov                 esi, dword ptr [ebp - 0x254]
            //   2bc6                 | sub                 eax, esi
            //   99                   | cdq                 
            //   f7f9                 | idiv                ecx
            //   85c0                 | test                eax, eax

        $sequence_4 = { 8b35???????? 85c0 740c 6a04 56 50 }
            // n = 6, score = 100
            //   8b35????????         |                     
            //   85c0                 | test                eax, eax
            //   740c                 | je                  0xe
            //   6a04                 | push                4
            //   56                   | push                esi
            //   50                   | push                eax

        $sequence_5 = { 50 8d8db8fdffff e8???????? 50 8d8d7cfdffff e8???????? }
            // n = 6, score = 100
            //   50                   | push                eax
            //   8d8db8fdffff         | lea                 ecx, [ebp - 0x248]
            //   e8????????           |                     
            //   50                   | push                eax
            //   8d8d7cfdffff         | lea                 ecx, [ebp - 0x284]
            //   e8????????           |                     

        $sequence_6 = { 888178c60110 41 84c0 75f1 }
            // n = 4, score = 100
            //   888178c60110         | mov                 byte ptr [ecx + 0x1001c678], al
            //   41                   | inc                 ecx
            //   84c0                 | test                al, al
            //   75f1                 | jne                 0xfffffff3

        $sequence_7 = { e8???????? 57 8d95d0fdffff 8d8db8fdffff e8???????? c645fc0a c70424???????? }
            // n = 7, score = 100
            //   e8????????           |                     
            //   57                   | push                edi
            //   8d95d0fdffff         | lea                 edx, [ebp - 0x230]
            //   8d8db8fdffff         | lea                 ecx, [ebp - 0x248]
            //   e8????????           |                     
            //   c645fc0a             | mov                 byte ptr [ebp - 4], 0xa
            //   c70424????????       |                     

        $sequence_8 = { 83c430 8d4dd0 e8???????? 33ff be???????? 47 8bce }
            // n = 7, score = 100
            //   83c430               | add                 esp, 0x30
            //   8d4dd0               | lea                 ecx, [ebp - 0x30]
            //   e8????????           |                     
            //   33ff                 | xor                 edi, edi
            //   be????????           |                     
            //   47                   | inc                 edi
            //   8bce                 | mov                 ecx, esi

        $sequence_9 = { 740c 6a04 56 50 e8???????? 83c40c 8325????????00 }
            // n = 7, score = 100
            //   740c                 | je                  0xe
            //   6a04                 | push                4
            //   56                   | push                esi
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   8325????????00       |                     

    condition:
        7 of them and filesize < 288768
}
