rule win_cadelspy_auto {

    meta:
        id = "7AnudbLJcZ8eiRJ86lb679"
        fingerprint = "v1_sha256_b3c44a014ad2fbee54fda667170619e7a6ae94d19236eba6a66ccc77fd775cd1"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.cadelspy."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.cadelspy"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { e8???????? 8d842460020000 8d4802 668b10 40 40 }
            // n = 6, score = 100
            //   e8????????           |                     
            //   8d842460020000       | lea                 eax, [esp + 0x260]
            //   8d4802               | lea                 ecx, [eax + 2]
            //   668b10               | mov                 dx, word ptr [eax]
            //   40                   | inc                 eax
            //   40                   | inc                 eax

        $sequence_1 = { 83e01f c1fa05 8b1495004c0110 59 c1e006 59 }
            // n = 6, score = 100
            //   83e01f               | and                 eax, 0x1f
            //   c1fa05               | sar                 edx, 5
            //   8b1495004c0110       | mov                 edx, dword ptr [edx*4 + 0x10014c00]
            //   59                   | pop                 ecx
            //   c1e006               | shl                 eax, 6
            //   59                   | pop                 ecx

        $sequence_2 = { 83e01f c1f905 8b0c8d004c0110 c1e006 03c1 f6400401 7524 }
            // n = 7, score = 100
            //   83e01f               | and                 eax, 0x1f
            //   c1f905               | sar                 ecx, 5
            //   8b0c8d004c0110       | mov                 ecx, dword ptr [ecx*4 + 0x10014c00]
            //   c1e006               | shl                 eax, 6
            //   03c1                 | add                 eax, ecx
            //   f6400401             | test                byte ptr [eax + 4], 1
            //   7524                 | jne                 0x26

        $sequence_3 = { 2bc1 d1f8 6683bc44760400005c 7411 }
            // n = 4, score = 100
            //   2bc1                 | sub                 eax, ecx
            //   d1f8                 | sar                 eax, 1
            //   6683bc44760400005c     | cmp    word ptr [esp + eax*2 + 0x476], 0x5c
            //   7411                 | je                  0x13

        $sequence_4 = { a1???????? 33c5 89857c070000 53 8b9d88070000 56 57 }
            // n = 7, score = 100
            //   a1????????           |                     
            //   33c5                 | xor                 eax, ebp
            //   89857c070000         | mov                 dword ptr [ebp + 0x77c], eax
            //   53                   | push                ebx
            //   8b9d88070000         | mov                 ebx, dword ptr [ebp + 0x788]
            //   56                   | push                esi
            //   57                   | push                edi

        $sequence_5 = { 57 ff742418 57 e8???????? 83c40c ff742414 }
            // n = 6, score = 100
            //   57                   | push                edi
            //   ff742418             | push                dword ptr [esp + 0x18]
            //   57                   | push                edi
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   ff742414             | push                dword ptr [esp + 0x14]

        $sequence_6 = { 6683bc447e0600005c 7411 68???????? 8d9c2484060000 e8???????? 8d44244c }
            // n = 6, score = 100
            //   6683bc447e0600005c     | cmp    word ptr [esp + eax*2 + 0x67e], 0x5c
            //   7411                 | je                  0x13
            //   68????????           |                     
            //   8d9c2484060000       | lea                 ebx, [esp + 0x684]
            //   e8????????           |                     
            //   8d44244c             | lea                 eax, [esp + 0x4c]

        $sequence_7 = { 83ffff 741d 8b54240c 56 6a64 8d442444 59 }
            // n = 7, score = 100
            //   83ffff               | cmp                 edi, -1
            //   741d                 | je                  0x1f
            //   8b54240c             | mov                 edx, dword ptr [esp + 0xc]
            //   56                   | push                esi
            //   6a64                 | push                0x64
            //   8d442444             | lea                 eax, [esp + 0x44]
            //   59                   | pop                 ecx

        $sequence_8 = { 57 6689842484060000 8d842486060000 56 50 e8???????? 83c40c }
            // n = 7, score = 100
            //   57                   | push                edi
            //   6689842484060000     | mov                 word ptr [esp + 0x684], ax
            //   8d842486060000       | lea                 eax, [esp + 0x686]
            //   56                   | push                esi
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc

        $sequence_9 = { 59 56 57 ff15???????? 68???????? e8???????? 68???????? }
            // n = 7, score = 100
            //   59                   | pop                 ecx
            //   56                   | push                esi
            //   57                   | push                edi
            //   ff15????????         |                     
            //   68????????           |                     
            //   e8????????           |                     
            //   68????????           |                     

    condition:
        7 of them and filesize < 204800
}
