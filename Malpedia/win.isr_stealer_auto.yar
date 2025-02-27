rule win_isr_stealer_auto {

    meta:
        id = "6Txdg5wpvwwuk0Ejr0Rz6r"
        fingerprint = "v1_sha256_75691989209029cb7a637cf5df87a857ef3ef18b6fe3194f56cba1ecab86658c"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.isr_stealer."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.isr_stealer"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { fb b05e 2bc1 e8???????? 661e }
            // n = 5, score = 200
            //   fb                   | sti                 
            //   b05e                 | mov                 al, 0x5e
            //   2bc1                 | sub                 eax, ecx
            //   e8????????           |                     
            //   661e                 | push                ds

        $sequence_1 = { 08ac22c115978d 0e e8???????? 07 }
            // n = 4, score = 200
            //   08ac22c115978d       | or                  byte ptr [edx - 0x7268ea3f], ch
            //   0e                   | push                cs
            //   e8????????           |                     
            //   07                   | pop                 es

        $sequence_2 = { 1c8b 53 2456 2bd1 807e6543 }
            // n = 5, score = 200
            //   1c8b                 | sbb                 al, 0x8b
            //   53                   | push                ebx
            //   2456                 | and                 al, 0x56
            //   2bd1                 | sub                 edx, ecx
            //   807e6543             | cmp                 byte ptr [esi + 0x65], 0x43

        $sequence_3 = { 46 1e 301b 15c2c8c807 d6 12d8 }
            // n = 6, score = 200
            //   46                   | inc                 esi
            //   1e                   | push                ds
            //   301b                 | xor                 byte ptr [ebx], bl
            //   15c2c8c807           | adc                 eax, 0x7c8c8c2
            //   d6                   | salc                
            //   12d8                 | adc                 bl, al

        $sequence_4 = { 8d16 b205 07 d32cb6 08ac22c115978d 0e e8???????? }
            // n = 7, score = 200
            //   8d16                 | lea                 edx, [esi]
            //   b205                 | mov                 dl, 5
            //   07                   | pop                 es
            //   d32cb6               | shr                 dword ptr [esi + esi*4], cl
            //   08ac22c115978d       | or                  byte ptr [edx - 0x7268ea3f], ch
            //   0e                   | push                cs
            //   e8????????           |                     

        $sequence_5 = { a7 8d16 b205 07 d32cb6 08ac22c115978d }
            // n = 6, score = 200
            //   a7                   | cmpsd               dword ptr [esi], dword ptr es:[edi]
            //   8d16                 | lea                 edx, [esi]
            //   b205                 | mov                 dl, 5
            //   07                   | pop                 es
            //   d32cb6               | shr                 dword ptr [esi + esi*4], cl
            //   08ac22c115978d       | or                  byte ptr [edx - 0x7268ea3f], ch

        $sequence_6 = { 07 fb b05e 2bc1 e8???????? }
            // n = 5, score = 200
            //   07                   | pop                 es
            //   fb                   | sti                 
            //   b05e                 | mov                 al, 0x5e
            //   2bc1                 | sub                 eax, ecx
            //   e8????????           |                     

        $sequence_7 = { 8d16 b205 07 d32cb6 08ac22c115978d 0e }
            // n = 6, score = 200
            //   8d16                 | lea                 edx, [esi]
            //   b205                 | mov                 dl, 5
            //   07                   | pop                 es
            //   d32cb6               | shr                 dword ptr [esi + esi*4], cl
            //   08ac22c115978d       | or                  byte ptr [edx - 0x7268ea3f], ch
            //   0e                   | push                cs

        $sequence_8 = { 07 d32cb6 08ac22c115978d 0e e8???????? }
            // n = 5, score = 200
            //   07                   | pop                 es
            //   d32cb6               | shr                 dword ptr [esi + esi*4], cl
            //   08ac22c115978d       | or                  byte ptr [edx - 0x7268ea3f], ch
            //   0e                   | push                cs
            //   e8????????           |                     

        $sequence_9 = { e8???????? 07 fb b05e 2bc1 e8???????? 661e }
            // n = 7, score = 200
            //   e8????????           |                     
            //   07                   | pop                 es
            //   fb                   | sti                 
            //   b05e                 | mov                 al, 0x5e
            //   2bc1                 | sub                 eax, ecx
            //   e8????????           |                     
            //   661e                 | push                ds

    condition:
        7 of them and filesize < 540672
}
