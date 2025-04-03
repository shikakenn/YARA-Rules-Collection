rule win_fobber_auto {

    meta:
        id = "7LuEqm1am8G2NQJHkbaf1Q"
        fingerprint = "v1_sha256_61538df65ce7e18f8d160f3c894437f915290dca7e112a40d32b84ca774989b9"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.fobber."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.fobber"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 8b5508 8b4d0c 3002 c0c803 }
            // n = 4, score = 1100
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   8b4d0c               | mov                 ecx, dword ptr [ebp + 0xc]
            //   3002                 | xor                 byte ptr [edx], al
            //   c0c803               | ror                 al, 3

        $sequence_1 = { 57 e8???????? 85c0 740f 89c1 8b450c fc }
            // n = 7, score = 1100
            //   57                   | push                edi
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   740f                 | je                  0x11
            //   89c1                 | mov                 ecx, eax
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   fc                   | cld                 

        $sequence_2 = { 660fc146f9 6685c0 7515 0fb646f8 50 0fb746f6 }
            // n = 6, score = 1100
            //   660fc146f9           | xadd                word ptr [esi - 7], ax
            //   6685c0               | test                ax, ax
            //   7515                 | jne                 0x17
            //   0fb646f8             | movzx               eax, byte ptr [esi - 8]
            //   50                   | push                eax
            //   0fb746f6             | movzx               eax, word ptr [esi - 0xa]

        $sequence_3 = { 8d4d08 51 ff31 ffd0 85c0 7403 8b4508 }
            // n = 7, score = 1100
            //   8d4d08               | lea                 ecx, [ebp + 8]
            //   51                   | push                ecx
            //   ff31                 | push                dword ptr [ecx]
            //   ffd0                 | call                eax
            //   85c0                 | test                eax, eax
            //   7403                 | je                  5
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]

        $sequence_4 = { 55 89e5 51 57 8b7d08 57 }
            // n = 6, score = 1100
            //   55                   | push                ebp
            //   89e5                 | mov                 ebp, esp
            //   51                   | push                ecx
            //   57                   | push                edi
            //   8b7d08               | mov                 edi, dword ptr [ebp + 8]
            //   57                   | push                edi

        $sequence_5 = { 31c9 f7d1 fc f2ae f7d1 }
            // n = 5, score = 1100
            //   31c9                 | xor                 ecx, ecx
            //   f7d1                 | not                 ecx
            //   fc                   | cld                 
            //   f2ae                 | repne scasb         al, byte ptr es:[edi]
            //   f7d1                 | not                 ecx

        $sequence_6 = { 55 89e5 31c0 50 50 ff750c ff7508 }
            // n = 7, score = 1100
            //   55                   | push                ebp
            //   89e5                 | mov                 ebp, esp
            //   31c0                 | xor                 eax, eax
            //   50                   | push                eax
            //   50                   | push                eax
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   ff7508               | push                dword ptr [ebp + 8]

        $sequence_7 = { 3002 c0c803 0453 42 }
            // n = 4, score = 1100
            //   3002                 | xor                 byte ptr [edx], al
            //   c0c803               | ror                 al, 3
            //   0453                 | add                 al, 0x53
            //   42                   | inc                 edx

        $sequence_8 = { 0485 40 47 c9 7283 e61f }
            // n = 6, score = 100
            //   0485                 | add                 al, 0x85
            //   40                   | inc                 eax
            //   47                   | inc                 edi
            //   c9                   | leave               
            //   7283                 | jb                  0xffffff85
            //   e61f                 | out                 0x1f, al

        $sequence_9 = { 028736c8f07c 7d41 6f 01e9 }
            // n = 4, score = 100
            //   028736c8f07c         | add                 al, byte ptr [edi + 0x7cf0c836]
            //   7d41                 | jge                 0x43
            //   6f                   | outsd               dx, dword ptr [esi]
            //   01e9                 | add                 ecx, ebp

        $sequence_10 = { 4a bdb098f55a 6798 5b 348d 5a }
            // n = 6, score = 100
            //   4a                   | dec                 edx
            //   bdb098f55a           | mov                 ebp, 0x5af598b0
            //   6798                 | cwde                
            //   5b                   | pop                 ebx
            //   348d                 | xor                 al, 0x8d
            //   5a                   | pop                 edx

        $sequence_11 = { 81c112500000 81c1d6530000 81e951b50000 81e9a88bffff 81c17d5b0000 }
            // n = 5, score = 100
            //   81c112500000         | add                 ecx, 0x5012
            //   81c1d6530000         | add                 ecx, 0x53d6
            //   81e951b50000         | sub                 ecx, 0xb551
            //   81e9a88bffff         | sub                 ecx, 0xffff8ba8
            //   81c17d5b0000         | add                 ecx, 0x5b7d

        $sequence_12 = { 8bec a1???????? 80383f 7414 6a00 }
            // n = 5, score = 100
            //   8bec                 | mov                 ebp, esp
            //   a1????????           |                     
            //   80383f               | cmp                 byte ptr [eax], 0x3f
            //   7414                 | je                  0x16
            //   6a00                 | push                0

        $sequence_13 = { df9c6182a5b1b2 e8???????? 54 e437 d3766f fa 42 }
            // n = 7, score = 100
            //   df9c6182a5b1b2       | fistp               word ptr [ecx - 0x4d4e5a7e]
            //   e8????????           |                     
            //   54                   | push                esp
            //   e437                 | in                  al, 0x37
            //   d3766f               | sal                 dword ptr [esi + 0x6f], cl
            //   fa                   | cli                 
            //   42                   | inc                 edx

        $sequence_14 = { d470 44 b200 4f }
            // n = 4, score = 100
            //   d470                 | aam                 0x70
            //   44                   | inc                 esp
            //   b200                 | mov                 dl, 0
            //   4f                   | dec                 edi

        $sequence_15 = { 8d46ff 0f85196e0100 807dfc00 7407 8b4df8 836170fd 5e }
            // n = 7, score = 100
            //   8d46ff               | lea                 eax, [esi - 1]
            //   0f85196e0100         | jne                 0x16e1f
            //   807dfc00             | cmp                 byte ptr [ebp - 4], 0
            //   7407                 | je                  9
            //   8b4df8               | mov                 ecx, dword ptr [ebp - 8]
            //   836170fd             | and                 dword ptr [ecx + 0x70], 0xfffffffd
            //   5e                   | pop                 esi

    condition:
        7 of them and filesize < 188416
}
