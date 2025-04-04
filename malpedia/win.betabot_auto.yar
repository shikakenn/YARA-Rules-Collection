rule win_betabot_auto {

    meta:
        id = "41VC2YTmFm3LTBaaVqfpCC"
        fingerprint = "v1_sha256_07dd0ba00e2d3513e1cad1cf2b7d11e94e25b4a1985b335a6dca6b1199e5355b"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.betabot."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.betabot"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { ff15???????? ff15???????? 89859cfcffff 83a594fcffff00 eb0d 8b8594fcffff 40 }
            // n = 7, score = 400
            //   ff15????????         |                     
            //   ff15????????         |                     
            //   89859cfcffff         | mov                 dword ptr [ebp - 0x364], eax
            //   83a594fcffff00       | and                 dword ptr [ebp - 0x36c], 0
            //   eb0d                 | jmp                 0xf
            //   8b8594fcffff         | mov                 eax, dword ptr [ebp - 0x36c]
            //   40                   | inc                 eax

        $sequence_1 = { 663901 7408 6a02 58 e9???????? a1???????? 3bc3 }
            // n = 7, score = 400
            //   663901               | cmp                 word ptr [ecx], ax
            //   7408                 | je                  0xa
            //   6a02                 | push                2
            //   58                   | pop                 eax
            //   e9????????           |                     
            //   a1????????           |                     
            //   3bc3                 | cmp                 eax, ebx

        $sequence_2 = { 7507 32c0 e9???????? 0591f4ffff 50 56 ff15???????? }
            // n = 7, score = 400
            //   7507                 | jne                 9
            //   32c0                 | xor                 al, al
            //   e9????????           |                     
            //   0591f4ffff           | add                 eax, 0xfffff491
            //   50                   | push                eax
            //   56                   | push                esi
            //   ff15????????         |                     

        $sequence_3 = { 84d2 7905 884613 eb08 f6c240 7403 }
            // n = 6, score = 400
            //   84d2                 | test                dl, dl
            //   7905                 | jns                 7
            //   884613               | mov                 byte ptr [esi + 0x13], al
            //   eb08                 | jmp                 0xa
            //   f6c240               | test                dl, 0x40
            //   7403                 | je                  5

        $sequence_4 = { 8d85c0fcffff 50 8d85f8feffff 50 8d85d0fdffff 50 8b85a4fcffff }
            // n = 7, score = 400
            //   8d85c0fcffff         | lea                 eax, [ebp - 0x340]
            //   50                   | push                eax
            //   8d85f8feffff         | lea                 eax, [ebp - 0x108]
            //   50                   | push                eax
            //   8d85d0fdffff         | lea                 eax, [ebp - 0x230]
            //   50                   | push                eax
            //   8b85a4fcffff         | mov                 eax, dword ptr [ebp - 0x35c]

        $sequence_5 = { 8bec 81ec44020000 f605????????80 7405 33c0 }
            // n = 5, score = 400
            //   8bec                 | mov                 ebp, esp
            //   81ec44020000         | sub                 esp, 0x244
            //   f605????????80       |                     
            //   7405                 | je                  7
            //   33c0                 | xor                 eax, eax

        $sequence_6 = { 894610 895e14 898e18010000 85c0 7426 3dffff0000 731f }
            // n = 7, score = 400
            //   894610               | mov                 dword ptr [esi + 0x10], eax
            //   895e14               | mov                 dword ptr [esi + 0x14], ebx
            //   898e18010000         | mov                 dword ptr [esi + 0x118], ecx
            //   85c0                 | test                eax, eax
            //   7426                 | je                  0x28
            //   3dffff0000           | cmp                 eax, 0xffff
            //   731f                 | jae                 0x21

        $sequence_7 = { a1???????? f6401280 7405 6a02 58 c9 c3 }
            // n = 7, score = 400
            //   a1????????           |                     
            //   f6401280             | test                byte ptr [eax + 0x12], 0x80
            //   7405                 | je                  7
            //   6a02                 | push                2
            //   58                   | pop                 eax
            //   c9                   | leave               
            //   c3                   | ret                 

        $sequence_8 = { 50 57 e8???????? 56 8d45f0 50 ff7510 }
            // n = 7, score = 400
            //   50                   | push                eax
            //   57                   | push                edi
            //   e8????????           |                     
            //   56                   | push                esi
            //   8d45f0               | lea                 eax, [ebp - 0x10]
            //   50                   | push                eax
            //   ff7510               | push                dword ptr [ebp + 0x10]

        $sequence_9 = { e8???????? eb12 a1???????? 85c0 740b 8d4dfc }
            // n = 6, score = 400
            //   e8????????           |                     
            //   eb12                 | jmp                 0x14
            //   a1????????           |                     
            //   85c0                 | test                eax, eax
            //   740b                 | je                  0xd
            //   8d4dfc               | lea                 ecx, [ebp - 4]

    condition:
        7 of them and filesize < 835584
}
