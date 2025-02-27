rule win_atlantida_auto {

    meta:
        id = "65TkYxvugAK4XckegpALBg"
        fingerprint = "v1_sha256_de93365ad64d88523ed488fd5b5635b3ae5e4c0d8a34a9201e696d8414f63e31"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.atlantida."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.atlantida"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 8bfa 3bcf 7459 56 8d7114 6690 8d4e04 }
            // n = 7, score = 100
            //   8bfa                 | mov                 edi, edx
            //   3bcf                 | cmp                 ecx, edi
            //   7459                 | je                  0x5b
            //   56                   | push                esi
            //   8d7114               | lea                 esi, [ecx + 0x14]
            //   6690                 | nop                 
            //   8d4e04               | lea                 ecx, [esi + 4]

        $sequence_1 = { ed f6a3ff1cd671 c1f6a3 ff7082 59 255caf7f8f d34636 }
            // n = 7, score = 100
            //   ed                   | in                  eax, dx
            //   f6a3ff1cd671         | mul                 byte ptr [ebx + 0x71d61cff]
            //   c1f6a3               | sal                 esi, 0xa3
            //   ff7082               | push                dword ptr [eax - 0x7e]
            //   59                   | pop                 ecx
            //   255caf7f8f           | and                 eax, 0x8f7faf5c
            //   d34636               | rol                 dword ptr [esi + 0x36], cl

        $sequence_2 = { e8???????? c7442400c69a991b e8???????? ba847b1e24 8d8cd226571b73 660fc1d1 8b94576ca2c2b7 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   c7442400c69a991b     | mov                 dword ptr [esp], 0x1b999ac6
            //   e8????????           |                     
            //   ba847b1e24           | mov                 edx, 0x241e7b84
            //   8d8cd226571b73       | lea                 ecx, [edx + edx*8 + 0x731b5726]
            //   660fc1d1             | xadd                cx, dx
            //   8b94576ca2c2b7       | mov                 edx, dword ptr [edi + edx*2 - 0x483d5d94]

        $sequence_3 = { e9???????? d3840c9e29cbff 8994483c5396ff 8bd1 23ca 5a 8b940da629cbff }
            // n = 7, score = 100
            //   e9????????           |                     
            //   d3840c9e29cbff       | rol                 dword ptr [esp + ecx - 0x34d662], cl
            //   8994483c5396ff       | mov                 dword ptr [eax + ecx*2 - 0x69acc4], edx
            //   8bd1                 | mov                 edx, ecx
            //   23ca                 | and                 ecx, edx
            //   5a                   | pop                 edx
            //   8b940da629cbff       | mov                 edx, dword ptr [ebp + ecx - 0x34d65a]

        $sequence_4 = { 8b8c16f7c9e0bd 8d845284cd81f7 0fabd0 8db416fbc9e0bd 52 219414f8c9e0bd 33cb }
            // n = 7, score = 100
            //   8b8c16f7c9e0bd       | mov                 ecx, dword ptr [esi + edx - 0x421f3609]
            //   8d845284cd81f7       | lea                 eax, [edx + edx*2 - 0x87e327c]
            //   0fabd0               | bts                 eax, edx
            //   8db416fbc9e0bd       | lea                 esi, [esi + edx - 0x421f3605]
            //   52                   | push                edx
            //   219414f8c9e0bd       | and                 dword ptr [esp + edx - 0x421f3608], edx
            //   33cb                 | xor                 ecx, ebx

        $sequence_5 = { e8???????? c1c803 33d8 8d14cdbca7077c 52 d3e1 13e8 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   c1c803               | ror                 eax, 3
            //   33d8                 | xor                 ebx, eax
            //   8d14cdbca7077c       | lea                 edx, [ecx*8 + 0x7c07a7bc]
            //   52                   | push                edx
            //   d3e1                 | shl                 ecx, cl
            //   13e8                 | adc                 ebp, eax

        $sequence_6 = { ff7508 57 e8???????? 5e 5d c3 56 }
            // n = 7, score = 100
            //   ff7508               | push                dword ptr [ebp + 8]
            //   57                   | push                edi
            //   e8????????           |                     
            //   5e                   | pop                 esi
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   56                   | push                esi

        $sequence_7 = { ba1b3187c4 f7d2 668b843a1c3187c4 8d9454a4620e89 b918903d41 22cd c1f968 }
            // n = 7, score = 100
            //   ba1b3187c4           | mov                 edx, 0xc487311b
            //   f7d2                 | not                 edx
            //   668b843a1c3187c4     | mov                 ax, word ptr [edx + edi - 0x3b78cee4]
            //   8d9454a4620e89       | lea                 edx, [esp + edx*2 - 0x76f19d5c]
            //   b918903d41           | mov                 ecx, 0x413d9018
            //   22cd                 | and                 cl, ch
            //   c1f968               | sar                 ecx, 0x68

        $sequence_8 = { f6d8 0fca 32d8 660fbafa38 c1e2bb 13c4 c0faa1 }
            // n = 7, score = 100
            //   f6d8                 | neg                 al
            //   0fca                 | bswap               edx
            //   32d8                 | xor                 bl, al
            //   660fbafa38           | btc                 dx, 0x38
            //   c1e2bb               | shl                 edx, 0xbb
            //   13c4                 | adc                 eax, esp
            //   c0faa1               | sar                 dl, 0xa1

        $sequence_9 = { e8???????? 8b13 41 be35e00fe4 41 0fb7ce 6644 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   8b13                 | mov                 edx, dword ptr [ebx]
            //   41                   | inc                 ecx
            //   be35e00fe4           | mov                 esi, 0xe40fe035
            //   41                   | inc                 ecx
            //   0fb7ce               | movzx               ecx, si
            //   6644                 | inc                 sp

    condition:
        7 of them and filesize < 13793280
}
