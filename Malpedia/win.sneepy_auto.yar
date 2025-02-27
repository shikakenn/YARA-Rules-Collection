rule win_sneepy_auto {

    meta:
        id = "6akzfzWtQjYw8YrOVRvfho"
        fingerprint = "v1_sha256_93bb250be962b8e39c384decdfc047f665d0471aa8b95be7ae603f090eace95c"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.sneepy."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.sneepy"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 75e6 c6460401 830eff 2b34bd60314100 }
            // n = 4, score = 100
            //   75e6                 | jne                 0xffffffe8
            //   c6460401             | mov                 byte ptr [esi + 4], 1
            //   830eff               | or                  dword ptr [esi], 0xffffffff
            //   2b34bd60314100       | sub                 esi, dword ptr [edi*4 + 0x413160]

        $sequence_1 = { 80e17f 3008 8b06 8bc8 c1f905 8b0c8d60314100 83e01f }
            // n = 7, score = 100
            //   80e17f               | and                 cl, 0x7f
            //   3008                 | xor                 byte ptr [eax], cl
            //   8b06                 | mov                 eax, dword ptr [esi]
            //   8bc8                 | mov                 ecx, eax
            //   c1f905               | sar                 ecx, 5
            //   8b0c8d60314100       | mov                 ecx, dword ptr [ecx*4 + 0x413160]
            //   83e01f               | and                 eax, 0x1f

        $sequence_2 = { 83c40c 8bc8 8a10 40 84d2 75f9 8dbdacfeffff }
            // n = 7, score = 100
            //   83c40c               | add                 esp, 0xc
            //   8bc8                 | mov                 ecx, eax
            //   8a10                 | mov                 dl, byte ptr [eax]
            //   40                   | inc                 eax
            //   84d2                 | test                dl, dl
            //   75f9                 | jne                 0xfffffffb
            //   8dbdacfeffff         | lea                 edi, [ebp - 0x154]

        $sequence_3 = { 6801000080 ff15???????? 85c0 754e 8b5508 8bc2 }
            // n = 6, score = 100
            //   6801000080           | push                0x80000001
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   754e                 | jne                 0x50
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   8bc2                 | mov                 eax, edx

        $sequence_4 = { c1f805 8d3c8560314100 8bf3 83e61f c1e606 }
            // n = 5, score = 100
            //   c1f805               | sar                 eax, 5
            //   8d3c8560314100       | lea                 edi, [eax*4 + 0x413160]
            //   8bf3                 | mov                 esi, ebx
            //   83e61f               | and                 esi, 0x1f
            //   c1e606               | shl                 esi, 6

        $sequence_5 = { 83f86f 7518 56 e8???????? 8b55fc }
            // n = 5, score = 100
            //   83f86f               | cmp                 eax, 0x6f
            //   7518                 | jne                 0x1a
            //   56                   | push                esi
            //   e8????????           |                     
            //   8b55fc               | mov                 edx, dword ptr [ebp - 4]

        $sequence_6 = { e8???????? 83c40c 6a00 68ff000000 8d85c4feffff }
            // n = 5, score = 100
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   6a00                 | push                0
            //   68ff000000           | push                0xff
            //   8d85c4feffff         | lea                 eax, [ebp - 0x13c]

        $sequence_7 = { 33c0 5d c3 8b04c524de4000 }
            // n = 4, score = 100
            //   33c0                 | xor                 eax, eax
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   8b04c524de4000       | mov                 eax, dword ptr [eax*8 + 0x40de24]

        $sequence_8 = { 0f85f3020000 e8???????? 84c0 0f85e6020000 6800010000 6a00 }
            // n = 6, score = 100
            //   0f85f3020000         | jne                 0x2f9
            //   e8????????           |                     
            //   84c0                 | test                al, al
            //   0f85e6020000         | jne                 0x2ec
            //   6800010000           | push                0x100
            //   6a00                 | push                0

        $sequence_9 = { 75f6 33c0 68???????? 8945cc 8845d0 }
            // n = 5, score = 100
            //   75f6                 | jne                 0xfffffff8
            //   33c0                 | xor                 eax, eax
            //   68????????           |                     
            //   8945cc               | mov                 dword ptr [ebp - 0x34], eax
            //   8845d0               | mov                 byte ptr [ebp - 0x30], al

    condition:
        7 of them and filesize < 188416
}
