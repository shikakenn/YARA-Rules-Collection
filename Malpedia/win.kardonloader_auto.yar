rule win_kardonloader_auto {

    meta:
        id = "6xXawP7FN05ZnNPPlR3LM7"
        fingerprint = "v1_sha256_af6ba3e21c382f2fd654060dcfde8b3eb16b50330472c81358760501218ffed8"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.kardonloader."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.kardonloader"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 8975f8 e8???????? 84c0 ba???????? b9???????? 8d857cffffff 0f44ca }
            // n = 7, score = 200
            //   8975f8               | mov                 dword ptr [ebp - 8], esi
            //   e8????????           |                     
            //   84c0                 | test                al, al
            //   ba????????           |                     
            //   b9????????           |                     
            //   8d857cffffff         | lea                 eax, [ebp - 0x84]
            //   0f44ca               | cmove               ecx, edx

        $sequence_1 = { 57 ff15???????? 8bf0 83feff 0f849d000000 8d45e0 }
            // n = 6, score = 200
            //   57                   | push                edi
            //   ff15????????         |                     
            //   8bf0                 | mov                 esi, eax
            //   83feff               | cmp                 esi, -1
            //   0f849d000000         | je                  0xa3
            //   8d45e0               | lea                 eax, [ebp - 0x20]

        $sequence_2 = { c745f8???????? c745fc???????? ff74b5d8 ff15???????? }
            // n = 4, score = 200
            //   c745f8????????       |                     
            //   c745fc????????       |                     
            //   ff74b5d8             | push                dword ptr [ebp + esi*4 - 0x28]
            //   ff15????????         |                     

        $sequence_3 = { 59 59 85c0 0f84f7010000 56 57 }
            // n = 6, score = 200
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx
            //   85c0                 | test                eax, eax
            //   0f84f7010000         | je                  0x1fd
            //   56                   | push                esi
            //   57                   | push                edi

        $sequence_4 = { 7861 ff7510 ff7510 e8???????? 59 50 }
            // n = 6, score = 200
            //   7861                 | js                  0x63
            //   ff7510               | push                dword ptr [ebp + 0x10]
            //   ff7510               | push                dword ptr [ebp + 0x10]
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   50                   | push                eax

        $sequence_5 = { 83c40c 894714 b001 5f 5e }
            // n = 5, score = 200
            //   83c40c               | add                 esp, 0xc
            //   894714               | mov                 dword ptr [edi + 0x14], eax
            //   b001                 | mov                 al, 1
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi

        $sequence_6 = { c3 55 8bec 81ec00040000 8d8500fcffff 56 ff35???????? }
            // n = 7, score = 200
            //   c3                   | ret                 
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   81ec00040000         | sub                 esp, 0x400
            //   8d8500fcffff         | lea                 eax, [ebp - 0x400]
            //   56                   | push                esi
            //   ff35????????         |                     

        $sequence_7 = { 33c0 e9???????? 33c0 53 8b5d08 }
            // n = 5, score = 200
            //   33c0                 | xor                 eax, eax
            //   e9????????           |                     
            //   33c0                 | xor                 eax, eax
            //   53                   | push                ebx
            //   8b5d08               | mov                 ebx, dword ptr [ebp + 8]

        $sequence_8 = { c745f8???????? c745fc???????? ff74b5d8 ff15???????? 85c0 750a }
            // n = 6, score = 200
            //   c745f8????????       |                     
            //   c745fc????????       |                     
            //   ff74b5d8             | push                dword ptr [ebp + esi*4 - 0x28]
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   750a                 | jne                 0xc

        $sequence_9 = { 40 8945fc 894d08 8a01 }
            // n = 4, score = 200
            //   40                   | inc                 eax
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   894d08               | mov                 dword ptr [ebp + 8], ecx
            //   8a01                 | mov                 al, byte ptr [ecx]

    condition:
        7 of them and filesize < 57344
}
