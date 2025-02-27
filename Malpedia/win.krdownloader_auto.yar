rule win_krdownloader_auto {

    meta:
        id = "3eJlsVPIhlO9E8CchHkTsY"
        fingerprint = "v1_sha256_5c0e3ed0b3f2de4235868995565358a807a3f9a7ed056ed4108e22469b818ef9"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.krdownloader."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.krdownloader"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { c645e161 c645e22e c645e370 c645e468 c645e570 c645e63f c645e76d }
            // n = 7, score = 200
            //   c645e161             | mov                 byte ptr [ebp - 0x1f], 0x61
            //   c645e22e             | mov                 byte ptr [ebp - 0x1e], 0x2e
            //   c645e370             | mov                 byte ptr [ebp - 0x1d], 0x70
            //   c645e468             | mov                 byte ptr [ebp - 0x1c], 0x68
            //   c645e570             | mov                 byte ptr [ebp - 0x1b], 0x70
            //   c645e63f             | mov                 byte ptr [ebp - 0x1a], 0x3f
            //   c645e76d             | mov                 byte ptr [ebp - 0x19], 0x6d

        $sequence_1 = { 8b4dbc 894db4 8b55b8 81c200010000 52 }
            // n = 5, score = 200
            //   8b4dbc               | mov                 ecx, dword ptr [ebp - 0x44]
            //   894db4               | mov                 dword ptr [ebp - 0x4c], ecx
            //   8b55b8               | mov                 edx, dword ptr [ebp - 0x48]
            //   81c200010000         | add                 edx, 0x100
            //   52                   | push                edx

        $sequence_2 = { e8???????? 8945f0 8b45f8 8b4df0 3b4808 7708 }
            // n = 6, score = 200
            //   e8????????           |                     
            //   8945f0               | mov                 dword ptr [ebp - 0x10], eax
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]
            //   8b4df0               | mov                 ecx, dword ptr [ebp - 0x10]
            //   3b4808               | cmp                 ecx, dword ptr [eax + 8]
            //   7708                 | ja                  0xa

        $sequence_3 = { 8b55ec 52 68???????? 68???????? e8???????? }
            // n = 5, score = 200
            //   8b55ec               | mov                 edx, dword ptr [ebp - 0x14]
            //   52                   | push                edx
            //   68????????           |                     
            //   68????????           |                     
            //   e8????????           |                     

        $sequence_4 = { 52 e8???????? 83c40c 85c0 752c 837d0c00 741d }
            // n = 7, score = 200
            //   52                   | push                edx
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   85c0                 | test                eax, eax
            //   752c                 | jne                 0x2e
            //   837d0c00             | cmp                 dword ptr [ebp + 0xc], 0
            //   741d                 | je                  0x1f

        $sequence_5 = { 8b4510 50 e8???????? 83c40c eb23 8b4d14 c70150000000 }
            // n = 7, score = 200
            //   8b4510               | mov                 eax, dword ptr [ebp + 0x10]
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   eb23                 | jmp                 0x25
            //   8b4d14               | mov                 ecx, dword ptr [ebp + 0x14]
            //   c70150000000         | mov                 dword ptr [ecx], 0x50

        $sequence_6 = { 50 ff15???????? 6aff ff15???????? 6a3c e8???????? 83c404 }
            // n = 7, score = 200
            //   50                   | push                eax
            //   ff15????????         |                     
            //   6aff                 | push                -1
            //   ff15????????         |                     
            //   6a3c                 | push                0x3c
            //   e8????????           |                     
            //   83c404               | add                 esp, 4

        $sequence_7 = { 894dc0 8b55c0 8955ac 8b45fc }
            // n = 4, score = 200
            //   894dc0               | mov                 dword ptr [ebp - 0x40], ecx
            //   8b55c0               | mov                 edx, dword ptr [ebp - 0x40]
            //   8955ac               | mov                 dword ptr [ebp - 0x54], edx
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]

        $sequence_8 = { 8b4df8 894df4 8b55f4 83c210 }
            // n = 4, score = 200
            //   8b4df8               | mov                 ecx, dword ptr [ebp - 8]
            //   894df4               | mov                 dword ptr [ebp - 0xc], ecx
            //   8b55f4               | mov                 edx, dword ptr [ebp - 0xc]
            //   83c210               | add                 edx, 0x10

        $sequence_9 = { 51 6a00 8b4d10 e8???????? 894590 8b5590 89558c }
            // n = 7, score = 200
            //   51                   | push                ecx
            //   6a00                 | push                0
            //   8b4d10               | mov                 ecx, dword ptr [ebp + 0x10]
            //   e8????????           |                     
            //   894590               | mov                 dword ptr [ebp - 0x70], eax
            //   8b5590               | mov                 edx, dword ptr [ebp - 0x70]
            //   89558c               | mov                 dword ptr [ebp - 0x74], edx

    condition:
        7 of them and filesize < 352256
}
