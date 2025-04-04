rule win_slave_auto {

    meta:
        id = "LNziBORF5Uzmcgpk3rrBj"
        fingerprint = "v1_sha256_32dc8f0602dd0c995ffd6f35edd82eaee41a96ee44816d90c15c92afe3d59d57"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.slave."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.slave"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { c0eb06 0ad8 8899e7020000 8a17 d0ea 32d3 80e21c }
            // n = 7, score = 300
            //   c0eb06               | shr                 bl, 6
            //   0ad8                 | or                  bl, al
            //   8899e7020000         | mov                 byte ptr [ecx + 0x2e7], bl
            //   8a17                 | mov                 dl, byte ptr [edi]
            //   d0ea                 | shr                 dl, 1
            //   32d3                 | xor                 dl, bl
            //   80e21c               | and                 dl, 0x1c

        $sequence_1 = { 50 ffd3 008608010000 83c40c 83be1403000000 8a8e08010000 7c3a }
            // n = 7, score = 300
            //   50                   | push                eax
            //   ffd3                 | call                ebx
            //   008608010000         | add                 byte ptr [esi + 0x108], al
            //   83c40c               | add                 esp, 0xc
            //   83be1403000000       | cmp                 dword ptr [esi + 0x314], 0
            //   8a8e08010000         | mov                 cl, byte ptr [esi + 0x108]
            //   7c3a                 | jl                  0x3c

        $sequence_2 = { 33c7 03c1 81c28647beef 03d0 8b45d4 }
            // n = 5, score = 300
            //   33c7                 | xor                 eax, edi
            //   03c1                 | add                 eax, ecx
            //   81c28647beef         | add                 edx, 0xefbe4786
            //   03d0                 | add                 edx, eax
            //   8b45d4               | mov                 eax, dword ptr [ebp - 0x2c]

        $sequence_3 = { 837df400 0f846c2d0000 8a8608030000 240f 0fb6c0 66894706 }
            // n = 6, score = 300
            //   837df400             | cmp                 dword ptr [ebp - 0xc], 0
            //   0f846c2d0000         | je                  0x2d72
            //   8a8608030000         | mov                 al, byte ptr [esi + 0x308]
            //   240f                 | and                 al, 0xf
            //   0fb6c0               | movzx               eax, al
            //   66894706             | mov                 word ptr [edi + 6], ax

        $sequence_4 = { 8b45ec 8b00 894720 8b45ec 8b4004 894724 e9???????? }
            // n = 7, score = 300
            //   8b45ec               | mov                 eax, dword ptr [ebp - 0x14]
            //   8b00                 | mov                 eax, dword ptr [eax]
            //   894720               | mov                 dword ptr [edi + 0x20], eax
            //   8b45ec               | mov                 eax, dword ptr [ebp - 0x14]
            //   8b4004               | mov                 eax, dword ptr [eax + 4]
            //   894724               | mov                 dword ptr [edi + 0x24], eax
            //   e9????????           |                     

        $sequence_5 = { f6c110 7509 80c910 888e94030000 8a475d 24bf 0c20 }
            // n = 7, score = 300
            //   f6c110               | test                cl, 0x10
            //   7509                 | jne                 0xb
            //   80c910               | or                  cl, 0x10
            //   888e94030000         | mov                 byte ptr [esi + 0x394], cl
            //   8a475d               | mov                 al, byte ptr [edi + 0x5d]
            //   24bf                 | and                 al, 0xbf
            //   0c20                 | or                  al, 0x20

        $sequence_6 = { 33c8 8bc3 8b5dd8 c1c806 33c8 8bc7 }
            // n = 6, score = 300
            //   33c8                 | xor                 ecx, eax
            //   8bc3                 | mov                 eax, ebx
            //   8b5dd8               | mov                 ebx, dword ptr [ebp - 0x28]
            //   c1c806               | ror                 eax, 6
            //   33c8                 | xor                 ecx, eax
            //   8bc7                 | mov                 eax, edi

        $sequence_7 = { 50 8d4208 50 ff15???????? 8b45fc 2bfe f30f7e05???????? }
            // n = 7, score = 300
            //   50                   | push                eax
            //   8d4208               | lea                 eax, [edx + 8]
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   2bfe                 | sub                 edi, esi
            //   f30f7e05????????     |                     

        $sequence_8 = { 3a4202 750d 83feff 741c 8a4103 3a4203 7414 }
            // n = 7, score = 300
            //   3a4202               | cmp                 al, byte ptr [edx + 2]
            //   750d                 | jne                 0xf
            //   83feff               | cmp                 esi, -1
            //   741c                 | je                  0x1e
            //   8a4103               | mov                 al, byte ptr [ecx + 3]
            //   3a4203               | cmp                 al, byte ptr [edx + 3]
            //   7414                 | je                  0x16

        $sequence_9 = { 810e80000100 f70600400000 8b550c 743c 0fb68707030000 808f0603000002 c1e804 }
            // n = 7, score = 300
            //   810e80000100         | or                  dword ptr [esi], 0x10080
            //   f70600400000         | test                dword ptr [esi], 0x4000
            //   8b550c               | mov                 edx, dword ptr [ebp + 0xc]
            //   743c                 | je                  0x3e
            //   0fb68707030000       | movzx               eax, byte ptr [edi + 0x307]
            //   808f0603000002       | or                  byte ptr [edi + 0x306], 2
            //   c1e804               | shr                 eax, 4

    condition:
        7 of them and filesize < 532480
}
