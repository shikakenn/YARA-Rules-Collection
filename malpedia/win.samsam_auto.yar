rule win_samsam_auto {

    meta:
        id = "2pxHoT0gxOeRxvsCTiedqk"
        fingerprint = "v1_sha256_7dfde5eb2b271ed697f40da535503822a01adae5daa82889969f50640e533b94"
        version = "1"
        date = "2020-04-21"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "autogenerated rule brought to you by yara-signator"
        category = "INFO"
        tool = "yara-signator v0.3.1"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.samsam"
        malpedia_version = "20200421"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 082b c883e10f 03c1 1bc9 0bc1 59 e9???????? }
            // n = 7, score = 200
            //   082b                 | or                  byte ptr [ebx], ch
            //   c883e10f             | enter               -0x1e7d, 0xf
            //   03c1                 | add                 eax, ecx
            //   1bc9                 | sbb                 ecx, ecx
            //   0bc1                 | or                  eax, ecx
            //   59                   | pop                 ecx
            //   e9????????           |                     

        $sequence_1 = { ec 8b4508 56 33f6 3bc6 751d e8???????? }
            // n = 7, score = 200
            //   ec                   | in                  al, dx
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   56                   | push                esi
            //   33f6                 | xor                 esi, esi
            //   3bc6                 | cmp                 eax, esi
            //   751d                 | jne                 0x1f
            //   e8????????           |                     

        $sequence_2 = { ec 83ec10 53 ff7510 8d4df0 e8???????? }
            // n = 6, score = 100
            //   ec                   | in                  al, dx
            //   83ec10               | sub                 esp, 0x10
            //   53                   | push                ebx
            //   ff7510               | push                dword ptr [ebp + 0x10]
            //   8d4df0               | lea                 ecx, [ebp - 0x10]
            //   e8????????           |                     

        $sequence_3 = { ec 83ec10 53 33db 56 57 }
            // n = 6, score = 100
            //   ec                   | in                  al, dx
            //   83ec10               | sub                 esp, 0x10
            //   53                   | push                ebx
            //   33db                 | xor                 ebx, ebx
            //   56                   | push                esi
            //   57                   | push                edi

        $sequence_4 = { ec 6a0a 6a00 ff7508 e8???????? }
            // n = 5, score = 100
            //   ec                   | in                  al, dx
            //   6a0a                 | push                0xa
            //   6a00                 | push                0
            //   ff7508               | push                dword ptr [ebp + 8]
            //   e8????????           |                     

    condition:
        all of them and filesize < 483328
}
