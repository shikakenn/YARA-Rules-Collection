rule win_meterpreter_auto {

    meta:
        id = "IzCY7GZ6p23J98ddAui1y"
        fingerprint = "v1_sha256_1631dc247baef420a5deaf156c823d0d4f3e3c68f2c5cd0e3fcbf8155c8e3d6f"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.meterpreter."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.meterpreter"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 99 f7fb 043b 8801 }
            // n = 4, score = 200
            //   99                   | cdq                 
            //   f7fb                 | idiv                ebx
            //   043b                 | add                 al, 0x3b
            //   8801                 | mov                 byte ptr [ecx], al

        $sequence_1 = { 0580fc5600 2ab3780b0019 43 51 360000 }
            // n = 5, score = 200
            //   0580fc5600           | add                 eax, 0x56fc80
            //   2ab3780b0019         | sub                 dh, byte ptr [ebx + 0x19000b78]
            //   43                   | inc                 ebx
            //   51                   | push                ecx
            //   360000               | add                 byte ptr ss:[eax], al

        $sequence_2 = { 53 8b22 0c56 8b7508 57 8b7d10 }
            // n = 6, score = 200
            //   53                   | push                ebx
            //   8b22                 | mov                 esp, dword ptr [edx]
            //   0c56                 | or                  al, 0x56
            //   8b7508               | mov                 esi, dword ptr [ebp + 8]
            //   57                   | push                edi
            //   8b7d10               | mov                 edi, dword ptr [ebp + 0x10]

        $sequence_3 = { b80100f200 5d bc90909090 90 90 90 55 }
            // n = 7, score = 200
            //   b80100f200           | mov                 eax, 0xf20001
            //   5d                   | pop                 ebp
            //   bc90909090           | mov                 esp, 0x90909090
            //   90                   | nop                 
            //   90                   | nop                 
            //   90                   | nop                 
            //   55                   | push                ebp

        $sequence_4 = { b80cfdc100 15c3b8d0fc 40 005dc3 058e3053ff 7ef8 }
            // n = 6, score = 200
            //   b80cfdc100           | mov                 eax, 0xc1fd0c
            //   15c3b8d0fc           | adc                 eax, 0xfcd0b8c3
            //   40                   | inc                 eax
            //   005dc3               | add                 byte ptr [ebp - 0x3d], bl
            //   058e3053ff           | add                 eax, 0xff53308e
            //   7ef8                 | jle                 0xfffffffa

        $sequence_5 = { 8be5 5d c27f00 8d4df4 8d55ec }
            // n = 5, score = 200
            //   8be5                 | mov                 esp, ebp
            //   5d                   | pop                 ebp
            //   c27f00               | ret                 0x7f
            //   8d4df4               | lea                 ecx, [ebp - 0xc]
            //   8d55ec               | lea                 edx, [ebp - 0x14]

        $sequence_6 = { 90 90 90 90 83775840 41 00ff }
            // n = 7, score = 200
            //   90                   | nop                 
            //   90                   | nop                 
            //   90                   | nop                 
            //   90                   | nop                 
            //   83775840             | xor                 dword ptr [edi + 0x58], 0x40
            //   41                   | inc                 ecx
            //   00ff                 | add                 bh, bh

        $sequence_7 = { 6878e98cff ffd6 68???????? ffd6 68???????? }
            // n = 5, score = 200
            //   6878e98cff           | push                0xff8ce978
            //   ffd6                 | call                esi
            //   68????????           |                     
            //   ffd6                 | call                esi
            //   68????????           |                     

        $sequence_8 = { 8b2410 895e20 897e24 33c0 5f 5e }
            // n = 6, score = 200
            //   8b2410               | mov                 esp, dword ptr [eax + edx]
            //   895e20               | mov                 dword ptr [esi + 0x20], ebx
            //   897e24               | mov                 dword ptr [esi + 0x24], edi
            //   33c0                 | xor                 eax, eax
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi

        $sequence_9 = { 7562 8b4c2418 8b441e09 01d2 f7f1 8bd8 68442410f7 }
            // n = 7, score = 200
            //   7562                 | jne                 0x64
            //   8b4c2418             | mov                 ecx, dword ptr [esp + 0x18]
            //   8b441e09             | mov                 eax, dword ptr [esi + ebx + 9]
            //   01d2                 | add                 edx, edx
            //   f7f1                 | div                 ecx
            //   8bd8                 | mov                 ebx, eax
            //   68442410f7           | push                0xf7102444

    condition:
        7 of them and filesize < 188416
}
