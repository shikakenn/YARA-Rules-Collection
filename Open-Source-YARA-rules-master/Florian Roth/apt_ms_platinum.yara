rule Trojan_Win32_PlaSrv : Platinum
{
    meta:
        id = "524tO0KDhjibhFIoLzCgUh"
        fingerprint = "v1_sha256_5978502454d66a930a535ffe61d78f2106c3c17c8df9be1b22bc10ef900c891f"
        version = "1.0"
        modified = "2016-04-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Microsoft"
        description = "Hotpatching Injector"
        category = "INFO"
        original_sample_sha1 = "ff7f949da665ba8ce9fb01da357b51415634eaad"
        unpacked_sample_sha1 = "dff2fee984ba9f5a8f5d97582c83fca4fa1fe131"
        activity_group = "Platinum"

    strings:
        $Section_name = ".hotp1"
        $offset_x59 = { C7 80 64 01 00 00 00 00 01 00 }
    
    condition:
        $Section_name and $offset_x59
}

rule Trojan_Win32_Platual : Platinum
{
    meta:
        id = "6m3Y0FhdAojLcj97Lonpio"
        fingerprint = "v1_sha256_3692b5c1d873fb799b64ea69f3762177198dbb0fb971bc29bb80048c0de735d4"
        version = "1.0"
        modified = "2016-04-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Microsoft"
        description = "Installer component"
        category = "INFO"
        original_sample_sha1 = "e0ac2ae221328313a7eee33e9be0924c46e2beb9"
        unpacked_sample_sha1 = "ccaf36c2d02c3c5ca24eeeb7b1eae7742a23a86a"
        activity_group = "Platinum"

    strings:
        $class_name = "AVCObfuscation"
        $scrambled_dir = { A8 8B B8 E3 B1 D7 FE 85 51 32 3E C0 F1 B7 73 99 }

    condition:
        $class_name and $scrambled_dir
}

rule Trojan_Win32_Plaplex : Platinum
{
    meta:
        id = "5xJqU48AquoxGuaRDO4OPj"
        fingerprint = "v1_sha256_ff7b9a52befae5f22f7c6093af44bef4a4cf271548c1caf22f30d3c8aec42de4"
        version = "1.0"
        modified = "2016-04-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Microsoft"
        description = "Variant of the JPin backdoor"
        category = "INFO"
        original_sample_sha1 = "ca3bda30a3cdc15afb78e54fa1bbb9300d268d66"
        unpacked_sample_sha1 = "2fe3c80e98bbb0cf5a0c4da286cd48ec78130a24"
        activity_group = "Platinum"

    strings:
        $class_name1 = "AVCObfuscation"
        $class_name2 = "AVCSetiriControl"

    condition:
        $class_name1 and $class_name2
}

rule Trojan_Win32_Dipsind_B : Platinum
{
    meta:
        id = "7MDA4VTJ8lrXMUZ9pkGBE0"
        fingerprint = "v1_sha256_1f99f298dc4d1483eb95cfb898dd9eee32b2f72a8da562f58a57f44559cbd2c7"
        version = "1.0"
        modified = "2016-04-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Microsoft"
        description = "Dipsind Family"
        category = "INFO"
        sample_sha1 = "09e0dfbb5543c708c0dd6a89fd22bbb96dc4ca1c"
        activity_group = "Platinum"

    strings:
        $frg1 = {8D 90 04 01 00 00 33 C0 F2 AE F7 D1 2B F9 8B C1 8B F7 8B FA C1 E9 02 F3 A5 8B C8 83 E1 03 F3 A4 8B 4D EC 8B 15 ?? ?? ?? ?? 89 91 ?? 07 00 00 }
        $frg2 = {68 A1 86 01 00 C1 E9 02 F3 AB 8B CA 83 E1 03 F3 AA}
        $frg3 = {C0 E8 07 D0 E1 0A C1 8A C8 32 D0 C0 E9 07 D0 E0 0A C8 32 CA 80 F1 63}

    condition:
        $frg1 and $frg2 and $frg3
}

rule Trojan_Win32_PlaKeylog_B : Platinum
{
    meta:
        id = "1GFBNbuOZsbQywhwa3aNP5"
        fingerprint = "v1_sha256_288fb5a724baaa032ca36124cf803698e315aaf61662f999f3b894049ece63f2"
        version = "1.0"
        modified = "2016-04-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Microsoft"
        description = "Keylogger component"
        category = "INFO"
        original_sample_sha1 = "0096a3e0c97b85ca75164f48230ae530c94a2b77"
        unpacked_sample_sha1 = "6a1412daaa9bdc553689537df0a004d44f8a45fd"
        activity_group = "Platinum"

    strings:
        $hook = {C6 06 FF 46 C6 06 25}
        $dasm_engine = {80 C9 10 88 0E 8A CA 80 E1 07 43 88 56 03 80 F9 05}

    condition:
        $hook and $dasm_engine
}

rule Trojan_Win32_Adupib : Platinum
{
    meta:
        id = "1gJerM7lEFPZks3x50pzJ3"
        fingerprint = "v1_sha256_4d93b6a041468b51763d9497acf3d01ee59ac05f1807a6b140c557ef96d26df9"
        version = "1.0"
        modified = "2016-04-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Microsoft"
        description = "Adupib SSL Backdoor"
        category = "INFO"
        original_sample_sha1 = "d3ad0933e1b114b14c2b3a2c59d7f8a95ea0bcbd"
        unpacked_sample_sha1 = "a80051d5ae124fd9e5cc03e699dd91c2b373978b"
        activity_group = "Platinum"

    strings:
        $str1 = "POLL_RATE"
        $str2 = "OP_TIME(end hour)"
        $str3 = "%d:TCP:*:Enabled"
        $str4 = "%s[PwFF_cfg%d]"
        $str5 = "Fake_GetDlgItemTextW: ***value***="

    condition:
        $str1 and $str2 and $str3 and $str4 and $str5
}

rule Trojan_Win32_PlaLsaLog : Platinum
{
    meta:
        id = "49iPeXEpPOaiZcL8EwJclF"
        fingerprint = "v1_sha256_58d937be220c0f356396c28367ab63ff4c4a6bf2cbf9e0ce8f8cac25e4fe3fec"
        version = "1.0"
        modified = "2016-04-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Microsoft"
        description = "Loader / possible incomplete LSA Password Filter"
        category = "INFO"
        original_sample_sha1 = "fa087986697e4117c394c9a58cb9f316b2d9f7d8"
        unpacked_sample_sha1 = "29cb81dbe491143b2f8b67beaeae6557d8944ab4"
        activity_group = "Platinum"

    strings:
        $str1 = {8A 1C 01 32 DA 88 1C 01 8B 74 24 0C 41 3B CE 7C EF 5B 5F C6 04 01 00 5E 81 C4 04 01 00 00 C3}
        $str2 = "PasswordChangeNotify"

    condition:
        $str1 and $str2
}

rule Trojan_Win32_Plagon : Platinum
{
    meta:
        id = "4jy2qGDJ44ZgXrkJsKfBn4"
        fingerprint = "v1_sha256_99e0d300f030bb6407de1fda488b47c73f8278e9c015bf779259ddf1b68903a2"
        version = "1.0"
        modified = "2016-04-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Microsoft"
        description = "Dipsind variant"
        category = "INFO"
        original_sample_sha1 = "48b89f61d58b57dba6a0ca857bce97bab636af65"
        unpacked_sample_sha1 = "6dccf88d89ad7b8611b1bc2e9fb8baea41bdb65a"
        activity_group = "Platinum"

    strings:
        $str1 = "VPLRXZHTU"
        $str2 = {64 6F 67 32 6A 7E 6C}
        $str3 = "Dqpqftk(Wou\"Isztk)"
        $str4 = "StartThreadAtWinLogon"

    condition:
        $str1 and $str2 and $str3 and $str4
}

rule Trojan_Win32_Plakelog : Platinum
{
    meta:
        id = "1j0XauPDPKmwvzlxFI2KgU"
        fingerprint = "v1_sha256_e18cae8bb2a79f7d39a80669896b1f7a7c1726f14192abcc91388fd53781ffef"
        version = "1.0"
        modified = "2016-04-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Microsoft"
        description = "Raw-input based keylogger"
        category = "INFO"
        original_sample_sha1 = "3907a9e41df805f912f821a47031164b6636bd04"
        unpacked_sample_sha1 = "960feeb15a0939ec0b53dcb6815adbf7ac1e7bb2"
        activity_group = "Platinum"

    strings:
        $str1 = "<0x02>" wide
        $str2 = "[CTR-BRK]" wide
        $str3 = "[/WIN]" wide
        $str4 = {8A 16 8A 18 32 DA 46 88 18 8B 15 08 E6 42 00 40 41 3B CA 72 EB 5E 5B}

    condition:
        $str1 and $str2 and $str3 and $str4
}

rule Trojan_Win32_Plainst : Platinum
{
    meta:
        id = "4nM1r67zW16mXepjuyJy6c"
        fingerprint = "v1_sha256_5fa8e52c044e05d96c2c09b69ef884ed0ea863ceb3ba00cdf243a4907050de69"
        version = "1.0"
        modified = "2016-04-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Microsoft"
        description = "Installer component"
        category = "INFO"
        original_sample_sha1 = "99c08d31af211a0e17f92dd312ec7ca2b9469ecb"
        unpacked_sample_sha1 = "dcb6cf7cf7c8fdfc89656a042f81136bda354ba6"
        activity_group = "Platinum"

    strings:
        $str1 = {66 8B 14 4D 18 50 01 10 8B 45 08 66 33 14 70 46 66 89 54 77 FE 66 83 7C 77 FE 00 75 B7 8B 4D FC 89 41 08 8D 04 36 89 41 0C 89 79 04}
        $str2 = {4b D3 91 49 A1 80 91 42 83 B6 33 28 36 6B 90 97}

    condition:
        $str1 and $str2
}

rule Trojan_Win32_Plagicom : Platinum
{
    meta:
        id = "2fk4xQhFjJq3CzMhurvKVu"
        fingerprint = "v1_sha256_d2645ecc3b4400af7d9949eeca01b1ed5d74516010658c66934772e04040d9cf"
        version = "1.0"
        modified = "2016-04-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Microsoft"
        description = "Installer component"
        category = "INFO"
        original_sample_sha1 = "99dcb148b053f4cef6df5fa1ec5d33971a58bd1e"
        unpacked_sample_sha1 = "c1c950bc6a2ad67488e675da4dfc8916831239a7"
        activity_group = "Platinum"

    strings:
        $str1 = {C6 44 24 ?? 68 C6 44 24 ?? 4D C6 44 24 ?? 53 C6 44 24 ?? 56 C6 44 24 ??
00}
        $str2 = "OUEMM/EMM"
        $str3 = {85 C9 7E 08 FE 0C 10 40 3B C1 7C F8 C3}

    condition:
        $str1 and $str2 and $str3
}

rule Trojan_Win32_Plaklog : Platinum
{
    meta:
        id = "1WwpJPvavuyptDzVZYI1cN"
        fingerprint = "v1_sha256_af8dd0749d07f0b99cf3dd24bc144d38fe6db00f699bc7f45f197ac6e1663cad"
        version = "1.0"
        modified = "2016-04-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Microsoft"
        description = "Hook-based keylogger"
        category = "INFO"
        original_sample_sha1 = "831a5a29d47ab85ee3216d4e75f18d93641a9819"
        unpacked_sample_sha1 = "e18750207ddbd939975466a0e01bd84e75327dda"
        activity_group = "Platinum"

    strings:
        $str1 = "++[%s^^unknown^^%s]++"
        $str2 = "vtfs43/emm"
        $str3 = {33 C9 39 4C 24 08 7E 10 8B 44 24 04 03 C1 80 00 08 41 3B 4C 24 08 7C F0 C3}

    condition:
        $str1 and $str2 and $str3
}

rule Trojan_Win32_Plapiio : Platinum
{
    meta:
        id = "cKytqlSE3CrB3A2bfjjTl"
        fingerprint = "v1_sha256_580fb1377d98e7ffcb9823b5c485ff536813e3df5d8bded745373b2a3a82fcfd"
        version = "1.0"
        modified = "2016-04-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Microsoft"
        description = "JPin backdoor"
        category = "INFO"
        original_sample_sha1 = "3119de80088c52bd8097394092847cd984606c88"
        unpacked_sample_sha1 = "3acb8fe2a5eb3478b4553907a571b6614eb5455c"
        activity_group = "Platinum"

    strings:
        $str1 = "ServiceMain"
        $str2 = "Startup"
        $str3 = {C6 45 ?? 68 C6 45 ?? 4D C6 45 ?? 53 C6 45 ?? 56 C6 45 ?? 6D C6 45 ?? 6D}

    condition:
        $str1 and $str2 and $str3
}

rule Trojan_Win32_Plabit : Platinum
{
    meta:
        id = "4Y0LHnA3stxBjB1VsQ5WVH"
        fingerprint = "v1_sha256_35f12d45c8ee5f8e2b0bcd57ae14c0ba52670abc1212f94aa276efbbe1043146"
        version = "1.0"
        modified = "2016-04-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Microsoft"
        description = "Installer component"
        category = "INFO"
        sample_sha1 = "6d1169775a552230302131f9385135d385efd166"
        activity_group = "Platinum"

    strings:
        $str1 = {4b D3 91 49 A1 80 91 42 83 B6 33 28 36 6B 90 97}
        $str2 = "GetInstanceW"
        $str3 = {8B D0 83 E2 1F 8A 14 0A 30 14 30 40 3B 44 24 04 72 EE}

    condition:
        $str1 and $str2 and $str3
}

rule Trojan_Win32_Placisc2 : Platinum
{
    meta:
        id = "4J7pJSEKiODiT1kMq9Zyt5"
        fingerprint = "v1_sha256_6629ca96c73e48bc14c811df781973f8040f88bcbf9eda601e9f5db86e11c20b"
        version = "1.0"
        modified = "2016-04-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Microsoft"
        description = "Dipsind variant"
        category = "INFO"
        original_sample_sha1 = "bf944eb70a382bd77ee5b47548ea9a4969de0527"
        unpacked_sample_sha1 = "d807648ddecc4572c7b04405f496d25700e0be6e"
        activity_group = "Platinum"

    strings:
        $str1 = {76 16 8B D0 83 E2 07 8A 4C 14 24 8A 14 18 32 D1 88 14 18 40 3B C7 72 EA}
        $str2 = "VPLRXZHTU"
        $str3 = "%d) Command:%s"
        $str4 = {0D 0A 2D 2D 2D 2D 2D 09 2D 2D 2D 2D 2D 2D 0D 0A}

    condition:
        $str1 and $str2 and $str3 and $str4
}

rule Trojan_Win32_Placisc3 : Platinum
{
    meta:
        id = "2hWmaYrUIGByzTxKzELlfx"
        fingerprint = "v1_sha256_3a1afe737c08b4d9149380e04f5d6240a00b237822c3c82d82eccf5412cb05d1"
        version = "1.0"
        modified = "2016-04-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Microsoft"
        description = "Dipsind variant"
        category = "INFO"
        original_sample_sha1 = "1b542dd0dacfcd4200879221709f5fa9683cdcda"
        unpacked_sample_sha1 = "bbd4992ee3f3a3267732151636359cf94fb4575d"
        activity_group = "Platinum"

    strings:
        $str1 = {BA 6E 00 00 00 66 89 95 ?? ?? FF FF B8 73 00 00 00 66 89 85 ?? ?? FF FF B9 64 00 00 00 66 89 8D ?? ?? FF FF BA 65 00 00 00 66 89 95 ?? ?? FF FF B8 6C 00 00 00}
        $str2 = "VPLRXZHTU"
        $str3 = {8B 44 24 ?? 8A 04 01 41 32 C2 3B CF 7C F2 88 03}

    condition:
        $str1 and $str2 and $str3
}

rule Trojan_Win32_Placisc4 : Platinum
{
    meta:
        id = "2RpZjSWgB7Jcpnm5HOmlga"
        fingerprint = "v1_sha256_4fa4f48d6747cde6d635eca2f5277da7be17473a561828eafa604fbc2801073a"
        version = "1.0"
        modified = "2016-04-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Microsoft"
        description = "Installer for Dipsind variant"
        category = "INFO"
        original_sample_sha1 = "3d17828632e8ff1560f6094703ece5433bc69586"
        unpacked_sample_sha1 = "2abb8e1e9cac24be474e4955c63108ff86d1a034"
        activity_group = "Platinum"

    strings:
        $str1 = {8D 71 01 8B C6 99 BB 0A 00 00 00 F7 FB 0F BE D2 0F BE 04 39 2B C2 88 04 39 84 C0 74 0A}
        $str2 = {6A 04 68 00 20 00 00 68 00 00 40 00 6A 00 FF D5}
        $str3 = {C6 44 24 ?? 64 C6 44 24 ?? 6F C6 44 24 ?? 67 C6 44 24 ?? 32 C6 44 24 ?? 6A}

    condition:
        $str1 and $str2 and $str3
}

rule Trojan_Win32_Plakpers : Platinum
{
    meta:
        id = "7mBA7oFbvobWFpCxHOP2By"
        fingerprint = "v1_sha256_d3705a34232ba2b00786b32f84823d3a6b037ed6a5882983e69addc020bc0b35"
        version = "1.0"
        modified = "2016-04-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Microsoft"
        description = "Injector / loader component"
        category = "INFO"
        original_sample_sha1 = "fa083d744d278c6f4865f095cfd2feabee558056"
        unpacked_sample_sha1 = "3a678b5c9c46b5b87bfcb18306ed50fadfc6372e"
        activity_group = "Platinum"

    strings:
        $str1 = "MyFileMappingObject"
        $str2 = "[%.3u]  %s  %s  %s [%s:" wide
        $str3 = "%s\\{%s}\\%s" wide

    condition:
        $str1 and $str2 and $str3
}

rule Trojan_Win32_Plainst2 : Platinum
{
    meta:
        id = "2sFk6rI5tiwAfIDgiNAD3T"
        fingerprint = "v1_sha256_4dc897a598fd491694f8fe3ec4ae9278dc341ffd9f95f416eb5e98fb5aa200e4"
        version = "1.0"
        modified = "2016-04-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Microsoft"
        description = "Zc tool"
        category = "INFO"
        original_sample_sha1 = "3f2ce812c38ff5ac3d813394291a5867e2cddcf2"
        unpacked_sample_sha1 = "88ff852b1b8077ad5a19cc438afb2402462fbd1a"
        activity_group = "Platinum"

    strings:
        $str1 = "Connected [%s:%d]..."
        $str2 = "reuse possible: %c"
        $str3 = "] => %d%%\x0a"

    condition:
        $str1 and $str2 and $str3
}

rule Trojan_Win32_Plakpeer : Platinum
{
    meta:
        id = "7OMvWpeQqgPadZcXOpZZSk"
        fingerprint = "v1_sha256_cc34ce9f12c95133872783090efd5813d3e2f44a1c726d29b2ba834509c9a1d5"
        version = "1.0"
        modified = "2016-04-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Microsoft"
        description = "Zc tool v2"
        category = "INFO"
        original_sample_sha1 = "2155c20483528377b5e3fde004bb604198463d29"
        unpacked_sample_sha1 = "dc991ef598825daabd9e70bac92c79154363bab2"
        activity_group = "Platinum"

    strings:
        $str1 = "@@E0020(%d)" wide
        $str2 = /exit.{0,3}@exit.{0,3}new.{0,3}query.{0,3}rcz.{0,3}scz/ wide
        $str3 = "---###---" wide
        $str4 = "---@@@---" wide

    condition:
        $str1 and $str2 and $str3 and $str4
}
