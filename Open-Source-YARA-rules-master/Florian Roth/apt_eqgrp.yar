/*
    Yara Rule Set
    Author: Florian Roth
    Date: 2016-08-15
    Identifier: EQGRP
*/

/* Rule Set ----------------------------------------------------------------- */

rule EQGRP_noclient_3_0_5 {
    meta:
        id = "4wINjjkVi2nVsbnoKbHI6F"
        fingerprint = "v1_sha256_51a6bf03c8d034942bf02fae2bea52436f53b4d437006b1dbe9c0c67387fe17a"
        version = "1.0"
        score = 75
        date = "2016-08-15"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects tool from EQGRP toolset - file noclient-3.0.5.3"
        category = "INFO"
        reference = "Research"

    strings:
        $x1 = "-C %s 127.0.0.1\" scripme -F -t JACKPOPIN4 '&" fullword ascii
        $x2 = "Command too long!  What the HELL are you trying to do to me?!?!  Try one smaller than %d bozo." fullword ascii
        $x3 = "sh -c \"ping -c 2 %s; grep %s /proc/net/arp >/tmp/gx \"" fullword ascii
        $x4 = "Error from ourtn, did not find keys=target in tn.spayed" fullword ascii
        $x5 = "ourtn -d -D %s -W 127.0.0.1:%d  -i %s -p %d %s %s" fullword ascii
    condition:
        ( uint16(0) == 0x457f and filesize < 700KB and 1 of them ) or ( all of them )
}

rule EQGRP_installdate {
    meta:
        id = "2Zv33Um1SJM6z9NBBuEZth"
        fingerprint = "v1_sha256_363a9c92c4d2560ba6dd0ec41acf136dff4346f20d54f971d319ed2aa531fe31"
        version = "1.0"
        score = 75
        date = "2016-08-15"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects tool from EQGRP toolset - file installdate.pl"
        category = "INFO"
        reference = "Research"

    strings:
        $x1 = "#Provide hex or EP log as command-line argument or as input" fullword ascii
        $x2 = "print \"Gimme hex: \";" fullword ascii
        $x3 = "if ($line =~ /Reg_Dword:  (\\d\\d:\\d\\d:\\d\\d.\\d+ \\d+ - )?(\\S*)/) {" fullword ascii

        $s1 = "if ($_ =~ /InstallDate/) {" fullword ascii
        $s2 = "if (not($cmdInput)) {" fullword ascii
        $s3 = "print \"$hex in decimal=$dec\\n\\n\";" fullword ascii
    condition:
        filesize < 2KB and ( 1 of ($x*) or 3 of them )
}

rule EQGRP_teflondoor {
    meta:
        id = "3A6Aw4nFvm14gbQ4s0dFOd"
        fingerprint = "v1_sha256_38be3cfa638509d539bf4ada3b5c7e44e01ee4cfb74a53a76cd2f4287c5a56f5"
        version = "1.0"
        score = 75
        date = "2016-08-15"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects tool from EQGRP toolset - file teflondoor.exe"
        category = "INFO"
        reference = "Research"

    strings:
        $x1 = "%s: abort.  Code is %d.  Message is '%s'" fullword ascii
        $x2 = "%s: %li b (%li%%)" fullword ascii

        $s1 = "no winsock" fullword ascii
        $s2 = "%s: %s file '%s'" fullword ascii
        $s3 = "peer: connect" fullword ascii
        $s4 = "read: write" fullword ascii
        $s5 = "%s: done!" fullword ascii
        $s6 = "%s: %li b" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 30KB and 1 of ($x*) and 3 of them
}

rule EQGRP_durablenapkin_solaris_2_0_1 {
    meta:
        id = "1SVqcbaBOeHUfg2uLMf7lH"
        fingerprint = "v1_sha256_113f9451d6792511baa168957c643de02f37826b32944ef882f49b68496ec596"
        version = "1.0"
        score = 75
        date = "2016-08-15"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects tool from EQGRP toolset - file durablenapkin.solaris.2.0.1.1"
        category = "INFO"
        reference = "Research"

    strings:
        $s1 = "recv_ack: %s: Service not supplied by provider" fullword ascii
        $s2 = "send_request: putmsg \"%s\": %s" fullword ascii
        $s3 = "port undefined" fullword ascii
        $s4 = "recv_ack: %s getmsg: %s" fullword ascii
        $s5 = ">> %d -- %d" fullword ascii
    condition:
        ( uint16(0) == 0x457f and filesize < 40KB and 2 of them )
}

rule EQGRP_teflonhandle {
    meta:
        id = "4KbFSsBAp6jEutDSgB2SDK"
        fingerprint = "v1_sha256_7dfa713b763c983219f008405e1ebf3dfe386672f2d4e5fb54b2b362023ae08a"
        version = "1.0"
        score = 75
        date = "2016-08-15"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects tool from EQGRP toolset - file teflonhandle.exe"
        category = "INFO"
        reference = "Research"

    strings:
        $s1 = "%s [infile] [outfile] /k 0x[%i character hex key] </g>" fullword ascii
        $s2 = "File %s already exists.  Overwrite? (y/n) " fullword ascii
        $s3 = "Random Key : 0x" fullword ascii
        $s4 = "done (%i bytes written)." fullword ascii
        $s5 = "%s --> %s..." fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 20KB and 2 of them
}

rule EQGRP_false {
    meta:
        id = "3OFzHHTbufdPm8un2hGk1z"
        fingerprint = "v1_sha256_a1938bc7a5a7a1bb382c2bab976013a1adedc045e0312daabe1bdcdd65d0c606"
        version = "1.0"
        score = 75
        date = "2016-08-15"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects tool from EQGRP toolset - file false.exe"
        category = "INFO"
        reference = "Research"

    strings:
        $s1 = { 00 25 64 2E 0A 00 00 00 00 25 64 2E 0A 00 00 00
            00 25 6C 75 2E 25 6C 75 2E 25 6C 75 2E 25 6C 75
            00 25 64 2E 0A 00 00 00 00 25 64 2E 0A 00 00 00
            00 25 64 2E 0A 00 00 00 00 25 64 2E 0A 00 00 00
            00 25 32 2E 32 58 20 00 00 0A 00 00 00 25 64 20
            2D 20 25 64 20 25 64 0A 00 25 64 0A 00 25 64 2E
            0A 00 00 00 00 25 64 2E 0A 00 00 00 00 25 64 2E
            0A 00 00 00 00 25 64 20 2D 20 25 64 0A 00 00 00
            00 25 64 20 2D 20 25 64 }
    condition:
        uint16(0) == 0x5a4d and filesize < 50KB and $s1
}

rule EQGRP_bc_genpkt {
    meta:
        id = "4wK3d3XeNwYPZbunUIjSax"
        fingerprint = "v1_sha256_b3d38e290e1506540cb86824b00bd0ea7b59ec5664d44c2576e80ea387bdba19"
        version = "1.0"
        score = 75
        date = "2016-08-15"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects tool from EQGRP toolset - file bc-genpkt"
        category = "INFO"
        reference = "Research"

    strings:
        $x1 = "load auxiliary object=%s requested by file=%s" fullword ascii
        $x2 = "size of new packet, should be %d <= size <= %d bytes" fullword ascii
        $x3 = "verbosity - show lengths, packet dumps, etc" fullword ascii

        $s1 = "%s: error while loading shared libraries: %s%s%s%s%s" fullword ascii
        $s2 = "cannot dynamically load executable" fullword ascii
        $s3 = "binding file %s to %s: %s symbol `%s' [%s]" fullword ascii
        $s4 = "randomize the initiator cookie" fullword ascii
    condition:
        uint16(0) == 0x457f and filesize < 1000KB and ( 1 of ($s*) and 3 of them )
}

rule EQGRP_dn_1_0_2_1 {
    meta:
        id = "pDDdA6QdIJm7F0GVzGbeu"
        fingerprint = "v1_sha256_9b6420401419b280f01f7fc73412386a19e94a57e589a043b231b6a721585c99"
        version = "1.0"
        score = 75
        date = "2016-08-15"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects tool from EQGRP toolset - file dn.1.0.2.1.linux"
        category = "INFO"
        reference = "Research"

    strings:
        $s1 = "Valid commands are: SMAC, DMAC, INT, PACK, DONE, GO" fullword ascii
        $s2 = "invalid format suggest DMAC=00:00:00:00:00:00" fullword ascii
        $s3 = "SMAC=%02x:%02x:%02x:%02x:%02x:%02x" fullword ascii
        $s4 = "Not everything is set yet" fullword ascii
    condition:
        ( uint16(0) == 0x457f and filesize < 30KB and 2 of them )
}

rule EQGRP_morel {
    meta:
        id = "50zHYw52KrlrnrYPgGYQhB"
        fingerprint = "v1_sha256_463d628bb19e27e94dcccc4c7d435d86111d51aa9f77c5ca1a199d9aaa9017ba"
        version = "1.0"
        score = 75
        date = "2016-08-15"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects tool from EQGRP toolset - file morel.exe"
        category = "INFO"
        reference = "Research"
        hash1 = "a9152e67f507c9a179bb8478b58e5c71c444a5a39ae3082e04820a0613cd6d9f"

    strings:
        $s1 = "%d - %d, %d" fullword ascii
        $s2 = "%d - %lu.%lu %d.%lu" fullword ascii
        $s3 = "%d - %d %d" fullword ascii
    condition:
        ( uint16(0) == 0x5a4d and filesize < 60KB and all of them )
}

rule EQGRP_bc_parser {
    meta:
        id = "2f7AP3yDoe3p7pgixSf0JH"
        fingerprint = "v1_sha256_e8911acc1173e1149fd11dd795b72ba26bc654cbc7f9d95053ce420663fcafe9"
        version = "1.0"
        score = 75
        date = "2016-08-15"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects tool from EQGRP toolset - file bc-parser"
        category = "INFO"
        reference = "Research"
        hash1 = "879f2f1ae5d18a3a5310aeeafec22484607649644e5ecb7d8a72f0877ac19cee"

    strings:
        $s1 = "*** Target may be susceptible to FALSEMOREL      ***" fullword ascii
        $s2 = "*** Target is susceptible to FALSEMOREL          ***" fullword ascii
    condition:
        uint16(0) == 0x457f and 1 of them
}

rule EQGRP_1212 {
    meta:
        id = "72ULZoq8m9ZJV2BJz8Rg3b"
        fingerprint = "v1_sha256_1be7ed8fdfaecc6e55c4d1e75cf841f4620df3d2abe6aed2761aed20c42f70bd"
        version = "1.0"
        score = 75
        date = "2016-08-15"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects tool from EQGRP toolset - file 1212.pl"
        category = "INFO"
        reference = "Research"

    strings:
        $s1 = "if (!(($srcip,$dstip,$srcport,$dstport) = ($line=~/^([a-f0-9]{8})([a-f0-9]{8})([a-f0-9]{4})([a-f0-9]{4})$/)))" fullword ascii
        $s2 = "$ans=\"$srcip:$srcport -> $dstip:$dstport\";" fullword ascii
        $s3 = "return \"ERROR:$line is not a valid port\";" fullword ascii
        $s4 = "$dstport=hextoPort($dstport);" fullword ascii
        $s5 = "sub hextoPort" fullword ascii
        $s6 = "$byte_table{\"$chars[$sixteens]$chars[$ones]\"}=$i;" fullword ascii
    condition:
        filesize < 6KB and 4 of them
}

rule EQGRP_1212_dehex {
    meta:
        id = "608JfyfdEDwTriPmBfxqdr"
        fingerprint = "v1_sha256_74d1b0e820696cd5507996996bead50d283e83095bc7288a6e8e484738b6348b"
        version = "1.0"
        score = 75
        date = "2016-08-15"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects tool from EQGRP toolset - from files 1212.pl, dehex.pl"
        category = "INFO"
        reference = "Research"

    strings:
        $s1 = "return \"ERROR:$line is not a valid address\";" fullword ascii
        $s2 = "print \"ERROR: the filename or hex representation needs to be one argument try using \\\"'s\\n\";" fullword ascii
        $s3 = "push(@octets,$byte_table{$tempi});" fullword ascii
        $s4 = "$byte_table{\"$chars[$sixteens]$chars[$ones]\"}=$i;" fullword ascii
        $s5 = "print hextoIP($ARGV[0]);" fullword ascii
    condition:
        ( uint16(0) == 0x2123 and filesize < 6KB and ( 5 of ($s*) ) ) or ( all of them )
}

/*
    Yara Rule Set
    Author: Florian Roth
    Date: 2016-08-16
    Identifier: EQGRP
*/

/* Rule Set ----------------------------------------------------------------- */

rule install_get_persistent_filenames {
    meta:
        id = "4lRC3z7fP5eblIMVZte08n"
        fingerprint = "v1_sha256_be07e3e3e96dd4676a76b32eb8fc47b2ab1f66ebbd6c2a3f1c88fc224f9f39ef"
        version = "1.0"
        date = "2016-08-16"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "EQGRP Toolset Firewall - file install_get_persistent_filenames"
        category = "INFO"
        reference = "Research"
        hash1 = "4a50ec4bf42087e932e9e67e0ea4c09e52a475d351981bb4c9851fda02b35291"

    strings:
        $s1 = "Generates the persistence file name and prints it out." fullword ascii
    condition:
        ( uint16(0) == 0x457f and all of them )
}

rule EQGRP_create_dns_injection {
    meta:
        id = "1mZrVMeZC3W0JvKkuN41ca"
        fingerprint = "v1_sha256_4701549d61cf671352388ca372cb5dec78aa863baca65f324bb586ef46a50da7"
        version = "1.0"
        date = "2016-08-16"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "EQGRP Toolset Firewall - file create_dns_injection.py"
        category = "INFO"
        reference = "Research"
        hash1 = "488f3cc21db0688d09e13eb85a197a1d37902612c3e302132c84e07bc42b1c32"

    strings:
        $s1 = "Name:   A hostname: 'host.network.com', a decimal numeric offset within" fullword ascii
        $s2 = "-a www.badguy.net,CNAME,1800,host.badguy.net \\\\" fullword ascii
    condition:
        1 of them
}

rule EQGRP_screamingplow {
    meta:
        id = "1Vj9iOVBp9LokJ6TTmbjE0"
        fingerprint = "v1_sha256_429ff81b6079785cc45d81b5ebf8bccd49f30484ca692017b0b66484463606d4"
        version = "1.0"
        date = "2016-08-16"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "EQGRP Toolset Firewall - file screamingplow.sh"
        category = "INFO"
        reference = "Research"
        hash1 = "c7f4104c4607a03a1d27c832e1ebfc6ab252a27a1709015b5f1617b534f0090a"

    strings:
        $s1 = "What is the name of your PBD:" fullword ascii
        $s2 = "You are now ready for a ScreamPlow" fullword ascii
    condition:
        1 of them
}

rule EQGRP_MixText {
    meta:
        id = "6y1UUz5uuRJssRGpqc3F6V"
        fingerprint = "v1_sha256_cae2437124ad6e69b04a1338b651e33c7358b7fedd0613f3fa1025cf980e14ab"
        version = "1.0"
        date = "2016-08-16"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "EQGRP Toolset Firewall - file MixText.py"
        category = "INFO"
        reference = "Research"
        hash1 = "e4d24e30e6cc3a0aa0032dbbd2b68c60bac216bef524eaf56296430aa05b3795"

    strings:
        $s1 = "BinStore enabled implants." fullword ascii
    condition:
        1 of them
}

rule EQGRP_tunnel_state_reader {
    meta:
        id = "2k9Xr2yPvBfEi7qYMfvk6K"
        fingerprint = "v1_sha256_d0653650aad10e7ff69b7ef1e61fac64310c63cc68c6d924655f082925e4fd04"
        version = "1.0"
        date = "2016-08-16"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "EQGRP Toolset Firewall - file tunnel_state_reader"
        category = "INFO"
        reference = "Research"
        hash1 = "49d48ca1ec741f462fde80da68b64dfa5090855647520d29e345ef563113616c"

    strings:
        $s1 = "Active connections will be maintained for this tunnel. Timeout:" fullword ascii
        $s5 = "%s: compatible with BLATSTING version 1.2" fullword ascii
    condition:
        1 of them
}

rule EQGRP_payload {
    meta:
        id = "3l6TYwGKvhLuu4hXk2NwdC"
        fingerprint = "v1_sha256_22e2a4809f6646437ab0824238fec791f3760ac305f9c818089797b011425b3d"
        version = "1.0"
        date = "2016-08-16"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "EQGRP Toolset Firewall - file payload.py"
        category = "INFO"
        reference = "Research"
        hash1 = "21bed6d699b1fbde74cbcec93575c9694d5bea832cd191f59eb3e4140e5c5e07"

    strings:
        $s1 = "can't find target version module!" fullword ascii
        $s2 = "class Payload:" fullword ascii
    condition:
        all of them
}

rule EQGRP_eligiblecandidate {
    meta:
        id = "6ClnAQbvcRJIMrlwOCC5GG"
        fingerprint = "v1_sha256_e7e1b206f9c51ffe0ab016a93d551a9ede8f87adfc38fe70278be8c2f0fe0696"
        version = "1.0"
        date = "2016-08-16"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "EQGRP Toolset Firewall - file eligiblecandidate.py"
        category = "INFO"
        reference = "Research"
        hash1 = "c4567c00734dedf1c875ecbbd56c1561a1610bedb4621d9c8899acec57353d86"

    strings:
        $o1 = "Connection timed out. Only a problem if the callback was not received." fullword ascii
        $o2 = "Could not reliably detect cookie. Using 'session_id'..." fullword ascii

        $c1 = "def build_exploit_payload(self,cmd=\"/tmp/httpd\"):" fullword ascii
        $c2 = "self.build_exploit_payload(cmd)" fullword ascii
    condition:
        1 of them
}

rule EQGRP_BUSURPER_2211_724 {
    meta:
        id = "4yEL75Me22rXr7l31t0kyb"
        fingerprint = "v1_sha256_439362b32ca8d8c4992956f6cec8336cb1b1415e8b88b3f903b94504417297fb"
        version = "1.0"
        date = "2016-08-16"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "EQGRP Toolset Firewall - file BUSURPER-2211-724.exe"
        category = "INFO"
        reference = "Research"
        hash1 = "d809d6ff23a9eee53d2132d2c13a9ac5d0cb3037c60e229373fc59a4f14bc744"

    strings:
        $s1 = ".got_loader" fullword ascii
        $s2 = "_start_text" fullword ascii
        $s3 = "IMPLANT" fullword ascii
        $s4 = "KEEPGOING" fullword ascii
        $s5 = "upgrade_implant" fullword ascii
    condition:
        all of them
}

rule EQGRP_networkProfiler_orderScans {
    meta:
        id = "2lnnOpExVdSWkbkz0ZOmOX"
        fingerprint = "v1_sha256_0cdf4f3d8f668ce5d5aab652c83cb4d2a9acc3471ff720448d021707b34402ef"
        version = "1.0"
        date = "2016-08-16"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "EQGRP Toolset Firewall - file networkProfiler_orderScans.sh"
        category = "INFO"
        reference = "Research"
        hash1 = "ea986ddee09352f342ac160e805312e3a901e58d2beddf79cd421443ba8c9898"

    strings:
        $x1 = "Unable to save off predefinedScans directory" fullword ascii
        $x2 = "Re-orders the networkProfiler scans so they show up in order in the LP" fullword ascii
    condition:
        1 of them
}

rule EQGRP_epicbanana_2_1_0_1 {
    meta:
        id = "3M3a94m7wAzDhTvRzx4NXF"
        fingerprint = "v1_sha256_be0b180e0dfdda35725ac6d9c35752a0b56bdbdaf985b6932c7d2ff342d4cde3"
        version = "1.0"
        date = "2016-08-16"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "EQGRP Toolset Firewall - file epicbanana_2.1.0.1.py"
        category = "INFO"
        reference = "Research"
        hash1 = "4b13cc183c3aaa8af43ef3721e254b54296c8089a0cd545ee3b867419bb66f61"

    strings:
        $s1 = "failed to create version-specific payload" fullword ascii
        $s2 = "(are you sure you did \"make [version]\" in versions?)" fullword ascii
    condition:
        1 of them
}

rule EQGRP_sniffer_xml2pcap {
    meta:
        id = "5idiIHOmn1qlaJlq4ujQqA"
        fingerprint = "v1_sha256_3c3aa9f42edbca32725f8c02023e3b9644162a001ded099513d12f94d70dd4c8"
        version = "1.0"
        date = "2016-08-16"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "EQGRP Toolset Firewall - file sniffer_xml2pcap"
        category = "INFO"
        reference = "Research"
        hash1 = "f5e5d75cfcd86e5c94b0e6f21bbac886c7e540698b1556d88a83cc58165b8e42"

    strings:
        $x1 = "-s/--srcip <sourceIP>  Use given source IP (if sniffer doesn't collect source IP)" fullword ascii
        $x2 = "convert an XML file generated by the BLATSTING sniffer module into a pcap capture file." fullword ascii
    condition:
        1 of them
}

rule EQGRP_BananaAid {
    meta:
        id = "63FEy99TOKtV4HNPX2azH5"
        fingerprint = "v1_sha256_2ae52529547866dcfe66fffb3f5b37eba89844b7675129c66636ebef01b0f49a"
        version = "1.0"
        date = "2016-08-16"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "EQGRP Toolset Firewall - file BananaAid"
        category = "INFO"
        reference = "Research"
        hash1 = "7a4fb825e63dc612de81bc83313acf5eccaa7285afc05941ac1fef199279519f"

    strings:
        $x1 = "(might have to delete key in ~/.ssh/known_hosts on linux box)" fullword ascii
        $x2 = "scp BGLEE-" ascii
        $x3 = "should be 4bfe94b1 for clean bootloader version 3.0; " fullword ascii
        $x4 = "scp <configured implant> <username>@<IPaddr>:onfig" fullword ascii
    condition:
        1 of them
}

rule EQGRP_bo {
    meta:
        id = "22Plx8bNI3ebSzFPSQD57q"
        fingerprint = "v1_sha256_2683919f1ea1eead79339d6d1283fe2a70859e4e5d595134bdde253bfca1c6e3"
        version = "1.0"
        date = "2016-08-16"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "EQGRP Toolset Firewall - file bo"
        category = "INFO"
        reference = "Research"
        hash1 = "aa8b363073e8ae754b1836c30f440d7619890ded92fb5b97c73294b15d22441d"

    strings:
        $s1 = "ERROR: failed to open %s: %d" fullword ascii
        $s2 = "__libc_start_main@@GLIBC_2.0" fullword ascii
        $s3 = "serial number: %s" fullword ascii
        $s4 = "strerror@@GLIBC_2.0" fullword ascii
        $s5 = "ERROR: mmap failed: %d" fullword ascii
    condition:
        ( uint16(0) == 0x457f and filesize < 20KB and all of them )
}

rule EQGRP_SecondDate_2211 {
    meta:
        id = "1fb1d80Wp9GvrI4i4eyWfN"
        fingerprint = "v1_sha256_f51f4cfb3b1c77f03a3627cccfee72e57731b26b01907cc837f246a8f7677580"
        version = "1.0"
        date = "2016-08-16"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "EQGRP Toolset Firewall - file SecondDate-2211.exe"
        category = "INFO"
        reference = "Research"
        hash1 = "2337d0c81474d03a02c404cada699cf1b86c3c248ea808d4045b86305daa2607"

    strings:
        $s1 = "SD_processControlPacket" fullword ascii
        $s2 = "Encryption_rc4SetKey" fullword ascii
        $s3 = ".got_loader" fullword ascii
        $s4 = "^GET.*(?:/ |\\.(?:htm|asp|php)).*\\r\\n" fullword ascii
    condition:
        ( uint16(0) == 0x457f and filesize < 200KB and all of them )
}

rule EQGRP_config_jp1_UA {
    meta:
        id = "295GP1sWGH4Ib55tLip90n"
        fingerprint = "v1_sha256_8dd504bd00f72b1500375fbe451f5abb055cb2ff440f6ae4314b1e3d64097b83"
        version = "1.0"
        date = "2016-08-16"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "EQGRP Toolset Firewall - file config_jp1_UA.pl"
        category = "INFO"
        reference = "Research"
        hash1 = "2f50b6e9891e4d7fd24cc467e7f5cfe348f56f6248929fec4bbee42a5001ae56"

    strings:
        $x1 = "This program will configure a JETPLOW Userarea file." fullword ascii
        $x2 = "Error running config_implant." fullword ascii
        $x3 = "NOTE:  IT ASSUMES YOU ARE OPERATING IN THE INSTALL/LP/JP DIRECTORY. THIS ASSUMPTION " fullword ascii
        $x4 = "First IP address for beacon destination [127.0.0.1]" fullword ascii
    condition:
        1 of them
}

rule EQGRP_userscript {
    meta:
        id = "7e53gZFnlDHXCnuQ2P4LNr"
        fingerprint = "v1_sha256_718ee434c8ae61e2709df6dd431dbb0a2230085f0132ae82c7ceda4de75248cf"
        version = "1.0"
        date = "2016-08-16"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "EQGRP Toolset Firewall - file userscript.FW"
        category = "INFO"
        reference = "Research"
        hash1 = "5098ff110d1af56115e2c32f332ff6e3973fb7ceccbd317637c9a72a3baa43d7"

    strings:
        $x1 = "Are you sure? Don't forget that NETSCREEN firewalls require BANANALIAR!! " fullword ascii
    condition:
        1 of them
}

rule EQGRP_BBALL_M50FW08_2201 {
    meta:
        id = "1NtYK6ZjxhppMTxWR6yUcH"
        fingerprint = "v1_sha256_a586571aef81596d2bbf8927566d6bcdbdb2f6e394b3207f1117538bfd9de981"
        version = "1.0"
        date = "2016-08-16"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "EQGRP Toolset Firewall - file BBALL_M50FW08-2201.exe"
        category = "INFO"
        reference = "Research"
        hash1 = "80c0b68adb12bf3c15eff9db70a57ab999aad015da99c4417fdfd28156d8d3f7"

    strings:
        $s1 = ".got_loader" fullword ascii
        $s2 = "LOADED" fullword ascii
        $s3 = "pageTable.c" fullword ascii
        $s4 = "_start_text" fullword ascii
        $s5 = "handler_readBIOS" fullword ascii
        $s6 = "KEEPGOING" fullword ascii
    condition:
        ( uint16(0) == 0x457f and filesize < 40KB and 5 of ($s*) )
}

rule EQGRP_BUSURPER_3001_724 {
    meta:
        id = "2FArSmVvxoEu9pur2Hi3la"
        fingerprint = "v1_sha256_531f7039290b386f070378cb4ba49a57b5031fb16b3972b61f4fb904770fc4ac"
        version = "1.0"
        date = "2016-08-16"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "EQGRP Toolset Firewall - file BUSURPER-3001-724.exe"
        category = "INFO"
        reference = "Research"
        hash1 = "6b558a6b8bf3735a869365256f9f2ad2ed75ccaa0eefdc61d6274df4705e978b"

    strings:
        $s1 = "IMPLANT" fullword ascii
        $s2 = "KEEPGOING" fullword ascii
        $s3 = "upgrade_implant" fullword ascii
    condition:
        ( uint16(0) == 0x457f and filesize < 200KB and 2 of them ) or ( all of them )
}

rule EQGRP_workit {
    meta:
        id = "76uNJKKiAuy8mFikMb8QhN"
        fingerprint = "v1_sha256_4532521649c0efa93b34de06812575c650efe18cf1398f95693923637854c5cf"
        version = "1.0"
        date = "2016-08-16"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "EQGRP Toolset Firewall - file workit.py"
        category = "INFO"
        reference = "Research"
        hash1 = "fb533b4d255b4e6072a4fa2e1794e38a165f9aa66033340c2f4f8fd1da155fac"

    strings:
        $s1 = "macdef init > /tmp/.netrc;" fullword ascii
        $s2 = "/usr/bin/wget http://" fullword ascii
        $s3 = "HOME=/tmp ftp" fullword ascii
        $s4 = " >> /tmp/.netrc;" fullword ascii
        $s5 = "/usr/rapidstream/bin/tftp" fullword ascii
        $s6 = "created shell_command:" fullword ascii
        $s7 = "rm -f /tmp/.netrc;" fullword ascii
        $s8 = "echo quit >> /tmp/.netrc;" fullword ascii
        $s9 = "echo binary >> /tmp/.netrc;" fullword ascii
        $s10 = "chmod 600 /tmp/.netrc;" fullword ascii
        $s11 = "created cli_command:" fullword ascii
    condition:
        6 of them
}

rule EQGRP_tinyhttp_setup {
    meta:
        id = "4HAAbLlEll1RJwGohJ9Urb"
        fingerprint = "v1_sha256_0d560206e634f3bfeffe5b7de3edf02f6c76443ffb5c0de37180e63276a19457"
        version = "1.0"
        date = "2016-08-16"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "EQGRP Toolset Firewall - file tinyhttp_setup.sh"
        category = "INFO"
        reference = "Research"
        hash1 = "3d12c83067a9f40f2f5558d3cf3434bbc9a4c3bb9d66d0e3c0b09b9841c766a0"

    strings:
        $x1 = "firefox http://127.0.0.1:8000/$_name" fullword ascii
        $x2 = "What is the name of your implant:" fullword ascii /* it's called conscience */
        $x3 = "killall thttpd" fullword ascii
        $x4 = "copy http://<IP>:80/$_name flash:/$_name" fullword ascii
    condition:
        ( uint16(0) == 0x2123 and filesize < 2KB and 1 of ($x*) ) or ( all of them )
}

rule EQGRP_shellcode {
    meta:
        id = "j7k7xsVjo4egbuKUxsqs2"
        fingerprint = "v1_sha256_69a04db721a0d17720f9db9386d47309f01d1fc31bd5e833cedb9e1c2eb573ae"
        version = "1.0"
        date = "2016-08-16"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "EQGRP Toolset Firewall - file shellcode.py"
        category = "INFO"
        reference = "Research"
        hash1 = "ac9decb971dd44127a6ca0d35ac153951f0735bb4df422733046098eca8f8b7f"

    strings:
        $s1 = "execute_post = '\\xe8\\x00\\x00\\x00\\x00\\x5d\\xbe\\xef\\xbe\\xad\\xde\\x89\\xf7\\x89\\xec\\x29\\xf4\\xb8\\x03\\x00\\x00\\x00" ascii
        $s2 = "tiny_exec = '\\x7f\\x45\\x4c\\x46\\x01\\x01\\x01\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x02\\x00\\x03\\x00\\x01\\x00\\x00" ascii
        $s3 = "auth_id = '\\x31\\xc0\\xb0\\x03\\x31\\xdb\\x89\\xe1\\x31\\xd2\\xb6\\xf0\\xb2\\x0d\\xcd\\x80\\x3d\\xff\\xff\\xff\\xff\\x75\\x07" ascii

        $c1 = { e8 00 00 00 00 5d be ef be ad de 89 f7 89 ec 29 f4 b8 03 00 00 00 }
        /* $c2 = { 7f 45 4c 46 01 01 01 00 00 00 00 00 00 00 00 00 02 00 03 00 01 00 00 }  too many fps */
        $c3 = { 31 c0 b0 03 31 db 89 e1 31 d2 b6 f0 b2 0d cd 80 3d ff ff ff ff 75 07 }
    condition:
        1 of them
}

rule EQGRP_EPBA {
    meta:
        id = "635lrA3ouPJsjkY413B7n2"
        fingerprint = "v1_sha256_c483efdcfbb0dd8602a552b519d3aa52fca12549c0ec1660d813a2a1da66c3a6"
        version = "1.0"
        date = "2016-08-16"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "EQGRP Toolset Firewall - file EPBA.script"
        category = "INFO"
        reference = "Research"
        hash1 = "53e1af1b410ace0934c152b5df717d8a5a8f5fdd8b9eb329a44d94c39b066ff7"

    strings:
        $x1 = "./epicbanana_2.0.0.1.py -t 127.0.0.1 --proto=ssh --username=cisco --password=cisco --target_vers=asa804 --mem=NA -p 22 " fullword ascii
        $x2 = "-t TARGET_IP, --target_ip=TARGET_IP -- Either 127.0.0.1 or Win Ops IP" fullword ascii
        $x3 = "./bride-1100 --lp 127.0.0.1 --implant 127.0.0.1 --sport RHP --dport RHP" fullword ascii
        $x4 = "--target_vers=TARGET_VERS    target Pix version (pix712, asa804) (REQUIRED)" fullword ascii
        $x5 = "-p DEST_PORT, --dest_port=DEST_PORT defaults: telnet=23, ssh=22 (optional) - Change to LOCAL redirect port" fullword ascii
        $x6 = "this operation is complete, BananaGlee will" fullword ascii
        $x7 = "cd /current/bin/FW/BGXXXX/Install/LP" fullword ascii
    condition:
        ( uint16(0) == 0x2023 and filesize < 7KB and 1 of ($x*) ) or ( 3 of them )
}

rule EQGRP_BPIE {
    meta:
        id = "7RE4U0ZRVSIUaAgPpv6Je"
        fingerprint = "v1_sha256_ab13dde40015fba80f55bc9d1b82c94ec2421e9ea263b70ad8ec0a7a74c43c9a"
        version = "1.0"
        date = "2016-08-16"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "EQGRP Toolset Firewall - file BPIE-2201.exe"
        category = "INFO"
        reference = "Research"
        hash1 = "697e80cf2595c85f7c931693946d295994c55da17a400f2c9674014f130b4688"

    strings:
        $s1 = "profProcessPacket" fullword ascii
        $s2 = ".got_loader" fullword ascii
        $s3 = "getTimeSlotCmdHandler" fullword ascii
        $s4 = "getIpIpCmdHandler" fullword ascii
        $s5 = "LOADED" fullword ascii
        $s6 = "profStartScan" fullword ascii
        $s7 = "tmpData.1" fullword ascii
        $s8 = "resetCmdHandler" fullword ascii
    condition:
        ( uint16(0) == 0x457f and filesize < 70KB and 6 of ($s*) )
}

rule EQGRP_jetplow_SH {
    meta:
        id = "4PYdlv34IwBBQmwjrnCJJU"
        fingerprint = "v1_sha256_8ae203527c4e41ae169c63521bb08d5199c43dfd1028574a1791ab1f8f198105"
        version = "1.0"
        date = "2016-08-16"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "EQGRP Toolset Firewall - file jetplow.sh"
        category = "INFO"
        reference = "Research"
        hash1 = "ee266f84a1a4ccf2e789a73b0a11242223ed6eba6868875b5922aea931a2199c"

    strings:
        $s1 = "cd /current/bin/FW/BANANAGLEE/$bgver/Install/LP/jetplow" fullword ascii
        $s2 = "***** Please place your UA in /current/bin/FW/OPS *****" fullword ascii
        $s3 = "ln -s ../jp/orig_code.bin orig_code_pixGen.bin" fullword ascii
        $s4 = "*****             Welcome to JetPlow              *****" fullword ascii
    condition:
        1 of them
}

rule EQGRP_BBANJO {
    meta:
        id = "489LvnUhCSnWWX7HV063KD"
        fingerprint = "v1_sha256_8ee2e817732674bf7ff5f396271a2a90da8f401d7ea0f0a3f51c21712adb3ea4"
        version = "1.0"
        date = "2016-08-16"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "EQGRP Toolset Firewall - file BBANJO-3011.exe"
        category = "INFO"
        reference = "Research"
        hash1 = "f09c2f90464781a08436321f6549d350ecef3d92b4f25b95518760f5d4c9b2c3"

    strings:
        $s1 = "get_lsl_interfaces" fullword ascii
        $s2 = "encryptFC4Payload" fullword ascii
        $s3 = ".got_loader" fullword ascii
        $s4 = "beacon_getconfig" fullword ascii
        $s5 = "LOADED" fullword ascii
        $s6 = "FormBeaconPacket" fullword ascii
        $s7 = "beacon_reconfigure" fullword ascii
    condition:
        ( uint16(0) == 0x457f and filesize < 50KB and all of them )
}

rule EQGRP_BPATROL_2201 {
    meta:
        id = "5NFScUG57E9RQBGm2Imyc4"
        fingerprint = "v1_sha256_a2e9aa4627924c99dd3a342174855df3f0d545a67fd2293ca5601eeae70ae010"
        version = "1.0"
        date = "2016-08-16"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "EQGRP Toolset Firewall - file BPATROL-2201.exe"
        category = "INFO"
        reference = "Research"
        hash1 = "aa892750b893033eed2fedb2f4d872f79421174eb217f0c34a933c424ae66395"

    strings:
        $s1 = "dumpConfig" fullword ascii
        $s2 = "getstatusHandler" fullword ascii
        $s3 = ".got_loader" fullword ascii
        $s4 = "xtractdata" fullword ascii
        $s5 = "KEEPGOING" fullword ascii
    condition:
        ( uint16(0) == 0x457f and filesize < 40KB and all of them )
}

rule EQGRP_extrabacon {
    meta:
        id = "4h0vlqsbV0mBg7qVctkSVE"
        fingerprint = "v1_sha256_1a010d5e6324715f8e1bf29e957c365fabd2986fece53aaea23bba8ee59bd808"
        version = "1.0"
        date = "2016-08-16"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "EQGRP Toolset Firewall - file extrabacon_1.1.0.1.py"
        category = "INFO"
        reference = "Research"
        hash1 = "59d60835fe200515ece36a6e87e642ee8059a40cb04ba5f4b9cce7374a3e7735"

    strings:
        $x1 = "To disable password checking on target:" fullword ascii
        $x2 = "[-] target is running" fullword ascii
        $x3 = "[-] problem importing version-specific shellcode from" fullword ascii
        $x4 = "[+] importing version-specific shellcode" fullword ascii
        $s5 = "[-] unsupported target version, abort" fullword ascii
    condition:
        1 of them
}

rule EQGRP_sploit_py {
    meta:
        id = "52ZYZjpBVIF0deJBL4gAxu"
        fingerprint = "v1_sha256_874eaffcbc191951db39ba6c85e8c80b83b0df8d33136b6cdcdefcb28e596474"
        version = "1.0"
        date = "2016-08-16"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "EQGRP Toolset Firewall - file sploit.py"
        category = "INFO"
        reference = "Research"
        hash1 = "0316d70a5bbf068a7fc791e08e816015d04ec98f088a7ff42af8b9e769b8d1f6"

    strings:
        $x1 = "the --spoof option requires 3 or 4 fields as follows redir_ip" ascii
        $x2 = "[-] timeout waiting for response - target may have crashed" fullword ascii
        $x3 = "[-] no response from health check - target may have crashed" fullword ascii
    condition:
        1 of them
}

rule EQGRP_uninstallPBD {
    meta:
        id = "1GrEGEkw0OBtnhu3JQ23ph"
        fingerprint = "v1_sha256_634625e8d813166b4262fd3cc8b3406912a0177fd5f40f8f1ce8e81382dbfc07"
        version = "1.0"
        date = "2016-08-16"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "EQGRP Toolset Firewall - file uninstallPBD.bat"
        category = "INFO"
        reference = "Research"
        hash1 = "692fdb449f10057a114cf2963000f52ce118d9a40682194838006c66af159bd0"

    strings:
        $s1 = "memset 00e9a05c 4 38845b88" fullword ascii
        $s2 = "_hidecmd" fullword ascii
        $s3 = "memset 013abd04 1 0d" fullword ascii
    condition:
        all of them
}

rule EQGRP_BICECREAM {
    meta:
        id = "74BiuegPmU492RztqlS8bY"
        fingerprint = "v1_sha256_adaa6b7d4bf9e6f95fbae781382e72afc07993582473cbee7139a93df0fe3283"
        version = "1.0"
        date = "2016-08-16"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "EQGRP Toolset Firewall - file BICECREAM-2140"
        category = "INFO"
        reference = "Research"
        hash1 = "4842076af9ba49e6dfae21cf39847b4172c06a0bd3d2f1ca6f30622e14b77210"

    strings:
        $s1 = "Could not connect to target device: %s:%d. Please check IP address." fullword ascii
        $s2 = "command data size is invalid for an exec cmd" fullword ascii
        $s3 = "A script was specified but target is not a PPC405-based NetScreen (NS5XT, NS25, and NS50). Executing scripts is supported but ma" ascii
        $s4 = "Execute 0x%08x with args (%08x, %08x, %08x, %08x): [y/n]" fullword ascii
        $s5 = "Execute 0x%08x with args (%08x, %08x, %08x): [y/n]" fullword ascii
        $s6 = "[%d] Execute code." fullword ascii
        $s7 = "Execute 0x%08x with args (%08x): [y/n]" fullword ascii
        $s8 = "dump_value_LHASH_DOALL_ARG" fullword ascii
        $s9 = "Eggcode is complete. Pass execution to it? [y/n]" fullword ascii
    condition:
        ( uint16(0) == 0x457f and filesize < 5000KB and 2 of them ) or ( 5 of them )
}

rule EQGRP_create_http_injection {
    meta:
        id = "3uGztaaKSSPiB6mcoBtYxc"
        fingerprint = "v1_sha256_3a2ee46c6fec1b7a501e8c0e2963d4873ede89d192d0f4701d051f782e8ece99"
        version = "1.0"
        date = "2016-08-16"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "EQGRP Toolset Firewall - file create_http_injection.py"
        category = "INFO"
        reference = "Research"
        hash1 = "de52f5621b4f3896d4bd1fb93ee8be827e71a2b189a9f8552b68baed062a992d"

    strings:
        $x1 = "required by SECONDDATE" fullword ascii

        $s1 = "help='Output file name (optional). By default the resulting data is written to stdout.')" fullword ascii
        $s2 = "data = '<html><body onload=\"location.reload(true)\"><iframe src=\"%s\" height=\"1\" width=\"1\" scrolling=\"no\" frameborder=\"" ascii
        $s3 = "version='%prog 1.0'," fullword ascii
        $s4 = "usage='%prog [ ... options ... ] url'," fullword ascii
    condition:
        ( uint16(0) == 0x2123 and filesize < 3KB and ( $x1 or 2 of them ) ) or ( all of them )
}

rule EQGRP_BFLEA_2201 {
    meta:
        id = "1fj2ZSMZmCZPAmb6htKA40"
        fingerprint = "v1_sha256_d0fd4d0ffe98856abed685c4b9ff770daba22aa16bd860440874fd94df2d54ea"
        version = "1.0"
        date = "2016-08-16"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "EQGRP Toolset Firewall - file BFLEA-2201.exe"
        category = "INFO"
        reference = "Research"
        hash1 = "15e8c743770e44314496c5f27b6297c5d7a4af09404c4aa507757e0cc8edc79e"

    strings:
        $s1 = ".got_loader" fullword ascii
        $s2 = "LOADED" fullword ascii
        $s3 = "readFlashHandler" fullword ascii
        $s4 = "KEEPGOING" fullword ascii
        $s5 = "flashRtnsPix6x.c" fullword ascii
        $s6 = "fix_ip_cksum_incr" fullword ascii
        $s7 = "writeFlashHandler" fullword ascii
    condition:
        ( uint16(0) == 0x457f and filesize < 30KB and 5 of them ) or ( all of them )
}

rule EQGRP_BpfCreator_RHEL4 {
    meta:
        id = "2UpaPXETqsIq0JmY5PDpR6"
        fingerprint = "v1_sha256_8586425b13355170137d66fe8d52ed98982d7c5699b26a8c0132f107b4af43d8"
        version = "1.0"
        date = "2016-08-16"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "EQGRP Toolset Firewall - file BpfCreator-RHEL4"
        category = "INFO"
        reference = "Research"
        hash1 = "bd7303393409623cabf0fcf2127a0b81fae52fe40a0d2b8db0f9f092902bbd92"

    strings:
        $s1 = "usage %s \"<tcpdump pcap string>\" <outfile>" fullword ascii
        $s2 = "error reading dump file: %s" fullword ascii
        $s3 = "truncated dump file; tried to read %u captured bytes, only got %lu" fullword ascii
        $s4 = "%s: link-layer type %d isn't supported in savefiles" fullword ascii
        $s5 = "DLT %d is not one of the DLTs supported by this device" fullword ascii
    condition:
        ( uint16(0) == 0x457f and filesize < 2000KB and all of them )
}

rule EQGRP_StoreFc {
    meta:
        id = "2orJZqOGzZn6uozAxPmAny"
        fingerprint = "v1_sha256_f07c3ef83808852f70fb5cbc4436d531675344ab74f83888cd70d987c3544cce"
        version = "1.0"
        date = "2016-08-16"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "EQGRP Toolset Firewall - file StoreFc.py"
        category = "INFO"
        reference = "Research"
        hash1 = "f155cce4eecff8598243a721389046ae2b6ca8ba6cb7b4ac00fd724601a56108"

    strings:
        $x1 = "Usage: StoreFc.py --configFile=<path to xml file> --implantFile=<path to BinStore implant> [--outputFile=<file to write the conf" ascii
        $x2 = "raise Exception, \"Must supply both a config file and implant file.\"" fullword ascii
        $x3 = "This is wrapper for Store.py that FELONYCROWBAR will use. This" fullword ascii
    condition:
        1 of them
}

rule EQGRP_hexdump {
    meta:
        id = "2f2ROiC5qnYRHf9YqTNg2"
        fingerprint = "v1_sha256_ed36aa5a69296088bdd1db42e6561377294b7bd99c30104b9d4a618d899d7e9a"
        version = "1.0"
        date = "2016-08-16"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "EQGRP Toolset Firewall - file hexdump.py"
        category = "INFO"
        reference = "Research"
        hash1 = "95a9a6a8de60d3215c1c9f82d2d8b2640b42f5cabdc8b50bd1f4be2ea9d7575a"

    strings:
        $s1 = "def hexdump(x,lead=\"[+] \",out=sys.stdout):" fullword ascii
        $s2 = "print >>out, \"%s%04x  \" % (lead,i)," fullword ascii
        $s3 = "print >>out, \"%02X\" % ord(x[i+j])," fullword ascii
        $s4 = "print >>out, sane(x[i:i+16])" fullword ascii
    condition:
        ( uint16(0) == 0x2123 and filesize < 1KB and 2 of ($s*) ) or ( all of them )
}

rule EQGRP_BBALL {
    meta:
        id = "23tv6oDI06x2YVhOpMI2U2"
        fingerprint = "v1_sha256_b02d17a13725b5215c89590abf77f960e79f9fd155c9ea4e9eb903710a7a375e"
        version = "1.0"
        date = "2016-08-16"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "EQGRP Toolset Firewall - file BBALL_E28F6-2201.exe"
        category = "INFO"
        reference = "Research"
        hash1 = "498fc9f20b938b8111adfa3ca215325f265a08092eefd5300c4168876deb7bf6"

    strings:
        $s1 = "Components/Modules/BiosModule/Implant/E28F6/../e28f640j3_asm.S" fullword ascii
        $s2 = ".got_loader" fullword ascii
        $s3 = "handler_readBIOS" fullword ascii
        $s4 = "cmosReadByte" fullword ascii
        $s5 = "KEEPGOING" fullword ascii
        $s6 = "checksumAreaConfirmed.0" fullword ascii
        $s7 = "writeSpeedPlow.c" fullword ascii
    condition:
        ( uint16(0) == 0x457f and filesize < 40KB and 4 of ($s*) ) or ( all of them )
}

/* Super Rules ------------------------------------------------------------- */

rule EQGRP_BARPUNCH_BPICKER {
    meta:
        id = "531V0Htdn0gIjTY9tdWvxZ"
        fingerprint = "v1_sha256_f5d0cc881bedad736a90109933da8dbd32c4435aa255676c68ae3541bbb61e74"
        version = "1.0"
        date = "2016-08-16"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "EQGRP Toolset Firewall - from files BARPUNCH-3110, BPICKER-3100"
        category = "INFO"
        reference = "Research"
        super_rule = 1
        hash1 = "830538fe8c981ca386c6c7d55635ac61161b23e6e25d96280ac2fc638c2d82cc"
        hash2 = "d859ce034751cac960825268a157ced7c7001d553b03aec54e6794ff66185e6f"

    strings:
        $x1 = "--cmd %x --idkey %s --sport %i --dport %i --lp %s --implant %s --bsize %hu --logdir %s --lptimeout %u" fullword ascii
        $x2 = "%s -c <cmdtype> -l <lp> -i <implant> -k <ikey> -s <port> -d <port> [operation] [options]" fullword ascii
        $x3 = "* [%lu] 0x%x is marked as stateless (the module will be persisted without its configuration)" fullword ascii
        $x4 = "%s version %s already has persistence installed. If you want to uninstall," fullword ascii
        $x5 = "The active module(s) on the target are not meant to be persisted" fullword ascii
    condition:
        ( uint16(0) == 0x457f and filesize < 6000KB and 1 of them ) or ( 3 of them )
}

rule EQGRP_Implants_Gen6 {
    meta:
        id = "Kk0QLd8lsWZC0P7hFtOJG"
        fingerprint = "v1_sha256_9f0aa1994199c8cef543b7602b574726171dd96df159a0c496db0c60c339c4d0"
        version = "1.0"
        date = "2016-08-16"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "EQGRP Toolset Firewall - from files BananaUsurper-2120, BLIAR-2110, BLIQUER-2230, BLIQUER-3030, BLIQUER-3120, BPICKER-3100, writeJetPlow-2130"
        category = "INFO"
        reference = "Research"
        super_rule = 1
        hash1 = "3366b4bbf265716869a487203a8ac39867920880990493dd4dd8385e42b0c119"
        hash2 = "05031898f3d52a5e05de119868c0ec7caad3c9f3e9780e12f6f28b02941895a4"
        hash3 = "d9756e3ba272cd4502d88f4520747e9e69d241dee6561f30423840123c1a7939"
        hash4 = "8e4a76c4b50350b67cabbb2fed47d781ee52d8d21121647b0c0356498aeda2a2"
        hash5 = "6059bec5cf297266079d52dbb29ab9b9e0b35ce43f718022b5b5f760c1976ec3"
        hash6 = "d859ce034751cac960825268a157ced7c7001d553b03aec54e6794ff66185e6f"
        hash7 = "464b4c01f93f31500d2d770360d23bdc37e5ad4885e274a629ea86b2accb7a5c"

    strings:
        $s1 = "LP.c:pixSecurity - Improper number of bytes read in Security/Interface Information" fullword ascii
        $s2 = "LP.c:pixSecurity - Not in Session" fullword ascii
        $s3 = "getModInterface__preloadedModules" fullword ascii
        $s4 = "showCommands" fullword ascii
        $s5 = "readModuleInterface" fullword ascii
        $s6 = "Wrapping_Not_Necessary_Or_Wrapping_Ok" fullword ascii
        $s7 = "Get_CMD_List" fullword ascii
        $s8 = "LP_Listen2" fullword ascii
        $s9 = "killCmdList" fullword ascii
    condition:
        ( uint16(0) == 0x457f and filesize < 6000KB and all of them )
}

rule EQGRP_Implants_Gen5 {
    meta:
        id = "7dbUMCIWEGRxDErFWD87xH"
        fingerprint = "v1_sha256_d4bbd9dbde4ca1da80d49157363ade3ec47d55828529ec7e1a46b64d07c991f0"
        version = "1.0"
        date = "2016-08-16"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "EQGRP Toolset Firewall - from files BananaUsurper-2120, BARPUNCH-3110, BLIAR-2110, BLIQUER-2230, BLIQUER-3030, BLIQUER-3120, BPICKER-3100, writeJetPlow-2130"
        category = "INFO"
        reference = "Research"
        super_rule = 1
        hash1 = "3366b4bbf265716869a487203a8ac39867920880990493dd4dd8385e42b0c119"
        hash2 = "830538fe8c981ca386c6c7d55635ac61161b23e6e25d96280ac2fc638c2d82cc"
        hash3 = "05031898f3d52a5e05de119868c0ec7caad3c9f3e9780e12f6f28b02941895a4"
        hash4 = "d9756e3ba272cd4502d88f4520747e9e69d241dee6561f30423840123c1a7939"
        hash5 = "8e4a76c4b50350b67cabbb2fed47d781ee52d8d21121647b0c0356498aeda2a2"
        hash6 = "6059bec5cf297266079d52dbb29ab9b9e0b35ce43f718022b5b5f760c1976ec3"
        hash7 = "d859ce034751cac960825268a157ced7c7001d553b03aec54e6794ff66185e6f"
        hash8 = "464b4c01f93f31500d2d770360d23bdc37e5ad4885e274a629ea86b2accb7a5c"

    strings:
        $x1 = "Module and Implant versions do not match.  This module is not compatible with the target implant" fullword ascii

        $s1 = "%s/BF_READ_%08x_%04d%02d%02d_%02d%02d%02d.log" fullword ascii
        $s2 = "%s/BF_%04d%02d%02d.log" fullword ascii
        $s3 = "%s/BF_READ_%08x_%04d%02d%02d_%02d%02d%02d.bin" fullword ascii
    condition:
        ( uint16(0) == 0x457f and 1 of ($x*) ) or ( all of them )
}

rule EQGRP_pandarock {
    meta:
        id = "3RNravtjDT8URdboB2aVtg"
        fingerprint = "v1_sha256_706b10acd40d02268e93fab0b22c6e42358e82728995d2ab5cb9962f9a3e6b27"
        version = "1.0"
        date = "2016-08-16"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "EQGRP Toolset Firewall - from files pandarock_v1.11.1.1.bin, pit"
        category = "INFO"
        reference = "Research"
        super_rule = 1
        hash1 = "1214e282ac7258e616ebd76f912d4b2455d1b415b7216823caa3fc0d09045a5f"
        hash2 = "c8a151df7605cb48feb8be2ab43ec965b561d2b6e2a837d645fdf6a6191ab5fe"

    strings:
        $x1 = "* Not attempting to execute \"%s\" command" fullword ascii
        $x2 = "TERMINATING SCRIPT (command error or \"quit\" encountered)" fullword ascii
        $x3 = "execute code in <file> passing <argX> (HEX)" fullword ascii
        $x4 = "* Use arrow keys to scroll through command history" fullword ascii

        $s1 = "pitCmd_processCmdLine" fullword ascii
        $s2 = "execute all commands in <file>" fullword ascii
        $s3 = "__processShellCmd" fullword ascii
        $s4 = "pitTarget_getDstPort" fullword ascii
        $s5 = "__processSetTargetIp" fullword ascii

        $o1 = "Logging commands and output - ON" fullword ascii
        $o2 = "This command is too dangerous.  If you'd like to run it, contact the development team" fullword ascii
    condition:
        ( uint16(0) == 0x457f and filesize < 3000KB and 1 of ($x*) ) or ( 4 of them ) or 1 of ($o*)
}

rule EQGRP_BananaUsurper_writeJetPlow {
    meta:
        id = "AOeKkkTdG0pLglD5gd3Oe"
        fingerprint = "v1_sha256_101e75800291a7603e03145bff298d7587c9b5f19102e7ba9ed3bf2b544fa5cf"
        version = "1.0"
        date = "2016-08-16"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "EQGRP Toolset Firewall - from files BananaUsurper-2120, writeJetPlow-2130"
        category = "INFO"
        reference = "Research"
        super_rule = 1
        hash1 = "3366b4bbf265716869a487203a8ac39867920880990493dd4dd8385e42b0c119"
        hash2 = "464b4c01f93f31500d2d770360d23bdc37e5ad4885e274a629ea86b2accb7a5c"

    strings:
        $x1 = "Implant Version-Specific Values:" fullword ascii
        $x2 = "This function should not be used with a Netscreen, something has gone horribly wrong" fullword ascii

        $s1 = "createSendRecv: recv'd an error from the target." fullword ascii
        $s2 = "Error: WatchDogTimeout read returned %d instead of 4" fullword ascii
    condition:
        ( uint16(0) == 0x457f and filesize < 2000KB and 1 of ($x*) ) or ( 3 of them )
}

rule EQGRP_Implants_Gen4 {
    meta:
        id = "4BAUNIPozSQMrjFtwxAP6t"
        fingerprint = "v1_sha256_3bfcef33e9a0a1753fd21458ee3173284f98942d30a496c5183c79a7df960208"
        version = "1.0"
        date = "2016-08-16"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "EQGRP Toolset Firewall - from files BLIAR-2110, BLIQUER-2230, BLIQUER-3030, BLIQUER-3120"
        category = "INFO"
        reference = "Research"
        super_rule = 1
        hash1 = "05031898f3d52a5e05de119868c0ec7caad3c9f3e9780e12f6f28b02941895a4"
        hash2 = "d9756e3ba272cd4502d88f4520747e9e69d241dee6561f30423840123c1a7939"
        hash3 = "8e4a76c4b50350b67cabbb2fed47d781ee52d8d21121647b0c0356498aeda2a2"
        hash4 = "6059bec5cf297266079d52dbb29ab9b9e0b35ce43f718022b5b5f760c1976ec3"

    strings:
        $s1 = "Command has not yet been coded" fullword ascii
        $s2 = "Beacon Domain  : www.%s.com" fullword ascii
        $s3 = "This command can only be run on a PIX/ASA" fullword ascii
        $s4 = "Warning! Bad or missing Flash values (in section 2 of .dat file)" fullword ascii
        $s5 = "Printing the interface info and security levels. PIX ONLY." fullword ascii
    condition:
        ( uint16(0) == 0x457f and filesize < 3000KB and 3 of them ) or ( all of them )
}

rule EQGRP_Implants_Gen3 {
    meta:
        id = "2hECJR7X0z0a3MBbrlLPTU"
        fingerprint = "v1_sha256_32d4dd0e35ea480199f5b2032145326c3eef73243783c580605a4de6877df982"
        version = "1.0"
        date = "2016-08-16"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "EQGRP Toolset Firewall - from files BARPUNCH-3110, BLIAR-2110, BLIQUER-2230, BLIQUER-3030, BLIQUER-3120, BPICKER-3100"
        category = "INFO"
        reference = "Research"
        super_rule = 1
        hash1 = "830538fe8c981ca386c6c7d55635ac61161b23e6e25d96280ac2fc638c2d82cc"
        hash2 = "05031898f3d52a5e05de119868c0ec7caad3c9f3e9780e12f6f28b02941895a4"
        hash3 = "d9756e3ba272cd4502d88f4520747e9e69d241dee6561f30423840123c1a7939"
        hash4 = "8e4a76c4b50350b67cabbb2fed47d781ee52d8d21121647b0c0356498aeda2a2"
        hash5 = "6059bec5cf297266079d52dbb29ab9b9e0b35ce43f718022b5b5f760c1976ec3"
        hash6 = "d859ce034751cac960825268a157ced7c7001d553b03aec54e6794ff66185e6f"

    strings:
        $x1 = "incomplete and must be removed manually.)" fullword ascii

        $s1 = "%s: recv'd an error from the target." fullword ascii
        $s2 = "Unable to fetch the address to the get_uptime_secs function for this OS version" fullword ascii
        $s3 = "upload/activate/de-activate/remove/cmd function failed" fullword ascii
    condition:
        ( uint16(0) == 0x457f and filesize < 6000KB and 2 of them ) or ( all of them )
}

rule EQGRP_BLIAR_BLIQUER {
    meta:
        id = "fpLN6aXSFePngcsSlpm0f"
        fingerprint = "v1_sha256_59b7303dba0a79919d79627697a8724337145cd6d7b5c53cda970bf437162865"
        version = "1.0"
        date = "2016-08-16"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "EQGRP Toolset Firewall - from files BLIAR-2110, BLIQUER-2230"
        category = "INFO"
        reference = "Research"
        super_rule = 1
        hash1 = "05031898f3d52a5e05de119868c0ec7caad3c9f3e9780e12f6f28b02941895a4"
        hash2 = "d9756e3ba272cd4502d88f4520747e9e69d241dee6561f30423840123c1a7939"

    strings:
        $x1 = "Do you wish to activate the implant that is already on the firewall? (y/n): " fullword ascii
        $x2 = "There is no implant present on the firewall." fullword ascii
        $x3 = "Implant Version :%lx%lx%lx" fullword ascii
        $x4 = "You may now connect to the implant using the pbd idkey" fullword ascii
        $x5 = "No reply from persistant back door." fullword ascii
        $x6 = "rm -rf pbd.wc; wc -c %s > pbd.wc" fullword ascii

        $p1 = "PBD_GetVersion" fullword ascii
        $p2 = "pbd/pbdEncrypt.bin" fullword ascii
        $p3 = "pbd/pbdGetVersion.pkt" fullword ascii
        $p4 = "pbd/pbdStartWrite.bin" fullword ascii
        $p5 = "pbd/pbd_setNewHookPt.pkt" fullword ascii
        $p6 = "pbd/pbd_Upload_SinglePkt.pkt" fullword ascii

        $s1 = "Unable to fetch hook and jmp addresses for this OS version" fullword ascii
        $s2 = "Could not get hook and jump addresses" fullword ascii
        $s3 = "Enter the name of a clean implant binary (NOT an image):" fullword ascii
        $s4 = "Unable to read dat file for OS version 0x%08lx" fullword ascii
        $s5 = "Invalid implant file" fullword ascii
    condition:
        ( uint16(0) == 0x457f and filesize < 3000KB and ( 1 of ($x*) or 1 of ($p*) ) ) or ( 3 of them )
}

rule EQGRP_sploit {
    meta:
        id = "2Pbmagqir5EYkssjWK4edR"
        fingerprint = "v1_sha256_083f103dee6b209626c4d790dff0e53af757945ded63409b26bbe143c78e30eb"
        version = "1.0"
        date = "2016-08-16"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "EQGRP Toolset Firewall - from files sploit.py, sploit.py"
        category = "INFO"
        reference = "Research"
        super_rule = 1
        hash1 = "0316d70a5bbf068a7fc791e08e816015d04ec98f088a7ff42af8b9e769b8d1f6"
        hash2 = "0316d70a5bbf068a7fc791e08e816015d04ec98f088a7ff42af8b9e769b8d1f6"

    strings:
        $s1 = "print \"[+] Connecting to %s:%s\" % (self.params.dst['ip'], self.params.dst['port'])" fullword ascii
        $s2 = "@overridable(\"Must be overriden if the target will be touched.  Base implementation should not be called.\")" fullword ascii
        $s3 = "@overridable(\"Must be overriden.  Base implementation should not be called.\")" fullword ascii
        $s4 = "exp.load_vinfo()" fullword ascii
        $s5 = "if not okay and self.terminateFlingOnException:" fullword ascii
        $s6 = "print \"[-] keyboard interrupt before response received\"" fullword ascii
        $s7 = "if self.terminateFlingOnException:" fullword ascii
        $s8 = "print 'Debug info ','='*40" fullword ascii
    condition:
        ( uint16(0) == 0x2123 and filesize < 90KB and 1 of ($s*) ) or ( 4 of them )
}

rule EQGRP_Implants_Gen2 {
    meta:
        id = "6DVnLguDzMm7ljA5eHD1HX"
        fingerprint = "v1_sha256_c3cbe11ae38f5affffab247cdc618d0afb5a0feda6ea4b2f43dd8edb2fbf2b11"
        version = "1.0"
        date = "2016-08-16"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "EQGRP Toolset Firewall - from files BananaUsurper-2120, BLIAR-2110, BLIQUER-2230, BLIQUER-3030, BLIQUER-3120, writeJetPlow-2130"
        category = "INFO"
        reference = "Research"
        super_rule = 1
        hash1 = "3366b4bbf265716869a487203a8ac39867920880990493dd4dd8385e42b0c119"
        hash2 = "05031898f3d52a5e05de119868c0ec7caad3c9f3e9780e12f6f28b02941895a4"
        hash3 = "d9756e3ba272cd4502d88f4520747e9e69d241dee6561f30423840123c1a7939"
        hash4 = "8e4a76c4b50350b67cabbb2fed47d781ee52d8d21121647b0c0356498aeda2a2"
        hash5 = "6059bec5cf297266079d52dbb29ab9b9e0b35ce43f718022b5b5f760c1976ec3"
        hash6 = "464b4c01f93f31500d2d770360d23bdc37e5ad4885e274a629ea86b2accb7a5c"

    strings:
        $x1 = "Modules persistence file written successfully" fullword ascii
        $x2 = "Modules persistence data successfully removed" fullword ascii
        $x3 = "No Modules are active on the firewall, nothing to persist" fullword ascii

        $s1 = "--cmd %x --idkey %s --sport %i --dport %i --lp %s --implant %s --bsize %hu --logdir %s " fullword ascii
        $s2 = "Error while attemping to persist modules:" fullword ascii
        $s3 = "Error while reading interface info from PIX" fullword ascii
        $s4 = "LP.c:pixFree - Failed to get response" fullword ascii
        $s5 = "WARNING: LP Timeout specified (%lu seconds) less than default (%u seconds).  Setting default" fullword ascii
        $s6 = "Unable to fetch config address for this OS version" fullword ascii
        $s7 = "LP.c: interface information not available for this session" fullword ascii
        $s8 = "[%s:%s:%d] ERROR: " fullword ascii
        $s9 = "extract_fgbg" fullword ascii
    condition:
        ( uint16(0) == 0x457f and filesize < 3000KB and 1 of ($x*) ) or ( 5 of them )
}

rule EQGRP_Implants_Gen1 {
    meta:
        id = "2CwXLDl3aDQQzxGZvaRNxc"
        fingerprint = "v1_sha256_1493f78e74503c367e3c5d8eac32167a7ad34d2435eba00e1f7bf864682e10a5"
        version = "1.0"
        date = "2016-08-16"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "EQGRP Toolset Firewall - from files BananaUsurper-2120, BARPUNCH-3110, BLIAR-2110, BLIQUER-2230, BLIQUER-3030, BLIQUER-3120, BPICKER-3100, lpexe, writeJetPlow-2130"
        category = "INFO"
        reference = "Research"
        super_rule = 1
        hash1 = "3366b4bbf265716869a487203a8ac39867920880990493dd4dd8385e42b0c119"
        hash2 = "830538fe8c981ca386c6c7d55635ac61161b23e6e25d96280ac2fc638c2d82cc"
        hash3 = "05031898f3d52a5e05de119868c0ec7caad3c9f3e9780e12f6f28b02941895a4"
        hash4 = "d9756e3ba272cd4502d88f4520747e9e69d241dee6561f30423840123c1a7939"
        hash5 = "8e4a76c4b50350b67cabbb2fed47d781ee52d8d21121647b0c0356498aeda2a2"
        hash6 = "6059bec5cf297266079d52dbb29ab9b9e0b35ce43f718022b5b5f760c1976ec3"
        hash7 = "d859ce034751cac960825268a157ced7c7001d553b03aec54e6794ff66185e6f"
        hash8 = "ee3e3487a9582181892e27b4078c5a3cb47bb31fc607634468cc67753f7e61d7"
        hash9 = "464b4c01f93f31500d2d770360d23bdc37e5ad4885e274a629ea86b2accb7a5c"

    strings:
        $s1 = "WARNING:  Session may not have been closed!" fullword ascii
        $s2 = "EXEC Packet Processed" fullword ascii
        $s3 = "Failed to insert the command into command list." fullword ascii
        $s4 = "Send_Packet: Trying to send too much data." fullword ascii
        $s5 = "payloadLength >= MAX_ALLOW_SIZE." fullword ascii
        $s6 = "Wrong Payload Size" fullword ascii
        $s7 = "Unknown packet received......" fullword ascii
        $s8 = "Returned eax = %08x" fullword ascii
    condition:
        ( uint16(0) == 0x457f and filesize < 6000KB and ( 2 of ($s*) ) ) or ( 5 of them )
}

rule EQGRP_eligiblebombshell_generic {
    meta:
        id = "3AVCgCx2ZGKqS7yhgWI7qz"
        fingerprint = "v1_sha256_a2e13300736f99aff30c7b4f7f0b148d62ecb1e72435a3e15e4f85b30d904ffd"
        version = "1.0"
        date = "2016-08-16"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "EQGRP Toolset Firewall - from files eligiblebombshell_1.2.0.1.py, eligiblebombshell_1.2.0.1.py"
        category = "INFO"
        reference = "Research"
        super_rule = 1
        hash1 = "dd0e3ae6e1039a755bf6cb28bf726b4d6ab4a1da2392ba66d114a43a55491eb1"
        hash2 = "dd0e3ae6e1039a755bf6cb28bf726b4d6ab4a1da2392ba66d114a43a55491eb1"

    strings:
        $s1 = "logging.error(\"       Perhaps you should run with --scan?\")" fullword ascii
        $s2 = "logging.error(\"ERROR: No entry for ETag [%s] in %s.\" %" fullword ascii
        $s3 = "\"be supplied\")" fullword ascii
    condition:
        ( filesize < 70KB and 2 of ($s*) ) or ( all of them )
}

rule EQGRP_ssh_telnet_29 {
    meta:
        id = "2tndPjMfN93YQmfGGRH6B7"
        fingerprint = "v1_sha256_e93a54f4de089d460bfb966feacc377c0467863f481a210c81970f4909fb3bd8"
        version = "1.0"
        date = "2016-08-16"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "EQGRP Toolset Firewall - from files ssh.py, telnet.py"
        category = "INFO"
        reference = "Research"
        super_rule = 1
        hash1 = "630d464b1d08c4dfd0bd50552bee2d6a591fb0b5597ecebaa556a3c3d4e0aa4e"
        hash2 = "07f4c60505f4d5fb5c4a76a8c899d9b63291444a3980d94c06e1d5889ae85482"

    strings:
        $s1 = "received prompt, we're in" fullword ascii
        $s2 = "failed to login, bad creds, abort" fullword ascii
        $s3 = "sending command \" + str(n) + \"/\" + str(tot) + \", len \" + str(len(chunk) + " fullword ascii
        $s4 = "received nat - EPBA: ok, payload: mangled, did not run" fullword ascii
        $s5 = "no status returned from target, could be an exploit failure, or this is a version where we don't expect a stus return" ascii
        $s6 = "received arp - EPBA: ok, payload: fail" fullword ascii
        $s7 = "chopped = string.rstrip(payload, \"\\x0a\")" fullword ascii
    condition:
        ( filesize < 10KB and 2 of them ) or ( 3 of them )
}

/* Extras */

rule EQGRP_tinyexec {
    meta:
        id = "7dJmTqiKIj7v1rKSQ78FZk"
        fingerprint = "v1_sha256_19b8d7e946d72424f81cd48ad4bf8791bf50a4cc146866e55ad501443a8d1e45"
        version = "1.0"
        date = "2016-08-16"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "EQGRP Toolset Firewall - from files tinyexec"
        category = "INFO"
        reference = "Research"

    strings:
        $s1 = { 73 68 73 74 72 74 61 62 00 2E 74 65 78 74 }
        $s2 = { 5A 58 55 52 89 E2 55 50 89 E1 }
    condition:
        uint32(0) == 0x464c457f and filesize < 270 and all of them
}

rule EQGRP_callbacks {
    meta:
        id = "1GAAyTyXbOejpCHszGbp3V"
        fingerprint = "v1_sha256_34881cf8f9f29482a1e129f0f61470d4cc3fa6b78b9f6dda25862371896deca7"
        version = "1.0"
        date = "2016-08-16"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "EQGRP Toolset Firewall - Callback addresses"
        category = "INFO"
        reference = "Research"

    strings:
        $s1 = "30.40.50.60:9342" fullword ascii wide /* DoD */
    condition:
        1 of them
}

rule EQGRP_Extrabacon_Output {
    meta:
        id = "5sVh81dutOGs76IAjJx3es"
        fingerprint = "v1_sha256_5e71a4380dd30e68d89add1718976d3207a161d2d61fd4c3250fc4b10a0f53a0"
        version = "1.0"
        date = "2016-08-16"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "EQGRP Toolset Firewall - Extrabacon exploit output"
        category = "INFO"
        reference = "Research"

    strings:
        $s1 = "|###[ SNMPresponse ]###" fullword ascii
        $s2 = "[+] generating exploit for exec mode pass-disable" fullword ascii
        $s3 = "[+] building payload for mode pass-disable" fullword ascii
        $s4 = "[+] Executing:  extrabacon" fullword ascii
        $s5 = "appended AAAADMINAUTH_ENABLE payload" fullword ascii
    condition:
        2 of them
}

rule EQGRP_Unique_Strings {
    meta:
        id = "16puqTgVFn1DfinUmxBD0y"
        fingerprint = "v1_sha256_070358ec9cccb5d9daa4e5a016d4f9a988b600d675484f06dc9a897cadf7af0c"
        version = "1.0"
        date = "2016-08-16"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "EQGRP Toolset Firewall - Unique strings"
        category = "INFO"
        reference = "Research"

    strings:
        $s1 = "/BananaGlee/ELIGIBLEBOMB" ascii
        $s2 = "Protocol must be either http or https (Ex: https://1.2.3.4:1234)"
    condition:
        1 of them
}

rule EQGRP_RC5_RC6_Opcode {
    meta:
        id = "3gC9blzxCBUykCXMljdSus"
        fingerprint = "v1_sha256_a79208c5924e1d5cc9db922f80403514e516eadb725393c1ebc9a6236ca90b98"
        version = "1.0"
        date = "2016-08-17"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "EQGRP Toolset Firewall - RC5 / RC6 opcode"
        category = "INFO"
        reference = "https://securelist.com/blog/incidents/75812/the-equation-giveaway/"

    strings:
        /*
            mov     esi, [ecx+edx*4-4]
            sub     esi, 61C88647h
            mov     [ecx+edx*4], esi
            inc     edx
            cmp     edx, 2Bh
        */
        $s1 = { 8B 74 91 FC 81 EE 47 86 C8 61 89 34 91 42 83 FA 2B }
    condition:
        1 of them
}
