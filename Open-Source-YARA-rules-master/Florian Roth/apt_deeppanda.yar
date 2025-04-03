/* Deep Panda APT */

rule DeepPanda_sl_txt_packed {
    meta:
        id = "4V6ByplPFCPO9kTLL2hJ3y"
        fingerprint = "v1_sha256_37f875dcb2c920278c2625085c97a9dcce1907198409595a10e6a3fbce767f35"
        version = "1.0"
        date = "2015/02/08"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Hack Deep Panda - ScanLine sl-txt-packed"
        category = "INFO"
        hash = "ffb1d8ea3039d3d5eb7196d27f5450cac0ea4f34"

    strings:
        $s0 = "Command line port scanner" fullword wide
        $s1 = "sl.exe" fullword wide
        $s2 = "CPports.txt" fullword ascii
        $s3 = ",GET / HTTP/.}" fullword ascii
        $s4 = "Foundstone Inc." fullword wide
        $s9 = " 2002 Foundstone Inc." fullword wide
        $s15 = ", Inc. 2002" fullword ascii
        $s20 = "ICMP Time" fullword ascii
    condition:
        all of them
}

rule DeepPanda_lot1 {
    meta:
        id = "5cOhKl6vBDGC2GezfT8fSq"
        fingerprint = "v1_sha256_92169a1288f30dc6008e1a8c9b2b700f878c90aa09634e36fea586e19657dbd1"
        version = "1.0"
        date = "2015/02/08"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Hack Deep Panda - lot1.tmp-pwdump"
        category = "INFO"
        hash = "5d201a0fb0f4a96cefc5f73effb61acff9c818e1"

    strings:
        $s0 = "Unable to open target process: %d, pid %d" fullword ascii
        $s1 = "Couldn't delete target executable from remote machine: %d" fullword ascii
        $s2 = "Target: Failed to load SAM functions." fullword ascii
        $s5 = "Error writing the test file %s, skipping this share" fullword ascii
        $s6 = "Failed to create service (%s/%s), error %d" fullword ascii
        $s8 = "Service start failed: %d (%s/%s)" fullword ascii
        $s12 = "PwDump.exe" fullword ascii
        $s13 = "GetAvailableWriteableShare returned an error of %ld" fullword ascii
        $s14 = ":\\\\.\\pipe\\%s" fullword ascii
        $s15 = "Couldn't copy %s to destination %s. (Error %d)" fullword ascii
        $s16 = "dump logon session" fullword ascii
        $s17 = "Timed out waiting to get our pipe back" fullword ascii
        $s19 = "SetNamedPipeHandleState failed, error %d" fullword ascii
        $s20 = "%s\\%s.exe" fullword ascii
    condition:
        10 of them
}

rule DeepPanda_htran_exe {
    meta:
        id = "1NizArpgoRYJFrBW9Pto2b"
        fingerprint = "v1_sha256_188f475566767d1955b26d5f7e2d5c0ddfbb26e6681ec18046051f95862e22cc"
        version = "1.0"
        date = "2015/02/08"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Hack Deep Panda - htran-exe"
        category = "INFO"
        hash = "38e21f0b87b3052b536408fdf59185f8b3d210b9"

    strings:
        $s0 = "%s -<listen|tran|slave> <option> [-log logfile]" fullword ascii
        $s1 = "[-] Gethostbyname(%s) error:%s" fullword ascii
        $s2 = "e:\\VS 2008 Project\\htran\\Release\\htran.pdb" fullword ascii
        $s3 = "[SERVER]connection to %s:%d error" fullword ascii
        $s4 = "-tran  <ConnectPort> <TransmitHost> <TransmitPort>" fullword ascii
        $s5 = "[-] ERROR: Must supply logfile name." fullword ascii
        $s6 = "[-] There is a error...Create a new connection." fullword ascii
        $s7 = "[+] Accept a Client on port %d from %s" fullword ascii
        $s8 = "======================== htran V%s =======================" fullword ascii
        $s9 = "[-] Socket Listen error." fullword ascii
        $s10 = "[-] ERROR: open logfile" fullword ascii
        $s11 = "-slave  <ConnectHost> <ConnectPort> <TransmitHost> <TransmitPort>" fullword ascii
        $s12 = "[+] Make a Connection to %s:%d ......" fullword ascii
        $s14 = "Recv %5d bytes from %s:%d" fullword ascii
        $s15 = "[+] OK! I Closed The Two Socket." fullword ascii
        $s16 = "[+] Waiting another Client on port:%d...." fullword ascii
        $s17 = "[+] Accept a Client on port %d from %s ......" fullword ascii
        $s20 = "-listen <ConnectPort> <TransmitPort>" fullword ascii
    condition:
        10 of them
}

rule DeepPanda_Trojan_Kakfum {
    meta:
        id = "78A8EaPjJlrhJQXIhab7Nm"
        fingerprint = "v1_sha256_0710edea973dce6f5feccf2e7e508cd5f65aa451e0bb5aca503778ffe2363401"
        version = "1.0"
        date = "2015/02/08"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Hack Deep Panda - Trojan.Kakfum sqlsrv32.dll"
        category = "INFO"
        hash1 = "ab58b6aa7dcc25d8f6e4b70a24e0ccede0d5f6129df02a9e61293c1d7d7640a2"
        hash2 = "c6c3bb72896f8f0b9a5351614fd94e889864cf924b40a318c79560bbbcfa372f"

    strings:
        $s0 = "%SystemRoot%\\System32\\svchost.exe -k sqlserver" fullword ascii
        $s1 = "%s\\sqlsrv32.dll" fullword ascii
        $s2 = "%s\\sqlsrv64.dll" fullword ascii
        $s3 = "%s\\%d.tmp" fullword ascii
        $s4 = "ServiceMaix" fullword ascii
        $s15 = "sqlserver" fullword ascii
    condition:
        all of them
}
