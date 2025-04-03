
rule custom_ssh_backdoor_server {
    meta:
        id = "4dcz168yY9CCwjR7ivNMPw"
        fingerprint = "v1_sha256_67ebb01f2c01ef38fdcd2604320be41dbab3695e7106c46837c3547f931c4708"
        version = "1.0"
        date = "2015-05-14"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Custome SSH backdoor based on python and paramiko - file server.py"
        category = "INFO"
        reference = "https://goo.gl/S46L3o"
        hash = "0953b6c2181249b94282ca5736471f85d80d41c9"

    strings:
        $s0 = "command= raw_input(\"Enter command: \").strip('n')" fullword ascii
        $s1 = "print '[-] (Failed to load moduli -- gex will be unsupported.)'" fullword ascii
        $s2 = "print '[-] Listen/bind/accept failed: ' + str(e)" fullword ascii
        $s3 = "chan.send(command)" fullword ascii
        $s4 = "print '[-] SSH negotiation failed.'" fullword ascii
        $s5 = "except paramiko.SSHException, x:" fullword ascii
    condition:
        filesize < 10KB and 5 of them
}
