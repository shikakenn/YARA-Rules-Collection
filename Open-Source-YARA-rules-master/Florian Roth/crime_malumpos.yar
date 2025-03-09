rule PoS_Malware_MalumPOS
{
    meta:
        id = "A6fxsPwrQmyJYqICCODww"
        fingerprint = "v1_sha256_ece32e51a12adf0d68420c8d98efbe7df27b9061ddfe4dcedf151f9f06287eee"
        version = "1.0"
        date = "2015-05-25"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Trend Micro, Inc."
        description = "Used to detect MalumPOS memory dumper"
        category = "INFO"
        sample_filtype = "exe"

    strings:
        $string1 = "SOFTWARE\\Borland\\Delphi\\RTL"
        $string2 = "B)[0-9]{13,19}\\"
        $string3 = "[A-Za-z\\s]{0,30}\\/[A-Za-z\\s]{0,30}\\"
        $string4 = "TRegExpr(exec): ExecNext Without Exec[Pos]"
        $string5 = /Y:\\PROGRAMS\\.{20,300}\.pas/ 
    condition:
        all of ($string*)
}

rule PoS_Malware_MalumPOS_Config
{
    meta:
        id = "1vBs3cLJVrysXOdpXFWF7a"
        fingerprint = "v1_sha256_6a4b868ff356d998722204444841d0327b4b4c7cb8a5a8078b9bf73b24ef8023"
        version = "1.0"
        date = "2015-06-25"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "MalumPOS Config File"
        category = "INFO"
        reference = "http://blog.trendmicro.com/trendlabs-security-intelligence/trend-micro-discovers-malumpos-targets-hotels-and-other-us-industries/"

    strings:
        $s1 = "[PARAMS]"
        $s2 = "Name="
        $s3 = "InterfacesIP="
        $s4 = "Port="
    condition:
        all of ($s*) and filename == "log.ini" and filesize < 20KB
}
