rule COATHANGER_files
{
    meta:
        id = "4wzGXkcvvIexzSCt23ll2s"
        fingerprint = "v1_sha256_5406d8a99e16f08f1ffca548ea1dd1e27e7707506e796e0fc263bcdbb681632d"
        version = "1.0"
        date = "20240206"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "NLD MIVD - JSCU"
        description = "Detects COATHANGER files by used filenames"
        category = "INFO"
        malware = "COATHANGER"

    strings:
        $1 = "/data2/"
        $2 = "/httpsd"
        $3 = "/preload.so"
        $4 = "/authd"
        $5 = "/tmp/packfile"
        $6 = "/smartctl"
        $7 = "/etc/ld.so.preload"
        $8 = "/newcli"
        $9 = "/bin/busybox"

    condition:
        (uint32(0) == 0x464c457f or uint32(4) == 0x464c457f)
        and filesize < 5MB and 4 of them
}
