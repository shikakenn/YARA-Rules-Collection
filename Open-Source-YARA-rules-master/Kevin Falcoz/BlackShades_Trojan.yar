import "pe"

rule BlackShades : Trojan
{
    meta:
        id = "3HU3sZQqgyJB2OQUcugib2"
        fingerprint = "v1_sha256_48a9d0268084f6a720332f645ec66861972d046f2b05cdfe42e94eac737fc52a"
        version = "1.0"
        date = "26/06/2013"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Kevin Falcoz"
        description = "BlackShades Server"
        category = "INFO"

    strings:
        $signature1={62 73 73 5F 73 65 72 76 65 72}
        $signature2={43 4C 49 43 4B 5F 44 45 4C 41 59 00 53 43 4B 5F 49 44}
        $signature3={6D 6F 64 49 6E 6A 50 45}
        
    condition:
        $signature1 and $signature2 and $signature3
}
