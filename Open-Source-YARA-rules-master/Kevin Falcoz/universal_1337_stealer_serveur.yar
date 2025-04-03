rule universal_1337_stealer_serveur : Stealer
{
    meta:
        id = "4aSgV73RR1nfbQfO7iDSDn"
        fingerprint = "v1_sha256_1193197c2f85efb99aba802ffe0efd6f10171e4e2db1a2ad44ee75755b182858"
        version = "1.0"
        date = "24/02/2013"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Kevin Falcoz"
        description = "Universal 1337 Stealer Serveur"
        category = "INFO"

    strings:
        $signature1={2A 5B 53 2D 50 2D 4C 2D 49 2D 54 5D 2A} /*[S-P-L-I-T]*/
        $signature2={2A 5B 48 2D 45 2D 52 2D 45 5D 2A} /*[H-E-R-E]*/
        $signature3={46 54 50 7E} /*FTP~*/
        $signature4={7E 31 7E 31 7E 30 7E 30} /*~1~1~0~0*/
        
    condition:
        $signature1 and $signature2 or $signature3 and $signature4
}
