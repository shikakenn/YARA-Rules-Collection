rule Poisioned_Hurricane_Certs
{
    meta:
        id = "48Kzemmr4DMTxiMp56hvSh"
        fingerprint = "v1_sha256_ef274660e65b9dc59bac7138dd6efc4d7390665c10cb0c4eec7b4e82687b6162"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "NA"
        category = "INFO"
        Author = "mikesxrs"
        Description = "Looking for certificates found in report"
        Reference = "https://www.fireeye.com/blog/threat-research/2014/08/operation-poisoned-hurricane.html"
        Date = "2017-10-28"

    strings:
        $cert1 = {06 55 69 a3 e2 61 40 91 28 a4 0a ff a9 0d 6d 10} //Police Mutual Aid Association
        $cert2 = {03 e5 a0 10 b0 5c 92 87 f8 23 c2 58 5f 54 7b 80} //MOCOMSYS INC
        $cert3 = {2e df b9 fd cf a0 0c cb 5a b0 09 ee 3a db 97 b9} //QTI INTERNATIONAL INC
        $cert4 = {0f e7 df 6c 4b 9a 33 b8 3d 04 e2 3e 98 a7 7c ce} //PIXELPLUS CO., LTD
        $cert5 = {1D 2B C8 46 D1 00 D8 FB 94 FA EA 4B 7B 5F D8 94} //Ssangyong Motor Co. 
        $cert6 = {72 B4 F5 66 7F 69 F5 43 21 A9 40 09 97 4C CC F8} //jtc
    condition:
        any of them
}
