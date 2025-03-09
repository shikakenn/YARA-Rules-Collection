rule doc_efax_buran {
    meta:
        id = "1QzKpxjPonlGZ2cItatBiy"
        fingerprint = "v1_sha256_5cff075f3586dcdd52795253930eb6f3a7a86333b192750d94e7e2f8dc06056e"
        version = "1.0"
        date = "2019-10-10"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Alex Holland (@cryptogramfan)"
        description = "NA"
        category = "INFO"
        reference = "https://threatresearch.ext.hp.com/buran-ransomware-targets-german-organisations-through-malicious-spam-campaign/"
        sample_1 = "7DD46D28AAEC9F5B6C5F7C907BA73EA012CDE5B5DC2A45CDA80F28F7D630F1B0"
        sample_2 = "856D0C14850BE7D45FA6EE58425881E5F7702FBFBAD987122BB4FF59C72507E2"
        sample_3 = "33C8E805D8D8A37A93D681268ACCA252314FF02CF9488B6B2F7A27DD07A1E33A"

    strings:
        $vba = "vbaProject.bin" ascii nocase
        $image = "image1.jpeg" ascii nocase
        $padding_xml = /[a-zA-Z0-9]{5,40}\d{10}\.xml/ ascii
        
    condition:
        all of them and filesize < 800KB
}
