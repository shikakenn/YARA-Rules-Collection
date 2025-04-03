rule genericSMS : smsFraud
{
    meta:
        id = "4cOCtrXiSzNaMndYaFtAc3"
        fingerprint = "v1_sha256_890a9affaec2884d0d666775ab8d3be50fe009966669ab4c759720abcdba57cc"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "https://twitter.com/plutec_net"
        description = "NA"
        category = "INFO"
        reference = "https://koodous.com/"
        sample = "3fc533d832e22dc3bc161e5190edf242f70fbc4764267ca073de5a8e3ae23272"
        sample2 = "3d85bdd0faea9c985749c614a0676bb05f017f6bde3651f2b819c7ac40a02d5f"

    strings:
        $a = "SHA1-Digest: +RsrTx5SNjstrnt7pNaeQAzY4kc="
        $b = "SHA1-Digest: Rt2oRts0wWTjffGlETGfFix1dfE="
        $c = "http://image.baidu.com/wisebrowse/index?tag1=%E6%98%8E%E6%98%9F&tag2=%E5%A5%B3%E6%98%8E%E6%98%9F&tag3=%E5%85%A8%E9%83%A8&pn=0&rn=10&fmpage=index&pos=magic#/channel"
        $d = "pitchfork=022D4"

    condition:
        all of them
        
}

rule genericSMS2 : smsFraud
{
    meta:
        id = "Q6XZOks1Baj8osgWMEOq0"
        fingerprint = "v1_sha256_f3ae08e5ec267aad4b7bfcfe17eb54bcb4ba9aa4c496f31b190928cddb236dca"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "https://twitter.com/plutec_net"
        description = "NA"
        category = "INFO"
        reference = "https://koodous.com/"
        sample = "1f23524e32c12c56be0c9a25c69ab7dc21501169c57f8d6a95c051397263cf9f"
        sample2 = "2cf073bd8de8aad6cc0d6ad5c98e1ba458bd0910b043a69a25aabdc2728ea2bd"
        sample3 = "20575a3e5e97bcfbf2c3c1d905d967e91a00d69758eb15588bdafacb4c854cba"

    strings:
        $a = "NotLeftTriangleEqual=022EC"
        $b = "SHA1-Digest: X27Zpw9c6eyXvEFuZfCL2LmumtI="
        $c = "_ZNSt12_Vector_baseISsSaISsEE13_M_deallocateEPSsj"
        $d = "FBTP2AHR3WKC6LEYON7D5GZXVISMJ4QU"

    condition:
        all of them
        
}
