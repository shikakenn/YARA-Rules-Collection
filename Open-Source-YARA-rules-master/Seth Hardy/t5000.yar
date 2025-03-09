private rule T5000Strings : T5000 Family
{
    meta:
        id = "4GsE1ZjxKHApk3RFSxR3lh"
        fingerprint = "v1_sha256_b16e5245f605b8f0b75a65da106c20e184c5b47b7ff36639d5ec93552a4b999f"
        version = "1.0"
        modified = "2014-06-26"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Seth Hardy"
        description = "T5000 Identifying Strings"
        category = "INFO"

    strings:
        $ = "_tmpR.vbs"
        $ = "_tmpg.vbs"
        $ = "Dtl.dat" wide ascii
        $ = "3C6FB3CA-69B1-454f-8B2F-BD157762810E"
        $ = "EED5CA6C-9958-4611-B7A7-1238F2E1B17E"
        $ = "8A8FF8AD-D1DE-4cef-B87C-82627677662E"
        $ = "43EE34A9-9063-4d2c-AACD-F5C62B849089"
        $ = "A8859547-C62D-4e8b-A82D-BE1479C684C9"
        $ = "A59CF429-D0DD-4207-88A1-04090680F714"
        $ = "utd_CE31" wide ascii
        $ = "f:\\Project\\T5000\\Src\\Target\\1 KjetDll.pdb"
        $ = "l:\\MyProject\\Vc 7.1\\T5000\\T5000Ver1.28\\Target\\4 CaptureDLL.pdb"
        $ = "f:\\Project\\T5000\\Src\\Target\\4 CaptureDLL.pdb"
        $ = "E:\\VS2010\\xPlat2\\Release\\InstRes32.pdb"
        
    condition:
       any of them
}

rule T5000 : Family
{
    meta:
        id = "5bU7oEt2y9q6MsdjlTp5TX"
        fingerprint = "v1_sha256_10853eeecb740ab1c3b442eff8b1397adb893f8628407acb55e19d1520615c31"
        version = "1.0"
        modified = "2014-06-26"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Seth Hardy"
        description = "T5000"
        category = "INFO"

    condition:
        T5000Strings
}
