rule apt_ext4_linuxlistener
{
    meta:
        id = "3mSc8SrI6Z1XiywZiW4nwZ"
        fingerprint = "v1_sha256_94ce06087482e14cec58181e411f2bc1be7ea2bd4f2164d83efb22fb95865264"
        version = "1.0"
        date = "2018-08-14"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Insikt Group, Recorded Future"
        author = "https://go.recordedfuture.com/hubfs/reports/cta-2018-0816.pdf"
        description = "Detects Unique Linux Backdoor, Ext4"
        category = "INFO"
        TLP = "White"
        md5_x64 = "d08de00e7168a441052672219e717957"

 strings:
 $s1="rm /tmp/0baaf161db39"
 $op1= {3c 61 0f}
 $op2= {3c 6e 0f}
 $op3= {3c 74 0f}
 $op4= {3c 69 0f}
 $op5= {3c 3a 0f}
 condition:
 all of them
}
