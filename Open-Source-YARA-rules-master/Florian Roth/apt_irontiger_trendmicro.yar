rule IronTiger_ASPXSpy
{
    meta:
        id = "5NXFJw4296CMCqx44SdY20"
        fingerprint = "v1_sha256_f183830e6a0d7f404ceca40d76a73ef1ffb0cc6dc0bc40320c4e376023cb55b0"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Cyber Safety Solutions, Trend Micro"
        description = "ASPXSpy detection. It might be used by other fraudsters"
        category = "INFO"
        reference = "http://goo.gl/T5fSJC"

    strings:
        $str2 = "IIS Spy" wide ascii
        $str3 = "protected void DGCoW(object sender,EventArgs e)" nocase wide ascii
    condition:
        any of ($str*)
}

rule IronTiger_ChangePort_Toolkit_driversinstall
{
    meta:
        id = "4FhVeLC52cTRaV7SQsUqZB"
        fingerprint = "v1_sha256_e9985599ead7ed957b16eeff4f629fe3a341bd3e108450de8d071b132b615b92"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Cyber Safety Solutions, Trend Micro"
        description = "Iron Tiger Malware - Changeport Toolkit driverinstall"
        category = "INFO"
        reference = "http://goo.gl/T5fSJC"

    strings:
        $str1 = "openmydoor" nocase wide ascii
        $str2 = "Install service error" nocase wide ascii
        $str3 = "start remove service" nocase wide ascii
        $str4 = "NdisVersion" nocase wide ascii
    condition:
        uint16(0) == 0x5a4d and (2 of ($str*))
}

rule IronTiger_ChangePort_Toolkit_ChangePortExe
{
    meta:
        id = "SF2kpqc439n7lZ8bKFAD1"
        fingerprint = "v1_sha256_fc2362dec411920bb65c06912a24508072683fae1e8d651780252d14404a013a"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Cyber Safety Solutions, Trend Micro"
        description = "Iron Tiger Malware - Toolkit ChangePort"
        category = "INFO"
        reference = "http://goo.gl/T5fSJC"

    strings:
        $str1 = "Unable to alloc the adapter!" nocase wide ascii
        $str2 = "Wait for master fuck" nocase wide ascii
        $str3 = "xx.exe <HOST> <PORT>" nocase wide ascii
        $str4 = "chkroot2007" nocase wide ascii
        $str5 = "Door is bind on %s" nocase wide ascii
    condition:
        uint16(0) == 0x5a4d and (2 of ($str*))
}

rule IronTiger_dllshellexc2010
{
    meta:
        id = "3wcEjPTkRGgH1RdlBRWgqx"
        fingerprint = "v1_sha256_b3a04329be1540b9bb27e6483829ad1723a849744de806a1accc11466572755f"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Cyber Safety Solutions, Trend Micro"
        description = "dllshellexc2010 Exchange backdoor + remote shell"
        category = "INFO"
        reference = "http://goo.gl/T5fSJC"

    strings:
        $str1 = "Microsoft.Exchange.Clients.Auth.dll" nocase ascii wide
        $str2 = "Dllshellexc2010" nocase wide ascii
        $str3 = "Users\\ljw\\Documents" nocase wide ascii
        $bla1 = "please input path" nocase wide ascii
        $bla2 = "auth.owa" nocase wide ascii
    condition:
        (uint16(0) == 0x5a4d) and ((any of ($str*)) or (all of ($bla*)))
}

rule IronTiger_dnstunnel
{
    meta:
        id = "2gHRHAFoNLb4lM4Wraozcn"
        fingerprint = "v1_sha256_95cd18d804835cd9221f1691bb743459670d77aeeac22569a2c5e5eb78d95b1f"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Cyber Safety Solutions, Trend Micro"
        description = "This rule detects a dns tunnel tool used in Operation Iron Tiger"
        category = "INFO"
        reference = "http://goo.gl/T5fSJC"

    strings:
        $str1 = "\\DnsTunClient\\" nocase wide ascii
        $str2 = "\\t-DNSTunnel\\" nocase wide ascii
        $str3 = "xssok.blogspot" nocase wide ascii
        $str4 = "dnstunclient" nocase wide ascii
        $mistake1 = "because of error, can not analysis" nocase wide ascii
        $mistake2 = "can not deal witn the error" nocase wide ascii
        $mistake3 = "the other retun one RST" nocase wide ascii
        $mistake4 = "Coversation produce one error" nocase wide ascii
        $mistake5 = "Program try to use the have deleted the buffer" nocase wide ascii
    condition:
        (uint16(0) == 0x5a4d) and ((any of ($str*)) or (any of ($mistake*)))
}

rule IronTiger_EFH3_encoder
{
    meta:
        id = "5GQjkfC8ek4RsnH5IddZbP"
        fingerprint = "v1_sha256_8331d27e35a4ac3cc77fb75f3c7dc01fd5cd3b35fb03e80d4bd0011314903d18"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Cyber Safety Solutions, Trend Micro"
        description = "Iron Tiger EFH3 Encoder"
        category = "INFO"
        reference = "http://goo.gl/T5fSJC"

    strings:
        $str1 = "EFH3 [HEX] [SRCFILE] [DSTFILE]" nocase wide ascii
        $str2 = "123.EXE 123.EFH" nocase wide ascii
        $str3 = "ENCODER: b[i]: = " nocase wide ascii
    condition:
        uint16(0) == 0x5a4d and (any of ($str*))
}

rule IronTiger_GetPassword_x64
{
    meta:
        id = "7XhsVLLnLWwIG3Ze5FXKkW"
        fingerprint = "v1_sha256_3ef9980d4fa6ba07f1e722e76de56a14a9ccfb83ff9560475c4a9040bca3ad4c"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Cyber Safety Solutions, Trend Micro"
        description = "Iron Tiger Malware - GetPassword x64"
        category = "INFO"
        reference = "http://goo.gl/T5fSJC"

    strings:
        $str1 = "(LUID ERROR)" nocase wide ascii
        $str2 = "Users\\K8team\\Desktop\\GetPassword" nocase wide ascii
        $str3 = "Debug x64\\GetPassword.pdb" nocase wide ascii
        $bla1 = "Authentication Package:" nocase wide ascii
        $bla2 = "Authentication Domain:" nocase wide ascii
        $bla3 = "* Password:" nocase wide ascii
        $bla4 = "Primary User:" nocase wide ascii
    condition:
        uint16(0) == 0x5a4d and ((any of ($str*)) or (all of ($bla*)))
}

rule IronTiger_Gh0stRAT_variant
{
    meta:
        id = "NtPtqf6WJnkR0aM7x8A16"
        fingerprint = "v1_sha256_65e31b1a37772b572a7e3e0e1d006079efebd817101006929c6e011e6a70cb00"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Cyber Safety Solutions, Trend Micro"
        description = "This is a detection for a s.exe variant seen in Op. Iron Tiger"
        category = "INFO"
        reference = "http://goo.gl/T5fSJC"

    strings:
        $str1 = "Game Over Good Luck By Wind" nocase wide ascii
        $str2 = "ReleiceName" nocase wide ascii
        $str3 = "jingtisanmenxiachuanxiao.vbs" nocase wide ascii
        $str4 = "Winds Update" nocase wide ascii
    condition:
        uint16(0) == 0x5a4d and (any of ($str*))
        and not filename == "UpdateSystemMib.exe"
}

rule IronTiger_GTalk_Trojan
{
    meta:
        id = "76Fydj4h6cpwpRIWxKLv4r"
        fingerprint = "v1_sha256_87787895a1188101204d9f06f1fd67713f0aee607556b8f36d8807145a3ff0a5"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Cyber Safety Solutions, Trend Micro"
        description = "Iron Tiger Malware - GTalk Trojan"
        category = "INFO"
        reference = "http://goo.gl/T5fSJC"

    strings:
        $str1 = "gtalklite.com" nocase wide ascii
        $str2 = "computer=%s&lanip=%s&uid=%s&os=%s&data=%s" nocase wide ascii
        $str3 = "D13idmAdm" nocase wide ascii
        $str4 = "Error: PeekNamedPipe failed with %i" nocase wide ascii
    condition:
        uint16(0) == 0x5a4d and (2 of ($str*))
}

rule IronTiger_HTTPBrowser_Dropper
{
    meta:
        id = "4VQaQ75ml2UnSWdxYGMgpF"
        fingerprint = "v1_sha256_bd80057f0c9bce6dc1edc82db19439db6b0cef0f2d747a0b94333ceed18507b0"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Cyber Safety Solutions, Trend Micro"
        description = "Iron Tiger Malware - HTTPBrowser Dropper"
        category = "INFO"
        reference = "http://goo.gl/T5fSJC"

    strings:
        $str1 = ".dllUT" nocase wide ascii
        $str2 = ".exeUT" nocase wide ascii
        $str3 = ".urlUT" nocase wide ascii
    condition:
        uint16(0) == 0x5a4d and (2 of ($str*))
}

rule IronTiger_HTTP_SOCKS_Proxy_soexe
{
    meta:
        id = "5ldD70rwD7OtLsbY5Aj9fE"
        fingerprint = "v1_sha256_ffc917910d283cf790d5109243fc363b5aae9e0667cc50c5c9d0e2c087e51a80"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Cyber Safety Solutions, Trend Micro"
        description = "Iron Tiger Toolset - HTTP SOCKS Proxy soexe"
        category = "INFO"
        reference = "http://goo.gl/T5fSJC"

    strings:
        $str1 = "listen SOCKET error." nocase wide ascii
        $str2 = "WSAAsyncSelect SOCKET error." nocase wide ascii
        $str3 = "new SOCKETINFO error!" nocase wide ascii
        $str4 = "Http/1.1 403 Forbidden" nocase wide ascii
        $str5 = "Create SOCKET error." nocase wide ascii
    condition:
        uint16(0) == 0x5a4d and (3 of ($str*))
}

rule IronTiger_NBDDos_Gh0stvariant_dropper
{
    meta:
        id = "3aoWbE5ZWTI4SL5eGHZdG3"
        fingerprint = "v1_sha256_cb4766bc707101e0f5222f32c1d4191f0019b8a04f21244fe6f6dacaeec7c14d"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Cyber Safety Solutions, Trend Micro"
        description = "Iron Tiger Malware - NBDDos Gh0stvariant Dropper"
        category = "INFO"
        reference = "http://goo.gl/T5fSJC"

    strings:
        $str1 = "This service can't be stoped." nocase wide ascii
        $str2 = "Provides support for media palyer" nocase wide ascii
        $str4 = "CreaetProcess Error" nocase wide ascii
        $bla1 = "Kill You" nocase wide ascii
        $bla2 = "%4.2f GB" nocase wide ascii
    condition:
        uint16(0) == 0x5a4d and ((any of ($str*)) or (all of ($bla*)))
}

rule IronTiger_PlugX_DosEmulator
{
    meta:
        id = "47blTXzE1cT2GscvBuNNZK"
        fingerprint = "v1_sha256_1c0c2cf98a90d646b2de69a0570ce984441e58c369d62f9b9143fa418a3d63f7"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Cyber Safety Solutions, Trend Micro"
        description = "Iron Tiger Malware - PlugX DosEmulator"
        category = "INFO"
        reference = "http://goo.gl/T5fSJC"

    strings:
        $str1 = "Dos Emluator Ver" nocase wide ascii
        $str2 = "\\PIPE\\FASTDOS" nocase wide ascii
        $str3 = "FastDos.cpp" nocase wide ascii
        $str4 = "fail,error code = %d." nocase wide ascii
    condition:
        uint16(0) == 0x5a4d and (any of ($str*))
}

rule IronTiger_PlugX_FastProxy
{
    meta:
        id = "18g0Eu6bFkzkCqwkU0QBjZ"
        fingerprint = "v1_sha256_681c21e440f79a1fac87ce79a367b36e8f17d4edefa31e6c2cdb2feb4b80bb9f"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Cyber Safety Solutions, Trend Micro"
        description = "Iron Tiger Malware - PlugX FastProxy"
        category = "INFO"
        reference = "http://goo.gl/T5fSJC"

    strings:
        $str1 = "SAFEPROXY HTServerTimer Quit!" nocase wide ascii
        $str2 = "Useage: %s pid" nocase wide ascii
        $str3 = "%s PORT[%d] TO PORT[%d] SUCCESS!" nocase wide ascii
        $str4 = "p0: port for listener" nocase wide ascii
        $str5 = "\\users\\whg\\desktop\\plug\\" nocase wide ascii
        $str6 = "[+Y] cwnd : %3d, fligth:" nocase wide ascii
    condition:
        uint16(0) == 0x5a4d and (any of ($str*))
}

rule IronTiger_PlugX_Server
{
    meta:
        id = "6XCV56g3dBiDeL3HkvyC0d"
        fingerprint = "v1_sha256_f2fd475b40d026631a4c4f8125a53b3f3d50b9c2b997d2f0f737c5be332bb92e"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Cyber Safety Solutions, Trend Micro"
        description = "Iron Tiger Malware - PlugX Server"
        category = "INFO"
        reference = "http://goo.gl/T5fSJC"

    strings:
        $str1 = "\\UnitFrmManagerKeyLog.pas" nocase wide ascii
        $str2 = "\\UnitFrmManagerRegister.pas" nocase wide ascii
        $str3 = "Input Name..." nocase wide ascii
        $str4 = "New Value#" nocase wide ascii
        $str5 = "TThreadRControl.Execute SEH!!!" nocase wide ascii
        $str6 = "\\UnitFrmRControl.pas" nocase wide ascii
        $str7 = "OnSocket(event is error)!" nocase wide ascii
        $str8 = "Make 3F Version Ok!!!" nocase wide ascii
        $str9 = "PELEASE DO NOT CHANGE THE DOCAMENT" nocase wide ascii
        $str10 = "Press [Ok] Continue Run, Press [Cancel] Exit" nocase wide ascii
    condition:
        uint16(0) == 0x5a4d and (2 of ($str*))
}

rule IronTiger_ReadPWD86
{
    meta:
        id = "5x5I9XpMuAGHpU55AZwWVP"
        fingerprint = "v1_sha256_549944591b112fda3f9bd81d06b483d95edf483b403842df517cc5cf4b2a9bbe"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Cyber Safety Solutions, Trend Micro"
        description = "Iron Tiger Malware - ReadPWD86"
        category = "INFO"
        reference = "http://goo.gl/T5fSJC"

    strings:
        $str1 = "Fail To Load LSASRV" nocase wide ascii
        $str2 = "Fail To Search LSASS Data" nocase wide ascii
        $str3 = "User Principal" nocase wide ascii
    condition:
        uint16(0) == 0x5a4d and (all of ($str*))
}

rule IronTiger_Ring_Gh0stvariant
{
    meta:
        id = "7X5VBK2RFskUO2XH9MV0SA"
        fingerprint = "v1_sha256_915fcee3f6b751c21d535c78aed8beb2975ab7134e5666d2101e448b7ca38c88"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Cyber Safety Solutions, Trend Micro"
        description = "Iron Tiger Malware - Ring Gh0stvariant"
        category = "INFO"
        reference = "http://goo.gl/T5fSJC"

    strings:
        $str1 = "RING RAT Exception" nocase wide ascii
        $str2 = "(can not update server recently)!" nocase wide ascii
        $str4 = "CreaetProcess Error" nocase wide ascii
        $bla1 = "Sucess!" nocase wide ascii
        $bla2 = "user canceled!" nocase wide ascii
    condition:
        uint16(0) == 0x5a4d and ((any of ($str*)) or (all of ($bla*)))
}

rule IronTiger_wmiexec
{
    meta:
        id = "13V8bT669tV3ArnVBpBiL8"
        fingerprint = "v1_sha256_5365fd2a62aad58acd68b48740dddf48916a26811a7662e9d7aa98c39a079ba2"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Cyber Safety Solutions, Trend Micro"
        description = "Iron Tiger Tool - wmi.vbs detection"
        category = "INFO"
        reference = "http://goo.gl/T5fSJC"

    strings:
        $str1 = "Temp Result File , Change it to where you like" nocase wide ascii
        $str2 = "wmiexec" nocase wide ascii
        $str3 = "By. Twi1ight" nocase wide ascii
        $str4 = "[both mode] ,delay TIME to read result" nocase wide ascii
        $str5 = "such as nc.exe or Trojan" nocase wide ascii
        $str6 = "+++shell mode+++" nocase wide ascii
        $str7 = "win2008 fso has no privilege to delete file" nocase wide ascii
    condition:
        2 of ($str*)
}
