// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
import "pe"
rule APT_Backdoor_PS1_BASICPIPESHELL_1
{
    meta:
        id = "7GLAQofuPuDsWUdwcOA43I"
        fingerprint = "v1_sha256_7a9f0002055ffe826562cab3d02d8babd14c5fcd6d0b528a2988e2649034279d"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "FireEye"
        description = "NA"
        category = "INFO"

    strings:
        $s1 = "function Invoke-Client()" ascii nocase wide
        $s2 = "function Invoke-Server" ascii nocase wide
        $s3 = "Read-Host 'Enter Command:'" ascii nocase wide
        $s4 = "new-object System.IO.Pipes.NamedPipeClientStream(" ascii nocase wide
        $s5 = "new-object System.IO.Pipes.NamedPipeServerStream(" ascii nocase wide
        $s6 = " = iex $" ascii nocase wide
    condition:
        all of them
}
