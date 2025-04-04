// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule Hunting_LNK_Win_GenericLauncher
{
    meta:
        id = "5EU6IjfNFY43Lnc0UfMSu5"
        fingerprint = "v1_sha256_a654cd3594e2d09950fb11bf8721a5cdb89f5d5be6e706f12e18c7fcdf7dd0fe"
        version = "1.0"
        date = "09/04/2018"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "FireEye"
        description = "Signature to detect LNK files or OLE objects with embedded LNK files and generic launcher commands, except powershell which is large enough to have its own gene"
        category = "INFO"
        md5 = "14dd758e8f89f14612c8df9f862c31e4"
        rev = 7

    strings:
        $a01 = "cmd.exe /" ascii nocase wide
        $a02 = "cscript" ascii nocase wide
        $a03 = "jscript" ascii nocase wide
        $a04 = "wscript" ascii nocase wide
        $a05 = "wmic" ascii nocase wide
        $a07 = "mshta" ascii nocase wide
        $header = { 4C 00 00 00 01 14 02 }
    condition:
        (($header at 0) or ((uint32(0) == 0xE011CFD0) and $header)) and (1 of ($a*))
}
