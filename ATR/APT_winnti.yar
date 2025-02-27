rule APT_winnti {

    meta:
        id = "3XAT9E9Nvjy3RplKtFsGpL"
        fingerprint = "v1_sha256_f94b2c552fbb30e1005e5c75a2f449d60b9558a0916197bed41bf32c6477daef"
        version = "1.0"
        date = "2020-06-04"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ATR"
        author = "McAfee ATR Team"
        description = "Detects Winnti variants"
        category = "INFO"
        reference = "https://attack.mitre.org/software/S0141/"
        hash = "fd539d345821d9ac9b885811b1f642aa1817ba8501d47bc1de575f5bef2fbf9e"
        rule_version = "v1"
        malware_family = "Backdoor:W32/Winnti"
        actor_group = "Unknown"

    strings:
        /*
        BYTES:
        9090909090909090909090909090C7413801000000C2040090909090909081E95C0C0000E925AD0000CCCCCCCCCC8A4424088B4C240C538AD88AFB568BC3578B7C24108BD1C1E010668BC38BF7C1E902F3AB8BCA83E103F3AA8BC65F5E5BC390909090909090909090909090909083EC105333DB568D4424085350895C2414895C2410E8960000008A1033C93AD38D5424100F94C183E10153895C2414528BF1895C241CC644241880E8700000008B1033C981FA800000008D5424180F94C16A01895C241C5223F1895C2424C644242001C644242302E84300000033C96639188D5424206A010F94C1895C2428895C24245223F1C644242803C644242D04E81B0000008B1083C42033C93BD30F94C123CE5E495BF7D91BC98BC183C410C38B4424088B4C240403C1C390909090908B44240485C00F84830000008B44240883F8FF740583F80275758B44240C83F8FF740583F80475678B44241083F8FF740583F80475598B44241483F8FF740583F804754B8B44241883F8FF740583F804753D8B44241C83F8FF740583F804752F8B44242083F8FF740583F80475218B44242483F8FF740583F80475138B44242883F8FF740583F8187505E9B1FEFFFF83C8FFC39090909090909090909090909083EC088B54240C53558B6C241833DB568B74242083FD145789542410766D81FD00C000008BFD7605BF00C000008B4424108D0C1F03C7C1E90503C8894424143BC876488B54242C68008000006A0052E80CFEFFFF8B4424388B4C24348B54241C505351565752E8E50000008B4C244C8BD88B4424382BEF8B1183C42403F28B54241C83FD1489442410779303DD0F84920000008B4C24208B4424242BD303D13BF08954242C750E81FBEE00000077068AC30411EB6483FB037705085EFEEB5D83FB1277098ACB80E903880EEB4E8D43EEC60600463DFF0000008944241C763A8D50FFB881808080F7E2C1EA078BCA33C08BE98BFEC1E902F3AB8BCD83E10303F2F3AA8B4C241C81E9FF0000004A894C241C75EF8B54242C8BC18806468A02880646424B75F78B4C2424C60611465FC6060046C606002BF18B4C24244633C089315E5D5B83C408C390909090909090909083EC108B44241853558B6C241C568B7424288D0C2857894C24188B4C243483F9047309B8040000002BC1EB0233C003C58BD02BD5C1FA058D441001894424288B5424188B4C24288D42EC3BC80F83D50200008B098BC169C09D4224188B5424388B5C2424C1E81233FF668B3C4203FB8B5C24282B5C2424897C241466891C428B073BC80F85950200008B4C2434C7442434000000002BE98B4C24288BD92BDD0F84DE00000083FB0377148A56FE0AD38856FE8B5500891603F3E9C500000083FB1077258AC32C038806468B550089168B45048946048B55088956088B450C89460C03F3E99B00000083FB12770A8AD380EA03881646EB598D43EEC60600463DFF0000008944241076408D48FFB881808080F7E18BCA33C0C1E907894C241C8BD18BFEC1E902F3AB8BCA83E103F3AA8BC203F08B54241081EAFF000000488954241075EF8B7C24148BC28B4C24288806468B450089068B55048956048B45088946088B550C89560C83EB1083C61083C51083FB1073DB85DB760A8A4500880646454B75F6BB040000008B47048B510433C2753ABB0800000003CB8B47088B1133C28B54241883C2EC3BCA732D8BEF2B6C242885C0751783C10483C3048B04298B3933C78B7C24143BCA72E7EB0C84C07508C1E8084384C074F88B6C24288BC503EB2BC783FB08896C242877263D00080000771F4880C3078AC880E107C0E102C0E3050ACB880E46C1E803880646E92EFEFFFF3D00400000776D4883FB2189442414770880EB0280CB20EB4583EB21C606204681FBFF00000076368D53FFB881808080F7E28BCA33C0C1E907894C241C8BD18BFEC1E902F3AB8BCA83E103F3AA8BC203F081EBFF0000004875F78B442414881E8AC846C0E102880E46C1E806880646E9BAFDFFFF2D0040000083FB098944241477268BD080EB02C1EA0B80E2088AC80AD380CA10881646C0E102880E46C1E806880646E986FDFFFF8BC883EB09C1E90B80E10880C910880E4681FBFF000000769D8D53FFB881808080F7E28BCA33C0C1E907894C241C8BD18BFEC1E902F3AB8BCA83E103F3AA8BC203F081EBFF0000004875F78B442414881E8AC846C0E102880E46C1E806880646E921FDFFFF8B442428E909FDFFFF8B7C242C8B4424308B4C24342BF789308BC25F2BC55E5D03C15B83C410C390909090909090909090908B442408538B5C241455568B742410C70300000000578A168D2C068B44241C80FA118BCE762281E2FF0000008D4E0183EA118BFA83FF040F82BD0000008A11881040414F75F7EB6C33D28A11418BF283FE100F83C500000085F6751C803900750E8A510181C6FF0000004184D274F233D28A11418D74160F8B11891083C00483C1044E742F83FE0472218B11891083EE0483C00483C10483FE0473EE85F676148A11881040414E75F7EB098A11881040414E75F733D28A11418BF283FE10735D33D28BF88A11C1EE022BFEC1E2022BFA8A97FFF7FFFF81EF0108000041881040478A1788108A5701408810408A51FE83E2038BFA0F844EFFFFFF8A118810404183FF0176118A118810404183FF0276068A118810404133D28A11418BF283FE4072338BD68BF8C1EA0283E2072BFA33D28A11C1E2032BFA4F41C1EE054E8A1788108A57014047881040478A17881040474E75F7EB9783FE20723783E61F751C803900750E8A510181C6FF0000004184D274F233D28A11418D74161F8D78FF668B1181E2FFFF0000C1EA022BFA83C102EB5183FE100F82930000008BD68BF883E208C1E20B2BFA83E607751C803900750E8A510181C6FF0000004184D274F233D28A11418D741607668B1181E2FFFF0000C1EA022BFA83C1023BF8746881EF0040000083FE060F8252FFFFFF8BD02BD783FA040F8C45FFFFFF8B17891083C00483C70483EE028B17891083EE0483C00483C70483FE0473EE85F60F86CDFEFFFF8A17881040474E75F7E9BFFEFFFF33D28BF88A11C1EE022BFEC1E2022BFA4F41E99DFEFFFF8B54241C2BC23BCD890375075F5E5D33C05BC31BC05F24FC5E5D83C0FC5BC39090909090909090909090909081EC90010000568BF16828230310C706F8590110FF151041011083F801753A57B96300000033C08D7C240A66C74424080000F3AB66AB8D442408506802020000FF159842011083F8FF5F750D6A006828230310FF150C4101108BC65E81C490010000C390909090909090909090909090568BF1E818000000F644240801740956E87F5B000083C4048BC65EC2040090906828230310C701F8590110FF151441011085C07506FF258C420110C39090909053558B6C240C5685ED57744E8B5C241885DB744633C933F633FF85DB763C8A8684A201108A9778A2011032D080E22732D08A042932C233D28804298D4601BE0C000000F7F68D4701BF0C0000008BF233D2F7F7413BCB8BFA72C45F5E5D5BC39083EC10538B5C241C5556576890A2011068FC5901105333EDFF15B44001108BF885FF0F849C0000006820970110FF15084101108BF0B065884424158844241B8D442410B16F5056C64424184C884C2419C644241A61C644241B64C644241C52C644241E73884C241FC644242075C644242172C644242263C644242400FF15344101105753FFD0568BF8FF152C41011085FF743157FF15B84001108BF08B442424B9C00400008BF8680013000050F3A5E8ECFEFFFF83C408B8010000005F5E5D5B83C410C35F8BC55E5D5B83C410C39090538B1D204201105657C7010C5A01108D7144BF10000000
        */

        $pattern = { 9090909090909090909090909090C7????????????C2????90909090909081??????????E9????????CCCCCCCCCC8A??????8B??????538A??8A??568B??578B??????8B??C1????66????8B??C1????F3AB8B??83????F3AA8B??5F5E5BC390909090909090909090909090909083????5333??568D??????535089??????89??????E8????????8A??33??3A??8D??????0F94??83????5389??????528B??89??????C6????????E8????????8B??33??81??????????8D??????0F94??6A??89??????5223??89??????C6????????C6????????E8????????33??66????8D??????6A??0F94??89??????89??????5223??C6????????C6????????E8????????8B??83????33??3B??0F94??23??5E495BF7??1B??8B??83????C38B??????8B??????03??C390909090908B??????85??0F84????????8B??????83????74??83????75??8B??????83????74??83????75??8B??????83????74??83????75??8B??????83????74??83????75??8B??????83????74??83????75??8B??????83????74??83????75??8B??????83????74??83????75??8B??????83????74??83????75??8B??????83????74??83????75??E9????????83????C39090909090909090909090909083????8B??????53558B??????33??568B??????83????5789??????76??81??????????8B??76??BF????????8B??????8D????03??C1????03??89??????3B??76??8B??????68????????6A??52E8????????8B??????8B??????8B??????505351565752E8????????8B??????8B??8B??????2B??8B??83????03??8B??????83????89??????77??03??0F84????????8B??????8B??????2B??03??3B??89??????75??81??????????77??8A??04??EB??83????77??08????EB??83????77??8A??80????88??EB??8D????C6????463D????????89??????76??8D????B8????????F7??C1????8B??33??8B??8B??C1????F3AB8B??83????03??F3AA8B??????81??????????4A89??????75??8B??????8B??88??468A??88??46424B75??8B??????C6????465FC6????46C6????2B??8B??????4633??89??5E5D5B83????C390909090909090909083????8B??????53558B??????568B??????8D????5789??????8B??????83????73??B8????????2B??EB??33??03??8B??2B??C1????8D??????89??????8B??????8B??????8D????3B??0F83????????8B??8B??69??????????8B??????8B??????C1????33??66??????03??8B??????2B??????89??????66??????8B??3B??0F85????????8B??????C7??????????????2B??8B??????8B??2B??0F84????????83????77??8A????0A??88????8B????89??03??E9????????83????77??8A??2C??88??468B????89??8B????89????8B????89????8B????89????03??E9????????83????77??8A??80????88??46EB??8D????C6????463D????????89??????76??8D????B8????????F7??8B??33??C1????89??????8B??8B??C1????F3AB8B??83????F3AA8B??03??8B??????81??????????4889??????75??8B??????8B??8B??????88??468B????89??8B????89????8B????89????8B????89????83????83????83????83????73??85??76??8A????88??46454B75??BB????????8B????8B????33??75??BB????????03??8B????8B??33??8B??????83????3B??73??8B??2B??????85??75??83????83????8B????8B??33??8B??????3B??72??EB??84??75??C1????4384??74??8B??????8B??03??2B??83????89??????77??3D????????77??4880????8A??80????C0????C0????0A??88??46C1????88??46E9????????3D????????77??4883????89??????77??80????80????EB??83????C6????4681??????????76??8D????B8????????F7??8B??33??C1????89??????8B??8B??C1????F3AB8B??83????F3AA8B??03??81??????????4875??8B??????88??8A??46C0????88??46C1????88??46E9????????2D????????83????89??????77??8B??80????C1????80????8A??0A??80????88??46C0????88??46C1????88??46E9????????8B??83????C1????80????80????88??4681??????????76??8D????B8????????F7??8B??33??C1????89??????8B??8B??C1????F3AB8B??83????F3AA8B??03??81??????????4875??8B??????88??8A??46C0????88??46C1????88??46E9????????8B??????E9????????8B??????8B??????8B??????2B??89??8B??5F2B??5E5D03??5B83????C390909090909090909090908B??????538B??????55568B??????C7??????????578A??8D????8B??????80????8B??76??81??????????8D????83????8B??83????0F82????????8A??88??40414F75??EB??33??8A??418B??83????0F83????????85??75??80????75??8A????81??????????4184??74??33??8A??418D??????8B??89??83????83????4E74??83????72??8B??89??83????83????83????83????73??85??76??8A??88??40414E75??EB??8A??88??40414E75??33??8A??418B??83????73??33??8B??8A??C1????2B??C1????2B??8A??????????81??????????4188??40478A??88??8A????4088??408A????83????8B??0F84????????8A??88??404183????76??8A??88??404183????76??8A??88??404133??8A??418B??83????72??8B??8B??C1????83????2B??33??8A??C1????2B??4F41C1????4E8A??88??8A????404788??40478A??88??40474E75??EB??83????72??83????75??80????75??8A????81??????????4184??74??33??8A??418D??????8D????66????81??????????C1????2B??83????EB??83????0F82????????8B??8B??83????C1????2B??83????75??80????75??8A????81??????????4184??74??33??8A??418D??????66????81??????????C1????2B??83????3B??74??81??????????83????0F82????????8B??2B??83????0F8C????????8B??89??83????83????83????8B??89??83????83????83????83????73??85??0F86????????8A??88??40474E75??E9????????33??8B??8A??C1????2B??C1????2B??4F41E9????????8B??????2B??3B??89??75??5F5E5D33??5BC31B??5F24??5E5D83????5BC39090909090909090909090909081??????????568B??68????????C7??????????FF??????????83????75??57B9????????33??8D??????66????????????F3AB66AB8D??????5068????????FF??????????83????5F75??6A??68????????FF??????????8B??5E81??????????C390909090909090909090909090568B??E8????????F6????????74??56E8????????83????8B??5EC2????909068????????C7??????????FF??????????85??75??FF??????????C39090909053558B??????5685??5774??8B??????85??74??33??33??33??85??76??8A??????????8A??????????32??80????32??8A????32??33??88????8D????BE????????F7??8D????BF????????8B??33??F7??413B??8B??72??5F5E5D5BC39083????538B??????55565768????????68????????5333??FF??????????8B??85??0F84????????68????????FF??????????8B??B0??88??????88??????8D??????B1??5056C6????????88??????C6????????C6????????C6????????C6????????88??????C6????????C6????????C6????????C6????????FF??????????5753FF??568B??FF??????????85??74??57FF??????????8B??8B??????B9????????8B??68????????50F3A5E8????????83????B8????????5F5E5D5B83????C35F8B??5E5D5B83????C39090538B??????????5657C7??????????8D????BF???????? }

        condition:
             uint16(0) == 0x5a4d and
             filesize < 400KB and
             all of them
}
