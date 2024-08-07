import "pe"

rule Borland
{
      meta:
        atk_type = "packer"
		author="malware-lu"
	strings:
		$patternBorland = "Borland" wide ascii
	condition:
		$patternBorland
}

rule borland_cpp {
	meta:
        atk_type = "packer"
		author = "_pusher_"
		description = "Borland C++"
		date = "2015-08"
		version = "0.1"
	strings:
		$c0 = { 59 5F 6A 00 E8 ?? ?? ?? ?? 59 68 ?? ?? ?? ?? 6A 00 E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? 6A 00 E9 ?? ?? ?? ?? E9 ?? ?? ?? ?? 33 C0 A0 ?? ?? ?? ?? C3 A1 ?? ?? ?? ?? C3 }
		$c1 = { A1 ?? ?? ?? ?? C1 E0 02 A3 ?? ?? ?? ?? 52 6A 00 E8 ?? ?? ?? ?? 8B D0 E8 ?? ?? ?? ?? 5A E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 6A 00 E8 ?? ?? ?? ?? 59 68 ?? ?? ?? ?? 6A 00 E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? 6A 00 E9 ?? ?? ?? ?? E9 ?? ?? ?? ?? 33 C0 A0 ?? ?? ?? ?? C3 A1 ?? ?? ?? ?? C3 }
		$c2 = { 6A 00 E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? 6A 00 E9 ?? ?? ?? ?? E9 ?? ?? ?? ?? 33 C0 A0 ?? ?? ?? ?? C3 A1 ?? ?? ?? ?? C3 }
	condition:
		(
		//linker 2.25 and 5.00
		((pe.linker_version.major == 2) and (pe.linker_version.minor == 25 )) or
		((pe.linker_version.major == 5) and (pe.linker_version.minor == 0 ))
		) and
		any of them
}

rule borland_delphi {
	meta:
        atk_type = "packer"
		author = "_pusher_"
		description = "Borland Delphi 2.0 - 7.0 / 2005 - 2007"
		date = "2016-03"
		version = "0.2"
	strings:
		$c0 = { 53 8B D8 33 C0 A3 ?? ?? ?? ?? 6A ?? E8 ?? ?? ?? FF A3 ?? ?? ?? ?? A1 ?? ?? ?? ?? A3 ?? ?? ?? ?? 33 C0 A3 ?? ?? ?? ?? 33 C0 A3 }
		$c1 = { 53 8B D8 33 C0 A3 ?? ?? ?? ?? 6A ?? E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? A1 ?? ?? ?? ?? A3 ?? ?? ?? ?? 33 C0 A3 ?? ?? ?? ?? 33 C0 A3 ?? ?? ?? ?? 8D 43 08 A3 ?? ?? ?? ?? E8 ?? ?? ?? ?? BA ?? ?? ?? ?? 8B C3 E8 ?? ?? ?? ?? 5B C3 }
		//some x64 version of delphi
		$c2 = { 53 48 83 EC 20 48 89 CB C7 05 ?? ?? ?? ?? ?? ?? ?? ?? 48 33 C9 E8 ?? ?? ?? ?? 48 89 05 ?? ?? ?? ?? 48 8B 05 ?? ?? ?? ?? 48 89 05 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 8D 43 10 48 89 05 ?? ?? ?? ?? 48 8D 05 ?? FC FF FF 48 89 05 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 89 D9 48 8D 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 83 C4 20 5B C3 }
		//unusual delphi version unknown version (unpackme- FSG 1.31 - dulek)
		$c3 = { 50 6A 00 E8 ?? ?? ?? ?? BA ?? ?? ?? ?? 52 89 05 ?? ?? ?? ?? 89 42 04 C7 42 08 00 00 00 00 C7 42 0C 00 00 00 00 E8 ?? ?? ?? ?? 5A 58 E8 ?? ?? ?? ?? C3 }
		//delphi2
		$c4 = { E8 ?? ?? ?? ?? 6A ?? E8 ?? ?? ?? ?? 89 05 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 05 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 0A ?? ?? ?? B8 ?? ?? ?? ?? C3 }
		//delphi3
		$c5 = { 50 6A 00 E8 ?? ?? FF FF BA ?? ?? ?? ?? 52 89 05 ?? ?? ?? ?? 89 42 04 E8 ?? ?? ?? ?? 5A 58 E8 ?? ?? ?? ?? C3 55 8B EC 33 C0 }
		//delphi5
		$c6 = { 50 6A ?? E8 ?? ?? FF FF BA ?? ?? ?? ?? 52 89 05 ?? ?? ?? ?? 89 42 04 C7 42 08 ?? ?? ?? ?? C7 42 0C ?? ?? ?? ?? E8 ?? ?? ?? ?? 5A 58 E8 ?? ?? ?? ?? C3 }
	condition:
		any of them
		and
		(
		//if its not linker 2.25 its been modified (unpacked usually)
												//unknown x64 build of delphi
		((pe.linker_version.major == 2) and (pe.linker_version.minor == 25 )) or ((pe.linker_version.major == 8) and (pe.linker_version.minor == 0 ))
		//unpacked files usually have this linker:
		or ((pe.linker_version.major == 0) and (pe.linker_version.minor == 0 )) )
		//could check for dvclal.. maybe too much
}

rule borland_delphi_dll {
	meta:
        atk_type = "packer"
		author = "_pusher_"
		description = "Borland Delphi DLL"
		date = "2015-08"
		version = "0.1"
		info = "one is at entrypoint"
	strings:
		$c0 = { BA ?? ?? ?? ?? 83 7D 0C 01 75 ?? 50 52 C6 05 ?? ?? ?? ?? ?? 8B 4D 08 89 0D ?? ?? ?? ?? 89 4A 04 }
		$c1 = { 55 8B EC 83 C4 ?? B8 ?? ?? ?? ?? E8 ?? ?? FF FF E8 ?? ?? FF FF 8D 40 00 }
	condition:
		any of them
}

rule borland_component {
	meta:
        atk_type = "packer"
		author = "_pusher_"
		description = "Borland Component"
		date = "2015-08"
		version = "0.1"
	strings:
		$c0 = { E9 ?? ?? ?? FF 8D 40 00 }
	condition:
		$c0 at pe.entry_point
}

rule SkDUndetectabler : SkDrat {
	meta:
        atk_type = "packer"
		author = "_pusher_"
	condition:
		(
		borland_delphi or //check All FSG or
		((pe.linker_version.major == 6) and (pe.linker_version.minor == 0 ))
		)
		and
		(pe.sections[pe.number_of_sections-1].raw_data_offset+pe.sections[pe.number_of_sections-1].raw_data_size < filesize) and
		//is overlay at offset 2A00,1A00,C00,745,739
		//pe.overlay & pe.overlay_size would have been prettier
		( 
		(pe.sections[pe.number_of_sections-1].raw_data_offset+pe.sections[pe.number_of_sections-1].raw_data_size == 0x00000739)  or
		(pe.sections[pe.number_of_sections-1].raw_data_offset+pe.sections[pe.number_of_sections-1].raw_data_size == 0x00000745)  or
		//Uncompressed
		(pe.sections[pe.number_of_sections-1].raw_data_offset+pe.sections[pe.number_of_sections-1].raw_data_size == 0x00000C00)  or
		(pe.sections[pe.number_of_sections-1].raw_data_offset+pe.sections[pe.number_of_sections-1].raw_data_size == 0x00002A00)  or
		(pe.sections[pe.number_of_sections-1].raw_data_offset+pe.sections[pe.number_of_sections-1].raw_data_size == 0x00001A00)
		)
		and
		//is xored MZ ?
		( 
		uint16(pe.sections[pe.number_of_sections-1].raw_data_offset+pe.sections[pe.number_of_sections-1].raw_data_size) == 0x6275 or
		uint16(pe.sections[pe.number_of_sections-1].raw_data_offset+pe.sections[pe.number_of_sections-1].raw_data_size) == 0x4057
		)
}

rule FSGv120EngdulekxtBorlandDelphiBorlandC
{
      meta:
        atk_type = "packer"
		author="malware-lu"
strings:
		$a0 = { 0F BE C1 EB 01 0E 8D 35 C3 BE B6 22 F7 D1 68 43 [2] 22 EB 02 B5 15 5F C1 F1 15 33 F7 80 E9 F9 BB F4 00 00 00 EB 02 8F D0 EB 02 08 AD 8A 16 2B C7 1B C7 80 C2 7A 41 80 EA 10 EB 01 3C 81 EA CF AE F1 AA EB 01 EC 81 EA BB C6 AB EE 2C E3 32 D3 0B CB 81 EA AB }

condition:
		$a0 at pe.entry_point
}

rule FSGv110EngdulekxtBorlandDelphiMicrosoftVisualCx
{
      meta:
        atk_type = "packer"
		author="malware-lu"
strings:
		$a0 = { 1B DB E8 02 00 00 00 1A 0D 5B 68 80 [2] 00 E8 01 00 00 00 EA 5A 58 EB 02 CD 20 68 F4 00 }

condition:
		$a0 at pe.entry_point
}

rule UPXFreakv01BorlandDelphiHMX0101
{
      meta:
        atk_type = "packer"
		author="malware-lu"
strings:
		$a0 = { BE [4] 83 C6 01 FF E6 00 00 00 [3] 00 03 00 00 00 [4] 00 10 00 00 00 00 [4] 00 00 ?? F6 ?? 00 B2 4F 45 00 ?? F9 ?? 00 EF 4F 45 00 ?? F6 ?? 00 8C D1 42 00 ?? 56 ?? 00 [3] 00 [3] 00 [3] 00 ?? 24 ?? 00 [3] 00 }
	$a1 = { BE [4] 83 C6 01 FF E6 00 00 00 [3] 00 03 00 00 00 [4] 00 10 00 00 00 00 [4] 00 00 ?? F6 ?? 00 B2 4F 45 00 ?? F9 ?? 00 EF 4F 45 00 ?? F6 ?? 00 8C D1 42 00 ?? 56 ?? 00 [3] 00 [3] 00 [3] 00 ?? 24 ?? 00 [3] 00 34 50 45 00 [3] 00 FF FF 00 00 ?? 24 ?? 00 ?? 24 ?? 00 [3] 00 40 00 00 C0 00 00 [4] 00 00 ?? 00 00 00 ?? 1E ?? 00 ?? F7 ?? 00 A6 4E 43 00 ?? 56 ?? 00 AD D1 42 00 ?? F7 ?? 00 A1 D2 42 00 ?? 56 ?? 00 0B 4D 43 00 ?? F7 ?? 00 ?? F7 ?? 00 ?? 56 ?? 00 [5] 00 00 00 [7] 77 [3] 00 [3] 00 [3] 77 [2] 00 00 [3] 00 [6] 00 00 [3] 00 [11] 00 [4] 00 00 00 00 [3] 00 }

condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}

rule PseudoSigner02BorlandC1999Anorganix
{
      meta:
        atk_type = "packer"
		author="malware-lu"
strings:
		$a0 = { EB 10 66 62 3A 43 2B 2B 48 4F 4F 4B 90 E9 90 90 90 90 A1 [4] A3 }

condition:
		$a0 at pe.entry_point
}

rule FSGv110EngdulekxtBorlandC1999
{
      meta:
        atk_type = "packer"
		author="malware-lu"
strings:
		$a0 = { EB 02 CD 20 2B C8 68 80 [2] 00 EB 02 1E BB 5E EB 02 CD 20 68 B1 2B 6E 37 40 5B 0F B6 C9 }

condition:
		$a0 at pe.entry_point
}

rule FSGv110EngdulekxtBorlandC
{
      meta:
        atk_type = "packer"
		author="malware-lu"
strings:
		$a0 = { 23 CA EB 02 5A 0D E8 02 00 00 00 6A 35 58 C1 C9 10 BE 80 [2] 00 0F B6 C9 EB 02 CD 20 BB }
	$a1 = { 23 CA EB 02 5A 0D E8 02 00 00 00 6A 35 58 C1 C9 10 BE 80 [2] 00 0F B6 C9 EB 02 CD 20 BB F4 00 00 00 EB 02 04 FA EB 01 FA EB 01 5F EB 02 CD 20 8A 16 EB 02 11 31 80 E9 31 EB 02 30 11 C1 E9 11 80 EA 04 EB 02 F0 EA 33 CB 81 EA AB AB 19 08 04 D5 03 C2 80 EA }

condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}

rule AHTeamEPProtector03fakeBorlandDelphi6070FEUERRADER
{
      meta:
        atk_type = "packer"
		author="malware-lu"
strings:
		$a0 = { 90 [46] 90 FF E0 53 8B D8 33 C0 A3 00 00 00 00 6A 00 E8 00 00 00 FF A3 00 00 00 00 A1 00 00 00 00 A3 00 00 00 00 33 C0 A3 00 00 00 00 33 C0 A3 00 00 00 00 E8 }

condition:
		$a0 at pe.entry_point
}

rule PseudoSigner01BorlandDelphi6070Anorganix
{
      meta:
        atk_type = "packer"
		author="malware-lu"
strings:
		$a0 = { 90 90 90 90 68 [4] 67 64 FF 36 00 00 67 64 89 26 00 00 F1 90 90 90 90 53 8B D8 33 C0 A3 09 09 09 00 6A 00 E8 09 09 00 FF A3 09 09 09 00 A1 09 09 09 00 A3 09 09 09 00 33 C0 A3 09 09 09 00 33 C0 A3 09 09 09 00 E8 }

condition:
		$a0 at pe.entry_point
}

rule FSGv110EngdulekxtBorlandDelphiBorlandC
{
      meta:
        atk_type = "packer"
		author="malware-lu"
strings:
		$a0 = { 2B C2 E8 02 00 00 00 95 4A 59 8D 3D 52 F1 2A E8 C1 C8 1C BE 2E [2] 18 EB 02 AB A0 03 F7 }
	$a1 = { 2B C2 E8 02 00 00 00 95 4A 59 8D 3D 52 F1 2A E8 C1 C8 1C BE 2E [2] 18 EB 02 AB A0 03 F7 EB 02 CD 20 68 F4 00 00 00 0B C7 5B 03 CB 8A 06 8A 16 E8 02 00 00 00 8D 46 59 EB 01 A4 02 D3 EB 02 CD 20 02 D3 E8 02 00 00 00 57 AB 58 81 C2 AA 87 AC B9 0F BE C9 80 }
	$a2 = { EB 01 2E EB 02 A5 55 BB 80 [2] 00 87 FE 8D 05 AA CE E0 63 EB 01 75 BA 5E CE E0 63 EB 02 }

condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point or $a2 at pe.entry_point
}

rule FSGv120EngdulekxtBorlandDelphiMicrosoftVisualC
{
      meta:
        atk_type = "packer"
		author="malware-lu"
strings:
		$a0 = { 0F B6 D0 E8 01 00 00 00 0C 5A B8 80 [2] 00 EB 02 00 DE 8D 35 F4 00 00 00 F7 D2 EB 02 0E EA 8B 38 EB 01 A0 C1 F3 11 81 EF 84 88 F4 4C EB 02 CD 20 83 F7 22 87 D3 33 FE C1 C3 19 83 F7 26 E8 02 00 00 00 BC DE 5A 81 EF F7 EF 6F 18 EB 02 CD 20 83 EF 7F EB 01 }

condition:
		$a0 at pe.entry_point
}

rule PseudoSigner02BorlandDelphiSetupModuleAnorganix
{
      meta:
        atk_type = "packer"
		author="malware-lu"
strings:
		$a0 = { 55 8B EC 83 C4 90 53 56 57 33 C0 89 45 F0 89 45 D4 89 45 D0 E8 00 00 00 00 }

condition:
		$a0 at pe.entry_point
}

rule PseudoSigner02BorlandDelphiDLLAnorganix
{
      meta:
        atk_type = "packer"
		author="malware-lu"
strings:
		$a0 = { 55 8B EC 83 C4 B4 B8 90 90 90 90 E8 00 00 00 00 E8 00 00 00 00 8D 40 00 }

condition:
		$a0 at pe.entry_point
}

rule PseudoSigner01BorlandDelphi50KOLMCKAnorganix
{
      meta:
        atk_type = "packer"
		author="malware-lu"
strings:
		$a0 = { 55 8B EC 90 90 90 90 68 [4] 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 00 FF 90 90 90 90 90 90 90 90 00 01 90 90 90 90 90 90 90 90 90 EB 04 00 00 00 01 90 90 90 90 90 90 90 00 01 90 90 90 90 90 90 90 90 90 }

condition:
		$a0 at pe.entry_point
}

rule FSGv110EngdulekxtBorlandDelphiMicrosoftVisualCASM
{
      meta:
        atk_type = "packer"
		author="malware-lu"
strings:
		$a0 = { EB 02 CD 20 EB 02 CD 20 EB 02 CD 20 C1 E6 18 BB 80 [2] 00 EB 02 82 B8 EB 01 10 8D 05 F4 }

condition:
		$a0 at pe.entry_point
}

rule FSGv120EngdulekxtBorlandC
{
      meta:
        atk_type = "packer"
		author="malware-lu"
strings:
		$a0 = { C1 F0 07 EB 02 CD 20 BE 80 [2] 00 1B C6 8D 1D F4 00 00 00 0F B6 06 EB 02 CD 20 8A 16 0F B6 C3 E8 01 00 00 00 DC 59 80 EA 37 EB 02 CD 20 2A D3 EB 02 CD 20 80 EA 73 1B CF 32 D3 C1 C8 0E 80 EA 23 0F B6 C9 02 D3 EB 01 B5 02 D3 EB 02 DB 5B 81 C2 F6 56 7B F6 }

condition:
		$a0 at pe.entry_point
}

rule PseudoSigner02BorlandCDLLMethod2Anorganix
{
      meta:
        atk_type = "packer"
		author="malware-lu"
strings:
		$a0 = { EB 10 66 62 3A 43 2B 2B 48 4F 4F 4B 90 E9 90 90 90 90 }

condition:
		$a0 at pe.entry_point
}

rule FSGv110EngdulekxtBorlandDelphiMicrosoftVisualC
{
      meta:
        atk_type = "packer"
		author="malware-lu"
strings:
		$a0 = { 1B DB E8 02 00 00 00 1A 0D 5B 68 80 [2] 00 E8 01 00 00 00 EA 5A 58 EB 02 CD 20 68 F4 00 00 00 EB 02 CD 20 5E 0F B6 D0 80 CA 5C 8B 38 EB 01 35 EB 02 DC 97 81 EF F7 65 17 43 E8 02 00 00 00 97 CB 5B 81 C7 B2 8B A1 0C 8B D1 83 EF 17 EB 02 0C 65 83 EF 43 13 }
	$a1 = { C1 C8 10 EB 01 0F BF 03 74 66 77 C1 E9 1D 68 83 [2] 77 EB 02 CD 20 5E EB 02 CD 20 2B F7 }

condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}

rule FSGv110EngdulekxtBorlandDelphi20
{
      meta:
        atk_type = "packer"
		author="malware-lu"
strings:
		$a0 = { EB 01 56 E8 02 00 00 00 B2 D9 59 68 80 ?? 41 00 E8 02 00 00 00 65 32 59 5E EB 02 CD 20 BB }

condition:
		$a0 at pe.entry_point
}

rule PseudoSigner01BorlandDelphi30Anorganix
{
      meta:
        atk_type = "packer"
		author="malware-lu"
strings:
		$a0 = { 55 8B EC 83 C4 90 90 90 90 68 [4] 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }

condition:
		$a0 at pe.entry_point
}