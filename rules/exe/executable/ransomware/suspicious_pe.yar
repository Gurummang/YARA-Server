import "pe"

rule SuspiciousEntryPoint
{
    meta:
        atk_type= "suspicious_entrypoint"
        description = "Detects if entry point is greater than image size"

    condition:
        uint16(0) == 0x5A4D and
        pe.is_pe and
        pe.entry_point > pe.size_of_image or pe.entry_point > pe.size_of_image * 0.9
}

rule EntryPointZero
{
    meta:
        atk_type= "suspicious_entrypoint"
        description = "Detects if entry point is zero"
    
    condition:
        uint16(0) == 0x5A4D and
        pe.is_pe and
        pe.entry_point == 0x0
}

rule missing_certificate
{
    meta:
        atk_type= "missing_certificate"
        description = "Detects PE files that do not have a digital signature"
    condition:
        uint16(0) == 0x5A4D and         
        pe.is_pe and                     
        pe.number_of_signatures == 0    
}

rule SectionSizeGreaterThanImageSize
{
    meta:
        atk_type= "suspicious_section"
        description = "Detects if any section size is greater than image size"

    condition:
        uint16(0) == 0x5A4D and
        pe.is_pe and
        for any i in (0..pe.number_of_sections - 1) : (
            pe.sections[i].raw_data_size > pe.size_of_image
        )
}

rule TextSectionLargerThanHalfImageSize
{
    meta:
        atk_type= "suspicious_section"
        description = "Detects if .text section is larger than half of the image size"

    condition:
        uint16(0) == 0x5A4D and
        pe.is_pe and
        (pe.characteristics & 0x2000 == 0) and // .dll 파일이 아닌지 확인
        (pe.characteristics & 0x0002 != 0) and // .exe 파일인지 확인
        for any i in (0..pe.number_of_sections - 1) : (
                pe.sections[i].name == ".text" and pe.sections[i].raw_data_size > pe.size_of_image * 0.5
        )
}

rule SC_Signed_Executable_With_Custom_Elliptic_Curve_Parameters
{

	meta:
        atk_type= "suspicious_certificate"
		Author = "InQuest Labs"
		CVE = "CVE-2020-0601"
		Description = "This signature detects a Microsoft Windows executable that has been signed using Elliptic Curve Cryptography (ECC) certificates with an explicit curve. Additionally, this rule will detect files related to CVE-2020-0601 (ChainOfFools or CurveBall) which is a spoofing vulnerability that exists in the way Windows CryptoAPI (Crypt32.dll) validates the Elliptic Curve Cryptography (ECC) certificates. It is good to note that while not inherently malicious, such signatures are uncommon and can be used to bypass code signing verification in certain vulnerable configurations."
		References = "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-0601,https://gist.github.com/SwitHak/62fa7f8df378cae3a459670e3a18742d"

	strings:
			/* 06                            - OBJECT IDENTIFIER
       * 09 2A 86 48 86 F7 0D 01 07 02 - PKCS#7 signedData
       */
      $pkcs7_oid               = {06 09 2A 86 48 86 F7 0D 01 07 02}

      /* the \x30 and the first alternation check for the enclosing sequence;
       * we ensure that the sequence is longer than 10 bytes, and check for
       * lengths of up to 4GB
       *
       * if the length were equal to 10, that would imply that the sequence
       * containing our key algorithm OID is the only thing in the sequence,
       * meaning it doesnt have explicit curve parameters
       *
       * 06                            - OBJECT IDENTIFIER
       * 07 2A 86 48 CE 3D 02 01       - ANSI X9.52 Public Key Type - ecPublicKey
       * 30                            - Sequence tag (implies non-named-curve)
       */
      $oid_asn_public_key_type = /\x30([\x0b-\x7f]|\x81.|\x82..|\x83...|\x84....)\x06\x07\x2a\x86\x48\xce\x3d\x02\x01\x30/
	condition:
			/* its a signed PE */
      int16(0) == 0x5A4D and pe.number_of_signatures > 0
      and

      /* at least one signature is using ECDSA */
      for any i in (0..pe.number_of_signatures - 1):
      (
       	 pe.signatures[i].algorithm contains "ecdsa"
      )
      and

      /* the EC public key identifier exists, and its after the start of the certificate */
      for all i in (1..#pkcs7_oid) : (
          for all j in (1..#oid_asn_public_key_type) : (
              @oid_asn_public_key_type[j] > @pkcs7_oid[i]
          )
      )
}
