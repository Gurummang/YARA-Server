rule win_lodeinfo_auto {

    meta:
        atk_type = "win.lodeinfo."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.lodeinfo."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.lodeinfo"
        malpedia_rule_date = "20231130"
        malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
        malpedia_version = "20230808"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    /* DISCLAIMER
     * The strings used in this rule have been automatically selected from the
     * disassembly of memory dumps and unpacked files, using YARA-Signator.
     * The code and documentation is published here:
     * https://github.com/fxb-cocacoding/yara-signator
     * As Malpedia is used as data source, please note that for a given
     * number of families, only single samples are documented.
     * This likely impacts the degree of generalization these rules will offer.
     * Take the described generation method also into consideration when you
     * apply the rules in your use cases and assign them confidence levels.
     */


    strings:
        $sequence_0 = { 894de0 8955f0 8955f8 8955f4 85ff 740a 381433 }
            // n = 7, score = 200
            //   894de0               | mov                 dword ptr [ebp - 0x20], ecx
            //   8955f0               | mov                 dword ptr [ebp - 0x10], edx
            //   8955f8               | mov                 dword ptr [ebp - 8], edx
            //   8955f4               | mov                 dword ptr [ebp - 0xc], edx
            //   85ff                 | test                edi, edi
            //   740a                 | je                  0xc
            //   381433               | cmp                 byte ptr [ebx + esi], dl

        $sequence_1 = { 85c0 7412 ff75f4 8b55f0 8bc8 e8???????? 83c404 }
            // n = 7, score = 200
            //   85c0                 | test                eax, eax
            //   7412                 | je                  0x14
            //   ff75f4               | push                dword ptr [ebp - 0xc]
            //   8b55f0               | mov                 edx, dword ptr [ebp - 0x10]
            //   8bc8                 | mov                 ecx, eax
            //   e8????????           |                     
            //   83c404               | add                 esp, 4

        $sequence_2 = { 85ff 742e 8b4c2444 8bc7 }
            // n = 4, score = 200
            //   85ff                 | test                edi, edi
            //   742e                 | je                  0x30
            //   8b4c2444             | mov                 ecx, dword ptr [esp + 0x44]
            //   8bc7                 | mov                 eax, edi

        $sequence_3 = { 660fefc8 0f114c0620 0f10440630 0f28ca 660fefc8 0f114c0630 83c040 }
            // n = 7, score = 200
            //   660fefc8             | pxor                xmm1, xmm0
            //   0f114c0620           | movups              xmmword ptr [esi + eax + 0x20], xmm1
            //   0f10440630           | movups              xmm0, xmmword ptr [esi + eax + 0x30]
            //   0f28ca               | movaps              xmm1, xmm2
            //   660fefc8             | pxor                xmm1, xmm0
            //   0f114c0630           | movups              xmmword ptr [esi + eax + 0x30], xmm1
            //   83c040               | add                 eax, 0x40

        $sequence_4 = { 5d c3 8b75fc 8b55f0 33c9 85d2 7429 }
            // n = 7, score = 200
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   8b75fc               | mov                 esi, dword ptr [ebp - 4]
            //   8b55f0               | mov                 edx, dword ptr [ebp - 0x10]
            //   33c9                 | xor                 ecx, ecx
            //   85d2                 | test                edx, edx
            //   7429                 | je                  0x2b

        $sequence_5 = { 8bda 8b5508 57 8bf9 895df8 8b06 }
            // n = 6, score = 200
            //   8bda                 | mov                 ebx, edx
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   57                   | push                edi
            //   8bf9                 | mov                 edi, ecx
            //   895df8               | mov                 dword ptr [ebp - 8], ebx
            //   8b06                 | mov                 eax, dword ptr [esi]

        $sequence_6 = { e8???????? 83c404 894708 85c0 750d 39460c 7408 }
            // n = 7, score = 200
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   894708               | mov                 dword ptr [edi + 8], eax
            //   85c0                 | test                eax, eax
            //   750d                 | jne                 0xf
            //   39460c               | cmp                 dword ptr [esi + 0xc], eax
            //   7408                 | je                  0xa

        $sequence_7 = { 03c8 8b4510 d1e9 024fff 884c17ff 8b4dd4 3bf3 }
            // n = 7, score = 200
            //   03c8                 | add                 ecx, eax
            //   8b4510               | mov                 eax, dword ptr [ebp + 0x10]
            //   d1e9                 | shr                 ecx, 1
            //   024fff               | add                 cl, byte ptr [edi - 1]
            //   884c17ff             | mov                 byte ptr [edi + edx - 1], cl
            //   8b4dd4               | mov                 ecx, dword ptr [ebp - 0x2c]
            //   3bf3                 | cmp                 esi, ebx

        $sequence_8 = { eb72 8b45f0 8975f4 c64406ff00 eb65 8b45f8 8d7e01 }
            // n = 7, score = 200
            //   eb72                 | jmp                 0x74
            //   8b45f0               | mov                 eax, dword ptr [ebp - 0x10]
            //   8975f4               | mov                 dword ptr [ebp - 0xc], esi
            //   c64406ff00           | mov                 byte ptr [esi + eax - 1], 0
            //   eb65                 | jmp                 0x67
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]
            //   8d7e01               | lea                 edi, [esi + 1]

        $sequence_9 = { 85c0 748e 33c0 0f57c0 b920010000 8bfa }
            // n = 6, score = 200
            //   85c0                 | test                eax, eax
            //   748e                 | je                  0xffffff90
            //   33c0                 | xor                 eax, eax
            //   0f57c0               | xorps               xmm0, xmm0
            //   b920010000           | mov                 ecx, 0x120
            //   8bfa                 | mov                 edi, edx

    condition:
        7 of them and filesize < 712704
}