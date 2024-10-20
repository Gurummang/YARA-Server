rule win_mimikatz_auto {

    meta:
        atk_type = "win.mimikatz."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.mimikatz."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.mimikatz"
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
        $sequence_0 = { f7f1 85d2 7406 2bca }
            // n = 4, score = 300
            //   f7f1                 | div                 ecx
            //   85d2                 | test                edx, edx
            //   7406                 | je                  8
            //   2bca                 | sub                 ecx, edx

        $sequence_1 = { 83f8ff 750e ff15???????? c7002a000000 }
            // n = 4, score = 300
            //   83f8ff               | cmp                 eax, -1
            //   750e                 | jne                 0x10
            //   ff15????????         |                     
            //   c7002a000000         | mov                 dword ptr [eax], 0x2a

        $sequence_2 = { c3 81f998000000 7410 81f996000000 7408 }
            // n = 5, score = 200
            //   c3                   | ret                 
            //   81f998000000         | cmp                 ecx, 0x98
            //   7410                 | je                  0x12
            //   81f996000000         | cmp                 ecx, 0x96
            //   7408                 | je                  0xa

        $sequence_3 = { e8???????? 894720 85c0 7413 }
            // n = 4, score = 200
            //   e8????????           |                     
            //   894720               | mov                 dword ptr [edi + 0x20], eax
            //   85c0                 | test                eax, eax
            //   7413                 | je                  0x15

        $sequence_4 = { f30f6f4928 f30f7f8c24a0000000 f30f6f4138 f30f7f8424b8000000 }
            // n = 4, score = 200
            //   f30f6f4928           | movdqu              xmm1, xmmword ptr [ecx + 0x28]
            //   f30f7f8c24a0000000     | movdqu    xmmword ptr [esp + 0xa0], xmm1
            //   f30f6f4138           | movdqu              xmm0, xmmword ptr [ecx + 0x38]
            //   f30f7f8424b8000000     | movdqu    xmmword ptr [esp + 0xb8], xmm0

        $sequence_5 = { 83f812 72f1 33c0 c3 }
            // n = 4, score = 200
            //   83f812               | cmp                 eax, 0x12
            //   72f1                 | jb                  0xfffffff3
            //   33c0                 | xor                 eax, eax
            //   c3                   | ret                 

        $sequence_6 = { ff5028 8be8 85c0 787a }
            // n = 4, score = 200
            //   ff5028               | call                dword ptr [eax + 0x28]
            //   8be8                 | mov                 ebp, eax
            //   85c0                 | test                eax, eax
            //   787a                 | js                  0x7c

        $sequence_7 = { 66894108 33c0 39410c 740b }
            // n = 4, score = 200
            //   66894108             | mov                 word ptr [ecx + 8], ax
            //   33c0                 | xor                 eax, eax
            //   39410c               | cmp                 dword ptr [ecx + 0xc], eax
            //   740b                 | je                  0xd

        $sequence_8 = { eb0c bfdfff0000 6623fe 6683ef07 8b742474 }
            // n = 5, score = 200
            //   eb0c                 | jmp                 0xe
            //   bfdfff0000           | mov                 edi, 0xffdf
            //   6623fe               | and                 di, si
            //   6683ef07             | sub                 di, 7
            //   8b742474             | mov                 esi, dword ptr [esp + 0x74]

        $sequence_9 = { 6683f83f 7607 32c0 e9???????? }
            // n = 4, score = 200
            //   6683f83f             | cmp                 ax, 0x3f
            //   7607                 | jbe                 9
            //   32c0                 | xor                 al, al
            //   e9????????           |                     

        $sequence_10 = { 2bc1 85c9 7403 83c008 d1e8 8d441002 }
            // n = 6, score = 200
            //   2bc1                 | sub                 eax, ecx
            //   85c9                 | test                ecx, ecx
            //   7403                 | je                  5
            //   83c008               | add                 eax, 8
            //   d1e8                 | shr                 eax, 1
            //   8d441002             | lea                 eax, [eax + edx + 2]

        $sequence_11 = { ff15???????? b940000000 8bd0 89442430 }
            // n = 4, score = 200
            //   ff15????????         |                     
            //   b940000000           | mov                 ecx, 0x40
            //   8bd0                 | mov                 edx, eax
            //   89442430             | mov                 dword ptr [esp + 0x30], eax

        $sequence_12 = { 3c02 7207 e8???????? eb10 }
            // n = 4, score = 200
            //   3c02                 | cmp                 al, 2
            //   7207                 | jb                  9
            //   e8????????           |                     
            //   eb10                 | jmp                 0x12

        $sequence_13 = { ff15???????? b9e9fd0000 8905???????? ff15???????? }
            // n = 4, score = 200
            //   ff15????????         |                     
            //   b9e9fd0000           | mov                 ecx, 0xfde9
            //   8905????????         |                     
            //   ff15????????         |                     

        $sequence_14 = { 8d04f530d94600 8938 68a00f0000 ff30 83c718 ff15???????? 85c0 }
            // n = 7, score = 100
            //   8d04f530d94600       | lea                 eax, [esi*8 + 0x46d930]
            //   8938                 | mov                 dword ptr [eax], edi
            //   68a00f0000           | push                0xfa0
            //   ff30                 | push                dword ptr [eax]
            //   83c718               | add                 edi, 0x18
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax

        $sequence_15 = { 837e1800 7402 ffd0 e8???????? 53 }
            // n = 5, score = 100
            //   837e1800             | cmp                 dword ptr [esi + 0x18], 0
            //   7402                 | je                  4
            //   ffd0                 | call                eax
            //   e8????????           |                     
            //   53                   | push                ebx

        $sequence_16 = { 57 33ff ffb750da4600 ff15???????? 898750da4600 83c704 }
            // n = 6, score = 100
            //   57                   | push                edi
            //   33ff                 | xor                 edi, edi
            //   ffb750da4600         | push                dword ptr [edi + 0x46da50]
            //   ff15????????         |                     
            //   898750da4600         | mov                 dword ptr [edi + 0x46da50], eax
            //   83c704               | add                 edi, 4

        $sequence_17 = { e8???????? 8d04453cdb4600 8bc8 2bce 6a03 d1f9 68???????? }
            // n = 7, score = 100
            //   e8????????           |                     
            //   8d04453cdb4600       | lea                 eax, [eax*2 + 0x46db3c]
            //   8bc8                 | mov                 ecx, eax
            //   2bce                 | sub                 ecx, esi
            //   6a03                 | push                3
            //   d1f9                 | sar                 ecx, 1
            //   68????????           |                     

        $sequence_18 = { a1???????? a3???????? a1???????? c705????????cf2f4000 8935???????? }
            // n = 5, score = 100
            //   a1????????           |                     
            //   a3????????           |                     
            //   a1????????           |                     
            //   c705????????cf2f4000     |     
            //   8935????????         |                     

        $sequence_19 = { 8888a0d44600 40 ebe6 ff35???????? ff15???????? }
            // n = 5, score = 100
            //   8888a0d44600         | mov                 byte ptr [eax + 0x46d4a0], cl
            //   40                   | inc                 eax
            //   ebe6                 | jmp                 0xffffffe8
            //   ff35????????         |                     
            //   ff15????????         |                     

        $sequence_20 = { 8a80a4d54600 08443b1d 0fb64601 47 3bf8 76ea 8b7d08 }
            // n = 7, score = 100
            //   8a80a4d54600         | mov                 al, byte ptr [eax + 0x46d5a4]
            //   08443b1d             | or                  byte ptr [ebx + edi + 0x1d], al
            //   0fb64601             | movzx               eax, byte ptr [esi + 1]
            //   47                   | inc                 edi
            //   3bf8                 | cmp                 edi, eax
            //   76ea                 | jbe                 0xffffffec
            //   8b7d08               | mov                 edi, dword ptr [ebp + 8]

        $sequence_21 = { 43 83c408 83fb04 7cdc 8b5df8 8ad3 }
            // n = 6, score = 100
            //   43                   | inc                 ebx
            //   83c408               | add                 esp, 8
            //   83fb04               | cmp                 ebx, 4
            //   7cdc                 | jl                  0xffffffde
            //   8b5df8               | mov                 ebx, dword ptr [ebp - 8]
            //   8ad3                 | mov                 dl, bl

    condition:
        7 of them and filesize < 1642496
}