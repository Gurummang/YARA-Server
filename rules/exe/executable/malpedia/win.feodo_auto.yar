rule win_feodo_auto {

    meta:
        atk_type = "win.feodo."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.feodo."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.feodo"
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
        $sequence_0 = { 83c120 8d51d0 83fa09 7704 8bca eb10 8d519f }
            // n = 7, score = 1100
            //   83c120               | add                 ecx, 0x20
            //   8d51d0               | lea                 edx, [ecx - 0x30]
            //   83fa09               | cmp                 edx, 9
            //   7704                 | ja                  6
            //   8bca                 | mov                 ecx, edx
            //   eb10                 | jmp                 0x12
            //   8d519f               | lea                 edx, [ecx - 0x61]

        $sequence_1 = { 6a00 8d542424 52 6a00 ff15???????? 85c0 }
            // n = 6, score = 1100
            //   6a00                 | push                0
            //   8d542424             | lea                 edx, [esp + 0x24]
            //   52                   | push                edx
            //   6a00                 | push                0
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax

        $sequence_2 = { 7422 83e801 7404 83c8ff c3 8b4c2404 b802000000 }
            // n = 7, score = 1100
            //   7422                 | je                  0x24
            //   83e801               | sub                 eax, 1
            //   7404                 | je                  6
            //   83c8ff               | or                  eax, 0xffffffff
            //   c3                   | ret                 
            //   8b4c2404             | mov                 ecx, dword ptr [esp + 4]
            //   b802000000           | mov                 eax, 2

        $sequence_3 = { 6a00 8d4c240c 51 52 50 8b442414 50 }
            // n = 7, score = 1100
            //   6a00                 | push                0
            //   8d4c240c             | lea                 ecx, [esp + 0xc]
            //   51                   | push                ecx
            //   52                   | push                edx
            //   50                   | push                eax
            //   8b442414             | mov                 eax, dword ptr [esp + 0x14]
            //   50                   | push                eax

        $sequence_4 = { 56 57 33ff 57 6a02 6a02 57 }
            // n = 7, score = 1100
            //   56                   | push                esi
            //   57                   | push                edi
            //   33ff                 | xor                 edi, edi
            //   57                   | push                edi
            //   6a02                 | push                2
            //   6a02                 | push                2
            //   57                   | push                edi

        $sequence_5 = { 742f 8b0f 6a01 68???????? 68???????? }
            // n = 5, score = 1100
            //   742f                 | je                  0x31
            //   8b0f                 | mov                 ecx, dword ptr [edi]
            //   6a01                 | push                1
            //   68????????           |                     
            //   68????????           |                     

        $sequence_6 = { 50 8b442414 50 ff15???????? 85c0 7405 }
            // n = 6, score = 1100
            //   50                   | push                eax
            //   8b442414             | mov                 eax, dword ptr [esp + 0x14]
            //   50                   | push                eax
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7405                 | je                  7

        $sequence_7 = { 6a00 8d942418020000 52 50 }
            // n = 4, score = 1100
            //   6a00                 | push                0
            //   8d942418020000       | lea                 edx, [esp + 0x218]
            //   52                   | push                edx
            //   50                   | push                eax

        $sequence_8 = { 3452 e8???????? 0202 0202 1c83 0000 }
            // n = 6, score = 100
            //   3452                 | xor                 al, 0x52
            //   e8????????           |                     
            //   0202                 | add                 al, byte ptr [edx]
            //   0202                 | add                 al, byte ptr [edx]
            //   1c83                 | sbb                 al, 0x83
            //   0000                 | add                 byte ptr [eax], al

        $sequence_9 = { 229921688d3c 2ee83e207468 60 238b0d03c783 782e 1463 }
            // n = 6, score = 100
            //   229921688d3c         | and                 bl, byte ptr [ecx + 0x3c8d6821]
            //   2ee83e207468         | call                0x68742044
            //   60                   | pushal              
            //   238b0d03c783         | and                 ecx, dword ptr [ebx - 0x7c38fcf3]
            //   782e                 | js                  0x30
            //   1463                 | adc                 al, 0x63

        $sequence_10 = { 006c082e 08cc 6969690bc8cc69 690c2e2e0b8ce0 04f7 e10c 206d53 }
            // n = 7, score = 100
            //   006c082e             | add                 byte ptr [eax + ecx + 0x2e], ch
            //   08cc                 | or                  ah, cl
            //   6969690bc8cc69       | imul                ebp, dword ptr [ecx + 0x69], 0x69ccc80b
            //   690c2e2e0b8ce0       | imul                ecx, dword ptr [esi + ebp], 0xe08c0b2e
            //   04f7                 | add                 al, 0xf7
            //   e10c                 | loope               0xe
            //   206d53               | and                 byte ptr [ebp + 0x53], ch

        $sequence_11 = { 150d14f452 696969697f3cc3 af e2c3 }
            // n = 4, score = 100
            //   150d14f452           | adc                 eax, 0x52f4140d
            //   696969697f3cc3       | imul                ebp, dword ptr [ecx + 0x69], 0xc33c7f69
            //   af                   | scasd               eax, dword ptr es:[edi]
            //   e2c3                 | loop                0xffffffc5

        $sequence_12 = { 041e 6e 18b8161e6e18 b8161e33c9 0000 16 43 }
            // n = 7, score = 100
            //   041e                 | add                 al, 0x1e
            //   6e                   | outsb               dx, byte ptr [esi]
            //   18b8161e6e18         | sbb                 byte ptr [eax + 0x186e1e16], bh
            //   b8161e33c9           | mov                 eax, 0xc9331e16
            //   0000                 | add                 byte ptr [eax], al
            //   16                   | push                ss
            //   43                   | inc                 ebx

        $sequence_13 = { 0404 0404 0316 16 }
            // n = 4, score = 100
            //   0404                 | add                 al, 4
            //   0404                 | add                 al, 4
            //   0316                 | add                 edx, dword ptr [esi]
            //   16                   | push                ss

        $sequence_14 = { 0056b0 2e2801 0bd0 83c4ce 00576a 05c705c07f }
            // n = 6, score = 100
            //   0056b0               | add                 byte ptr [esi - 0x50], dl
            //   2e2801               | sub                 byte ptr cs:[ecx], al
            //   0bd0                 | or                  edx, eax
            //   83c4ce               | add                 esp, -0x32
            //   00576a               | add                 byte ptr [edi + 0x6a], dl
            //   05c705c07f           | add                 eax, 0x7fc005c7

        $sequence_15 = { 007538 034568 3327 325616 }
            // n = 4, score = 100
            //   007538               | add                 byte ptr [ebp + 0x38], dh
            //   034568               | add                 eax, dword ptr [ebp + 0x68]
            //   3327                 | xor                 esp, dword ptr [edi]
            //   325616               | xor                 dl, byte ptr [esi + 0x16]

    condition:
        7 of them and filesize < 270336
}