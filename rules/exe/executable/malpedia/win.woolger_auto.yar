rule win_woolger_auto {

    meta:
        atk_type = "win.woolger."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.woolger."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.woolger"
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
        $sequence_0 = { 83f814 750a be???????? e9???????? 83f81b }
            // n = 5, score = 200
            //   83f814               | cmp                 eax, 0x14
            //   750a                 | jne                 0xc
            //   be????????           |                     
            //   e9????????           |                     
            //   83f81b               | cmp                 eax, 0x1b

        $sequence_1 = { 83ec54 6a40 8d45b0 6a00 50 c745ac44000000 e8???????? }
            // n = 7, score = 200
            //   83ec54               | sub                 esp, 0x54
            //   6a40                 | push                0x40
            //   8d45b0               | lea                 eax, [ebp - 0x50]
            //   6a00                 | push                0
            //   50                   | push                eax
            //   c745ac44000000       | mov                 dword ptr [ebp - 0x54], 0x44
            //   e8????????           |                     

        $sequence_2 = { 33c5 8945fc 33c0 668945d4 }
            // n = 4, score = 200
            //   33c5                 | xor                 eax, ebp
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   33c0                 | xor                 eax, eax
            //   668945d4             | mov                 word ptr [ebp - 0x2c], ax

        $sequence_3 = { 6685c0 8d85fcfeffff 50 0f95c3 ff15???????? 8b4f08 }
            // n = 6, score = 200
            //   6685c0               | test                ax, ax
            //   8d85fcfeffff         | lea                 eax, [ebp - 0x104]
            //   50                   | push                eax
            //   0f95c3               | setne               bl
            //   ff15????????         |                     
            //   8b4f08               | mov                 ecx, dword ptr [edi + 8]

        $sequence_4 = { 52 ff15???????? 83f801 0f858d000000 }
            // n = 4, score = 200
            //   52                   | push                edx
            //   ff15????????         |                     
            //   83f801               | cmp                 eax, 1
            //   0f858d000000         | jne                 0x93

        $sequence_5 = { 6a00 68???????? ff15???????? 68???????? 6a01 6a00 }
            // n = 6, score = 200
            //   6a00                 | push                0
            //   68????????           |                     
            //   ff15????????         |                     
            //   68????????           |                     
            //   6a01                 | push                1
            //   6a00                 | push                0

        $sequence_6 = { 66a5 8dbdfcf8ffff 4f 8a4701 47 84c0 }
            // n = 6, score = 200
            //   66a5                 | movsw               word ptr es:[edi], word ptr [esi]
            //   8dbdfcf8ffff         | lea                 edi, [ebp - 0x704]
            //   4f                   | dec                 edi
            //   8a4701               | mov                 al, byte ptr [edi + 1]
            //   47                   | inc                 edi
            //   84c0                 | test                al, al

        $sequence_7 = { 6a00 8d8dd4f4ffff 51 ffd6 85c0 75db }
            // n = 6, score = 200
            //   6a00                 | push                0
            //   8d8dd4f4ffff         | lea                 ecx, [ebp - 0xb2c]
            //   51                   | push                ecx
            //   ffd6                 | call                esi
            //   85c0                 | test                eax, eax
            //   75db                 | jne                 0xffffffdd

        $sequence_8 = { 83c414 81ffb80b0000 5f 7c40 e8???????? e8???????? }
            // n = 6, score = 200
            //   83c414               | add                 esp, 0x14
            //   81ffb80b0000         | cmp                 edi, 0xbb8
            //   5f                   | pop                 edi
            //   7c40                 | jl                  0x42
            //   e8????????           |                     
            //   e8????????           |                     

        $sequence_9 = { 3da2000000 0f8403010000 3da3000000 0f84f8000000 3da4000000 0f84e6000000 3da5000000 }
            // n = 7, score = 200
            //   3da2000000           | cmp                 eax, 0xa2
            //   0f8403010000         | je                  0x109
            //   3da3000000           | cmp                 eax, 0xa3
            //   0f84f8000000         | je                  0xfe
            //   3da4000000           | cmp                 eax, 0xa4
            //   0f84e6000000         | je                  0xec
            //   3da5000000           | cmp                 eax, 0xa5

    condition:
        7 of them and filesize < 196608
}