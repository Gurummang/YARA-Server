rule win_karma_auto {

    meta:
        atk_type = "win.karma."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.karma."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.karma"
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
        $sequence_0 = { 8b7f08 8bc7 d3e8 8b4d08 }
            // n = 4, score = 100
            //   8b7f08               | mov                 edi, dword ptr [edi + 8]
            //   8bc7                 | mov                 eax, edi
            //   d3e8                 | shr                 eax, cl
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]

        $sequence_1 = { 8bf9 8955f0 33c0 663907 7408 40 66833c4700 }
            // n = 7, score = 100
            //   8bf9                 | mov                 edi, ecx
            //   8955f0               | mov                 dword ptr [ebp - 0x10], edx
            //   33c0                 | xor                 eax, eax
            //   663907               | cmp                 word ptr [edi], ax
            //   7408                 | je                  0xa
            //   40                   | inc                 eax
            //   66833c4700           | cmp                 word ptr [edi + eax*2], 0

        $sequence_2 = { 0f1006 0f114318 e8???????? 5f }
            // n = 4, score = 100
            //   0f1006               | movups              xmm0, xmmword ptr [esi]
            //   0f114318             | movups              xmmword ptr [ebx + 0x18], xmm0
            //   e8????????           |                     
            //   5f                   | pop                 edi

        $sequence_3 = { ebc5 33ff 6690 0fb78ffc434000 }
            // n = 4, score = 100
            //   ebc5                 | jmp                 0xffffffc7
            //   33ff                 | xor                 edi, edi
            //   6690                 | nop                 
            //   0fb78ffc434000       | movzx               ecx, word ptr [edi + 0x4043fc]

        $sequence_4 = { ff15???????? 6a00 8d442444 50 6800710200 }
            // n = 5, score = 100
            //   ff15????????         |                     
            //   6a00                 | push                0
            //   8d442444             | lea                 eax, [esp + 0x44]
            //   50                   | push                eax
            //   6800710200           | push                0x27100

        $sequence_5 = { 660fefc8 0f1148f0 83e901 75e7 8d55e0 }
            // n = 5, score = 100
            //   660fefc8             | pxor                xmm1, xmm0
            //   0f1148f0             | movups              xmmword ptr [eax - 0x10], xmm1
            //   83e901               | sub                 ecx, 1
            //   75e7                 | jne                 0xffffffe9
            //   8d55e0               | lea                 edx, [ebp - 0x20]

        $sequence_6 = { 894dfc 894dc0 894dc4 894dc8 894dcc }
            // n = 5, score = 100
            //   894dfc               | mov                 dword ptr [ebp - 4], ecx
            //   894dc0               | mov                 dword ptr [ebp - 0x40], ecx
            //   894dc4               | mov                 dword ptr [ebp - 0x3c], ecx
            //   894dc8               | mov                 dword ptr [ebp - 0x38], ecx
            //   894dcc               | mov                 dword ptr [ebp - 0x34], ecx

        $sequence_7 = { 8b4c2418 8b44241c 83c140 6a00 6a00 83d000 }
            // n = 6, score = 100
            //   8b4c2418             | mov                 ecx, dword ptr [esp + 0x18]
            //   8b44241c             | mov                 eax, dword ptr [esp + 0x1c]
            //   83c140               | add                 ecx, 0x40
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   83d000               | adc                 eax, 0

        $sequence_8 = { 8d4e20 0f47ce 2bca 750e 6685db 0f84c5000000 }
            // n = 6, score = 100
            //   8d4e20               | lea                 ecx, [esi + 0x20]
            //   0f47ce               | cmova               ecx, esi
            //   2bca                 | sub                 ecx, edx
            //   750e                 | jne                 0x10
            //   6685db               | test                bx, bx
            //   0f84c5000000         | je                  0xcb

        $sequence_9 = { 66833c45f051400000 75f4 33d2 663915???????? 7415 660f1f840000000000 }
            // n = 6, score = 100
            //   66833c45f051400000     | cmp    word ptr [eax*2 + 0x4051f0], 0
            //   75f4                 | jne                 0xfffffff6
            //   33d2                 | xor                 edx, edx
            //   663915????????       |                     
            //   7415                 | je                  0x17
            //   660f1f840000000000     | nop    word ptr [eax + eax]

    condition:
        7 of them and filesize < 49208
}