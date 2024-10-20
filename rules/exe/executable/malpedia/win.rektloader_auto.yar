rule win_rektloader_auto {

    meta:
        atk_type = "win.rektloader."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.rektloader."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.rektloader"
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
        $sequence_0 = { 83bd68ffffff00 742e 8b9568ffffff 52 8d4d98 e8???????? 0fbe00 }
            // n = 7, score = 100
            //   83bd68ffffff00       | cmp                 dword ptr [ebp - 0x98], 0
            //   742e                 | je                  0x30
            //   8b9568ffffff         | mov                 edx, dword ptr [ebp - 0x98]
            //   52                   | push                edx
            //   8d4d98               | lea                 ecx, [ebp - 0x68]
            //   e8????????           |                     
            //   0fbe00               | movsx               eax, byte ptr [eax]

        $sequence_1 = { 8b4d14 0fb73441 8b4d08 e8???????? 0fb7d0 3bf2 }
            // n = 6, score = 100
            //   8b4d14               | mov                 ecx, dword ptr [ebp + 0x14]
            //   0fb73441             | movzx               esi, word ptr [ecx + eax*2]
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   e8????????           |                     
            //   0fb7d0               | movzx               edx, ax
            //   3bf2                 | cmp                 esi, edx

        $sequence_2 = { 83c41c 89856cfeffff 8b856cfeffff 8b08 8b5004 894d0c 895510 }
            // n = 7, score = 100
            //   83c41c               | add                 esp, 0x1c
            //   89856cfeffff         | mov                 dword ptr [ebp - 0x194], eax
            //   8b856cfeffff         | mov                 eax, dword ptr [ebp - 0x194]
            //   8b08                 | mov                 ecx, dword ptr [eax]
            //   8b5004               | mov                 edx, dword ptr [eax + 4]
            //   894d0c               | mov                 dword ptr [ebp + 0xc], ecx
            //   895510               | mov                 dword ptr [ebp + 0x10], edx

        $sequence_3 = { 51 8b5508 52 8b45f8 8945fc 8b4dfc ff15???????? }
            // n = 7, score = 100
            //   51                   | push                ecx
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   52                   | push                edx
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   ff15????????         |                     

        $sequence_4 = { 8b8514faffff f7d8 83e801 898528faffff 8b8d28faffff 898d10faffff 8b550c }
            // n = 7, score = 100
            //   8b8514faffff         | mov                 eax, dword ptr [ebp - 0x5ec]
            //   f7d8                 | neg                 eax
            //   83e801               | sub                 eax, 1
            //   898528faffff         | mov                 dword ptr [ebp - 0x5d8], eax
            //   8b8d28faffff         | mov                 ecx, dword ptr [ebp - 0x5d8]
            //   898d10faffff         | mov                 dword ptr [ebp - 0x5f0], ecx
            //   8b550c               | mov                 edx, dword ptr [ebp + 0xc]

        $sequence_5 = { 8b4520 8b08 83c902 8b5520 890a eb35 8b45f0 }
            // n = 7, score = 100
            //   8b4520               | mov                 eax, dword ptr [ebp + 0x20]
            //   8b08                 | mov                 ecx, dword ptr [eax]
            //   83c902               | or                  ecx, 2
            //   8b5520               | mov                 edx, dword ptr [ebp + 0x20]
            //   890a                 | mov                 dword ptr [edx], ecx
            //   eb35                 | jmp                 0x37
            //   8b45f0               | mov                 eax, dword ptr [ebp - 0x10]

        $sequence_6 = { c6002d 8b4d90 83c101 894d90 }
            // n = 4, score = 100
            //   c6002d               | mov                 byte ptr [eax], 0x2d
            //   8b4d90               | mov                 ecx, dword ptr [ebp - 0x70]
            //   83c101               | add                 ecx, 1
            //   894d90               | mov                 dword ptr [ebp - 0x70], ecx

        $sequence_7 = { 50 8d4dd4 e8???????? 8945b0 8b4db0 0fbe11 0355cc }
            // n = 7, score = 100
            //   50                   | push                eax
            //   8d4dd4               | lea                 ecx, [ebp - 0x2c]
            //   e8????????           |                     
            //   8945b0               | mov                 dword ptr [ebp - 0x50], eax
            //   8b4db0               | mov                 ecx, dword ptr [ebp - 0x50]
            //   0fbe11               | movsx               edx, byte ptr [ecx]
            //   0355cc               | add                 edx, dword ptr [ebp - 0x34]

        $sequence_8 = { b8ffff0000 e9???????? 6a01 8d4df8 e8???????? 8845ff 6a04 }
            // n = 7, score = 100
            //   b8ffff0000           | mov                 eax, 0xffff
            //   e9????????           |                     
            //   6a01                 | push                1
            //   8d4df8               | lea                 ecx, [ebp - 8]
            //   e8????????           |                     
            //   8845ff               | mov                 byte ptr [ebp - 1], al
            //   6a04                 | push                4

        $sequence_9 = { e8???????? 83c404 33c9 8945e0 894de4 8b5508 }
            // n = 6, score = 100
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   33c9                 | xor                 ecx, ecx
            //   8945e0               | mov                 dword ptr [ebp - 0x20], eax
            //   894de4               | mov                 dword ptr [ebp - 0x1c], ecx
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]

    condition:
        7 of them and filesize < 3080192
}