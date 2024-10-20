rule win_nvisospit_auto {

    meta:
        atk_type = "win.nvisospit."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.nvisospit."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.nvisospit"
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
        $sequence_0 = { 83f801 0f851e010000 8d710c 81fe???????? 0f8350feffff 895dbc }
            // n = 6, score = 100
            //   83f801               | cmp                 eax, 1
            //   0f851e010000         | jne                 0x124
            //   8d710c               | lea                 esi, [ecx + 0xc]
            //   81fe????????         |                     
            //   0f8350feffff         | jae                 0xfffffe56
            //   895dbc               | mov                 dword ptr [ebp - 0x44], ebx

        $sequence_1 = { a1???????? ffd0 83ec04 0fb785a2f9ffff 0fb7c0 8d959cf9ffff 89542410 }
            // n = 7, score = 100
            //   a1????????           |                     
            //   ffd0                 | call                eax
            //   83ec04               | sub                 esp, 4
            //   0fb785a2f9ffff       | movzx               eax, word ptr [ebp - 0x65e]
            //   0fb7c0               | movzx               eax, ax
            //   8d959cf9ffff         | lea                 edx, [ebp - 0x664]
            //   89542410             | mov                 dword ptr [esp + 0x10], edx

        $sequence_2 = { c70424???????? e8???????? 85db c705????????02000000 0f85d1fdffff }
            // n = 5, score = 100
            //   c70424????????       |                     
            //   e8????????           |                     
            //   85db                 | test                ebx, ebx
            //   c705????????02000000     |     
            //   0f85d1fdffff         | jne                 0xfffffdd7

        $sequence_3 = { a1???????? 31c9 c705????????00004000 8b00 85c0 }
            // n = 5, score = 100
            //   a1????????           |                     
            //   31c9                 | xor                 ecx, ecx
            //   c705????????00004000     |     
            //   8b00                 | mov                 eax, dword ptr [eax]
            //   85c0                 | test                eax, eax

        $sequence_4 = { 89442404 c70424???????? e8???????? 0fb785a8f9ffff }
            // n = 4, score = 100
            //   89442404             | mov                 dword ptr [esp + 4], eax
            //   c70424????????       |                     
            //   e8????????           |                     
            //   0fb785a8f9ffff       | movzx               eax, word ptr [ebp - 0x658]

        $sequence_5 = { 0f8e16010000 85d2 0f8493010000 b9???????? 81f9???????? }
            // n = 5, score = 100
            //   0f8e16010000         | jle                 0x11c
            //   85d2                 | test                edx, edx
            //   0f8493010000         | je                  0x199
            //   b9????????           |                     
            //   81f9????????         |                     

        $sequence_6 = { 0fb7c0 8d959cf9ffff 89542410 c744240c00000000 8d958ef9ffff 89542408 }
            // n = 6, score = 100
            //   0fb7c0               | movzx               eax, ax
            //   8d959cf9ffff         | lea                 edx, [ebp - 0x664]
            //   89542410             | mov                 dword ptr [esp + 0x10], edx
            //   c744240c00000000     | mov                 dword ptr [esp + 0xc], 0
            //   8d958ef9ffff         | lea                 edx, [ebp - 0x672]
            //   89542408             | mov                 dword ptr [esp + 8], edx

        $sequence_7 = { 83ec0c 8945bc 8b45bc 89442404 }
            // n = 4, score = 100
            //   83ec0c               | sub                 esp, 0xc
            //   8945bc               | mov                 dword ptr [ebp - 0x44], eax
            //   8b45bc               | mov                 eax, dword ptr [ebp - 0x44]
            //   89442404             | mov                 dword ptr [esp + 4], eax

        $sequence_8 = { e8???????? c7442404b0feffff c70424???????? e8???????? c7442404ccffffff c70424???????? }
            // n = 6, score = 100
            //   e8????????           |                     
            //   c7442404b0feffff     | mov                 dword ptr [esp + 4], 0xfffffeb0
            //   c70424????????       |                     
            //   e8????????           |                     
            //   c7442404ccffffff     | mov                 dword ptr [esp + 4], 0xffffffcc
            //   c70424????????       |                     

        $sequence_9 = { 8d9dacfbffff 81c307010000 895c2414 8d9dacfbffff 83c306 895c2410 894c240c }
            // n = 7, score = 100
            //   8d9dacfbffff         | lea                 ebx, [ebp - 0x454]
            //   81c307010000         | add                 ebx, 0x107
            //   895c2414             | mov                 dword ptr [esp + 0x14], ebx
            //   8d9dacfbffff         | lea                 ebx, [ebp - 0x454]
            //   83c306               | add                 ebx, 6
            //   895c2410             | mov                 dword ptr [esp + 0x10], ebx
            //   894c240c             | mov                 dword ptr [esp + 0xc], ecx

    condition:
        7 of them and filesize < 66560
}