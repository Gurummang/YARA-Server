rule win_himan_auto {

    meta:
        atk_type = "win.himan."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.himan."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.himan"
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
        $sequence_0 = { 8b7b04 33ee 8b7068 0554010000 c1e204 33f7 }
            // n = 6, score = 100
            //   8b7b04               | mov                 edi, dword ptr [ebx + 4]
            //   33ee                 | xor                 ebp, esi
            //   8b7068               | mov                 esi, dword ptr [eax + 0x68]
            //   0554010000           | add                 eax, 0x154
            //   c1e204               | shl                 edx, 4
            //   33f7                 | xor                 esi, edi

        $sequence_1 = { 8b442410 3bd0 7422 56 ff15???????? 57 ff15???????? }
            // n = 7, score = 100
            //   8b442410             | mov                 eax, dword ptr [esp + 0x10]
            //   3bd0                 | cmp                 edx, eax
            //   7422                 | je                  0x24
            //   56                   | push                esi
            //   ff15????????         |                     
            //   57                   | push                edi
            //   ff15????????         |                     

        $sequence_2 = { 894c2414 8bcb c1e910 81e1ff000000 }
            // n = 4, score = 100
            //   894c2414             | mov                 dword ptr [esp + 0x14], ecx
            //   8bcb                 | mov                 ecx, ebx
            //   c1e910               | shr                 ecx, 0x10
            //   81e1ff000000         | and                 ecx, 0xff

        $sequence_3 = { c1e008 0bc7 c1e008 0bc1 8bc8 8904b594886e00 }
            // n = 6, score = 100
            //   c1e008               | shl                 eax, 8
            //   0bc7                 | or                  eax, edi
            //   c1e008               | shl                 eax, 8
            //   0bc1                 | or                  eax, ecx
            //   8bc8                 | mov                 ecx, eax
            //   8904b594886e00       | mov                 dword ptr [esi*4 + 0x6e8894], eax

        $sequence_4 = { 8bda c1eb18 8b2cad948c6e00 332c9d94946e00 8bd9 c1eb10 81e3ff000000 }
            // n = 7, score = 100
            //   8bda                 | mov                 ebx, edx
            //   c1eb18               | shr                 ebx, 0x18
            //   8b2cad948c6e00       | mov                 ebp, dword ptr [ebp*4 + 0x6e8c94]
            //   332c9d94946e00       | xor                 ebp, dword ptr [ebx*4 + 0x6e9494]
            //   8bd9                 | mov                 ebx, ecx
            //   c1eb10               | shr                 ebx, 0x10
            //   81e3ff000000         | and                 ebx, 0xff

        $sequence_5 = { 8b08 50 ff5108 8b8c24a8050000 5f }
            // n = 5, score = 100
            //   8b08                 | mov                 ecx, dword ptr [eax]
            //   50                   | push                eax
            //   ff5108               | call                dword ptr [ecx + 8]
            //   8b8c24a8050000       | mov                 ecx, dword ptr [esp + 0x5a8]
            //   5f                   | pop                 edi

        $sequence_6 = { 8d85a0fcffff 50 ff15???????? 8da594d4ffff 5f 5e 5b }
            // n = 7, score = 100
            //   8d85a0fcffff         | lea                 eax, [ebp - 0x360]
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8da594d4ffff         | lea                 esp, [ebp - 0x2b6c]
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   5b                   | pop                 ebx

        $sequence_7 = { c1e910 3334adbcc26e00 8beb 81e5ff000000 81e1ff000000 c1eb08 3334adbcba6e00 }
            // n = 7, score = 100
            //   c1e910               | shr                 ecx, 0x10
            //   3334adbcc26e00       | xor                 esi, dword ptr [ebp*4 + 0x6ec2bc]
            //   8beb                 | mov                 ebp, ebx
            //   81e5ff000000         | and                 ebp, 0xff
            //   81e1ff000000         | and                 ecx, 0xff
            //   c1eb08               | shr                 ebx, 8
            //   3334adbcba6e00       | xor                 esi, dword ptr [ebp*4 + 0x6ebabc]

        $sequence_8 = { 333c9594946e00 8b542414 c1ea10 81e2ff000000 333c9594906e00 8bd1 81e2ff000000 }
            // n = 7, score = 100
            //   333c9594946e00       | xor                 edi, dword ptr [edx*4 + 0x6e9494]
            //   8b542414             | mov                 edx, dword ptr [esp + 0x14]
            //   c1ea10               | shr                 edx, 0x10
            //   81e2ff000000         | and                 edx, 0xff
            //   333c9594906e00       | xor                 edi, dword ptr [edx*4 + 0x6e9094]
            //   8bd1                 | mov                 edx, ecx
            //   81e2ff000000         | and                 edx, 0xff

        $sequence_9 = { c1c108 890cb5948c6e00 8a8ebccb6e00 8bd0 884c2410 8b7c2410 c1c210 }
            // n = 7, score = 100
            //   c1c108               | rol                 ecx, 8
            //   890cb5948c6e00       | mov                 dword ptr [esi*4 + 0x6e8c94], ecx
            //   8a8ebccb6e00         | mov                 cl, byte ptr [esi + 0x6ecbbc]
            //   8bd0                 | mov                 edx, eax
            //   884c2410             | mov                 byte ptr [esp + 0x10], cl
            //   8b7c2410             | mov                 edi, dword ptr [esp + 0x10]
            //   c1c210               | rol                 edx, 0x10

    condition:
        7 of them and filesize < 139264
}