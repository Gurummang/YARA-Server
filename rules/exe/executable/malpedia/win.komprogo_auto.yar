rule win_komprogo_auto {

    meta:
        atk_type = "win.komprogo."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.komprogo."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.komprogo"
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
        $sequence_0 = { 8d8670720300 89861b630000 8d96f0a80300 8996e51d0300 8d8e40490400 }
            // n = 5, score = 100
            //   8d8670720300         | lea                 eax, [esi + 0x37270]
            //   89861b630000         | mov                 dword ptr [esi + 0x631b], eax
            //   8d96f0a80300         | lea                 edx, [esi + 0x3a8f0]
            //   8996e51d0300         | mov                 dword ptr [esi + 0x31de5], edx
            //   8d8e40490400         | lea                 ecx, [esi + 0x44940]

        $sequence_1 = { 8d86a82f0400 89862cb50200 8d86a8700300 89862cd50000 8d86f0380400 898616410200 8d8680720300 }
            // n = 7, score = 100
            //   8d86a82f0400         | lea                 eax, [esi + 0x42fa8]
            //   89862cb50200         | mov                 dword ptr [esi + 0x2b52c], eax
            //   8d86a8700300         | lea                 eax, [esi + 0x370a8]
            //   89862cd50000         | mov                 dword ptr [esi + 0xd52c], eax
            //   8d86f0380400         | lea                 eax, [esi + 0x438f0]
            //   898616410200         | mov                 dword ptr [esi + 0x24116], eax
            //   8d8680720300         | lea                 eax, [esi + 0x37280]

        $sequence_2 = { 51 8d8618cf0300 8bcf e8???????? 83c404 }
            // n = 5, score = 100
            //   51                   | push                ecx
            //   8d8618cf0300         | lea                 eax, [esi + 0x3cf18]
            //   8bcf                 | mov                 ecx, edi
            //   e8????????           |                     
            //   83c404               | add                 esp, 4

        $sequence_3 = { 8d96e4970300 899625080100 898633080100 8d96d0700300 8996e5650200 8d96f4380400 899643080100 }
            // n = 7, score = 100
            //   8d96e4970300         | lea                 edx, [esi + 0x397e4]
            //   899625080100         | mov                 dword ptr [esi + 0x10825], edx
            //   898633080100         | mov                 dword ptr [esi + 0x10833], eax
            //   8d96d0700300         | lea                 edx, [esi + 0x370d0]
            //   8996e5650200         | mov                 dword ptr [esi + 0x265e5], edx
            //   8d96f4380400         | lea                 edx, [esi + 0x438f4]
            //   899643080100         | mov                 dword ptr [esi + 0x10843], edx

        $sequence_4 = { 8d9614790300 899694e70300 8d86242c0400 8986c1210300 8d86e15c0300 898636ca0000 8d86a8ad0300 }
            // n = 7, score = 100
            //   8d9614790300         | lea                 edx, [esi + 0x37914]
            //   899694e70300         | mov                 dword ptr [esi + 0x3e794], edx
            //   8d86242c0400         | lea                 eax, [esi + 0x42c24]
            //   8986c1210300         | mov                 dword ptr [esi + 0x321c1], eax
            //   8d86e15c0300         | lea                 eax, [esi + 0x35ce1]
            //   898636ca0000         | mov                 dword ptr [esi + 0xca36], eax
            //   8d86a8ad0300         | lea                 eax, [esi + 0x3ada8]

        $sequence_5 = { 0f859e000000 85f6 0f8496000000 8b433c 0fb7541814 }
            // n = 5, score = 100
            //   0f859e000000         | jne                 0xa4
            //   85f6                 | test                esi, esi
            //   0f8496000000         | je                  0x9c
            //   8b433c               | mov                 eax, dword ptr [ebx + 0x3c]
            //   0fb7541814           | movzx               edx, word ptr [eax + ebx + 0x14]

        $sequence_6 = { 898e47bd0200 8d8e20e20300 898e4f7e0200 8d9694a30300 899674750300 8d8ea82f0400 898e897e0200 }
            // n = 7, score = 100
            //   898e47bd0200         | mov                 dword ptr [esi + 0x2bd47], ecx
            //   8d8e20e20300         | lea                 ecx, [esi + 0x3e220]
            //   898e4f7e0200         | mov                 dword ptr [esi + 0x27e4f], ecx
            //   8d9694a30300         | lea                 edx, [esi + 0x3a394]
            //   899674750300         | mov                 dword ptr [esi + 0x37574], edx
            //   8d8ea82f0400         | lea                 ecx, [esi + 0x42fa8]
            //   898e897e0200         | mov                 dword ptr [esi + 0x27e89], ecx

        $sequence_7 = { ff15???????? 8b95f0fdffff 8902 33db 85f6 7445 8bb5f0fdffff }
            // n = 7, score = 100
            //   ff15????????         |                     
            //   8b95f0fdffff         | mov                 edx, dword ptr [ebp - 0x210]
            //   8902                 | mov                 dword ptr [edx], eax
            //   33db                 | xor                 ebx, ebx
            //   85f6                 | test                esi, esi
            //   7445                 | je                  0x47
            //   8bb5f0fdffff         | mov                 esi, dword ptr [ebp - 0x210]

        $sequence_8 = { 52 ffd7 8b85d0f3ffff 50 ffd7 8b4df8 5f }
            // n = 7, score = 100
            //   52                   | push                edx
            //   ffd7                 | call                edi
            //   8b85d0f3ffff         | mov                 eax, dword ptr [ebp - 0xc30]
            //   50                   | push                eax
            //   ffd7                 | call                edi
            //   8b4df8               | mov                 ecx, dword ptr [ebp - 8]
            //   5f                   | pop                 edi

        $sequence_9 = { 8d86e0930200 8986d4930200 8d8ec1610300 898e14b20300 }
            // n = 4, score = 100
            //   8d86e0930200         | lea                 eax, [esi + 0x293e0]
            //   8986d4930200         | mov                 dword ptr [esi + 0x293d4], eax
            //   8d8ec1610300         | lea                 ecx, [esi + 0x361c1]
            //   898e14b20300         | mov                 dword ptr [esi + 0x3b214], ecx

    condition:
        7 of them and filesize < 1045504
}