rule win_bughatch_auto {

    meta:
        atk_type = "win.bughatch."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.bughatch."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.bughatch"
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
        $sequence_0 = { 51 ff15???????? 68???????? 8d9594f7ffff 52 ff15???????? }
            // n = 6, score = 100
            //   51                   | push                ecx
            //   ff15????????         |                     
            //   68????????           |                     
            //   8d9594f7ffff         | lea                 edx, [ebp - 0x86c]
            //   52                   | push                edx
            //   ff15????????         |                     

        $sequence_1 = { 8d8594f7ffff 50 ff15???????? c745d80c000000 c745e001000000 c745dc00000000 8d4d94 }
            // n = 7, score = 100
            //   8d8594f7ffff         | lea                 eax, [ebp - 0x86c]
            //   50                   | push                eax
            //   ff15????????         |                     
            //   c745d80c000000       | mov                 dword ptr [ebp - 0x28], 0xc
            //   c745e001000000       | mov                 dword ptr [ebp - 0x20], 1
            //   c745dc00000000       | mov                 dword ptr [ebp - 0x24], 0
            //   8d4d94               | lea                 ecx, [ebp - 0x6c]

        $sequence_2 = { 52 6a00 8b45f8 50 ff15???????? 8945ec 837dec00 }
            // n = 7, score = 100
            //   52                   | push                edx
            //   6a00                 | push                0
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8945ec               | mov                 dword ptr [ebp - 0x14], eax
            //   837dec00             | cmp                 dword ptr [ebp - 0x14], 0

        $sequence_3 = { 55 8bec 81ec30010000 c745e000000000 c745e860524000 }
            // n = 5, score = 100
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   81ec30010000         | sub                 esp, 0x130
            //   c745e000000000       | mov                 dword ptr [ebp - 0x20], 0
            //   c745e860524000       | mov                 dword ptr [ebp - 0x18], 0x405260

        $sequence_4 = { 894df4 8d55e4 52 8d4594 50 6a00 6a00 }
            // n = 7, score = 100
            //   894df4               | mov                 dword ptr [ebp - 0xc], ecx
            //   8d55e4               | lea                 edx, [ebp - 0x1c]
            //   52                   | push                edx
            //   8d4594               | lea                 eax, [ebp - 0x6c]
            //   50                   | push                eax
            //   6a00                 | push                0
            //   6a00                 | push                0

        $sequence_5 = { 8b55ec 52 ff15???????? c745f801000000 8b45fc }
            // n = 5, score = 100
            //   8b55ec               | mov                 edx, dword ptr [ebp - 0x14]
            //   52                   | push                edx
            //   ff15????????         |                     
            //   c745f801000000       | mov                 dword ptr [ebp - 8], 1
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]

        $sequence_6 = { 7308 8b45f8 8945f0 eb06 8b4d14 894df0 8b55f0 }
            // n = 7, score = 100
            //   7308                 | jae                 0xa
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]
            //   8945f0               | mov                 dword ptr [ebp - 0x10], eax
            //   eb06                 | jmp                 8
            //   8b4d14               | mov                 ecx, dword ptr [ebp + 0x14]
            //   894df0               | mov                 dword ptr [ebp - 0x10], ecx
            //   8b55f0               | mov                 edx, dword ptr [ebp - 0x10]

        $sequence_7 = { ff15???????? 8b4de0 51 ff15???????? 8b45dc }
            // n = 5, score = 100
            //   ff15????????         |                     
            //   8b4de0               | mov                 ecx, dword ptr [ebp - 0x20]
            //   51                   | push                ecx
            //   ff15????????         |                     
            //   8b45dc               | mov                 eax, dword ptr [ebp - 0x24]

        $sequence_8 = { 55 8bec 81ec60030000 837d0800 0f84d2000000 6a44 6a00 }
            // n = 7, score = 100
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   81ec60030000         | sub                 esp, 0x360
            //   837d0800             | cmp                 dword ptr [ebp + 8], 0
            //   0f84d2000000         | je                  0xd8
            //   6a44                 | push                0x44
            //   6a00                 | push                0

        $sequence_9 = { e8???????? 83c40c 85c0 7407 c745fc01000000 8b45f8 50 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   85c0                 | test                eax, eax
            //   7407                 | je                  9
            //   c745fc01000000       | mov                 dword ptr [ebp - 4], 1
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]
            //   50                   | push                eax

    condition:
        7 of them and filesize < 75776
}