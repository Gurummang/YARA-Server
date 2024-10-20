rule win_aveo_auto {

    meta:
        atk_type = "win.aveo."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.aveo."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.aveo"
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
        $sequence_0 = { 8b85ecfaffff 83c40c 50 8bcb 51 8db5f8fdffff }
            // n = 6, score = 200
            //   8b85ecfaffff         | mov                 eax, dword ptr [ebp - 0x514]
            //   83c40c               | add                 esp, 0xc
            //   50                   | push                eax
            //   8bcb                 | mov                 ecx, ebx
            //   51                   | push                ecx
            //   8db5f8fdffff         | lea                 esi, [ebp - 0x208]

        $sequence_1 = { 53 56 57 8db570faffff }
            // n = 4, score = 200
            //   53                   | push                ebx
            //   56                   | push                esi
            //   57                   | push                edi
            //   8db570faffff         | lea                 esi, [ebp - 0x590]

        $sequence_2 = { 8d8d10feffff e8???????? 8b95f8fdffff 52 8bf0 }
            // n = 5, score = 200
            //   8d8d10feffff         | lea                 ecx, [ebp - 0x1f0]
            //   e8????????           |                     
            //   8b95f8fdffff         | mov                 edx, dword ptr [ebp - 0x208]
            //   52                   | push                edx
            //   8bf0                 | mov                 esi, eax

        $sequence_3 = { 8b4de0 8d55dc 52 6800008000 }
            // n = 4, score = 200
            //   8b4de0               | mov                 ecx, dword ptr [ebp - 0x20]
            //   8d55dc               | lea                 edx, [ebp - 0x24]
            //   52                   | push                edx
            //   6800008000           | push                0x800000

        $sequence_4 = { 8d8554faffff 8d8d70faffff e8???????? 8b955cfaffff 52 e8???????? }
            // n = 6, score = 200
            //   8d8554faffff         | lea                 eax, [ebp - 0x5ac]
            //   8d8d70faffff         | lea                 ecx, [ebp - 0x590]
            //   e8????????           |                     
            //   8b955cfaffff         | mov                 edx, dword ptr [ebp - 0x5a4]
            //   52                   | push                edx
            //   e8????????           |                     

        $sequence_5 = { 50 f3a4 ff15???????? 6800010000 8d8df8feffff 6a00 51 }
            // n = 7, score = 200
            //   50                   | push                eax
            //   f3a4                 | rep movsb           byte ptr es:[edi], byte ptr [esi]
            //   ff15????????         |                     
            //   6800010000           | push                0x100
            //   8d8df8feffff         | lea                 ecx, [ebp - 0x108]
            //   6a00                 | push                0
            //   51                   | push                ecx

        $sequence_6 = { 53 8d4802 8955f4 56 8a51fe }
            // n = 5, score = 200
            //   53                   | push                ebx
            //   8d4802               | lea                 ecx, [eax + 2]
            //   8955f4               | mov                 dword ptr [ebp - 0xc], edx
            //   56                   | push                esi
            //   8a51fe               | mov                 dl, byte ptr [ecx - 2]

        $sequence_7 = { 7424 8b85f4efffff 3bc7 741a }
            // n = 4, score = 200
            //   7424                 | je                  0x26
            //   8b85f4efffff         | mov                 eax, dword ptr [ebp - 0x100c]
            //   3bc7                 | cmp                 eax, edi
            //   741a                 | je                  0x1c

        $sequence_8 = { c7442418e8030000 ff15???????? 3bc7 740c 68???????? 50 }
            // n = 6, score = 200
            //   c7442418e8030000     | mov                 dword ptr [esp + 0x18], 0x3e8
            //   ff15????????         |                     
            //   3bc7                 | cmp                 eax, edi
            //   740c                 | je                  0xe
            //   68????????           |                     
            //   50                   | push                eax

        $sequence_9 = { c7430801000000 e8???????? 6a06 89430c 8d4310 8d89d41a4100 5a }
            // n = 7, score = 200
            //   c7430801000000       | mov                 dword ptr [ebx + 8], 1
            //   e8????????           |                     
            //   6a06                 | push                6
            //   89430c               | mov                 dword ptr [ebx + 0xc], eax
            //   8d4310               | lea                 eax, [ebx + 0x10]
            //   8d89d41a4100         | lea                 ecx, [ecx + 0x411ad4]
            //   5a                   | pop                 edx

    condition:
        7 of them and filesize < 180224
}