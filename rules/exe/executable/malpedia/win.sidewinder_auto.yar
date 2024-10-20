rule win_sidewinder_auto {

    meta:
        atk_type = "win.sidewinder."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.sidewinder."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.sidewinder"
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
        $sequence_0 = { 83a570fdffff00 8b45c4 89853cffffff 8d8544ffffff 50 8b853cffffff 8b00 }
            // n = 7, score = 200
            //   83a570fdffff00       | and                 dword ptr [ebp - 0x290], 0
            //   8b45c4               | mov                 eax, dword ptr [ebp - 0x3c]
            //   89853cffffff         | mov                 dword ptr [ebp - 0xc4], eax
            //   8d8544ffffff         | lea                 eax, [ebp - 0xbc]
            //   50                   | push                eax
            //   8b853cffffff         | mov                 eax, dword ptr [ebp - 0xc4]
            //   8b00                 | mov                 eax, dword ptr [eax]

        $sequence_1 = { 50 e8???????? 89852cfbffff e8???????? 8d8568fbffff 50 e8???????? }
            // n = 7, score = 200
            //   50                   | push                eax
            //   e8????????           |                     
            //   89852cfbffff         | mov                 dword ptr [ebp - 0x4d4], eax
            //   e8????????           |                     
            //   8d8568fbffff         | lea                 eax, [ebp - 0x498]
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_2 = { e8???????? 8d45c4 50 8d45a0 50 e8???????? 8d45a0 }
            // n = 7, score = 200
            //   e8????????           |                     
            //   8d45c4               | lea                 eax, [ebp - 0x3c]
            //   50                   | push                eax
            //   8d45a0               | lea                 eax, [ebp - 0x60]
            //   50                   | push                eax
            //   e8????????           |                     
            //   8d45a0               | lea                 eax, [ebp - 0x60]

        $sequence_3 = { 8d45e0 50 e8???????? 0fbf45e8 50 ff75e0 e8???????? }
            // n = 7, score = 200
            //   8d45e0               | lea                 eax, [ebp - 0x20]
            //   50                   | push                eax
            //   e8????????           |                     
            //   0fbf45e8             | movsx               eax, word ptr [ebp - 0x18]
            //   50                   | push                eax
            //   ff75e0               | push                dword ptr [ebp - 0x20]
            //   e8????????           |                     

        $sequence_4 = { 7d20 6a30 68???????? ff35???????? ffb534ffffff e8???????? 898504ffffff }
            // n = 7, score = 200
            //   7d20                 | jge                 0x22
            //   6a30                 | push                0x30
            //   68????????           |                     
            //   ff35????????         |                     
            //   ffb534ffffff         | push                dword ptr [ebp - 0xcc]
            //   e8????????           |                     
            //   898504ffffff         | mov                 dword ptr [ebp - 0xfc], eax

        $sequence_5 = { 8b00 ff7508 ff5004 8b450c 832000 8d45e8 50 }
            // n = 7, score = 200
            //   8b00                 | mov                 eax, dword ptr [eax]
            //   ff7508               | push                dword ptr [ebp + 8]
            //   ff5004               | call                dword ptr [eax + 4]
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   832000               | and                 dword ptr [eax], 0
            //   8d45e8               | lea                 eax, [ebp - 0x18]
            //   50                   | push                eax

        $sequence_6 = { e8???????? 8bd0 8d4de8 e8???????? 8d45c8 50 8d45d8 }
            // n = 7, score = 200
            //   e8????????           |                     
            //   8bd0                 | mov                 edx, eax
            //   8d4de8               | lea                 ecx, [ebp - 0x18]
            //   e8????????           |                     
            //   8d45c8               | lea                 eax, [ebp - 0x38]
            //   50                   | push                eax
            //   8d45d8               | lea                 eax, [ebp - 0x28]

        $sequence_7 = { ff5020 dbe2 898528ffffff 83bd28ffffff00 7d1d 6a20 68???????? }
            // n = 7, score = 200
            //   ff5020               | call                dword ptr [eax + 0x20]
            //   dbe2                 | fnclex              
            //   898528ffffff         | mov                 dword ptr [ebp - 0xd8], eax
            //   83bd28ffffff00       | cmp                 dword ptr [ebp - 0xd8], 0
            //   7d1d                 | jge                 0x1f
            //   6a20                 | push                0x20
            //   68????????           |                     

        $sequence_8 = { 8945dc 8d45e4 50 8b45dc 8b00 ff75dc ff5024 }
            // n = 7, score = 200
            //   8945dc               | mov                 dword ptr [ebp - 0x24], eax
            //   8d45e4               | lea                 eax, [ebp - 0x1c]
            //   50                   | push                eax
            //   8b45dc               | mov                 eax, dword ptr [ebp - 0x24]
            //   8b00                 | mov                 eax, dword ptr [eax]
            //   ff75dc               | push                dword ptr [ebp - 0x24]
            //   ff5024               | call                dword ptr [eax + 0x24]

        $sequence_9 = { ff75b8 ff75d8 6aff 6820110000 e8???????? 83650c00 eb27 }
            // n = 7, score = 200
            //   ff75b8               | push                dword ptr [ebp - 0x48]
            //   ff75d8               | push                dword ptr [ebp - 0x28]
            //   6aff                 | push                -1
            //   6820110000           | push                0x1120
            //   e8????????           |                     
            //   83650c00             | and                 dword ptr [ebp + 0xc], 0
            //   eb27                 | jmp                 0x29

    condition:
        7 of them and filesize < 679936
}