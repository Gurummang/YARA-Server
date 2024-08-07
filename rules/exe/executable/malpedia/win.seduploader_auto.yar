rule win_seduploader_auto {

    meta:
        atk_type = "win.seduploader."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.seduploader."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.seduploader"
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
        $sequence_0 = { 50 ff7630 e8???????? 83c40c 3b4508 }
            // n = 5, score = 2400
            //   50                   | push                eax
            //   ff7630               | push                dword ptr [esi + 0x30]
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   3b4508               | cmp                 eax, dword ptr [ebp + 8]

        $sequence_1 = { c6411001 c3 55 8bec }
            // n = 4, score = 2400
            //   c6411001             | mov                 byte ptr [ecx + 0x10], 1
            //   c3                   | ret                 
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp

        $sequence_2 = { 8b4510 83c6fe 8930 8d4601 }
            // n = 4, score = 2400
            //   8b4510               | mov                 eax, dword ptr [ebp + 0x10]
            //   83c6fe               | add                 esi, -2
            //   8930                 | mov                 dword ptr [eax], esi
            //   8d4601               | lea                 eax, [esi + 1]

        $sequence_3 = { 8b4510 83c6fe 8930 8d4601 50 e8???????? }
            // n = 6, score = 2400
            //   8b4510               | mov                 eax, dword ptr [ebp + 0x10]
            //   83c6fe               | add                 esi, -2
            //   8930                 | mov                 dword ptr [eax], esi
            //   8d4601               | lea                 eax, [esi + 1]
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_4 = { 5e c3 55 8bec e8???????? 8b4d0c }
            // n = 6, score = 2400
            //   5e                   | pop                 esi
            //   c3                   | ret                 
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   e8????????           |                     
            //   8b4d0c               | mov                 ecx, dword ptr [ebp + 0xc]

        $sequence_5 = { 8b4510 83c6fe 8930 8d4601 50 }
            // n = 5, score = 2400
            //   8b4510               | mov                 eax, dword ptr [ebp + 0x10]
            //   83c6fe               | add                 esi, -2
            //   8930                 | mov                 dword ptr [eax], esi
            //   8d4601               | lea                 eax, [esi + 1]
            //   50                   | push                eax

        $sequence_6 = { e8???????? 8b4510 83c6fe 8930 }
            // n = 4, score = 2400
            //   e8????????           |                     
            //   8b4510               | mov                 eax, dword ptr [ebp + 0x10]
            //   83c6fe               | add                 esi, -2
            //   8930                 | mov                 dword ptr [eax], esi

        $sequence_7 = { ff763c e8???????? 83c40c 3b4508 }
            // n = 4, score = 2400
            //   ff763c               | push                dword ptr [esi + 0x3c]
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   3b4508               | cmp                 eax, dword ptr [ebp + 8]

        $sequence_8 = { ff7630 e8???????? 83c40c 3b4508 }
            // n = 4, score = 2400
            //   ff7630               | push                dword ptr [esi + 0x30]
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   3b4508               | cmp                 eax, dword ptr [ebp + 8]

        $sequence_9 = { 50 e8???????? 8b4510 83c6fe 8930 8d4601 50 }
            // n = 7, score = 2400
            //   50                   | push                eax
            //   e8????????           |                     
            //   8b4510               | mov                 eax, dword ptr [ebp + 0x10]
            //   83c6fe               | add                 esi, -2
            //   8930                 | mov                 dword ptr [eax], esi
            //   8d4601               | lea                 eax, [esi + 1]
            //   50                   | push                eax

    condition:
        7 of them and filesize < 401408
}