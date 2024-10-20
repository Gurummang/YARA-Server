rule win_observer_stealer_auto {

    meta:
        atk_type = "win.observer_stealer."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.observer_stealer."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.observer_stealer"
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
        $sequence_0 = { c1ea03 0fb60c02 8bc6 83e007 0fabc1 8b442414 }
            // n = 6, score = 100
            //   c1ea03               | shr                 edx, 3
            //   0fb60c02             | movzx               ecx, byte ptr [edx + eax]
            //   8bc6                 | mov                 eax, esi
            //   83e007               | and                 eax, 7
            //   0fabc1               | bts                 ecx, eax
            //   8b442414             | mov                 eax, dword ptr [esp + 0x14]

        $sequence_1 = { 8b5c2418 f6c301 746c 8b3e 85ff 7466 8b5e04 }
            // n = 7, score = 100
            //   8b5c2418             | mov                 ebx, dword ptr [esp + 0x18]
            //   f6c301               | test                bl, 1
            //   746c                 | je                  0x6e
            //   8b3e                 | mov                 edi, dword ptr [esi]
            //   85ff                 | test                edi, edi
            //   7466                 | je                  0x68
            //   8b5e04               | mov                 ebx, dword ptr [esi + 4]

        $sequence_2 = { 50 ff15???????? 8b4c2460 8d442440 50 e8???????? 8d4c2440 }
            // n = 7, score = 100
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8b4c2460             | mov                 ecx, dword ptr [esp + 0x60]
            //   8d442440             | lea                 eax, [esp + 0x40]
            //   50                   | push                eax
            //   e8????????           |                     
            //   8d4c2440             | lea                 ecx, [esp + 0x40]

        $sequence_3 = { e8???????? 68???????? 8d8d54ffffff e8???????? 68???????? 8d8d6cffffff }
            // n = 6, score = 100
            //   e8????????           |                     
            //   68????????           |                     
            //   8d8d54ffffff         | lea                 ecx, [ebp - 0xac]
            //   e8????????           |                     
            //   68????????           |                     
            //   8d8d6cffffff         | lea                 ecx, [ebp - 0x94]

        $sequence_4 = { 59 eb3b 55 8b6b04 2bee c1fd02 56 }
            // n = 7, score = 100
            //   59                   | pop                 ecx
            //   eb3b                 | jmp                 0x3d
            //   55                   | push                ebp
            //   8b6b04               | mov                 ebp, dword ptr [ebx + 4]
            //   2bee                 | sub                 ebp, esi
            //   c1fd02               | sar                 ebp, 2
            //   56                   | push                esi

        $sequence_5 = { 85f6 740b 83feff 0f859a000000 eb6c 8b1c8d287e4300 }
            // n = 6, score = 100
            //   85f6                 | test                esi, esi
            //   740b                 | je                  0xd
            //   83feff               | cmp                 esi, -1
            //   0f859a000000         | jne                 0xa0
            //   eb6c                 | jmp                 0x6e
            //   8b1c8d287e4300       | mov                 ebx, dword ptr [ecx*4 + 0x437e28]

        $sequence_6 = { 8d8d60ffffff e8???????? 59 83781408 7202 8b00 }
            // n = 6, score = 100
            //   8d8d60ffffff         | lea                 ecx, [ebp - 0xa0]
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   83781408             | cmp                 dword ptr [eax + 0x14], 8
            //   7202                 | jb                  4
            //   8b00                 | mov                 eax, dword ptr [eax]

        $sequence_7 = { 8b442420 8918 5f 5e 5d 5b 83c40c }
            // n = 7, score = 100
            //   8b442420             | mov                 eax, dword ptr [esp + 0x20]
            //   8918                 | mov                 dword ptr [eax], ebx
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   5d                   | pop                 ebp
            //   5b                   | pop                 ebx
            //   83c40c               | add                 esp, 0xc

        $sequence_8 = { 85d2 7912 f7da e8???????? 6a2d 8d48fe 58 }
            // n = 7, score = 100
            //   85d2                 | test                edx, edx
            //   7912                 | jns                 0x14
            //   f7da                 | neg                 edx
            //   e8????????           |                     
            //   6a2d                 | push                0x2d
            //   8d48fe               | lea                 ecx, [eax - 2]
            //   58                   | pop                 eax

        $sequence_9 = { 8d7c2468 894c2464 885c2450 ab ab ab ab }
            // n = 7, score = 100
            //   8d7c2468             | lea                 edi, [esp + 0x68]
            //   894c2464             | mov                 dword ptr [esp + 0x64], ecx
            //   885c2450             | mov                 byte ptr [esp + 0x50], bl
            //   ab                   | stosd               dword ptr es:[edi], eax
            //   ab                   | stosd               dword ptr es:[edi], eax
            //   ab                   | stosd               dword ptr es:[edi], eax
            //   ab                   | stosd               dword ptr es:[edi], eax

    condition:
        7 of them and filesize < 614400
}