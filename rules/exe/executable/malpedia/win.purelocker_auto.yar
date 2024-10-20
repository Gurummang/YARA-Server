rule win_purelocker_auto {

    meta:
        atk_type = "win.purelocker."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.purelocker."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.purelocker"
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
        $sequence_0 = { c7042400000000 8d442434 50 8d842440040000 50 8d842440020000 }
            // n = 6, score = 100
            //   c7042400000000       | mov                 dword ptr [esp], 0
            //   8d442434             | lea                 eax, [esp + 0x34]
            //   50                   | push                eax
            //   8d842440040000       | lea                 eax, [esp + 0x440]
            //   50                   | push                eax
            //   8d842440020000       | lea                 eax, [esp + 0x240]

        $sequence_1 = { c1e908 81e1ff000000 331c85201c0110 8b442414 8b148d20180110 335f08 }
            // n = 6, score = 100
            //   c1e908               | shr                 ecx, 8
            //   81e1ff000000         | and                 ecx, 0xff
            //   331c85201c0110       | xor                 ebx, dword ptr [eax*4 + 0x10011c20]
            //   8b442414             | mov                 eax, dword ptr [esp + 0x14]
            //   8b148d20180110       | mov                 edx, dword ptr [ecx*4 + 0x10011820]
            //   335f08               | xor                 ebx, dword ptr [edi + 8]

        $sequence_2 = { 8b442410 0fb6c0 330c8520300110 8bc6 }
            // n = 4, score = 100
            //   8b442410             | mov                 eax, dword ptr [esp + 0x10]
            //   0fb6c0               | movzx               eax, al
            //   330c8520300110       | xor                 ecx, dword ptr [eax*4 + 0x10013020]
            //   8bc6                 | mov                 eax, esi

        $sequence_3 = { 6a00 85c9 59 751a 8bda 53 }
            // n = 6, score = 100
            //   6a00                 | push                0
            //   85c9                 | test                ecx, ecx
            //   59                   | pop                 ecx
            //   751a                 | jne                 0x1c
            //   8bda                 | mov                 ebx, edx
            //   53                   | push                ebx

        $sequence_4 = { 53 ba17000000 83ec04 c7042400000000 4a 75f3 e8???????? }
            // n = 7, score = 100
            //   53                   | push                ebx
            //   ba17000000           | mov                 edx, 0x17
            //   83ec04               | sub                 esp, 4
            //   c7042400000000       | mov                 dword ptr [esp], 0
            //   4a                   | dec                 edx
            //   75f3                 | jne                 0xfffffff5
            //   e8????????           |                     

        $sequence_5 = { 8d1524400110 59 e8???????? 741e 8b542468 52 }
            // n = 6, score = 100
            //   8d1524400110         | lea                 edx, [0x10014024]
            //   59                   | pop                 ecx
            //   e8????????           |                     
            //   741e                 | je                  0x20
            //   8b542468             | mov                 edx, dword ptr [esp + 0x68]
            //   52                   | push                edx

        $sequence_6 = { 50 31c0 50 8b15???????? 52 e8???????? 5a }
            // n = 7, score = 100
            //   50                   | push                eax
            //   31c0                 | xor                 eax, eax
            //   50                   | push                eax
            //   8b15????????         |                     
            //   52                   | push                edx
            //   e8????????           |                     
            //   5a                   | pop                 edx

        $sequence_7 = { e8???????? 8d1524400110 8d0d285e0110 e8???????? 8d1524400110 8d0d845d0110 }
            // n = 6, score = 100
            //   e8????????           |                     
            //   8d1524400110         | lea                 edx, [0x10014024]
            //   8d0d285e0110         | lea                 ecx, [0x10015e28]
            //   e8????????           |                     
            //   8d1524400110         | lea                 edx, [0x10014024]
            //   8d0d845d0110         | lea                 ecx, [0x10015d84]

        $sequence_8 = { e8???????? e8???????? 011424 e8???????? 58 8b542408 52 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   e8????????           |                     
            //   011424               | add                 dword ptr [esp], edx
            //   e8????????           |                     
            //   58                   | pop                 eax
            //   8b542408             | mov                 edx, dword ptr [esp + 8]
            //   52                   | push                edx

        $sequence_9 = { 50 680a000000 ff742418 e8???????? e8???????? 52 e8???????? }
            // n = 7, score = 100
            //   50                   | push                eax
            //   680a000000           | push                0xa
            //   ff742418             | push                dword ptr [esp + 0x18]
            //   e8????????           |                     
            //   e8????????           |                     
            //   52                   | push                edx
            //   e8????????           |                     

    condition:
        7 of them and filesize < 193536
}