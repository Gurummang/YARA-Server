rule win_ismagent_auto {

    meta:
        atk_type = "win.ismagent."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.ismagent."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ismagent"
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
        $sequence_0 = { ba???????? 6a00 6800000080 6a00 6a00 68???????? 53 }
            // n = 7, score = 200
            //   ba????????           |                     
            //   6a00                 | push                0
            //   6800000080           | push                0x80000000
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   68????????           |                     
            //   53                   | push                ebx

        $sequence_1 = { 89442440 85c0 752b 50 68???????? }
            // n = 5, score = 200
            //   89442440             | mov                 dword ptr [esp + 0x40], eax
            //   85c0                 | test                eax, eax
            //   752b                 | jne                 0x2d
            //   50                   | push                eax
            //   68????????           |                     

        $sequence_2 = { eb7c c745e000fe4100 ebbb d9e8 8b4510 }
            // n = 5, score = 200
            //   eb7c                 | jmp                 0x7e
            //   c745e000fe4100       | mov                 dword ptr [ebp - 0x20], 0x41fe00
            //   ebbb                 | jmp                 0xffffffbd
            //   d9e8                 | fld1                
            //   8b4510               | mov                 eax, dword ptr [ebp + 0x10]

        $sequence_3 = { e8???????? 83c408 89442418 85c0 0f8479020000 }
            // n = 5, score = 200
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   89442418             | mov                 dword ptr [esp + 0x18], eax
            //   85c0                 | test                eax, eax
            //   0f8479020000         | je                  0x27f

        $sequence_4 = { 68e8030000 ff15???????? 8d8c2418030000 8d5101 }
            // n = 4, score = 200
            //   68e8030000           | push                0x3e8
            //   ff15????????         |                     
            //   8d8c2418030000       | lea                 ecx, [esp + 0x318]
            //   8d5101               | lea                 edx, [ecx + 1]

        $sequence_5 = { 7432 8d842418030000 68???????? 50 e8???????? 8bf0 }
            // n = 6, score = 200
            //   7432                 | je                  0x34
            //   8d842418030000       | lea                 eax, [esp + 0x318]
            //   68????????           |                     
            //   50                   | push                eax
            //   e8????????           |                     
            //   8bf0                 | mov                 esi, eax

        $sequence_6 = { 8bf2 0f1f4000 8a02 42 84c0 75f9 8dbc2400070000 }
            // n = 7, score = 200
            //   8bf2                 | mov                 esi, edx
            //   0f1f4000             | nop                 dword ptr [eax]
            //   8a02                 | mov                 al, byte ptr [edx]
            //   42                   | inc                 edx
            //   84c0                 | test                al, al
            //   75f9                 | jne                 0xfffffffb
            //   8dbc2400070000       | lea                 edi, [esp + 0x700]

        $sequence_7 = { 8d0439 7413 0f1f4000 803823 740a }
            // n = 5, score = 200
            //   8d0439               | lea                 eax, [ecx + edi]
            //   7413                 | je                  0x15
            //   0f1f4000             | nop                 dword ptr [eax]
            //   803823               | cmp                 byte ptr [eax], 0x23
            //   740a                 | je                  0xc

    condition:
        7 of them and filesize < 327680
}