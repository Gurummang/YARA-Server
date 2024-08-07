rule win_milkmaid_auto {

    meta:
        atk_type = "win.milkmaid."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.milkmaid."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.milkmaid"
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
        $sequence_0 = { 7440 56 ff15???????? 8d4c2414 }
            // n = 4, score = 100
            //   7440                 | je                  0x42
            //   56                   | push                esi
            //   ff15????????         |                     
            //   8d4c2414             | lea                 ecx, [esp + 0x14]

        $sequence_1 = { c68424dc28010002 e8???????? 8d4c2410 c68424dc28010001 }
            // n = 4, score = 100
            //   c68424dc28010002     | mov                 byte ptr [esp + 0x128dc], 2
            //   e8????????           |                     
            //   8d4c2410             | lea                 ecx, [esp + 0x10]
            //   c68424dc28010001     | mov                 byte ptr [esp + 0x128dc], 1

        $sequence_2 = { 50 53 ff15???????? 8d4c2478 c68424dc28010002 }
            // n = 5, score = 100
            //   50                   | push                eax
            //   53                   | push                ebx
            //   ff15????????         |                     
            //   8d4c2478             | lea                 ecx, [esp + 0x78]
            //   c68424dc28010002     | mov                 byte ptr [esp + 0x128dc], 2

        $sequence_3 = { 6a00 ff15???????? 6aff 8d4c2408 e8???????? 68???????? 8d4c2408 }
            // n = 7, score = 100
            //   6a00                 | push                0
            //   ff15????????         |                     
            //   6aff                 | push                -1
            //   8d4c2408             | lea                 ecx, [esp + 8]
            //   e8????????           |                     
            //   68????????           |                     
            //   8d4c2408             | lea                 ecx, [esp + 8]

        $sequence_4 = { 895c2428 7513 8b5508 52 53 }
            // n = 5, score = 100
            //   895c2428             | mov                 dword ptr [esp + 0x28], ebx
            //   7513                 | jne                 0x15
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   52                   | push                edx
            //   53                   | push                ebx

        $sequence_5 = { 8d442408 57 50 e8???????? 83c404 33db }
            // n = 6, score = 100
            //   8d442408             | lea                 eax, [esp + 8]
            //   57                   | push                edi
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   33db                 | xor                 ebx, ebx

        $sequence_6 = { 8be9 896c2420 8a8528280100 84c0 7528 8b4d04 }
            // n = 6, score = 100
            //   8be9                 | mov                 ebp, ecx
            //   896c2420             | mov                 dword ptr [esp + 0x20], ebp
            //   8a8528280100         | mov                 al, byte ptr [ebp + 0x12828]
            //   84c0                 | test                al, al
            //   7528                 | jne                 0x2a
            //   8b4d04               | mov                 ecx, dword ptr [ebp + 4]

        $sequence_7 = { 51 8d8c2480000000 c68424e428010003 e8???????? b911000000 }
            // n = 5, score = 100
            //   51                   | push                ecx
            //   8d8c2480000000       | lea                 ecx, [esp + 0x80]
            //   c68424e428010003     | mov                 byte ptr [esp + 0x128e4], 3
            //   e8????????           |                     
            //   b911000000           | mov                 ecx, 0x11

    condition:
        7 of them and filesize < 65536
}