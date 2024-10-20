rule win_cryptoshield_auto {

    meta:
        atk_type = "win.cryptoshield."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.cryptoshield."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.cryptoshield"
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
        $sequence_0 = { 8b18 8b45fc 85c0 740e }
            // n = 4, score = 300
            //   8b18                 | mov                 ebx, dword ptr [eax]
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   85c0                 | test                eax, eax
            //   740e                 | je                  0x10

        $sequence_1 = { 50 ffd7 83c40c 8d442418 50 8d84242c020000 68???????? }
            // n = 7, score = 300
            //   50                   | push                eax
            //   ffd7                 | call                edi
            //   83c40c               | add                 esp, 0xc
            //   8d442418             | lea                 eax, [esp + 0x18]
            //   50                   | push                eax
            //   8d84242c020000       | lea                 eax, [esp + 0x22c]
            //   68????????           |                     

        $sequence_2 = { 50 8d442428 50 ff15???????? 8d842430040000 }
            // n = 5, score = 300
            //   50                   | push                eax
            //   8d442428             | lea                 eax, [esp + 0x28]
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8d842430040000       | lea                 eax, [esp + 0x430]

        $sequence_3 = { 85c0 7461 ff7508 6a40 ff15???????? }
            // n = 5, score = 300
            //   85c0                 | test                eax, eax
            //   7461                 | je                  0x63
            //   ff7508               | push                dword ptr [ebp + 8]
            //   6a40                 | push                0x40
            //   ff15????????         |                     

        $sequence_4 = { 750b 83c202 66833a00 75ce eb08 }
            // n = 5, score = 300
            //   750b                 | jne                 0xd
            //   83c202               | add                 edx, 2
            //   66833a00             | cmp                 word ptr [edx], 0
            //   75ce                 | jne                 0xffffffd0
            //   eb08                 | jmp                 0xa

        $sequence_5 = { 6a00 6a23 50 6a00 ff15???????? 8d85f4fdffff 50 }
            // n = 7, score = 300
            //   6a00                 | push                0
            //   6a23                 | push                0x23
            //   50                   | push                eax
            //   6a00                 | push                0
            //   ff15????????         |                     
            //   8d85f4fdffff         | lea                 eax, [ebp - 0x20c]
            //   50                   | push                eax

        $sequence_6 = { b90a000000 83f801 0f44f1 8b4dfc }
            // n = 4, score = 300
            //   b90a000000           | mov                 ecx, 0xa
            //   83f801               | cmp                 eax, 1
            //   0f44f1               | cmove               esi, ecx
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]

        $sequence_7 = { be09000000 8bc6 5e 8b4dfc 33cd e8???????? 8be5 }
            // n = 7, score = 300
            //   be09000000           | mov                 esi, 9
            //   8bc6                 | mov                 eax, esi
            //   5e                   | pop                 esi
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   33cd                 | xor                 ecx, ebp
            //   e8????????           |                     
            //   8be5                 | mov                 esp, ebp

        $sequence_8 = { 56 6814010000 33f6 8d85e0feffff 56 }
            // n = 5, score = 300
            //   56                   | push                esi
            //   6814010000           | push                0x114
            //   33f6                 | xor                 esi, esi
            //   8d85e0feffff         | lea                 eax, [ebp - 0x120]
            //   56                   | push                esi

        $sequence_9 = { 56 ff15???????? 85ff 0f45df 5f 5e 8bc3 }
            // n = 7, score = 300
            //   56                   | push                esi
            //   ff15????????         |                     
            //   85ff                 | test                edi, edi
            //   0f45df               | cmovne              ebx, edi
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   8bc3                 | mov                 eax, ebx

    condition:
        7 of them and filesize < 131072
}