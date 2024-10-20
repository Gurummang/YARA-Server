rule win_rumish_auto {

    meta:
        atk_type = "win.rumish."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.rumish."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.rumish"
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
        $sequence_0 = { 8d450c 50 e8???????? 8b4df8 e8???????? 8b45f8 8be5 }
            // n = 7, score = 100
            //   8d450c               | lea                 eax, [ebp + 0xc]
            //   50                   | push                eax
            //   e8????????           |                     
            //   8b4df8               | mov                 ecx, dword ptr [ebp - 8]
            //   e8????????           |                     
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]
            //   8be5                 | mov                 esp, ebp

        $sequence_1 = { eb46 68???????? 8d8d78feffff e8???????? eb34 68???????? 8d8d78feffff }
            // n = 7, score = 100
            //   eb46                 | jmp                 0x48
            //   68????????           |                     
            //   8d8d78feffff         | lea                 ecx, [ebp - 0x188]
            //   e8????????           |                     
            //   eb34                 | jmp                 0x36
            //   68????????           |                     
            //   8d8d78feffff         | lea                 ecx, [ebp - 0x188]

        $sequence_2 = { 7375 8b9570ffffff 0faf5580 039574ffffff 899574feffff 8d8574feffff 50 }
            // n = 7, score = 100
            //   7375                 | jae                 0x77
            //   8b9570ffffff         | mov                 edx, dword ptr [ebp - 0x90]
            //   0faf5580             | imul                edx, dword ptr [ebp - 0x80]
            //   039574ffffff         | add                 edx, dword ptr [ebp - 0x8c]
            //   899574feffff         | mov                 dword ptr [ebp - 0x18c], edx
            //   8d8574feffff         | lea                 eax, [ebp - 0x18c]
            //   50                   | push                eax

        $sequence_3 = { 898534ffffff 8b8d34ffffff 3b4d94 7d40 e8???????? 8985a8feffff }
            // n = 6, score = 100
            //   898534ffffff         | mov                 dword ptr [ebp - 0xcc], eax
            //   8b8d34ffffff         | mov                 ecx, dword ptr [ebp - 0xcc]
            //   3b4d94               | cmp                 ecx, dword ptr [ebp - 0x6c]
            //   7d40                 | jge                 0x42
            //   e8????????           |                     
            //   8985a8feffff         | mov                 dword ptr [ebp - 0x158], eax

        $sequence_4 = { 8d8df0faffff e8???????? e9???????? 68???????? 8d8df0faffff e8???????? e9???????? }
            // n = 7, score = 100
            //   8d8df0faffff         | lea                 ecx, [ebp - 0x510]
            //   e8????????           |                     
            //   e9????????           |                     
            //   68????????           |                     
            //   8d8df0faffff         | lea                 ecx, [ebp - 0x510]
            //   e8????????           |                     
            //   e9????????           |                     

        $sequence_5 = { 0fbf4dbc 898d30ffffff 8b9530ffffff 83ea04 899530ffffff 83bd30ffffff0b 0f87a4020000 }
            // n = 7, score = 100
            //   0fbf4dbc             | movsx               ecx, word ptr [ebp - 0x44]
            //   898d30ffffff         | mov                 dword ptr [ebp - 0xd0], ecx
            //   8b9530ffffff         | mov                 edx, dword ptr [ebp - 0xd0]
            //   83ea04               | sub                 edx, 4
            //   899530ffffff         | mov                 dword ptr [ebp - 0xd0], edx
            //   83bd30ffffff0b       | cmp                 dword ptr [ebp - 0xd0], 0xb
            //   0f87a4020000         | ja                  0x2aa

        $sequence_6 = { 7d5d e8???????? 898560ffffff db8560ffffff dc0d???????? dc35???????? d9bd5effffff }
            // n = 7, score = 100
            //   7d5d                 | jge                 0x5f
            //   e8????????           |                     
            //   898560ffffff         | mov                 dword ptr [ebp - 0xa0], eax
            //   db8560ffffff         | fild                dword ptr [ebp - 0xa0]
            //   dc0d????????         |                     
            //   dc35????????         |                     
            //   d9bd5effffff         | fnstcw              word ptr [ebp - 0xa2]

        $sequence_7 = { e8???????? 6a01 8b55f0 52 8b4d9c 83c10c e8???????? }
            // n = 7, score = 100
            //   e8????????           |                     
            //   6a01                 | push                1
            //   8b55f0               | mov                 edx, dword ptr [ebp - 0x10]
            //   52                   | push                edx
            //   8b4d9c               | mov                 ecx, dword ptr [ebp - 0x64]
            //   83c10c               | add                 ecx, 0xc
            //   e8????????           |                     

        $sequence_8 = { 8bec 83ec08 894df8 51 8bcc 8965fc 8d450c }
            // n = 7, score = 100
            //   8bec                 | mov                 ebp, esp
            //   83ec08               | sub                 esp, 8
            //   894df8               | mov                 dword ptr [ebp - 8], ecx
            //   51                   | push                ecx
            //   8bcc                 | mov                 ecx, esp
            //   8965fc               | mov                 dword ptr [ebp - 4], esp
            //   8d450c               | lea                 eax, [ebp + 0xc]

        $sequence_9 = { 83e901 898d80feffff 8d9580feffff 52 8d4d84 e8???????? 8b4580 }
            // n = 7, score = 100
            //   83e901               | sub                 ecx, 1
            //   898d80feffff         | mov                 dword ptr [ebp - 0x180], ecx
            //   8d9580feffff         | lea                 edx, [ebp - 0x180]
            //   52                   | push                edx
            //   8d4d84               | lea                 ecx, [ebp - 0x7c]
            //   e8????????           |                     
            //   8b4580               | mov                 eax, dword ptr [ebp - 0x80]

    condition:
        7 of them and filesize < 770048
}