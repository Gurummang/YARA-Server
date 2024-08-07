rule win_stinger_auto {

    meta:
        atk_type = "win.stinger."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.stinger."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.stinger"
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
        $sequence_0 = { 8bec 81ec10000000 6804000080 6a00 8b5d08 }
            // n = 5, score = 200
            //   8bec                 | mov                 ebp, esp
            //   81ec10000000         | sub                 esp, 0x10
            //   6804000080           | push                0x80000004
            //   6a00                 | push                0
            //   8b5d08               | mov                 ebx, dword ptr [ebp + 8]

        $sequence_1 = { f6c441 0f854d010000 8b45f4 50 8b5d08 ff33 }
            // n = 6, score = 200
            //   f6c441               | test                ah, 0x41
            //   0f854d010000         | jne                 0x153
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]
            //   50                   | push                eax
            //   8b5d08               | mov                 ebx, dword ptr [ebp + 8]
            //   ff33                 | push                dword ptr [ebx]

        $sequence_2 = { 895df8 8965f4 ff75fc ff15???????? 90 90 }
            // n = 6, score = 200
            //   895df8               | mov                 dword ptr [ebp - 8], ebx
            //   8965f4               | mov                 dword ptr [ebp - 0xc], esp
            //   ff75fc               | push                dword ptr [ebp - 4]
            //   ff15????????         |                     
            //   90                   | nop                 
            //   90                   | nop                 

        $sequence_3 = { 6806000000 e8???????? 83c404 e9???????? 8be5 5d c21000 }
            // n = 7, score = 200
            //   6806000000           | push                6
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   e9????????           |                     
            //   8be5                 | mov                 esp, ebp
            //   5d                   | pop                 ebp
            //   c21000               | ret                 0x10

        $sequence_4 = { e9???????? 68???????? 8b5d0c ff33 e8???????? 83c408 }
            // n = 6, score = 200
            //   e9????????           |                     
            //   68????????           |                     
            //   8b5d0c               | mov                 ebx, dword ptr [ebp + 0xc]
            //   ff33                 | push                dword ptr [ebx]
            //   e8????????           |                     
            //   83c408               | add                 esp, 8

        $sequence_5 = { a1???????? 85c0 891c85ecbe4000 750a }
            // n = 4, score = 200
            //   a1????????           |                     
            //   85c0                 | test                eax, eax
            //   891c85ecbe4000       | mov                 dword ptr [eax*4 + 0x40beec], ebx
            //   750a                 | jne                 0xc

        $sequence_6 = { 6806000000 e8???????? 83c404 a3???????? 8965f8 68???????? }
            // n = 6, score = 200
            //   6806000000           | push                6
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   a3????????           |                     
            //   8965f8               | mov                 dword ptr [ebp - 8], esp
            //   68????????           |                     

        $sequence_7 = { ff75fc 6802000000 bb94020000 e8???????? 83c41c 8945e8 }
            // n = 6, score = 200
            //   ff75fc               | push                dword ptr [ebp - 4]
            //   6802000000           | push                2
            //   bb94020000           | mov                 ebx, 0x294
            //   e8????????           |                     
            //   83c41c               | add                 esp, 0x1c
            //   8945e8               | mov                 dword ptr [ebp - 0x18], eax

        $sequence_8 = { 6800000000 6800000000 68???????? ff35???????? 6800000000 ff15???????? 90 }
            // n = 7, score = 200
            //   6800000000           | push                0
            //   6800000000           | push                0
            //   68????????           |                     
            //   ff35????????         |                     
            //   6800000000           | push                0
            //   ff15????????         |                     
            //   90                   | nop                 

        $sequence_9 = { 8b5d08 ff33 b902000000 e8???????? 83c408 8945f0 ff750c }
            // n = 7, score = 200
            //   8b5d08               | mov                 ebx, dword ptr [ebp + 8]
            //   ff33                 | push                dword ptr [ebx]
            //   b902000000           | mov                 ecx, 2
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   8945f0               | mov                 dword ptr [ebp - 0x10], eax
            //   ff750c               | push                dword ptr [ebp + 0xc]

    condition:
        7 of them and filesize < 197096
}