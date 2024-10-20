rule win_tinyloader_auto {

    meta:
        atk_type = "win.tinyloader."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.tinyloader."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.tinyloader"
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
        $sequence_0 = { 90 8bbb97114000 90 8938 90 }
            // n = 5, score = 100
            //   90                   | nop                 
            //   8bbb97114000         | mov                 edi, dword ptr [ebx + 0x401197]
            //   90                   | nop                 
            //   8938                 | mov                 dword ptr [eax], edi
            //   90                   | nop                 

        $sequence_1 = { 6689c8 90 6a40 6800300000 6800800200 6a00 }
            // n = 6, score = 100
            //   6689c8               | mov                 ax, cx
            //   90                   | nop                 
            //   6a40                 | push                0x40
            //   6800300000           | push                0x3000
            //   6800800200           | push                0x28000
            //   6a00                 | push                0

        $sequence_2 = { 039d58080000 6a00 6800040000 53 ffb5b8050000 ff15???????? }
            // n = 6, score = 100
            //   039d58080000         | add                 ebx, dword ptr [ebp + 0x858]
            //   6a00                 | push                0
            //   6800040000           | push                0x400
            //   53                   | push                ebx
            //   ffb5b8050000         | push                dword ptr [ebp + 0x5b8]
            //   ff15????????         |                     

        $sequence_3 = { 31db 90 31c9 90 }
            // n = 4, score = 100
            //   31db                 | xor                 ebx, ebx
            //   90                   | nop                 
            //   31c9                 | xor                 ecx, ecx
            //   90                   | nop                 

        $sequence_4 = { 8b5510 01da 8b12 8b4500 }
            // n = 4, score = 100
            //   8b5510               | mov                 edx, dword ptr [ebp + 0x10]
            //   01da                 | add                 edx, ebx
            //   8b12                 | mov                 edx, dword ptr [edx]
            //   8b4500               | mov                 eax, dword ptr [ebp]

        $sequence_5 = { 81c300040000 6a00 ff33 ff7500 ffb5b8050000 ff15???????? 83f8ff }
            // n = 7, score = 100
            //   81c300040000         | add                 ebx, 0x400
            //   6a00                 | push                0
            //   ff33                 | push                dword ptr [ebx]
            //   ff7500               | push                dword ptr [ebp]
            //   ffb5b8050000         | push                dword ptr [ebp + 0x5b8]
            //   ff15????????         |                     
            //   83f8ff               | cmp                 eax, -1

        $sequence_6 = { 8b4500 83c008 c70000000000 c7855808000000000000 8b5d00 039d58080000 }
            // n = 6, score = 100
            //   8b4500               | mov                 eax, dword ptr [ebp]
            //   83c008               | add                 eax, 8
            //   c70000000000         | mov                 dword ptr [eax], 0
            //   c7855808000000000000     | mov    dword ptr [ebp + 0x858], 0
            //   8b5d00               | mov                 ebx, dword ptr [ebp]
            //   039d58080000         | add                 ebx, dword ptr [ebp + 0x858]

        $sequence_7 = { 83bd580800000c 7302 ebc3 8b5d00 }
            // n = 4, score = 100
            //   83bd580800000c       | cmp                 dword ptr [ebp + 0x858], 0xc
            //   7302                 | jae                 4
            //   ebc3                 | jmp                 0xffffffc5
            //   8b5d00               | mov                 ebx, dword ptr [ebp]

        $sequence_8 = { ff15???????? 8985b8050000 6832a00000 ff15???????? 8b9da8050000 66894302 66c7030200 }
            // n = 7, score = 100
            //   ff15????????         |                     
            //   8985b8050000         | mov                 dword ptr [ebp + 0x5b8], eax
            //   6832a00000           | push                0xa032
            //   ff15????????         |                     
            //   8b9da8050000         | mov                 ebx, dword ptr [ebp + 0x5a8]
            //   66894302             | mov                 word ptr [ebx + 2], ax
            //   66c7030200           | mov                 word ptr [ebx], 2

        $sequence_9 = { 90 89c6 90 0500400100 }
            // n = 4, score = 100
            //   90                   | nop                 
            //   89c6                 | mov                 esi, eax
            //   90                   | nop                 
            //   0500400100           | add                 eax, 0x14000

        $sequence_10 = { ffb5a0050000 6802020000 ff15???????? 6a06 6a01 6a02 ff15???????? }
            // n = 7, score = 100
            //   ffb5a0050000         | push                dword ptr [ebp + 0x5a0]
            //   6802020000           | push                0x202
            //   ff15????????         |                     
            //   6a06                 | push                6
            //   6a01                 | push                1
            //   6a02                 | push                2
            //   ff15????????         |                     

        $sequence_11 = { c705????????00010000 68???????? 68???????? ff15???????? 68???????? ff15???????? }
            // n = 6, score = 100
            //   c705????????00010000     |     
            //   68????????           |                     
            //   68????????           |                     
            //   ff15????????         |                     
            //   68????????           |                     
            //   ff15????????         |                     

        $sequence_12 = { 6a10 ffb5a8050000 ffb5b8050000 ff15???????? }
            // n = 4, score = 100
            //   6a10                 | push                0x10
            //   ffb5a8050000         | push                dword ptr [ebp + 0x5a8]
            //   ffb5b8050000         | push                dword ptr [ebp + 0x5b8]
            //   ff15????????         |                     

        $sequence_13 = { 81fb04030000 730c 90 83c004 }
            // n = 4, score = 100
            //   81fb04030000         | cmp                 ebx, 0x304
            //   730c                 | jae                 0xe
            //   90                   | nop                 
            //   83c004               | add                 eax, 4

        $sequence_14 = { 31c9 90 3108 90 813890909090 }
            // n = 5, score = 100
            //   31c9                 | xor                 ecx, ecx
            //   90                   | nop                 
            //   3108                 | xor                 dword ptr [eax], ecx
            //   90                   | nop                 
            //   813890909090         | cmp                 dword ptr [eax], 0x90909090

        $sequence_15 = { 637574 6541 0050ff 15???????? c705????????00010000 68???????? 68???????? }
            // n = 7, score = 100
            //   637574               | arpl                word ptr [ebp + 0x74], si
            //   6541                 | inc                 ecx
            //   0050ff               | add                 byte ptr [eax - 1], dl
            //   15????????           |                     
            //   c705????????00010000     |     
            //   68????????           |                     
            //   68????????           |                     

    condition:
        7 of them and filesize < 40960
}