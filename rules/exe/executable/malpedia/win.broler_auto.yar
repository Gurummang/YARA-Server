rule win_broler_auto {

    meta:
        atk_type = "win.broler."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.broler."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.broler"
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
        $sequence_0 = { 6a00 68???????? 50 68???????? 56 ff15???????? 898520dffcff }
            // n = 7, score = 100
            //   6a00                 | push                0
            //   68????????           |                     
            //   50                   | push                eax
            //   68????????           |                     
            //   56                   | push                esi
            //   ff15????????         |                     
            //   898520dffcff         | mov                 dword ptr [ebp - 0x320e0], eax

        $sequence_1 = { 39b820b54100 0f8491000000 ff45e4 83c030 3df0000000 72e7 81ffe8fd0000 }
            // n = 7, score = 100
            //   39b820b54100         | cmp                 dword ptr [eax + 0x41b520], edi
            //   0f8491000000         | je                  0x97
            //   ff45e4               | inc                 dword ptr [ebp - 0x1c]
            //   83c030               | add                 eax, 0x30
            //   3df0000000           | cmp                 eax, 0xf0
            //   72e7                 | jb                  0xffffffe9
            //   81ffe8fd0000         | cmp                 edi, 0xfde8

        $sequence_2 = { e8???????? 83c404 33c0 8845f0 8945f1 8945f5 668945f9 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   33c0                 | xor                 eax, eax
            //   8845f0               | mov                 byte ptr [ebp - 0x10], al
            //   8945f1               | mov                 dword ptr [ebp - 0xf], eax
            //   8945f5               | mov                 dword ptr [ebp - 0xb], eax
            //   668945f9             | mov                 word ptr [ebp - 7], ax

        $sequence_3 = { 8d8db0dffcff 51 ba???????? e8???????? }
            // n = 4, score = 100
            //   8d8db0dffcff         | lea                 ecx, [ebp - 0x32050]
            //   51                   | push                ecx
            //   ba????????           |                     
            //   e8????????           |                     

        $sequence_4 = { e8???????? 83c404 33ff be0f000000 89b588fdffff 89bd84fdffff c68574fdffff00 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   33ff                 | xor                 edi, edi
            //   be0f000000           | mov                 esi, 0xf
            //   89b588fdffff         | mov                 dword ptr [ebp - 0x278], esi
            //   89bd84fdffff         | mov                 dword ptr [ebp - 0x27c], edi
            //   c68574fdffff00       | mov                 byte ptr [ebp - 0x28c], 0

        $sequence_5 = { 33ff 3bcf 7564 c743140f000000 897b10 b8???????? }
            // n = 6, score = 100
            //   33ff                 | xor                 edi, edi
            //   3bcf                 | cmp                 ecx, edi
            //   7564                 | jne                 0x66
            //   c743140f000000       | mov                 dword ptr [ebx + 0x14], 0xf
            //   897b10               | mov                 dword ptr [ebx + 0x10], edi
            //   b8????????           |                     

        $sequence_6 = { 898ed4030000 8b5004 8996d8030000 8b4808 }
            // n = 4, score = 100
            //   898ed4030000         | mov                 dword ptr [esi + 0x3d4], ecx
            //   8b5004               | mov                 edx, dword ptr [eax + 4]
            //   8996d8030000         | mov                 dword ptr [esi + 0x3d8], edx
            //   8b4808               | mov                 ecx, dword ptr [eax + 8]

        $sequence_7 = { 899d50fdffff ff15???????? 8b9550fdffff 52 8d45a8 68???????? 50 }
            // n = 7, score = 100
            //   899d50fdffff         | mov                 dword ptr [ebp - 0x2b0], ebx
            //   ff15????????         |                     
            //   8b9550fdffff         | mov                 edx, dword ptr [ebp - 0x2b0]
            //   52                   | push                edx
            //   8d45a8               | lea                 eax, [ebp - 0x58]
            //   68????????           |                     
            //   50                   | push                eax

        $sequence_8 = { e8???????? e9???????? 50 8d459c 50 }
            // n = 5, score = 100
            //   e8????????           |                     
            //   e9????????           |                     
            //   50                   | push                eax
            //   8d459c               | lea                 eax, [ebp - 0x64]
            //   50                   | push                eax

        $sequence_9 = { 895910 c741140f000000 8d5508 89a51cdffcff 8819 52 }
            // n = 6, score = 100
            //   895910               | mov                 dword ptr [ecx + 0x10], ebx
            //   c741140f000000       | mov                 dword ptr [ecx + 0x14], 0xf
            //   8d5508               | lea                 edx, [ebp + 8]
            //   89a51cdffcff         | mov                 dword ptr [ebp - 0x320e4], esp
            //   8819                 | mov                 byte ptr [ecx], bl
            //   52                   | push                edx

    condition:
        7 of them and filesize < 275456
}