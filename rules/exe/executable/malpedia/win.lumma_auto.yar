rule win_lumma_auto {

    meta:
        atk_type = "win.lumma."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.lumma."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.lumma"
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
        $sequence_0 = { 57 53 ff767c ff7678 }
            // n = 4, score = 1100
            //   57                   | push                edi
            //   53                   | push                ebx
            //   ff767c               | push                dword ptr [esi + 0x7c]
            //   ff7678               | push                dword ptr [esi + 0x78]

        $sequence_1 = { ffd0 83c40c 894648 85c0 }
            // n = 4, score = 1000
            //   ffd0                 | call                eax
            //   83c40c               | add                 esp, 0xc
            //   894648               | mov                 dword ptr [esi + 0x48], eax
            //   85c0                 | test                eax, eax

        $sequence_2 = { ff5130 83c410 85c0 7407 }
            // n = 4, score = 1000
            //   ff5130               | call                dword ptr [ecx + 0x30]
            //   83c410               | add                 esp, 0x10
            //   85c0                 | test                eax, eax
            //   7407                 | je                  9

        $sequence_3 = { ff7678 ff7644 ff563c 83c414 }
            // n = 4, score = 1000
            //   ff7678               | push                dword ptr [esi + 0x78]
            //   ff7644               | push                dword ptr [esi + 0x44]
            //   ff563c               | call                dword ptr [esi + 0x3c]
            //   83c414               | add                 esp, 0x14

        $sequence_4 = { ff770c ff37 ff7134 ff5130 }
            // n = 4, score = 1000
            //   ff770c               | push                dword ptr [edi + 0xc]
            //   ff37                 | push                dword ptr [edi]
            //   ff7134               | push                dword ptr [ecx + 0x34]
            //   ff5130               | call                dword ptr [ecx + 0x30]

        $sequence_5 = { ff7608 ff7044 ff503c 83c414 }
            // n = 4, score = 1000
            //   ff7608               | push                dword ptr [esi + 8]
            //   ff7044               | push                dword ptr [eax + 0x44]
            //   ff503c               | call                dword ptr [eax + 0x3c]
            //   83c414               | add                 esp, 0x14

        $sequence_6 = { 894610 8b461c c1e002 50 }
            // n = 4, score = 1000
            //   894610               | mov                 dword ptr [esi + 0x10], eax
            //   8b461c               | mov                 eax, dword ptr [esi + 0x1c]
            //   c1e002               | shl                 eax, 2
            //   50                   | push                eax

        $sequence_7 = { 833800 740a e8???????? 833822 }
            // n = 4, score = 1000
            //   833800               | cmp                 dword ptr [eax], 0
            //   740a                 | je                  0xc
            //   e8????????           |                     
            //   833822               | cmp                 dword ptr [eax], 0x22

        $sequence_8 = { 83c40c 6a02 6804010000 e8???????? }
            // n = 4, score = 800
            //   83c40c               | add                 esp, 0xc
            //   6a02                 | push                2
            //   6804010000           | push                0x104
            //   e8????????           |                     

        $sequence_9 = { 017e78 83567c00 017e68 83566c00 }
            // n = 4, score = 800
            //   017e78               | add                 dword ptr [esi + 0x78], edi
            //   83567c00             | adc                 dword ptr [esi + 0x7c], 0
            //   017e68               | add                 dword ptr [esi + 0x68], edi
            //   83566c00             | adc                 dword ptr [esi + 0x6c], 0

        $sequence_10 = { 89e5 8b550c 6bd204 89d1 }
            // n = 4, score = 700
            //   89e5                 | mov                 ebp, esp
            //   8b550c               | mov                 edx, dword ptr [ebp + 0xc]
            //   6bd204               | imul                edx, edx, 4
            //   89d1                 | mov                 ecx, edx

        $sequence_11 = { 41 5d 41 5b 41 5c }
            // n = 6, score = 700
            //   41                   | inc                 ecx
            //   5d                   | pop                 ebp
            //   41                   | inc                 ecx
            //   5b                   | pop                 ebx
            //   41                   | inc                 ecx
            //   5c                   | pop                 esp

        $sequence_12 = { 48 83ec28 0f05 48 83c428 49 }
            // n = 6, score = 700
            //   48                   | dec                 eax
            //   83ec28               | sub                 esp, 0x28
            //   0f05                 | syscall             
            //   48                   | dec                 eax
            //   83c428               | add                 esp, 0x28
            //   49                   | dec                 ecx

    condition:
        7 of them and filesize < 1115136
}