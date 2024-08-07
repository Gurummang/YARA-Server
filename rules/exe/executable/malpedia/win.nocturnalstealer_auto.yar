rule win_nocturnalstealer_auto {

    meta:
        atk_type = "win.nocturnalstealer."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.nocturnalstealer."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.nocturnalstealer"
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
        $sequence_0 = { ff3424 5e 56 e9???????? 81e945418082 01ca e9???????? }
            // n = 7, score = 100
            //   ff3424               | push                dword ptr [esp]
            //   5e                   | pop                 esi
            //   56                   | push                esi
            //   e9????????           |                     
            //   81e945418082         | sub                 ecx, 0x82804145
            //   01ca                 | add                 edx, ecx
            //   e9????????           |                     

        $sequence_1 = { e9???????? 09d6 5f 81e220000000 ba00000000 81f700000080 81eeffffff7f }
            // n = 7, score = 100
            //   e9????????           |                     
            //   09d6                 | or                  esi, edx
            //   5f                   | pop                 edi
            //   81e220000000         | and                 edx, 0x20
            //   ba00000000           | mov                 edx, 0
            //   81f700000080         | xor                 edi, 0x80000000
            //   81eeffffff7f         | sub                 esi, 0x7fffffff

        $sequence_2 = { e9???????? 01742404 ff3424 5e 57 89e7 e9???????? }
            // n = 7, score = 100
            //   e9????????           |                     
            //   01742404             | add                 dword ptr [esp + 4], esi
            //   ff3424               | push                dword ptr [esp]
            //   5e                   | pop                 esi
            //   57                   | push                edi
            //   89e7                 | mov                 edi, esp
            //   e9????????           |                     

        $sequence_3 = { 89ef ba00020000 2524000000 09cb 05ffffff7f 81e6ffffff7f 81c7a2000000 }
            // n = 7, score = 100
            //   89ef                 | mov                 edi, ebp
            //   ba00020000           | mov                 edx, 0x200
            //   2524000000           | and                 eax, 0x24
            //   09cb                 | or                  ebx, ecx
            //   05ffffff7f           | add                 eax, 0x7fffffff
            //   81e6ffffff7f         | and                 esi, 0x7fffffff
            //   81c7a2000000         | add                 edi, 0xa2

        $sequence_4 = { e9???????? 83c004 330424 310424 330424 5c 55 }
            // n = 7, score = 100
            //   e9????????           |                     
            //   83c004               | add                 eax, 4
            //   330424               | xor                 eax, dword ptr [esp]
            //   310424               | xor                 dword ptr [esp], eax
            //   330424               | xor                 eax, dword ptr [esp]
            //   5c                   | pop                 esp
            //   55                   | push                ebp

        $sequence_5 = { b8b4888b7f 251810fb62 253a26e37e 05b68054fc 31c7 e9???????? 331c24 }
            // n = 7, score = 100
            //   b8b4888b7f           | mov                 eax, 0x7f8b88b4
            //   251810fb62           | and                 eax, 0x62fb1018
            //   253a26e37e           | and                 eax, 0x7ee3263a
            //   05b68054fc           | add                 eax, 0xfc5480b6
            //   31c7                 | xor                 edi, eax
            //   e9????????           |                     
            //   331c24               | xor                 ebx, dword ptr [esp]

        $sequence_6 = { e9???????? 8d852731bc18 52 89e2 50 b804000000 01c2 }
            // n = 7, score = 100
            //   e9????????           |                     
            //   8d852731bc18         | lea                 eax, [ebp + 0x18bc3127]
            //   52                   | push                edx
            //   89e2                 | mov                 edx, esp
            //   50                   | push                eax
            //   b804000000           | mov                 eax, 4
            //   01c2                 | add                 edx, eax

        $sequence_7 = { e9???????? 895c2404 8b1c24 83c404 893424 890424 e9???????? }
            // n = 7, score = 100
            //   e9????????           |                     
            //   895c2404             | mov                 dword ptr [esp + 4], ebx
            //   8b1c24               | mov                 ebx, dword ptr [esp]
            //   83c404               | add                 esp, 4
            //   893424               | mov                 dword ptr [esp], esi
            //   890424               | mov                 dword ptr [esp], eax
            //   e9????????           |                     

        $sequence_8 = { e9???????? 57 891c24 890424 e9???????? 81c704000000 81c704000000 }
            // n = 7, score = 100
            //   e9????????           |                     
            //   57                   | push                edi
            //   891c24               | mov                 dword ptr [esp], ebx
            //   890424               | mov                 dword ptr [esp], eax
            //   e9????????           |                     
            //   81c704000000         | add                 edi, 4
            //   81c704000000         | add                 edi, 4

        $sequence_9 = { f7d8 f7d0 c1e808 c1e802 e9???????? 29cf 8b0c24 }
            // n = 7, score = 100
            //   f7d8                 | neg                 eax
            //   f7d0                 | not                 eax
            //   c1e808               | shr                 eax, 8
            //   c1e802               | shr                 eax, 2
            //   e9????????           |                     
            //   29cf                 | sub                 edi, ecx
            //   8b0c24               | mov                 ecx, dword ptr [esp]

    condition:
        7 of them and filesize < 10739712
}