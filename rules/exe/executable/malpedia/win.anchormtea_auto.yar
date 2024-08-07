rule win_anchormtea_auto {

    meta:
        atk_type = "win.anchormtea."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.anchormtea."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.anchormtea"
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
        $sequence_0 = { e9???????? f7d8 1bc0 83e002 }
            // n = 4, score = 200
            //   e9????????           |                     
            //   f7d8                 | neg                 eax
            //   1bc0                 | sbb                 eax, eax
            //   83e002               | and                 eax, 2

        $sequence_1 = { 33c0 6689047e eb14 51 }
            // n = 4, score = 100
            //   33c0                 | cmovae              esi, edi
            //   6689047e             | dec                 esp
            //   eb14                 | mov                 ebp, dword ptr [esp + 0x70]
            //   51                   | dec                 ecx

        $sequence_2 = { 83f81f 0f87f3080000 52 51 e8???????? }
            // n = 5, score = 100
            //   83f81f               | cmp                 ebp, 0xb
            //   0f87f3080000         | jb                  0x72
            //   52                   | dec                 edi
            //   51                   | lea                 esp, [esi + ebp]
            //   e8????????           |                     

        $sequence_3 = { 7409 488bcf ff15???????? 33f6 4c8b7c2448 4c8b642460 }
            // n = 6, score = 100
            //   7409                 | dec                 eax
            //   488bcf               | mov                 dword ptr [ebp - 0x30], eax
            //   ff15????????         |                     
            //   33f6                 | dec                 eax
            //   4c8b7c2448           | lea                 eax, [ebp - 0x20]
            //   4c8b642460           | inc                 ebp

        $sequence_4 = { 488905???????? 488d055b7e0200 488905???????? 488d05897d0200 48890d???????? 48890d???????? }
            // n = 6, score = 100
            //   488905????????       |                     
            //   488d055b7e0200       | ja                  0x34
            //   488905????????       |                     
            //   488d05897d0200       | mov                 eax, esi
            //   48890d????????       |                     
            //   48890d????????       |                     

        $sequence_5 = { 899d1cffffff ffd7 50 ffd6 }
            // n = 4, score = 100
            //   899d1cffffff         | ja                  0xd5
            //   ffd7                 | mov                 ecx, dword ptr [esi + eax*4 + 0x1db18]
            //   50                   | dec                 eax
            //   ffd6                 | add                 ecx, esi

        $sequence_6 = { 8b9580f7ffff 89856cf7ffff 8b85acf7ffff 2bc7 898d5cf7ffff 89bd64f7ffff }
            // n = 6, score = 100
            //   8b9580f7ffff         | push                0x40
            //   89856cf7ffff         | call                edi
            //   8b85acf7ffff         | lea                 eax, [ebp - 8]
            //   2bc7                 | jne                 0x16
            //   898d5cf7ffff         | cmp                 eax, dword ptr [ebp - 0x268]
            //   89bd64f7ffff         | sbb                 eax, eax

        $sequence_7 = { 4983ff10 4c0f43f7 4c8b6c2470 4983fd0b 725f 4f8d242e }
            // n = 6, score = 100
            //   4983ff10             | xor                 ecx, ecx
            //   4c0f43f7             | dec                 eax
            //   4c8b6c2470           | mov                 dword ptr [esp + 0x48], eax
            //   4983fd0b             | inc                 ebp
            //   725f                 | xor                 eax, eax
            //   4f8d242e             | dec                 eax

        $sequence_8 = { 51 57 8d4dd8 e8???????? 33d2 895588 90 }
            // n = 7, score = 100
            //   51                   | jmp                 ecx
            //   57                   | pslldq              xmm1, 1
            //   8d4dd8               | neg                 eax
            //   e8????????           |                     
            //   33d2                 | sbb                 eax, eax
            //   895588               | and                 eax, 2
            //   90                   | je                  0x10

        $sequence_9 = { 4883c0f8 4883f81f 772e e8???????? 8bc6 }
            // n = 5, score = 100
            //   4883c0f8             | dec                 eax
            //   4883f81f             | add                 eax, -8
            //   772e                 | dec                 eax
            //   e8????????           |                     
            //   8bc6                 | cmp                 eax, 0x1f

        $sequence_10 = { 488d9510020000 488bcb ff15???????? 413b7624 }
            // n = 4, score = 100
            //   488d9510020000       | dec                 eax
            //   488bcb               | imul                ebx, eax, 0x98c
            //   ff15????????         |                     
            //   413b7624             | xor                 edi, edi

        $sequence_11 = { 4a8d3c39 488bc6 482bc2 4869d88c090000 }
            // n = 4, score = 100
            //   4a8d3c39             | dec                 eax
            //   488bc6               | lea                 eax, [0x27e5b]
            //   482bc2               | dec                 eax
            //   4869d88c090000       | lea                 eax, [0x27d89]

        $sequence_12 = { 33ff 488945d0 488d45e0 4533c9 4889442448 4533c0 }
            // n = 6, score = 100
            //   33ff                 | dec                 edx
            //   488945d0             | lea                 edi, [ecx + edi]
            //   488d45e0             | dec                 eax
            //   4533c9               | mov                 eax, esi
            //   4889442448           | dec                 eax
            //   4533c0               | sub                 eax, edx

        $sequence_13 = { 740e 6a40 68???????? 68???????? ffd7 8d45f8 }
            // n = 6, score = 100
            //   740e                 | xor                 esi, esi
            //   6a40                 | dec                 esp
            //   68????????           |                     
            //   68????????           |                     
            //   ffd7                 | mov                 edi, dword ptr [esp + 0x48]
            //   8d45f8               | dec                 esp

        $sequence_14 = { 7514 3b8598fdffff 1bc0 238598fdffff }
            // n = 4, score = 100
            //   7514                 | mov                 esp, dword ptr [esp + 0x60]
            //   3b8598fdffff         | dec                 ecx
            //   1bc0                 | cmp                 edi, 0x10
            //   238598fdffff         | dec                 esp

    condition:
        7 of them and filesize < 839680
}