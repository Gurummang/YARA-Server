rule win_virtualgate_auto {

    meta:
        atk_type = "win.virtualgate."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.virtualgate."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.virtualgate"
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
        $sequence_0 = { 4157 4883ec38 4c63e9 488bf2 498bc5 488d0dc7f10000 }
            // n = 6, score = 100
            //   4157                 | lea                 eax, [0x1d420]
            //   4883ec38             | mov                 edx, 0x104
            //   4c63e9               | dec                 eax
            //   488bf2               | lea                 edx, [esp + 0x48]
            //   498bc5               | dec                 eax
            //   488d0dc7f10000       | mov                 ecx, edi

        $sequence_1 = { 4b8794fed02a0200 eb2d 4c8b15???????? ebb8 4c8b15???????? 418bc2 b940000000 }
            // n = 7, score = 100
            //   4b8794fed02a0200     | test                eax, eax
            //   eb2d                 | je                  0x1c4
            //   4c8b15????????       |                     
            //   ebb8                 | dec                 eax
            //   4c8b15????????       |                     
            //   418bc2               | mov                 ecx, ebx
            //   b940000000           | jne                 0x217

        $sequence_2 = { 8d58b0 498bce 448bc3 488d1580bd0000 e8???????? 85c0 7429 }
            // n = 7, score = 100
            //   8d58b0               | lea                 ecx, [esp + 0x68]
            //   498bce               | cmp                 eax, -1
            //   448bc3               | je                  0x169d
            //   488d1580bd0000       | cmp                 byte ptr [esp + 0x60], 0x77
            //   e8????????           |                     
            //   85c0                 | inc                 ecx
            //   7429                 | sub                 eax, ecx

        $sequence_3 = { ff15???????? c705????????00001000 eb26 4183f802 }
            // n = 4, score = 100
            //   ff15????????         |                     
            //   c705????????00001000     |     
            //   eb26                 | mov                 ecx, ebx
            //   4183f802             | dec                 esp

        $sequence_4 = { 488bc8 ff15???????? 3b05???????? 488bcb 89442450 7608 }
            // n = 6, score = 100
            //   488bc8               | test                esp, esp
            //   ff15????????         |                     
            //   3b05????????         |                     
            //   488bcb               | jne                 0x489
            //   89442450             | dec                 esp
            //   7608                 | lea                 edi, [0x1396f]

        $sequence_5 = { 48894527 498bc0 48ffc0 41381407 75f7 498bc8 48ffc1 }
            // n = 7, score = 100
            //   48894527             | sar                 esi, 6
            //   498bc0               | dec                 eax
            //   48ffc0               | lea                 edi, [eax + eax*8]
            //   41381407             | dec                 ebp
            //   75f7                 | mov                 ecx, dword ptr [esp + esi*8 + 0x225f0]
            //   498bc8               | inc                 ecx
            //   48ffc1               | cmp                 byte ptr [ecx + edi*8 + 0x39], 0

        $sequence_6 = { 4c8d05b4d30000 488d15b1d30000 e8???????? 4885c0 7416 }
            // n = 5, score = 100
            //   4c8d05b4d30000       | inc                 ecx
            //   488d15b1d30000       | mov                 ebx, ebp
            //   e8????????           |                     
            //   4885c0               | inc                 esp
            //   7416                 | cmp                 byte ptr [ebp - 0x61], ch

        $sequence_7 = { 488bf5 4803d2 498b94d750b50100 e8???????? 85c0 }
            // n = 5, score = 100
            //   488bf5               | je                  0x1089
            //   4803d2               | cmp                 byte ptr [esp + 0x60], 0x77
            //   498b94d750b50100     | test                al, al
            //   e8????????           |                     
            //   85c0                 | je                  0x1179

        $sequence_8 = { 4c8d058dbe0100 488bd5 48c1fa06 4c893403 488bc5 }
            // n = 5, score = 100
            //   4c8d058dbe0100       | dec                 eax
            //   488bd5               | lea                 ecx, [esp + 0x90]
            //   48c1fa06             | inc                 ecx
            //   4c893403             | mov                 edx, edx
            //   488bc5               | dec                 ebp

        $sequence_9 = { 488b8c2420800200 4833cc e8???????? 488b9c2450800200 }
            // n = 4, score = 100
            //   488b8c2420800200     | and                 ecx, 0x3f
            //   4833cc               | dec                 eax
            //   e8????????           |                     
            //   488b9c2450800200     | arpl                cx, cx

    condition:
        7 of them and filesize < 323584
}