rule win_torrentlocker_auto {

    meta:
        atk_type = "win.torrentlocker."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.torrentlocker."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.torrentlocker"
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
        $sequence_0 = { c3 83f801 7405 83f802 }
            // n = 4, score = 500
            //   c3                   | ret                 
            //   83f801               | cmp                 eax, 1
            //   7405                 | je                  7
            //   83f802               | cmp                 eax, 2

        $sequence_1 = { 8b0d???????? 5f c7000c000000 894804 }
            // n = 4, score = 400
            //   8b0d????????         |                     
            //   5f                   | pop                 edi
            //   c7000c000000         | mov                 dword ptr [eax], 0xc
            //   894804               | mov                 dword ptr [eax + 4], ecx

        $sequence_2 = { 85c0 7514 e8???????? 3d00000600 }
            // n = 4, score = 400
            //   85c0                 | test                eax, eax
            //   7514                 | jne                 0x16
            //   e8????????           |                     
            //   3d00000600           | cmp                 eax, 0x60000

        $sequence_3 = { 50 56 6a00 6a01 6a02 ff15???????? }
            // n = 6, score = 400
            //   50                   | push                eax
            //   56                   | push                esi
            //   6a00                 | push                0
            //   6a01                 | push                1
            //   6a02                 | push                2
            //   ff15????????         |                     

        $sequence_4 = { 8b0d???????? 890e e8???????? 8bd8 e8???????? 6a00 6a01 }
            // n = 7, score = 400
            //   8b0d????????         |                     
            //   890e                 | mov                 dword ptr [esi], ecx
            //   e8????????           |                     
            //   8bd8                 | mov                 ebx, eax
            //   e8????????           |                     
            //   6a00                 | push                0
            //   6a01                 | push                1

        $sequence_5 = { 83ec24 6a00 6a01 68???????? ff15???????? 85c0 7551 }
            // n = 7, score = 400
            //   83ec24               | sub                 esp, 0x24
            //   6a00                 | push                0
            //   6a01                 | push                1
            //   68????????           |                     
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7551                 | jne                 0x53

        $sequence_6 = { 56 ff15???????? 83f802 740f 83f803 740a }
            // n = 6, score = 400
            //   56                   | push                esi
            //   ff15????????         |                     
            //   83f802               | cmp                 eax, 2
            //   740f                 | je                  0x11
            //   83f803               | cmp                 eax, 3
            //   740a                 | je                  0xc

        $sequence_7 = { e8???????? 3d00000600 1bc0 40 a3???????? eb05 }
            // n = 6, score = 400
            //   e8????????           |                     
            //   3d00000600           | cmp                 eax, 0x60000
            //   1bc0                 | sbb                 eax, eax
            //   40                   | inc                 eax
            //   a3????????           |                     
            //   eb05                 | jmp                 7

        $sequence_8 = { 83c002 6685c9 75f5 2bc2 d1f8 8d440014 }
            // n = 6, score = 400
            //   83c002               | add                 eax, 2
            //   6685c9               | test                cx, cx
            //   75f5                 | jne                 0xfffffff7
            //   2bc2                 | sub                 eax, edx
            //   d1f8                 | sar                 eax, 1
            //   8d440014             | lea                 eax, [eax + eax + 0x14]

        $sequence_9 = { 52 50 ff15???????? 85c0 7519 8b0d???????? 51 }
            // n = 7, score = 400
            //   52                   | push                edx
            //   50                   | push                eax
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7519                 | jne                 0x1b
            //   8b0d????????         |                     
            //   51                   | push                ecx

        $sequence_10 = { 51 6a01 6a00 0d00800000 50 6a00 }
            // n = 6, score = 400
            //   51                   | push                ecx
            //   6a01                 | push                1
            //   6a00                 | push                0
            //   0d00800000           | or                  eax, 0x8000
            //   50                   | push                eax
            //   6a00                 | push                0

        $sequence_11 = { 8b0d???????? 5f 894e0c 5e }
            // n = 4, score = 400
            //   8b0d????????         |                     
            //   5f                   | pop                 edi
            //   894e0c               | mov                 dword ptr [esi + 0xc], ecx
            //   5e                   | pop                 esi

        $sequence_12 = { 8b0d???????? 6a00 6a00 57 }
            // n = 4, score = 400
            //   8b0d????????         |                     
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   57                   | push                edi

        $sequence_13 = { 48 85c0 7ff4 5f 33c0 5e c3 }
            // n = 7, score = 400
            //   48                   | dec                 eax
            //   85c0                 | test                eax, eax
            //   7ff4                 | jg                  0xfffffff6
            //   5f                   | pop                 edi
            //   33c0                 | xor                 eax, eax
            //   5e                   | pop                 esi
            //   c3                   | ret                 

        $sequence_14 = { 8b0d???????? 57 6a00 51 ff15???????? 8bc6 }
            // n = 6, score = 400
            //   8b0d????????         |                     
            //   57                   | push                edi
            //   6a00                 | push                0
            //   51                   | push                ecx
            //   ff15????????         |                     
            //   8bc6                 | mov                 eax, esi

        $sequence_15 = { c705????????00000000 e8???????? 8bf0 e8???????? }
            // n = 4, score = 400
            //   c705????????00000000     |     
            //   e8????????           |                     
            //   8bf0                 | mov                 esi, eax
            //   e8????????           |                     

    condition:
        7 of them and filesize < 933888
}