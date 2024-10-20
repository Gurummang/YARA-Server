rule win_derohe_auto {

    meta:
        atk_type = "win.derohe."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.derohe."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.derohe"
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
        $sequence_0 = { ffd0 8b542404 c60424e3 8b02 ffd0 8b542404 c6042405 }
            // n = 7, score = 100
            //   ffd0                 | call                eax
            //   8b542404             | mov                 edx, dword ptr [esp + 4]
            //   c60424e3             | mov                 byte ptr [esp], 0xe3
            //   8b02                 | mov                 eax, dword ptr [edx]
            //   ffd0                 | call                eax
            //   8b542404             | mov                 edx, dword ptr [esp + 4]
            //   c6042405             | mov                 byte ptr [esp], 5

        $sequence_1 = { ffd0 8b542404 c604247d 8b02 ffd0 8b542404 c60424df }
            // n = 7, score = 100
            //   ffd0                 | call                eax
            //   8b542404             | mov                 edx, dword ptr [esp + 4]
            //   c604247d             | mov                 byte ptr [esp], 0x7d
            //   8b02                 | mov                 eax, dword ptr [edx]
            //   ffd0                 | call                eax
            //   8b542404             | mov                 edx, dword ptr [esp + 4]
            //   c60424df             | mov                 byte ptr [esp], 0xdf

        $sequence_2 = { ffd0 8b542404 c60424a1 8b02 ffd0 8b542404 c60424e8 }
            // n = 7, score = 100
            //   ffd0                 | call                eax
            //   8b542404             | mov                 edx, dword ptr [esp + 4]
            //   c60424a1             | mov                 byte ptr [esp], 0xa1
            //   8b02                 | mov                 eax, dword ptr [edx]
            //   ffd0                 | call                eax
            //   8b542404             | mov                 edx, dword ptr [esp + 4]
            //   c60424e8             | mov                 byte ptr [esp], 0xe8

        $sequence_3 = { ffd0 8b442418 8b4c2414 8b542420 898a8c010000 8b0d???????? 85c9 }
            // n = 7, score = 100
            //   ffd0                 | call                eax
            //   8b442418             | mov                 eax, dword ptr [esp + 0x18]
            //   8b4c2414             | mov                 ecx, dword ptr [esp + 0x14]
            //   8b542420             | mov                 edx, dword ptr [esp + 0x20]
            //   898a8c010000         | mov                 dword ptr [edx + 0x18c], ecx
            //   8b0d????????         |                     
            //   85c9                 | test                ecx, ecx

        $sequence_4 = { ffd0 8b542404 c60424de 8b02 ffd0 8b542404 c60424b8 }
            // n = 7, score = 100
            //   ffd0                 | call                eax
            //   8b542404             | mov                 edx, dword ptr [esp + 4]
            //   c60424de             | mov                 byte ptr [esp], 0xde
            //   8b02                 | mov                 eax, dword ptr [edx]
            //   ffd0                 | call                eax
            //   8b542404             | mov                 edx, dword ptr [esp + 4]
            //   c60424b8             | mov                 byte ptr [esp], 0xb8

        $sequence_5 = { ffd0 8b542404 c60424cc 8b02 ffd0 8b542404 c6042462 }
            // n = 7, score = 100
            //   ffd0                 | call                eax
            //   8b542404             | mov                 edx, dword ptr [esp + 4]
            //   c60424cc             | mov                 byte ptr [esp], 0xcc
            //   8b02                 | mov                 eax, dword ptr [edx]
            //   ffd0                 | call                eax
            //   8b542404             | mov                 edx, dword ptr [esp + 4]
            //   c6042462             | mov                 byte ptr [esp], 0x62

        $sequence_6 = { e8???????? 8b44241c 8b4c2420 8b542424 8b5c2434 894b08 89530c }
            // n = 7, score = 100
            //   e8????????           |                     
            //   8b44241c             | mov                 eax, dword ptr [esp + 0x1c]
            //   8b4c2420             | mov                 ecx, dword ptr [esp + 0x20]
            //   8b542424             | mov                 edx, dword ptr [esp + 0x24]
            //   8b5c2434             | mov                 ebx, dword ptr [esp + 0x34]
            //   894b08               | mov                 dword ptr [ebx + 8], ecx
            //   89530c               | mov                 dword ptr [ebx + 0xc], edx

        $sequence_7 = { ffd0 8b542404 c604247d 8b02 ffd0 8b542404 c60424a4 }
            // n = 7, score = 100
            //   ffd0                 | call                eax
            //   8b542404             | mov                 edx, dword ptr [esp + 4]
            //   c604247d             | mov                 byte ptr [esp], 0x7d
            //   8b02                 | mov                 eax, dword ptr [edx]
            //   ffd0                 | call                eax
            //   8b542404             | mov                 edx, dword ptr [esp + 4]
            //   c60424a4             | mov                 byte ptr [esp], 0xa4

        $sequence_8 = { ffd2 8b442404 83c0fa 83f801 0f869e000000 90 8b4c242c }
            // n = 7, score = 100
            //   ffd2                 | call                edx
            //   8b442404             | mov                 eax, dword ptr [esp + 4]
            //   83c0fa               | add                 eax, -6
            //   83f801               | cmp                 eax, 1
            //   0f869e000000         | jbe                 0xa4
            //   90                   | nop                 
            //   8b4c242c             | mov                 ecx, dword ptr [esp + 0x2c]

        $sequence_9 = { ffd0 8b542404 c60424e0 8b02 ffd0 8b542404 c6042407 }
            // n = 7, score = 100
            //   ffd0                 | call                eax
            //   8b542404             | mov                 edx, dword ptr [esp + 4]
            //   c60424e0             | mov                 byte ptr [esp], 0xe0
            //   8b02                 | mov                 eax, dword ptr [edx]
            //   ffd0                 | call                eax
            //   8b542404             | mov                 edx, dword ptr [esp + 4]
            //   c6042407             | mov                 byte ptr [esp], 7

    condition:
        7 of them and filesize < 35788800
}