rule win_hui_loader_auto {

    meta:
        atk_type = "win.hui_loader."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.hui_loader."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.hui_loader"
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
        $sequence_0 = { 68???????? 51 8bf8 ffd5 8d9424b8010000 8d842488090000 }
            // n = 6, score = 100
            //   68????????           |                     
            //   51                   | push                ecx
            //   8bf8                 | mov                 edi, eax
            //   ffd5                 | call                ebp
            //   8d9424b8010000       | lea                 edx, [esp + 0x1b8]
            //   8d842488090000       | lea                 eax, [esp + 0x988]

        $sequence_1 = { ffd0 68e8030000 ffd6 8b0d???????? 51 ff15???????? 5f }
            // n = 7, score = 100
            //   ffd0                 | call                eax
            //   68e8030000           | push                0x3e8
            //   ffd6                 | call                esi
            //   8b0d????????         |                     
            //   51                   | push                ecx
            //   ff15????????         |                     
            //   5f                   | pop                 edi

        $sequence_2 = { 8b1402 3bd3 7406 c70109000000 }
            // n = 4, score = 100
            //   8b1402               | mov                 edx, dword ptr [edx + eax]
            //   3bd3                 | cmp                 edx, ebx
            //   7406                 | je                  8
            //   c70109000000         | mov                 dword ptr [ecx], 9

        $sequence_3 = { 83e01f c1f905 8d04c0 8b0c8d60e20010 8d44810c 50 }
            // n = 6, score = 100
            //   83e01f               | and                 eax, 0x1f
            //   c1f905               | sar                 ecx, 5
            //   8d04c0               | lea                 eax, [eax + eax*8]
            //   8b0c8d60e20010       | mov                 ecx, dword ptr [ecx*4 + 0x1000e260]
            //   8d44810c             | lea                 eax, [ecx + eax*4 + 0xc]
            //   50                   | push                eax

        $sequence_4 = { 52 50 a3???????? ff15???????? a1???????? }
            // n = 5, score = 100
            //   52                   | push                edx
            //   50                   | push                eax
            //   a3????????           |                     
            //   ff15????????         |                     
            //   a1????????           |                     

        $sequence_5 = { 83c628 83f90a 7cd9 33d2 }
            // n = 4, score = 100
            //   83c628               | add                 esi, 0x28
            //   83f90a               | cmp                 ecx, 0xa
            //   7cd9                 | jl                  0xffffffdb
            //   33d2                 | xor                 edx, edx

        $sequence_6 = { 8d4a01 0338 83c004 49 75f8 42 83c628 }
            // n = 7, score = 100
            //   8d4a01               | lea                 ecx, [edx + 1]
            //   0338                 | add                 edi, dword ptr [eax]
            //   83c004               | add                 eax, 4
            //   49                   | dec                 ecx
            //   75f8                 | jne                 0xfffffffa
            //   42                   | inc                 edx
            //   83c628               | add                 esi, 0x28

        $sequence_7 = { c20400 8b15???????? 33c0 68???????? 52 }
            // n = 5, score = 100
            //   c20400               | ret                 4
            //   8b15????????         |                     
            //   33c0                 | xor                 eax, eax
            //   68????????           |                     
            //   52                   | push                edx

        $sequence_8 = { ff15???????? a3???????? 33ff 8d4c2428 }
            // n = 4, score = 100
            //   ff15????????         |                     
            //   a3????????           |                     
            //   33ff                 | xor                 edi, edi
            //   8d4c2428             | lea                 ecx, [esp + 0x28]

        $sequence_9 = { 7e0f 8b4efc 8b5401fc 031401 8b0e 891401 }
            // n = 6, score = 100
            //   7e0f                 | jle                 0x11
            //   8b4efc               | mov                 ecx, dword ptr [esi - 4]
            //   8b5401fc             | mov                 edx, dword ptr [ecx + eax - 4]
            //   031401               | add                 edx, dword ptr [ecx + eax]
            //   8b0e                 | mov                 ecx, dword ptr [esi]
            //   891401               | mov                 dword ptr [ecx + eax], edx

    condition:
        7 of them and filesize < 131072
}