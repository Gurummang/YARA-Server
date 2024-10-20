rule win_pebbledash_auto {

    meta:
        atk_type = "win.pebbledash."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.pebbledash."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.pebbledash"
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
        $sequence_0 = { 25ffff0000 3bd0 740a b800000004 e9???????? 83bd74fbffff00 751a }
            // n = 7, score = 100
            //   25ffff0000           | and                 eax, 0xffff
            //   3bd0                 | cmp                 edx, eax
            //   740a                 | je                  0xc
            //   b800000004           | mov                 eax, 0x4000000
            //   e9????????           |                     
            //   83bd74fbffff00       | cmp                 dword ptr [ebp - 0x48c], 0
            //   751a                 | jne                 0x1c

        $sequence_1 = { 8be5 5d c3 55 8bec 81ecd0000000 c68530ffffff8e }
            // n = 7, score = 100
            //   8be5                 | mov                 esp, ebp
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   81ecd0000000         | sub                 esp, 0xd0
            //   c68530ffffff8e       | mov                 byte ptr [ebp - 0xd0], 0x8e

        $sequence_2 = { 51 e8???????? 83c418 8d55f0 52 8d85a4f3ffff 50 }
            // n = 7, score = 100
            //   51                   | push                ecx
            //   e8????????           |                     
            //   83c418               | add                 esp, 0x18
            //   8d55f0               | lea                 edx, [ebp - 0x10]
            //   52                   | push                edx
            //   8d85a4f3ffff         | lea                 eax, [ebp - 0xc5c]
            //   50                   | push                eax

        $sequence_3 = { 8d95a0f5ffff 52 ff15???????? 898594f7ffff 83bd94f7ffffff 7505 }
            // n = 6, score = 100
            //   8d95a0f5ffff         | lea                 edx, [ebp - 0xa60]
            //   52                   | push                edx
            //   ff15????????         |                     
            //   898594f7ffff         | mov                 dword ptr [ebp - 0x86c], eax
            //   83bd94f7ffffff       | cmp                 dword ptr [ebp - 0x86c], -1
            //   7505                 | jne                 7

        $sequence_4 = { a3???????? 833d????????00 742c 8b55f0 8955dc 8b45dc 8945e0 }
            // n = 7, score = 100
            //   a3????????           |                     
            //   833d????????00       |                     
            //   742c                 | je                  0x2e
            //   8b55f0               | mov                 edx, dword ptr [ebp - 0x10]
            //   8955dc               | mov                 dword ptr [ebp - 0x24], edx
            //   8b45dc               | mov                 eax, dword ptr [ebp - 0x24]
            //   8945e0               | mov                 dword ptr [ebp - 0x20], eax

        $sequence_5 = { 8d1c85609f4200 c1e603 8b03 f644300401 7469 57 }
            // n = 6, score = 100
            //   8d1c85609f4200       | lea                 ebx, [eax*4 + 0x429f60]
            //   c1e603               | shl                 esi, 3
            //   8b03                 | mov                 eax, dword ptr [ebx]
            //   f644300401           | test                byte ptr [eax + esi + 4], 1
            //   7469                 | je                  0x6b
            //   57                   | push                edi

        $sequence_6 = { 8b08 8b550c 8b4110 8902 8d8d70feffff 51 8b550c }
            // n = 7, score = 100
            //   8b08                 | mov                 ecx, dword ptr [eax]
            //   8b550c               | mov                 edx, dword ptr [ebp + 0xc]
            //   8b4110               | mov                 eax, dword ptr [ecx + 0x10]
            //   8902                 | mov                 dword ptr [edx], eax
            //   8d8d70feffff         | lea                 ecx, [ebp - 0x190]
            //   51                   | push                ecx
            //   8b550c               | mov                 edx, dword ptr [ebp + 0xc]

        $sequence_7 = { 8b45e8 83c001 8945e8 837de80e 733b }
            // n = 5, score = 100
            //   8b45e8               | mov                 eax, dword ptr [ebp - 0x18]
            //   83c001               | add                 eax, 1
            //   8945e8               | mov                 dword ptr [ebp - 0x18], eax
            //   837de80e             | cmp                 dword ptr [ebp - 0x18], 0xe
            //   733b                 | jae                 0x3d

        $sequence_8 = { 51 e8???????? 83c40c 817d0c1e010000 7f15 837d101e }
            // n = 6, score = 100
            //   51                   | push                ecx
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   817d0c1e010000       | cmp                 dword ptr [ebp + 0xc], 0x11e
            //   7f15                 | jg                  0x17
            //   837d101e             | cmp                 dword ptr [ebp + 0x10], 0x1e

        $sequence_9 = { 8b55fc 0355e4 33c0 8a02 83f850 753b 8b4dfc }
            // n = 7, score = 100
            //   8b55fc               | mov                 edx, dword ptr [ebp - 4]
            //   0355e4               | add                 edx, dword ptr [ebp - 0x1c]
            //   33c0                 | xor                 eax, eax
            //   8a02                 | mov                 al, byte ptr [edx]
            //   83f850               | cmp                 eax, 0x50
            //   753b                 | jne                 0x3d
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]

    condition:
        7 of them and filesize < 360448
}