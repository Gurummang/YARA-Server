rule win_spedear_auto {

    meta:
        atk_type = "win.spedear."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.spedear."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.spedear"
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
        $sequence_0 = { 83e207 03c2 c1f803 83c40c }
            // n = 4, score = 600
            //   83e207               | and                 edx, 7
            //   03c2                 | add                 eax, edx
            //   c1f803               | sar                 eax, 3
            //   83c40c               | add                 esp, 0xc

        $sequence_1 = { 8b4718 8a5f06 50 894608 e8???????? }
            // n = 5, score = 500
            //   8b4718               | mov                 eax, dword ptr [edi + 0x18]
            //   8a5f06               | mov                 bl, byte ptr [edi + 6]
            //   50                   | push                eax
            //   894608               | mov                 dword ptr [esi + 8], eax
            //   e8????????           |                     

        $sequence_2 = { 53 50 e8???????? 8b7e0c 895e10 }
            // n = 5, score = 500
            //   53                   | push                ebx
            //   50                   | push                eax
            //   e8????????           |                     
            //   8b7e0c               | mov                 edi, dword ptr [esi + 0xc]
            //   895e10               | mov                 dword ptr [esi + 0x10], ebx

        $sequence_3 = { 894618 ffd7 89461c 5f }
            // n = 4, score = 400
            //   894618               | mov                 dword ptr [esi + 0x18], eax
            //   ffd7                 | call                edi
            //   89461c               | mov                 dword ptr [esi + 0x1c], eax
            //   5f                   | pop                 edi

        $sequence_4 = { 33f6 8b4704 8b4f08 53 50 8bde e8???????? }
            // n = 7, score = 400
            //   33f6                 | mov                 edi, dword ptr [esi + 0xc]
            //   8b4704               | mov                 dword ptr [esi + 0x10], ebx
            //   8b4f08               | mov                 eax, dword ptr [edi + 0x18]
            //   53                   | mov                 bl, byte ptr [edi + 6]
            //   50                   | push                eax
            //   8bde                 | mov                 dword ptr [esi + 8], eax
            //   e8????????           |                     

        $sequence_5 = { 8b44240c 8b08 8b442410 53 55 }
            // n = 5, score = 400
            //   8b44240c             | add                 esp, 0xc
            //   8b08                 | and                 edx, 7
            //   8b442410             | add                 eax, edx
            //   53                   | sar                 eax, 3
            //   55                   | add                 esp, 0xc

        $sequence_6 = { c1e208 40 0bca 3bc3 7c02 }
            // n = 5, score = 400
            //   c1e208               | push                eax
            //   40                   | mov                 edi, dword ptr [esi + 0xc]
            //   0bca                 | mov                 dword ptr [esi + 0x10], ebx
            //   3bc3                 | push                ebx
            //   7c02                 | push                eax

        $sequence_7 = { 5b c20400 8b4c240c 57 53 51 }
            // n = 6, score = 400
            //   5b                   | sar                 eax, 3
            //   c20400               | add                 esp, 0xc
            //   8b4c240c             | test                eax, eax
            //   57                   | mov                 bl, byte ptr [edi + 6]
            //   53                   | push                eax
            //   51                   | mov                 dword ptr [esi + 8], eax

        $sequence_8 = { 6a00 68???????? e8???????? 83c40c 68d0070000 }
            // n = 5, score = 400
            //   6a00                 | push                0
            //   68????????           |                     
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   68d0070000           | push                0x7d0

        $sequence_9 = { 833e00 741e 8b5608 8b4604 6a00 }
            // n = 5, score = 400
            //   833e00               | sar                 eax, 3
            //   741e                 | add                 esp, 0xc
            //   8b5608               | test                eax, eax
            //   8b4604               | and                 edx, 7
            //   6a00                 | add                 eax, edx

        $sequence_10 = { 833e00 741a 6a00 6a00 ff7608 }
            // n = 5, score = 300
            //   833e00               | cmp                 dword ptr [esi], 0
            //   741a                 | je                  0x1c
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   ff7608               | push                dword ptr [esi + 8]

        $sequence_11 = { 6a00 ff7608 ff5604 6800800000 }
            // n = 4, score = 300
            //   6a00                 | push                0
            //   ff7608               | push                dword ptr [esi + 8]
            //   ff5604               | call                dword ptr [esi + 4]
            //   6800800000           | push                0x8000

        $sequence_12 = { 394878 7456 39487c 7451 }
            // n = 4, score = 300
            //   394878               | cmp                 dword ptr [eax + 0x78], ecx
            //   7456                 | je                  0x58
            //   39487c               | cmp                 dword ptr [eax + 0x7c], ecx
            //   7451                 | je                  0x53

        $sequence_13 = { 8bc7 5e 5f 5b 5d c3 6a08 }
            // n = 7, score = 300
            //   8bc7                 | mov                 eax, edi
            //   5e                   | pop                 esi
            //   5f                   | pop                 edi
            //   5b                   | pop                 ebx
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   6a08                 | push                8

        $sequence_14 = { ff5604 6800800000 6a00 ff7608 }
            // n = 4, score = 300
            //   ff5604               | call                dword ptr [esi + 4]
            //   6800800000           | push                0x8000
            //   6a00                 | push                0
            //   ff7608               | push                dword ptr [esi + 8]

        $sequence_15 = { 74ce 56 53 ff7510 ff75d8 6a00 6a00 }
            // n = 7, score = 100
            //   74ce                 | push                0
            //   56                   | push                0
            //   53                   | push                dword ptr [esi + 8]
            //   ff7510               | push                0
            //   ff75d8               | push                0
            //   6a00                 | push                dword ptr [esi + 8]
            //   6a00                 | call                dword ptr [esi + 4]

        $sequence_16 = { 4154 4883ec20 4c8b5120 4d8be0 488bea 410fb74206 488bf1 }
            // n = 7, score = 100
            //   4154                 | dec                 eax
            //   4883ec20             | cmp                 ebx, eax
            //   4c8b5120             | ja                  0x30
            //   4d8be0               | inc                 ecx
            //   488bea               | lea                 edx, [eax + 1]
            //   410fb74206           | dec                 eax
            //   488bf1               | mov                 ecx, edi

        $sequence_17 = { 418d5001 488bcf 4803c7 48894308 }
            // n = 4, score = 100
            //   418d5001             | imul                ecx, ecx, 0x58
            //   488bcf               | jb                  0x3c
            //   4803c7               | dec                 eax
            //   48894308             | lea                 eax, [0x9b34]

        $sequence_18 = { 50 8d4de0 e8???????? 83781410 59 5b 7202 }
            // n = 7, score = 100
            //   50                   | push                0
            //   8d4de0               | push                0
            //   e8????????           |                     
            //   83781410             | push                dword ptr [esi + 8]
            //   59                   | call                dword ptr [esi + 4]
            //   5b                   | push                0x8000
            //   7202                 | push                0

        $sequence_19 = { 750b 488bcf ff15???????? eb07 488bd5 }
            // n = 5, score = 100
            //   750b                 | sub                 esp, 0x20
            //   488bcf               | dec                 esp
            //   ff15????????         |                     
            //   eb07                 | mov                 edx, dword ptr [ecx + 0x20]
            //   488bd5               | dec                 ebp

        $sequence_20 = { 488bc3 488d152bd50000 48c1f805 83e11f 488b04c2 486bc958 }
            // n = 6, score = 100
            //   488bc3               | dec                 eax
            //   488d152bd50000       | mov                 eax, ebx
            //   48c1f805             | dec                 eax
            //   83e11f               | lea                 edx, [0xd52b]
            //   488b04c2             | dec                 eax
            //   486bc958             | sar                 eax, 5

        $sequence_21 = { 723a 488d05349b0000 483bd8 772e }
            // n = 4, score = 100
            //   723a                 | and                 ecx, 0x1f
            //   488d05349b0000       | dec                 eax
            //   483bd8               | mov                 eax, dword ptr [edx + eax*8]
            //   772e                 | dec                 eax

        $sequence_22 = { 488364242000 40886c245c 488d0d10d10000 4c8d4c244c }
            // n = 4, score = 100
            //   488364242000         | mov                 esp, eax
            //   40886c245c           | dec                 eax
            //   488d0d10d10000       | mov                 ebp, edx
            //   4c8d4c244c           | inc                 ecx

        $sequence_23 = { 8a80b4182400 08443b1d 0fb64601 47 3bf8 76ea }
            // n = 6, score = 100
            //   8a80b4182400         | push                0
            //   08443b1d             | push                dword ptr [esi + 8]
            //   0fb64601             | call                dword ptr [esi + 4]
            //   47                   | push                0x8000
            //   3bf8                 | cmp                 dword ptr [esi], 0
            //   76ea                 | je                  0x1c

        $sequence_24 = { 4883ec20 488d05fe690000 488bfa 488bd9 488901 }
            // n = 5, score = 100
            //   4883ec20             | dec                 eax
            //   488d05fe690000       | add                 eax, edi
            //   488bfa               | dec                 eax
            //   488bd9               | mov                 dword ptr [ebx + 8], eax
            //   488901               | inc                 ecx

        $sequence_25 = { 488d15032e0000 488bce 488905???????? ff15???????? }
            // n = 4, score = 100
            //   488d15032e0000       | push                esp
            //   488bce               | dec                 eax
            //   488905????????       |                     
            //   ff15????????         |                     

    condition:
        7 of them and filesize < 188416
}