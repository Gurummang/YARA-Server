rule win_artfulpie_auto {

    meta:
        atk_type = "win.artfulpie."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.artfulpie."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.artfulpie"
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
        $sequence_0 = { 894ddc c745e0a8204100 e9???????? c745e0a4204100 }
            // n = 4, score = 100
            //   894ddc               | mov                 dword ptr [ebp - 0x24], ecx
            //   c745e0a8204100       | mov                 dword ptr [ebp - 0x20], 0x4120a8
            //   e9????????           |                     
            //   c745e0a4204100       | mov                 dword ptr [ebp - 0x20], 0x4120a4

        $sequence_1 = { 8d1c8568524100 8b03 8b15???????? 83cfff 8bca 8bf2 }
            // n = 6, score = 100
            //   8d1c8568524100       | lea                 ebx, [eax*4 + 0x415268]
            //   8b03                 | mov                 eax, dword ptr [ebx]
            //   8b15????????         |                     
            //   83cfff               | or                  edi, 0xffffffff
            //   8bca                 | mov                 ecx, edx
            //   8bf2                 | mov                 esi, edx

        $sequence_2 = { 23c1 83c008 5d c3 8b04c544ec4000 5d }
            // n = 6, score = 100
            //   23c1                 | and                 eax, ecx
            //   83c008               | add                 eax, 8
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   8b04c544ec4000       | mov                 eax, dword ptr [eax*8 + 0x40ec44]
            //   5d                   | pop                 ebp

        $sequence_3 = { 7514 8b7830 8b00 397838 740a 33d2 }
            // n = 6, score = 100
            //   7514                 | jne                 0x16
            //   8b7830               | mov                 edi, dword ptr [eax + 0x30]
            //   8b00                 | mov                 eax, dword ptr [eax]
            //   397838               | cmp                 dword ptr [eax + 0x38], edi
            //   740a                 | je                  0xc
            //   33d2                 | xor                 edx, edx

        $sequence_4 = { 6a00 8d854cfcffff c745fc2a2f2a00 50 }
            // n = 4, score = 100
            //   6a00                 | push                0
            //   8d854cfcffff         | lea                 eax, [ebp - 0x3b4]
            //   c745fc2a2f2a00       | mov                 dword ptr [ebp - 4], 0x2a2f2a
            //   50                   | push                eax

        $sequence_5 = { 660f282d???????? 660f59f5 660f28aa101f4100 660f54e5 660f58fe 660f58fc 660f59c8 }
            // n = 7, score = 100
            //   660f282d????????     |                     
            //   660f59f5             | mulpd               xmm6, xmm5
            //   660f28aa101f4100     | movapd              xmm5, xmmword ptr [edx + 0x411f10]
            //   660f54e5             | andpd               xmm4, xmm5
            //   660f58fe             | addpd               xmm7, xmm6
            //   660f58fc             | addpd               xmm7, xmm4
            //   660f59c8             | mulpd               xmm1, xmm0

        $sequence_6 = { e8???????? 85c0 7432 8bcb e8???????? }
            // n = 5, score = 100
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   7432                 | je                  0x34
            //   8bcb                 | mov                 ecx, ebx
            //   e8????????           |                     

        $sequence_7 = { 8b5d10 8b0485984e4100 56 8b7508 57 8b4c0818 }
            // n = 6, score = 100
            //   8b5d10               | mov                 ebx, dword ptr [ebp + 0x10]
            //   8b0485984e4100       | mov                 eax, dword ptr [eax*4 + 0x414e98]
            //   56                   | push                esi
            //   8b7508               | mov                 esi, dword ptr [ebp + 8]
            //   57                   | push                edi
            //   8b4c0818             | mov                 ecx, dword ptr [eax + ecx + 0x18]

        $sequence_8 = { 50 53 ff15???????? 85c0 7455 8b7df0 }
            // n = 6, score = 100
            //   50                   | push                eax
            //   53                   | push                ebx
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7455                 | je                  0x57
            //   8b7df0               | mov                 edi, dword ptr [ebp - 0x10]

        $sequence_9 = { 6a41 5f 894df0 8b34cdf00e4100 8b4d08 6a5a }
            // n = 6, score = 100
            //   6a41                 | push                0x41
            //   5f                   | pop                 edi
            //   894df0               | mov                 dword ptr [ebp - 0x10], ecx
            //   8b34cdf00e4100       | mov                 esi, dword ptr [ecx*8 + 0x410ef0]
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   6a5a                 | push                0x5a

    condition:
        7 of them and filesize < 204800
}