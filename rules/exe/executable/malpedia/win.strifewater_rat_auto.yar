rule win_strifewater_rat_auto {

    meta:
        atk_type = "win.strifewater_rat."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.strifewater_rat."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.strifewater_rat"
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
        $sequence_0 = { 83630800 488d0d10400500 48890b c6434400 448ac6 488bd0 }
            // n = 6, score = 100
            //   83630800             | dec                 eax
            //   488d0d10400500       | lea                 edx, [0x825e1]
            //   48890b               | jmp                 0x486
            //   c6434400             | dec                 eax
            //   448ac6               | mov                 dword ptr [esp + 0xc0], eax
            //   488bd0               | dec                 eax

        $sequence_1 = { 4183c9ff 4d8bc7 66448926 4889742420 8d4a03 ff15???????? f7d8 }
            // n = 7, score = 100
            //   4183c9ff             | nop                 
            //   4d8bc7               | mov                 edi, dword ptr [esp + 0x70]
            //   66448926             | dec                 eax
            //   4889742420           | lea                 edx, [esp + 0x60]
            //   8d4a03               | dec                 eax
            //   ff15????????         |                     
            //   f7d8                 | cmp                 dword ptr [esp + 0x78], 0x10

        $sequence_2 = { 663b3d???????? 0f8559010000 663b1d???????? 0f854c010000 66443b35???????? 0f853e010000 }
            // n = 6, score = 100
            //   663b3d????????       |                     
            //   0f8559010000         | lea                 edi, [eax + esi]
            //   663b1d????????       |                     
            //   0f854c010000         | dec                 ebp
            //   66443b35????????     |                     
            //   0f853e010000         | test                edi, edi

        $sequence_3 = { 488d05bb720600 488bf9 488901 8bda 488b4910 e8???????? 488b4f18 }
            // n = 7, score = 100
            //   488d05bb720600       | dec                 eax
            //   488bf9               | lea                 ecx, [esp + 0x20]
            //   488901               | ret                 
            //   8bda                 | dec                 eax
            //   488b4910             | lea                 edx, [0x4f06b]
            //   e8????????           |                     
            //   488b4f18             | dec                 eax

        $sequence_4 = { 4803c0 480101 4803db eb22 498b06 498bce }
            // n = 6, score = 100
            //   4803c0               | mov                 word ptr [ebp + eax + 0x190], cx
            //   480101               | js                  0x975
            //   4803db               | cmp                 eax, 0xe4
            //   eb22                 | jae                 0x975
            //   498b06               | dec                 eax
            //   498bce               | cwde                

        $sequence_5 = { 488bf8 48898424c0000000 488b4e08 4885c9 7509 488d15fc350900 eb0d }
            // n = 7, score = 100
            //   488bf8               | nop                 
            //   48898424c0000000     | dec                 eax
            //   488b4e08             | lea                 edx, [ebp + 0x150]
            //   4885c9               | dec                 eax
            //   7509                 | lea                 ecx, [ebp + 0x190]
            //   488d15fc350900       | dec                 eax
            //   eb0d                 | cmp                 dword ptr [eax + 0x18], 0x10

        $sequence_6 = { 0903 e9???????? 488d05d8940500 0f100f 0f1006 f30f7f4dd0 f30f7f45e0 }
            // n = 7, score = 100
            //   0903                 | lea                 ecx, [0x460f9]
            //   e9????????           |                     
            //   488d05d8940500       | dec                 eax
            //   0f100f               | mov                 dword ptr [ebx], ecx
            //   0f1006               | dec                 eax
            //   f30f7f4dd0           | lea                 edx, [ebx + 8]
            //   f30f7f45e0           | xor                 ecx, ecx

        $sequence_7 = { 418d45ff 410fb68c8332b30800 410fb6b48333b30800 8bd9 }
            // n = 4, score = 100
            //   418d45ff             | dec                 eax
            //   410fb68c8332b30800     | lea    eax, [0x3b0c7]
            //   410fb6b48333b30800     | dec    eax
            //   8bd9                 | mov                 ebx, ecx

        $sequence_8 = { 498b4e08 4c8d4508 33d2 ff15???????? 488b7508 4c8d4530 488bce }
            // n = 7, score = 100
            //   498b4e08             | dec                 eax
            //   4c8d4508             | test                ecx, ecx
            //   33d2                 | je                  0x1d4
            //   ff15????????         |                     
            //   488b7508             | dec                 esp
            //   4c8d4530             | lea                 eax, [0x41c6f]
            //   488bce               | dec                 esp

        $sequence_9 = { 884dd8 488bd3 482bd7 48d1fa 4883fa0f 7426 41b001 }
            // n = 7, score = 100
            //   884dd8               | dec                 eax
            //   488bd3               | add                 ebx, 0xa
            //   482bd7               | bts                 dword ptr [edi], 0x12
            //   48d1fa               | jmp                 0x1024
            //   4883fa0f             | inc                 ecx
            //   7426                 | mov                 eax, 8
            //   41b001               | dec                 eax

    condition:
        7 of them and filesize < 1552384
}