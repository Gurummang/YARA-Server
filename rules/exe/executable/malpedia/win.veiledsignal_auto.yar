rule win_veiledsignal_auto {

    meta:
        atk_type = "win.veiledsignal."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.veiledsignal."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.veiledsignal"
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
        $sequence_0 = { 7516 488d05c7390400 4a8b04e8 42385cf839 0f84c2000000 488d05b1390400 }
            // n = 6, score = 100
            //   7516                 | jb                  0x105
            //   488d05c7390400       | dec                 eax
            //   4a8b04e8             | shr                 eax, 0x2c
            //   42385cf839           | dec                 esp
            //   0f84c2000000         | lea                 ecx, [0x8566]
            //   488d05b1390400       | vsubsd              xmm1, xmm1, xmm2

        $sequence_1 = { 488d0dbabb0400 48c7040102000000 b808000000 486bc000 488b0d???????? 48894c0420 b808000000 }
            // n = 7, score = 100
            //   488d0dbabb0400       | dec                 esp
            //   48c7040102000000     | mov                 edx, ecx
            //   b808000000           | mov                 eax, 0x47
            //   486bc000             | syscall             
            //   488b0d????????       |                     
            //   48894c0420           | ret                 
            //   b808000000           | dec                 esp

        $sequence_2 = { 0f1f440000 488d54244c 488bce e8???????? 488bcb }
            // n = 5, score = 100
            //   0f1f440000           | lea                 eax, [0x8406]
            //   488d54244c           | dec                 eax
            //   488bce               | mov                 edi, ecx
            //   e8????????           |                     
            //   488bcb               | dec                 esp

        $sequence_3 = { 4881c458010000 c3 83f802 7571 488d0516010000 488905???????? 488d0529010000 }
            // n = 7, score = 100
            //   4881c458010000       | mov                 ecx, 6
            //   c3                   | dec                 esp
            //   83f802               | lea                 eax, [0x844b]
            //   7571                 | dec                 eax
            //   488d0516010000       | mov                 ebp, ecx
            //   488905????????       |                     
            //   488d0529010000       | dec                 esp

        $sequence_4 = { 7ec4 83c8ff eb0b 4803f6 418b84f7a8140100 85c0 }
            // n = 6, score = 100
            //   7ec4                 | dec                 eax
            //   83c8ff               | mov                 eax, dword ptr [esp + 0x38]
            //   eb0b                 | movzx               edx, dl
            //   4803f6               | movzx               edx, word ptr [esp + 0x60]
            //   418b84f7a8140100     | inc                 ecx
            //   85c0                 | mov                 edx, 0x100

        $sequence_5 = { 81f95a290000 752b 488d0df8030000 b801000000 48890d???????? }
            // n = 5, score = 100
            //   81f95a290000         | lea                 edx, [0xac37]
            //   752b                 | dec                 eax
            //   488d0df8030000       | sub                 esp, 0x20
            //   b801000000           | dec                 eax
            //   48890d????????       |                     

        $sequence_6 = { 4c8d0d97960000 498bd1 448d4008 3b0a 742b ffc0 }
            // n = 6, score = 100
            //   4c8d0d97960000       | vsubsd              xmm1, xmm1, xmm2
            //   498bd1               | vmulsd              xmm1, xmm1, qword ptr [ecx + eax*8]
            //   448d4008             | dec                 esp
            //   3b0a                 | lea                 ecx, [0x8566]
            //   742b                 | vsubsd              xmm1, xmm1, xmm2
            //   ffc0                 | vmulsd              xmm1, xmm1, qword ptr [ecx + eax*8]

        $sequence_7 = { e8???????? 488bd7 4c8d05e3270400 83e23f 488bcf 48c1f906 }
            // n = 6, score = 100
            //   e8????????           |                     
            //   488bd7               | imul                eax, eax, 0
            //   4c8d05e3270400       | dec                 eax
            //   83e23f               | lea                 ecx, [0x4bade]
            //   488bcf               | mov                 edx, dword ptr [esp + 0x30]
            //   48c1f906             | dec                 eax

        $sequence_8 = { 4883ec20 8b1d???????? eb1d 488d0573b10400 ffcb }
            // n = 5, score = 100
            //   4883ec20             | lea                 ebx, [0xffff592b]
            //   8b1d????????         |                     
            //   eb1d                 | mov                 al, byte ptr [esi + edi]
            //   488d0573b10400       | jne                 0x213
            //   ffcb                 | dec                 eax

        $sequence_9 = { ff15???????? 488b55cf 488bc8 ff15???????? 488b4dd7 }
            // n = 5, score = 100
            //   ff15????????         |                     
            //   488b55cf             | and                 edx, 0x3f
            //   488bc8               | dec                 eax
            //   ff15????????         |                     
            //   488b4dd7             | mov                 edx, ecx

    condition:
        7 of them and filesize < 667648
}