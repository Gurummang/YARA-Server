rule win_httpsuploader_auto {

    meta:
        atk_type = "win.httpsuploader."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.httpsuploader."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.httpsuploader"
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
        $sequence_0 = { 33ff 33d2 41b806020000 6689bc2470020000 e8???????? 488d4c2451 33d2 }
            // n = 7, score = 100
            //   33ff                 | test                eax, eax
            //   33d2                 | jne                 0xa95
            //   41b806020000         | dec                 eax
            //   6689bc2470020000     | lea                 eax, [0xb51f]
            //   e8????????           |                     
            //   488d4c2451           | dec                 eax
            //   33d2                 | sub                 esp, 0x20

        $sequence_1 = { 33d2 33c9 897c2428 48895c2420 ff15???????? eb3b 488d0dc3bd0000 }
            // n = 7, score = 100
            //   33d2                 | je                  0x96a
            //   33c9                 | dec                 eax
            //   897c2428             | add                 esp, 0x40
            //   48895c2420           | inc                 ecx
            //   ff15????????         |                     
            //   eb3b                 | pop                 esp
            //   488d0dc3bd0000       | ret                 

        $sequence_2 = { 4883ec20 488bfa 488bd9 488d0501700000 488981a0000000 83611000 }
            // n = 6, score = 100
            //   4883ec20             | mov                 ecx, 0x40
            //   488bfa               | dec                 esp
            //   488bd9               | mov                 dword ptr [esp + 0x498], ebp
            //   488d0501700000       | mov                 dword ptr [esp + 0x20], 3
            //   488981a0000000       | dec                 esp
            //   83611000             | mov                 ebp, eax

        $sequence_3 = { 4c8bc0 418bd4 e8???????? 488d8dd0000000 ff15???????? }
            // n = 5, score = 100
            //   4c8bc0               | dec                 eax
            //   418bd4               | mov                 ecx, dword ptr [ebp + 0x2e0]
            //   e8????????           |                     
            //   488d8dd0000000       | dec                 eax
            //   ff15????????         |                     

        $sequence_4 = { 488d0d6c280000 4533c9 ba00000040 4489442420 ff15???????? }
            // n = 5, score = 100
            //   488d0d6c280000       | movzx               eax, byte ptr [eax + ebp]
            //   4533c9               | inc                 ecx
            //   ba00000040           | mov                 byte ptr [edx], al
            //   4489442420           | mov                 eax, ecx
            //   ff15????????         |                     

        $sequence_5 = { 4c8d25cf7d0000 f0ff09 7511 488b8eb8000000 493bcc }
            // n = 5, score = 100
            //   4c8d25cf7d0000       | mov                 eax, 0x3fe
            //   f0ff09               | mov                 word ptr [ebp + 0x4f0], di
            //   7511                 | dec                 eax
            //   488b8eb8000000       | lea                 ecx, [ebp + 0x8f2]
            //   493bcc               | xor                 edx, edx

        $sequence_6 = { 488d0543b50000 eb04 4883c014 4883c428 c3 4053 }
            // n = 6, score = 100
            //   488d0543b50000       | lea                 ebx, [0x8db3]
            //   eb04                 | dec                 eax
            //   4883c014             | lea                 edi, [0x8db4]
            //   4883c428             | jne                 0x10e
            //   c3                   | dec                 eax
            //   4053                 | lea                 ecx, [esp + 0x270]

        $sequence_7 = { 488d158e380000 488bc8 ff15???????? 4885c0 0f847a010000 }
            // n = 5, score = 100
            //   488d158e380000       | lea                 eax, [0xde96]
            //   488bc8               | xor                 eax, eax
            //   ff15????????         |                     
            //   4885c0               | mov                 ebp, eax
            //   0f847a010000         | inc                 ebp

        $sequence_8 = { 81fa01010000 7d13 4863ca 8a44191c 4288840170fa0000 }
            // n = 5, score = 100
            //   81fa01010000         | dec                 eax
            //   7d13                 | arpl                si, cx
            //   4863ca               | dec                 eax
            //   8a44191c             | lea                 edx, [ebp + ecx + 0x620]
            //   4288840170fa0000     | inc                 ebp

        $sequence_9 = { 745e 6666660f1f840000000000 488b0d???????? 488d542440 4533c9 4533c0 ff15???????? }
            // n = 7, score = 100
            //   745e                 | mov                 word ptr [ebp + 0x8f0], di
            //   6666660f1f840000000000     | mov    dword ptr [esp + 0x44], edi
            //   488b0d????????       |                     
            //   488d542440           | mov                 dword ptr [esp + 0x40], edi
            //   4533c9               | xor                 edx, edx
            //   4533c0               | inc                 ecx
            //   ff15????????         |                     

    condition:
        7 of them and filesize < 190464
}