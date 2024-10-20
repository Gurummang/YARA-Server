rule win_cosmicduke_auto {

    meta:
        atk_type = "win.cosmicduke."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.cosmicduke."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.cosmicduke"
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
        $sequence_0 = { ff542418 83c602 47 3b742428 72ce 8b4514 }
            // n = 6, score = 100
            //   ff542418             | call                dword ptr [esp + 0x18]
            //   83c602               | add                 esi, 2
            //   47                   | inc                 edi
            //   3b742428             | cmp                 esi, dword ptr [esp + 0x28]
            //   72ce                 | jb                  0xffffffd0
            //   8b4514               | mov                 eax, dword ptr [ebp + 0x14]

        $sequence_1 = { ff8688050000 b001 5f c3 6a1f 5a 8bc1 }
            // n = 7, score = 100
            //   ff8688050000         | inc                 dword ptr [esi + 0x588]
            //   b001                 | mov                 al, 1
            //   5f                   | pop                 edi
            //   c3                   | ret                 
            //   6a1f                 | push                0x1f
            //   5a                   | pop                 edx
            //   8bc1                 | mov                 eax, ecx

        $sequence_2 = { c1e104 03cb 898439142c0000 e9???????? 3975e4 7408 ff75e4 }
            // n = 7, score = 100
            //   c1e104               | shl                 ecx, 4
            //   03cb                 | add                 ecx, ebx
            //   898439142c0000       | mov                 dword ptr [ecx + edi + 0x2c14], eax
            //   e9????????           |                     
            //   3975e4               | cmp                 dword ptr [ebp - 0x1c], esi
            //   7408                 | je                  0xa
            //   ff75e4               | push                dword ptr [ebp - 0x1c]

        $sequence_3 = { 8d7c241c e8???????? 3ac3 0f84ac010000 8b442420 89442430 8d842438200000 }
            // n = 7, score = 100
            //   8d7c241c             | lea                 edi, [esp + 0x1c]
            //   e8????????           |                     
            //   3ac3                 | cmp                 al, bl
            //   0f84ac010000         | je                  0x1b2
            //   8b442420             | mov                 eax, dword ptr [esp + 0x20]
            //   89442430             | mov                 dword ptr [esp + 0x30], eax
            //   8d842438200000       | lea                 eax, [esp + 0x2038]

        $sequence_4 = { 85db 7507 32c0 e9???????? 837d1400 74f3 807d1000 }
            // n = 7, score = 100
            //   85db                 | test                ebx, ebx
            //   7507                 | jne                 9
            //   32c0                 | xor                 al, al
            //   e9????????           |                     
            //   837d1400             | cmp                 dword ptr [ebp + 0x14], 0
            //   74f3                 | je                  0xfffffff5
            //   807d1000             | cmp                 byte ptr [ebp + 0x10], 0

        $sequence_5 = { 6a01 68???????? 56 53 e8???????? b001 5f }
            // n = 7, score = 100
            //   6a01                 | push                1
            //   68????????           |                     
            //   56                   | push                esi
            //   53                   | push                ebx
            //   e8????????           |                     
            //   b001                 | mov                 al, 1
            //   5f                   | pop                 edi

        $sequence_6 = { 8bc7 8d4c2414 e8???????? 53 8d44243c 50 }
            // n = 6, score = 100
            //   8bc7                 | mov                 eax, edi
            //   8d4c2414             | lea                 ecx, [esp + 0x14]
            //   e8????????           |                     
            //   53                   | push                ebx
            //   8d44243c             | lea                 eax, [esp + 0x3c]
            //   50                   | push                eax

        $sequence_7 = { e8???????? 0fb7c0 894510 6685c0 7512 33c0 40 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   0fb7c0               | movzx               eax, ax
            //   894510               | mov                 dword ptr [ebp + 0x10], eax
            //   6685c0               | test                ax, ax
            //   7512                 | jne                 0x14
            //   33c0                 | xor                 eax, eax
            //   40                   | inc                 eax

        $sequence_8 = { ff7508 8bf0 8d85ecfdffff 50 ff15???????? 8b3d???????? }
            // n = 6, score = 100
            //   ff7508               | push                dword ptr [ebp + 8]
            //   8bf0                 | mov                 esi, eax
            //   8d85ecfdffff         | lea                 eax, [ebp - 0x214]
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8b3d????????         |                     

        $sequence_9 = { e8???????? 84c0 742f 838c244c300000ff 8d74240c e8???????? 8b4508 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   84c0                 | test                al, al
            //   742f                 | je                  0x31
            //   838c244c300000ff     | or                  dword ptr [esp + 0x304c], 0xffffffff
            //   8d74240c             | lea                 esi, [esp + 0xc]
            //   e8????????           |                     
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]

    condition:
        7 of them and filesize < 456704
}