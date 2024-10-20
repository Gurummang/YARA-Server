rule win_halfrig_auto {

    meta:
        atk_type = "win.halfrig."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.halfrig."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.halfrig"
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
        $sequence_0 = { 833d????????ff 752a 488d0dee900400 c705????????679f9b01 c705????????6680ec92 c705????????3f7d27f5 e8???????? }
            // n = 7, score = 100
            //   833d????????ff       |                     
            //   752a                 | lea                 ecx, [0x79603]
            //   488d0dee900400       | mov                 byte ptr [ecx], al
            //   c705????????679f9b01     |     
            //   c705????????6680ec92     |     
            //   c705????????3f7d27f5     |     
            //   e8????????           |                     

        $sequence_1 = { 833d????????ff 7539 488d0d67740400 66c705????????fd01 c705????????6881e28d }
            // n = 5, score = 100
            //   833d????????ff       |                     
            //   7539                 | sub                 esp, 0x840
            //   488d0d67740400       | mov                 esi, 8
            //   66c705????????fd01     |     
            //   c705????????6881e28d     |     

        $sequence_2 = { e8???????? 488d0d6c950700 e8???????? 40383d???????? 7435 660f1f440000 }
            // n = 6, score = 100
            //   e8????????           |                     
            //   488d0d6c950700       | movzx               eax, byte ptr [eax]
            //   e8????????           |                     
            //   40383d????????       |                     
            //   7435                 | dec                 esp
            //   660f1f440000         | lea                 edi, [0x65633]

        $sequence_3 = { 75ad 0fb600 498bcf 8802 488d542420 e8???????? 488d0d58c70600 }
            // n = 7, score = 100
            //   75ad                 | mov                 ecx, edi
            //   0fb600               | mov                 byte ptr [edx], al
            //   498bcf               | dec                 eax
            //   8802                 | lea                 edx, [esp + 0x20]
            //   488d542420           | jne                 0x3e5
            //   e8????????           |                     
            //   488d0d58c70600       | movzx               eax, byte ptr [eax]

        $sequence_4 = { 48c1e008 488bd1 49ffc0 4833d0 4983f80f 72db 408835???????? }
            // n = 7, score = 100
            //   48c1e008             | dec                 eax
            //   488bd1               | lea                 ecx, [0x805ac]
            //   49ffc0               | dec                 ecx
            //   4833d0               | mov                 ecx, edi
            //   4983f80f             | mov                 byte ptr [edx], al
            //   72db                 | dec                 eax
            //   408835????????       |                     

        $sequence_5 = { 8802 488d542420 e8???????? 488d0d4cef0900 e8???????? 40383d???????? }
            // n = 6, score = 100
            //   8802                 | lea                 ecx, [0x8328f]
            //   488d542420           | jne                 0x325
            //   e8????????           |                     
            //   488d0d4cef0900       | dec                 eax
            //   e8????????           |                     
            //   40383d????????       |                     

        $sequence_6 = { 488d542420 e8???????? 488d0d08830600 e8???????? 40383d???????? 7435 488bd3 }
            // n = 7, score = 100
            //   488d542420           | lea                 eax, [0x40b7c]
            //   e8????????           |                     
            //   488d0d08830600       | dec                 ecx
            //   e8????????           |                     
            //   40383d????????       |                     
            //   7435                 | cmp                 eax, 0x401
            //   488bd3               | jb                  0x1987

        $sequence_7 = { 75ad 0fb600 498bcf 8802 488d542420 e8???????? 488d0df8da0500 }
            // n = 7, score = 100
            //   75ad                 | dec                 esp
            //   0fb600               | lea                 edi, [0x82a73]
            //   498bcf               | mov                 byte ptr [ecx], al
            //   8802                 | inc                 ecx
            //   488d542420           | mov                 eax, dword ptr [esi]
            //   e8????????           |                     
            //   488d0df8da0500       | jne                 0xc48

        $sequence_8 = { 8802 488d542420 e8???????? 488d0df8930600 e8???????? 40383d???????? }
            // n = 6, score = 100
            //   8802                 | lea                 ecx, [0x71adb]
            //   488d542420           | jne                 0x9fd
            //   e8????????           |                     
            //   488d0df8930600       | dec                 eax
            //   e8????????           |                     
            //   40383d????????       |                     

        $sequence_9 = { 488d0d88080800 e8???????? 40383d???????? 7435 }
            // n = 4, score = 100
            //   488d0d88080800       | dec                 eax
            //   e8????????           |                     
            //   40383d????????       |                     
            //   7435                 | inc                 edi

    condition:
        7 of them and filesize < 1369088
}