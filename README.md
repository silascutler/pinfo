# pinfo
Simple CLI tool for showing Windows PE Info

example_files:
  - calc.exe



Example 
```
MD5:    829e4805b0e12b383ee09abdc9e2dc3c
SHA1:   5a272b7441328e09704b6d7eabdbd51b8858fde4
SHA256: 37121ecb7c1e112b735bd21b0dfe3e526352ecb98c434c5f40e6a2a582380cdd

PE Sections:
 [ Name ]  vaddr    MSize     size    raddr   | Notes: 

 [.text]   0x1000  0x126b0   75776    0x400    Alternative Code Section 
 [.data]  0x14000   0x101c    2560   0x12c00   Data Section (Borland),Data Section 
 [.rsrc]  0x16000   0x8960   35328   0x13600   Resource section 
```

```
MD5:    7efda3327b26e6ff09688527a9c94e1a
SHA1:   20ba233248f187695859eb8558ad4826ada03c42
SHA256: 2944a19408c56bad23e27031e6b6b645b1236956626aa1f1ac6df16ccf4748cf

PE Sections:
 [ Name ]  vaddr    MSize     size    raddr   | Notes: 

 [.text]   0x1000   0x5a5a   23552    0x400    Alternative Code Section 
 [.rdata]  0x7000   0x1190    4608    0x6000   Read-only Data Section 
 [.data]   0x9000  0x1af98    1024    0x7200   Data Section (Borland),Data Section 
 [.ndata] 0x24000  0x16000     0       0x0     Nullsoft Installer section 
 [.rsrc]  0x3a000   0x8098   33280    0x7600   Resource section 
```

```
MD5:    3bb8d60966ee980c8e6ea2e940c41dd9
SHA1:   0e7d3470ead9be46b0548120ef6d1b4dd5f04ca8
SHA256: ea85ff7e05480940d2cd08c53031e080ff55a124cb00d961fea7c277de80c734

PE Sections:
 [ Name ]  vaddr    MSize     size    raddr   | Notes: 

  [UPX0]   0x1000  0x50000     0      0x200    UPX Packer 
  [UPX1]  0x51000  0x31000   198144   0x200    UPX Packer 
 [.rsrc]  0x82000   0x1000    1536   0x30800   Resource section 
```

Section notes from: http://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/
