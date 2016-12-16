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

Section notes from: http://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/
