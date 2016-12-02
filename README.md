
# Patcher



### Install

```bash
virtualenv venv
source venv/bin/activate
pip install -r requirements.txt

python setup.py build
python setup.py install
```

### ELFFile

#### Example:

```python
f = ELFFile(bin_name)
# change all segment permission to RWX
for segment in f.segments:
    segment.set_permission('RWX')
# change all section permission to RWX
for section in f.sections:
    section.set_permission('RWX')
# write at 0x08048000 (virtual address)
f.write_at(vaddr = 0x8048000, data = '\x90\x90\x90\x90')
f write at 10 (file_offset)
f.write_asm_at(vaddr = 0x8048000, data = 'ret;int 0x80;')
# write at 10 (file_offset)
f.write_at(offset = 10, data = '\x90\x90\x90\x90')
f.write_codecave_at(vaddr = 0x08048386, vcave = 0x0804979c, data = "mov eax, esp; mov ebx, 1; mov ecx, 33; cmp eax,ecx; call 0x080485E4;int 0x80;")

f.write_codecave_auto(vaddr= 0x080480a9, data = "mov ecx, DWORD PTR [ebp + 0xc]; mov edx, DWORD PTR [ebp + 0x8]; cmp eax, 0x10; jg 0x080480af; add esp, 0x48; pop ebp; ret", filename = "idapython_result.txt")
[*] Translate vaddr:0x80480a9 to offset:0xa9
[*] Translate vaddr:0x804b691 to offset:0x3691
[*] Translate vaddr:0x804b5c1 to offset:0x35c1
[*] Translate vaddr:0x804b571 to offset:0x3571

f.save(save)
```

### idapython_find_aligns_size.py

#### README
```
press ALT + F7 in ida, and choose the file.
then this script will find empty space in binary.
```

