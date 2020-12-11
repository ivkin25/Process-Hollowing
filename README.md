# Process Hollowing

An implementation of the Process Hollowing (also known as RunPE) technique.

The implementation supports:

* 64- & 32-bit images
* Relocations

### How To Run

The implementation expects to get the images' paths via command-line arguments:

`ProcessHollowing.exe <Target Path> <Payload Path>`

The images must be both 64-bit or 32-bit, and, must be subsystem-compatible:

Both of them must have the same subsystem (both have the console subsystem for example), or the payload's subsystem must be GUI.





### To Do:



- [ ] Add TLS Callback Injection option support, in addition to the option of overriding the target's entry point by modifying its context, for being stealthier

