# Process Hollowing

An implementation of the Process Hollowing (also known as RunPE) technique.

x64 builds can hollow 64- & 32-bit images, but x86 builds can only hollow 32-bit images.

The implementation supports:

* When built x64: 64- & 32-bit images
* When built x86: 32-bit images
* Relocations

### How To Run

The implementation expects to get the images' paths via command-line arguments:

`ProcessHollowing.exe <Target Path> <Payload Path>`

The images must be both 64-bit or 32-bit, and, must be subsystem-compatible:

The payload's subsystem must be GUI, or, both of the images must have the same subsystem (console for example).





### To Do:



- [ ] Add TLS Callback Injection option support, in addition to the option of overriding the target's entry point by modifying its context, for being stealthier

