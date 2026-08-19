# Problem 1

Problem:
Ubuntu installer failed to unmount /cdrom.

Cause:
Installation ISO was still attached to VMware's virtual CD/DVD device.

Resolution:
Disconnected the ISO and continued booting from the virtual disk.

# Problem 2

Problem:
Kali initially reported "No route to host."

Cause:
Ubuntu VM was powered off.

Resolution:
Started Ubuntu and verified the SOC-LAB interface.