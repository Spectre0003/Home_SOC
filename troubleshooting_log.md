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

# Problem 3

Problem:
Windows VM initially booted to `EFI Network` instead of the Windows installer.

Cause:
The VM was not successfully booting from the attached Windows ISO despite the ISO being configured in the virtual CD/DVD device.

Resolution:
Verified the Windows ISO was selected as the CD/DVD image, confirmed the device was connected at power-on, and manually booted the VM through UEFI firmware from the virtual CD/DVD device.