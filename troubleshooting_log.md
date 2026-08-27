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

# Problem 4

Problem:
Kali could discover the Windows SMB shares, but attempting to access the C$ administrative share returned `NT_STATUS_ACCESS_DENIED`.

Initial observation:
SMB TCP port 445 was reachable from Kali, and `smbclient -L` successfully displayed the following shares:

- ADMIN$
- C$
- IPC$

However, connecting directly to C$ failed with `NT_STATUS_ACCESS_DENIED`.

Investigation:
Verified that the `socadmin` account was a member of the local Administrators group using:

    net user socadmin

Also verified the account's administrator privileges with:

    whoami /groups

The `BUILTIN\Administrators` group was present and enabled.

The following command confirmed that `socadmin` was a member of the Administrators group:

    net localgroup "Administrators"

The registry value `LocalAccountTokenFilterPolicy` was initially not present:

    Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name LocalAccountTokenFilterPolicy

Cause:
Windows Remote UAC token filtering was preventing the local administrator account from receiving its full administrative token during the remote SMB connection.

Resolution:
Created the `LocalAccountTokenFilterPolicy` registry value and set it to `1`:

    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LocalAccountTokenFilterPolicy" -PropertyType DWord -Value 1 -Force

Restarted Windows for the change to take effect.

Verification:
Connected from Kali using SMB3:

    smbclient //192.168.8.130/C$ -U 'WORKGROUP\socadmin' -m SMB3

The connection succeeded and the C$ share was accessible.

Running:

    ls

successfully displayed the contents of the Windows C:\ drive, including:

- Program Files
- Program Files (x86)
- ProgramData
- Users
- Windows

Result:
Kali can now successfully access the Windows C$ administrative share using the `socadmin` account over SMB3.