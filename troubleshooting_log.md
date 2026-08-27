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

# Problem 5

## Problem

Kali could not initially reach the Windows endpoint at `192.168.8.130`.

Testing TCP port 445 from Kali resulted in:

    Connection timed out

## Investigation

Windows was confirmed to have the correct SOC-LAB IP address:

    192.168.8.130

Windows could communicate with other systems on the SOC-LAB network.

The Windows SOC-LAB network interface was initially configured with the `Public` network profile.

The SMB firewall rule was also checked and found to be enabled:

    FPS-SMB-In-TCP
    Enabled: True
    Profile: Private, Public
    Direction: Inbound
    Action: Allow

Despite this, Kali's connection to TCP port 445 was initially unsuccessful.

## Resolution

The SOC-LAB network interface was changed from the `Public` network profile to the `Private` profile.

After changing the profile, TCP port 445 was tested again from Kali:

    nc -nv 192.168.8.130 445

The connection was successfully established.

SMB access was then verified using:

    smbclient //192.168.8.130/C$ -U 'WORKGROUP\socadmin' -m SMB3

The Windows C$ administrative share was successfully accessed.

## Lesson

Windows network profiles can affect firewall behavior. When troubleshooting connectivity to a Windows endpoint, verify:

1. The interface IP configuration.
2. The network profile.
3. The applicable Windows Firewall rules.
4. Whether the target service is actually listening on the expected port.