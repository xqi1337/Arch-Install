# Arch Hardening


## Table of Contents

- [Kernel Hardening](#kernel-hardening)
- [Mandatory Access Control](#mandatory-access-control)
- [Sandboxing](#sandboxing)
- [Root Account Security](#root-account-security)
- [Systemd Sandboxing](#systemd-sandboxing)
- [Network Security](#network-security)
- [Virtualization](#virtualization)
- [System Configuration](#system-configuration)
- [Best Practices](#best-practices)

## Kernel Hardening

### Sysctl Configuration

Configure kernel security parameters by creating files in `/etc/sysctl.d/`:

#### Kernel Pointer Protection
Create `kptr_restrict.conf`:
```
kernel.kptr_restrict=2
```
Prevents kernel pointer leaks via `/proc/kallsyms` or `dmesg`.

#### Kernel Log Protection
Create `dmesg_restrict.conf`:
```
kernel.dmesg_restrict=1
```
Blocks non-root users from accessing kernel logs.

#### BPF Hardening
Create `harden_bpf.conf`:
```
kernel.unprivileged_bpf_disabled=1
net.core.bpf_jit_harden=2
```
Restricts BPF JIT compiler to root and hardens it against exploitation.

#### Ptrace Restrictions
Create `ptrace_scope.conf`:
```
kernel.yama.ptrace_scope=2
```
Limits ptrace usage to processes with `CAP_SYS_PTRACE`.

#### Kexec Protection
Create `kexec.conf`:
```
kernel.kexec_load_disabled=1
```
Disables kexec to prevent kernel replacement.

#### TCP/IP Stack Hardening
Create `tcp_hardening.conf`:
```
net.ipv4.tcp_syncookies=1
net.ipv4.tcp_rfc1337=1
net.ipv4.conf.default.rp_filter=1
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.secure_redirects=0
net.ipv4.conf.default.secure_redirects=0
net.ipv6.conf.all.accept_redirects=0
net.ipv6.conf.default.accept_redirects=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0
net.ipv4.icmp_echo_ignore_all=1
```

#### ASLR Enhancement
Create `mmap_aslr.conf`:
```
vm.mmap_rnd_bits=32
vm.mmap_rnd_compat_bits=16
```

#### Additional Security Settings
Create respective configuration files:

`sysrq.conf`:
```
kernel.sysrq=0
```

`unprivileged_users_clone.conf`:
```
kernel.unprivileged_userns_clone=0
```

`tcp_sack.conf`:
```
net.ipv4.tcp_sack=0
```

### Boot Parameters

Add these parameters to your bootloader configuration:

For GRUB, edit `/etc/default/grub`:
```
GRUB_CMDLINE_LINUX_DEFAULT="apparmor=1 security=apparmor slab_nomerge slub_debug=FZ init_on_alloc=1 init_on_free=1 mce=0 pti=on mds=full,nosmt module.sig_enforce=1 oops=panic"
```

Regenerate GRUB configuration:
```bash
grub-mkconfig -o /boot/grub/grub.cfg
```

### Process Visibility Restriction

Edit `/etc/fstab` to hide other users' processes:
```
proc /proc proc nosuid,nodev,noexec,hidepid=2,gid=proc 0 0
```

Configure systemd-logind in `/etc/systemd/system/systemd-logind.service.d/hidepid.conf`:
```
[Service]
SupplementaryGroups=proc
```

### Network Security

Disable automatic connection tracking helper:
Create `/etc/modprobe.d/no-conntrack-helper.conf`:
```
options nf_conntrack nf_conntrack_helper=0
```

## Mandatory Access Control

### AppArmor Setup

1. Install AppArmor package
2. Enable AppArmor service
3. Set kernel parameters (see boot parameters section)
4. Create application profiles:

```bash
aa-genprof /usr/bin/program
```

## Sandboxing

### Recommended: Bubblewrap
Use bubblewrap for application sandboxing due to its minimal attack surface.

### Not Recommended: Firejail
Avoid Firejail due to its large attack surface and history of privilege escalation vulnerabilities.

### Xorg Sandboxing
Consider using Wayland instead of Xorg for better window isolation. If using Xorg, sandbox with Xpra/Xephyr and bubblewrap.

## Root Account Security

### Secure TTY Access
Keep `/etc/securetty` empty to prevent root login from TTY.

### Restrict su Command
Edit `/etc/pam.d/su` and `/etc/pam.d/su-l`, uncomment:
```
auth required pam_wheel.so use_uid
```

### Lock Root Account
```bash
passwd -l root
```

### SSH Configuration
In `/etc/ssh/sshd_config`:
```
PermitRootLogin no
```

### Password Hashing
Edit `/etc/pam.d/passwd`:
```
password required pam_unix.so sha512 shadow nullok rounds=65536
```

Rehash existing passwords:
```bash
passwd uwu
```

## Systemd Sandboxing

Example hardened service configuration:
```ini
[Service]
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
ProtectSystem=strict
ReadWriteDirectories=/var/lib/service/
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
PrivateTmp=true
PrivateUsers=yes
MemoryDenyWriteExecute=true
NoNewPrivileges=true
RestrictRealtime=true
RestrictAddressFamilies=AF_INET AF_UNIX
SystemCallArchitectures=native
RestrictNamespaces=yes
RuntimeDirectoryMode=0700
SystemCallFilter=~@clock @cpu-emulation @debug @keyring @module @mount @obsolete @raw-io
```

## Network Security

### Firewalls
Implement strict iptables or nftables rules blocking all incoming traffic unless specifically required.

### Tor Configuration
For anonymity, use Tor Browser with proper AppArmor profiles. Configure stream isolation and transparent proxy if needed.

### Wireless Security
Disable unnecessary wireless devices:
```bash
rfkill block all
```

Blacklist wireless modules in `/etc/modprobe.d/blacklist-wireless.conf`:
```
install btusb /bin/true
install bluetooth /bin/true
```

### MAC Address Spoofing
Use macchanger for privacy:
```bash
macchanger -e interface
```

### IPv6 Privacy
Create `/etc/sysctl.d/ipv6_privacy.conf`:
```
net.ipv6.conf.all.use_tempaddr = 2
net.ipv6.conf.default.use_tempaddr = 2
net.ipv6.conf.eth0.use_tempaddr = 2
net.ipv6.conf.wlan0.use_tempaddr = 2
```

## System Configuration

### File Permissions
Change umask in `/etc/profile`:
```
umask 0077
```

### USB Security
Use USBGuard or disable USB support entirely with `nousb` boot parameter.

### DMA Attack Prevention
Blacklist DMA-capable modules in `/etc/modprobe.d/blacklist-dma.conf`:
```
install firewire-core /bin/true
install thunderbolt /bin/true
```

Enable IOMMU with boot parameters:
- Intel: `intel_iommu=on`
- AMD: `amd_iommu=on`

### Core Dump Disabling

#### Sysctl Method
Create `/etc/sysctl.d/coredump.conf`:
```
kernel.core_pattern=|/bin/false
```

#### Systemd Method
Create `/etc/systemd/coredump.conf.d/custom.conf`:
```
[Coredump]
Storage=none
```

#### Ulimit Method
In `/etc/security/limits.conf`:
```
* hard core 0
```

### Uncommon Network Protocols
Blacklist unused protocols in `/etc/modprobe.d/uncommon-network-protocols.conf`:
```
install dccp /bin/true
install sctp /bin/true
install rds /bin/true
install tipc /bin/true
install n-hdlc /bin/true
install ax25 /bin/true
install netrom /bin/true
install x25 /bin/true
install rose /bin/true
install decnet /bin/true
install econet /bin/true
install af_802154 /bin/true
install ipx /bin/true
install appletalk /bin/true
install psnap /bin/true
install p8023 /bin/true
install llc /bin/true
install p8022 /bin/true
```

### Uncommon Filesystems
Blacklist unused filesystems in `/etc/modprobe.d/uncommon-filesystems.conf`:
```
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install squashfs /bin/true
install udf /bin/true
```

## Virtualization

### Recommended: KVM/QEMU
Use KVM/QEMU with virt-manager or GNOME Boxes for secure virtualization.

### Not Recommended: VirtualBox
Avoid VirtualBox due to security concerns and proprietary components.

## Bootloader Security

### GRUB Password Protection
Generate password hash:
```bash
grub-mkpasswd-pbkdf2
```

Edit `/etc/grub.d/40_custom`:
```
set superusers="uwu"
password_pbkdf2 uwu [generated_hash]
```

Regenerate configuration:
```bash
grub-mkconfig -o /boot/grub/grub.cfg
```

## PAM Configuration

### Strong Password Policy
Edit `/etc/pam.d/passwd`:
```
password required pam_cracklib.so retry=2 minlen=10 difok=6 dcredit=-1 ucredit=-1 ocredit=-1 lcredit=-1
password required pam_unix.so use_authtok sha512 shadow
```

### Login Delays and Lockouts
Edit `/etc/pam.d/system-login`:
```
auth optional pam_faildelay.so delay=4000000
auth required pam_tally2.so deny=3 unlock_time=600 onerr=succeed file=/var/log/tallylog
```

## Additional Security Measures

### Microcode Updates
Install appropriate microcode package:
- AMD: `amd-ucode`
- Intel: `intel-ucode`

### Hardware Security
- Disable webcam and microphone in BIOS when possible
- Physically remove unnecessary hardware components
- Use secure boot when available

### Time Synchronization
Consider disabling NTP due to security concerns:
```bash
timedatectl set-ntp 0
systemctl disable systemd-timesyncd.service
```

### Entropy Generation
Install entropy generators:
```bash
sudo pacman -S haveged jitterentropy
sudo systemctl enable --now haveged.service
```

## Best Practices

1. **Principle of Least Privilege**: Disable and remove unnecessary services and features
2. **Strong Authentication**: Use complex passwords and consider multi-factor authentication
3. **Regular Updates**: Configure automatic security updates
4. **Information Disclosure**: Avoid leaking system information
5. **Monitoring**: Implement logging and monitoring solutions
6. **Backup Strategy**: Maintain secure, tested backups
7. **Security Awareness**: Stay informed about new vulnerabilities and mitigation techniques

## File Editing Security

Use `sudoedit` instead of running text editors as root:
```bash
sudoedit /path/to/file
EDITOR=nano sudoedit /path/to/file
```

## Partitioning and Mount Options

Use security-focused mount options in `/etc/fstab`:
```
/dev/sda1 /          ext4    defaults                      1 1
/dev/sda2 /tmp       ext4    defaults,nosuid,noexec,nodev  1 2
/dev/sda3 /home      ext4    defaults,nosuid,nodev         1 2
/dev/sda4 /var       ext4    defaults,nosuid               1 2
/dev/sda5 /boot      ext4    defaults,nosuid,noexec,nodev  1 2
```

## Warning

This guide contains advanced security configurations that may break system functionality. Always test configurations in a non-production environment first. Some settings may impact system performance or compatibility with certain applications.

## Contributing

This guide is based on security best practices for Linux systems. Contributions and improvements are welcome through pull requests.

## License

This guide is provided for educational purposes. Always verify configurations in your specific environment before implementation.
