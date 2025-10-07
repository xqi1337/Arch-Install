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
- [Bootloader Security](#bootloader-security)
- [PAM Configuration](#pam-configuration)
- [Best Practices](#best-practices)
- [File Editing Security](#file-editing-security)
- [Partitioning and Mount Options](#partitioning-and-mount-options)

---

## Kernel Hardening

### Sysctl Configuration

cerate `/etc/sysctl.d/`:

#### `/etc/sysctl.d/kptr_restrict.conf`
```
kernel.kptr_restrict=2
```

#### `/etc/sysctl.d/dmesg_restrict.conf`
```
kernel.dmesg_restrict=1
```

#### `/etc/sysctl.d/harden_bpf.conf`
```
kernel.unprivileged_bpf_disabled=1
net.core.bpf_jit_harden=2
```

#### `/etc/sysctl.d/ptrace_scope.conf`
```
kernel.yama.ptrace_scope=2
```

#### `/etc/sysctl.d/kexec.conf`
```
kernel.kexec_load_disabled=1
```

#### `/etc/sysctl.d/tcp_hardening.conf`
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

#### `/etc/sysctl.d/mmap_aslr.conf`
```
vm.mmap_rnd_bits=32
vm.mmap_rnd_compat_bits=16
```

#### `/etc/sysctl.d/sysrq.conf`
```
kernel.sysrq=0
```

#### `/etc/sysctl.d/unprivileged_userns_clone.conf`
```
kernel.unprivileged_userns_clone=0
```

#### `/etc/sysctl.d/tcp_sack.conf`
```
net.ipv4.tcp_sack=0
```

#### `/etc/sysctl.d/coredump.conf`
```
kernel.core_pattern=|/bin/false
```

#### `/etc/sysctl.d/filesystem-protect.conf`
```
fs.protected_symlinks=1
fs.protected_hardlinks=1
fs.protected_fifos=2
fs.protected_regular=2
```

Apply:
```bash
sudo sysctl --system
```

---

### Boot Parameters

Edit `/etc/default/grub`:
```
GRUB_CMDLINE_LINUX_DEFAULT="loglevel=3 quiet apparmor=1 lsm=landlock,lockdown,yama,integrity,apparmor,bpf security=apparmor slab_nomerge slub_debug=FZ init_on_alloc=1 init_on_free=1 page_alloc.shuffle=1 pti=on mds=full,nosmt module.sig_enforce=1 lockdown=confidentiality oops=panic"
```
Regenerate GRUB:
```bash
sudo grub-mkconfig -o /boot/grub/grub.cfg
```

---

### Process Visibility Restriction

Edit `/etc/fstab`:
```
proc /proc proc nosuid,nodev,noexec,hidepid=2,gid=proc 0 0
```

Create `/etc/systemd/system/systemd-logind.service.d/hidepid.conf`:
```
[Service]
SupplementaryGroups=proc
```

Apply:
```bash
sudo systemctl daemon-reexec
sudo mount -o remount /proc
```

---

### Module Blacklisting

Create `/etc/modprobe.d/blacklist-hardening.conf`:

```
# Wireless
install btusb /bin/false
install bluetooth /bin/false

# DMA Attacks
install firewire-core /bin/false
install thunderbolt /bin/false

# Uncommon Network Protocols
install dccp /bin/false
install sctp /bin/false
install rds /bin/false
install tipc /bin/false
install n-hdlc /bin/false
install ax25 /bin/false
install netrom /bin/false
install x25 /bin/false
install rose /bin/false
install decnet /bin/false
install econet /bin/false
install af_802154 /bin/false
install ipx /bin/false
install appletalk /bin/false
install psnap /bin/false
install p8023 /bin/false
install llc /bin/false
install p8022 /bin/false

# Uncommon Filesystems
install cramfs /bin/false
install freevxfs /bin/false
install jffs2 /bin/false
install hfs /bin/false
install hfsplus /bin/false
install squashfs /bin/false
install udf /bin/false

# Connection Tracking Helper
options nf_conntrack nf_conntrack_helper=0
```

Regenerate initramfs:
```bash
sudo mkinitcpio -P
```

---

## Mandatory Access Control

### AppArmor Setup
```bash
sudo pacman -S apparmor
sudo systemctl enable --now apparmor.service
sudo aa-genprof /usr/bin/program
sudo aa-enforce /etc/apparmor.d/*
sudo aa-status
```

---

## Sandboxing

### Recommended: Bubblewrap
```bash
sudo pacman -S bubblewrap
```

### Not Recommended: Firejail
Avoid Firejail due to privilege escalation vulnerabilities.

### Xorg Sandboxing
Prefer Wayland. For Xorg, sandbox with Xpra/Xephyr + bubblewrap.

---

## Root Account Security

### Secure TTY Access
```bash
sudo truncate -s 0 /etc/securetty
```

### Restrict `su` Command
```bash
sudo sed -i 's/^# auth\s*required\s*pam_wheel.so/auth required pam_wheel.so use_uid/' /etc/pam.d/su
```

### Lock Root Account
```bash
sudo passwd -l root
```

### SSH Configuration
```
PermitRootLogin no
```
```bash
sudo systemctl restart sshd
```

### Password Hashing
```
password required pam_unix.so sha512 shadow nullok rounds=65536
```

---

## Systemd Sandboxing

Example service override:
```ini
[Service]
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
ProtectSystem=strict
ReadWritePaths=/var/lib/service/
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

Apply:
```bash
sudo mkdir -p /etc/systemd/system/service-name.service.d/
sudo nano /etc/systemd/system/service-name.service.d/hardening.conf
sudo systemctl daemon-reload
sudo systemctl restart service-name
```

---

## Network Security

### Firewalls
```bash
sudo pacman -S firewalld
sudo systemctl enable --now firewalld
sudo firewall-cmd --set-default-zone=drop
sudo firewall-cmd --permanent --zone=drop --add-service=ssh
sudo firewall-cmd --reload
```

### Tor Configuration
Use Tor Browser with AppArmor and stream isolation.

### Wireless Security
```bash
sudo rfkill block all
```

### MAC Address Spoofing
```bash
sudo pacman -S macchanger
sudo macchanger -r interface
```

### IPv6 Privacy
Create `/etc/sysctl.d/ipv6_privacy.conf`:
```
net.ipv6.conf.all.use_tempaddr=2
net.ipv6.conf.default.use_tempaddr=2
net.ipv6.conf.eth0.use_tempaddr=2
net.ipv6.conf.wlan0.use_tempaddr=2
```
```bash
sudo sysctl --system
```

---

## System Configuration

### File Permissions
```
umask 0077
```

### USB Security
```bash
sudo pacman -S usbguard
sudo systemctl enable --now usbguard.service
sudo sh -c 'usbguard generate-policy > /etc/usbguard/rules.conf'
sudo systemctl restart usbguard.service
```

### DMA Attack Prevention
Enable IOMMU via boot parameters:
```
intel_iommu=on
amd_iommu=on
```

### Core Dump Disabling
See `/etc/sysctl.d/coredump.conf`, Systemd, and `/etc/security/limits.conf` (`* hard core 0`).

### Uncommon Network Protocols
Blacklist in `/etc/modprobe.d/uncommon-network-protocols.conf`.

### Uncommon Filesystems
Blacklist in `/etc/modprobe.d/uncommon-filesystems.conf`.

---

## Virtualization

### Recommended: KVM/QEMU
```bash
sudo pacman -S qemu-full virt-manager
sudo systemctl enable --now libvirtd
sudo usermod -aG libvirt $USER
```

### Not Recommended: VirtualBox

---

## Bootloader Security

```bash
grub-mkpasswd-pbkdf2
sudo tee -a /etc/grub.d/40_custom > /dev/null <<'EOF'
set superusers="admin"
password_pbkdf2 admin [generated_hash]
EOF
sudo chmod +x /etc/grub.d/40_custom
sudo grub-mkconfig -o /boot/grub/grub.cfg
```

---

## PAM Configuration

### Strong Password Policy
```bash
sudo pacman -S libpwquality
sudo tee /etc/security/pwquality.conf > /dev/null <<'EOF'
minlen = 14
dcredit = -1
ucredit = -1
ocredit = -1
lcredit = -1
minclass = 4
maxrepeat = 3
usercheck = 1
enforcing = 1
EOF
```

### Login Delays and Lockouts
```
auth optional pam_faildelay.so delay=4000000
auth required pam_tally2.so deny=3 unlock_time=600 onerr=succeed file=/var/log/tallylog
```

---

## Additional Security Measures

### Microcode Updates
- AMD: `amd-ucode`
- Intel: `intel-ucode`

### Hardware Security
- Disable webcam/microphone in BIOS
- Remove unnecessary hardware
- Use secure boot if possible

### Time Synchronization
```bash
timedatectl set-ntp 0
sudo systemctl disable --now systemd-timesyncd.service
```

For Chrony:
```bash
sudo pacman -S chrony
sudo systemctl enable --now chronyd.service
chronyc tracking
```

### Entropy Generation
```bash
sudo pacman -S haveged jitterentropy
sudo systemctl enable --now haveged.service
sudo systemctl enable --now jitterentropy-rngd.service
```

---

## Best Practices

1. Principle of Least Privilege  
2. Strong Authentication (complex passwords, MFA)  
3. Regular Updates  
4. Information Disclosure Minimization  
5. Monitoring & Logging  
6. Backup Strategy  
7. Security Awareness  

---

## File Editing Security

```bash
sudoedit /path/to/file
EDITOR=vim sudoedit /path/to/file
```

---

## Partitioning and Mount Options

```
/dev/sda1 /          ext4    defaults                      1 1
/dev/sda2 /tmp       ext4    defaults,nosuid,noexec,nodev  1 2
/dev/sda3 /home      ext4    defaults,nosuid,nodev         1 2
/dev/sda4 /var       ext4    defaults,nosuid               1 2
/dev/sda5 /boot      ext4    defaults,nosuid,noexec,nodev  1 2
```

---

## Warning

Test configurations in a non-production environment first
---

## License

Educational purposes only. Verify configurations before use.

---

## Ending Note

<p align="center">
	<img src="https://raw.githubusercontent.com/catppuccin/catppuccin/main/assets/footers/gray0_ctp_on_line.svg?sanitize=true" />
</p>
