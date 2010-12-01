#!/bin/csh
#
# This will format a new machine with a BOOT+HAMMER setup and install
# the live CD.  You would boot the live CD, dhclient your network up,
# then run 'rconfig :hammer', assuming you have a rconfig server on the
# LAN.  Alternately fetch the script from a known location and just run it.
#
# ad0s1a will be setup as a small UFS /boot.  ad0s1d will be setup as
# HAMMER with all remaining disk space.  Pseudo file-systems will be
# created for /var, /usr, etc (giving them separate inode spaces and
# backup domains).
#
# ad0s1d will be set up as encrypted root file system using cryptsetup.
# During the installation process you have to choose a password and enter
# it three times.  Remember your password as you won't be able to recover
# your data without it!
#
# WARNING: HAMMER filesystems (and pseudo-filesystems) must be
# occassionally pruned and reblocked.  'man hammer' for more information.

set disk = "ad0"

# For safety this only runs on a CD-booted machine
#
df / | awk '{ print $1; }' | fgrep cd
if ( $status > 0 ) then
    echo "This program formats your disk and you didn't run it from"
    echo "A CD boot!"
    exit 1
endif

echo "This program formats disk ${disk}!  Hit ^C now or its gone."
foreach i ( 10 9 8 7 6 5 4 3 2 1 )
    echo -n " $i"
    sleep 1
end
echo ""

# Unmount any prior mounts on /mnt, reverse order to unwind
# sub-directory mounts.
#
foreach i ( `df | fgrep /mnt | awk '{ print $6; }' | tail -r` )
    echo "UMOUNT $i"
    umount $i
end

# Set our disk here
#
sleep 1
set echo

# Format and label the disk.  
#
#	'a' small UFS boot
#	'd' HAMMER filesystem
#
#	Use PFSs for backup domain separation
#
dd if=/dev/zero of=/dev/${disk} bs=32k count=16
fdisk -IB ${disk}
disklabel64 -r -w ${disk}s1 auto
disklabel64 -B ${disk}s1
disklabel64 ${disk}s1 > /tmp/label
cat >> /tmp/label << EOF
  a: 256m 0 4.2BSD
  b: 2g * swap
  d: * * HAMMER
EOF
disklabel64 -R ${disk}s1 /tmp/label

newfs /dev/${disk}s1a

# Load dm and setup a new encrypted root fs
#
kldload dm
cryptsetup -y luksFormat /dev/${disk}s1d
cryptsetup luksOpen /dev/${disk}s1d root || exit 1

newfs_hammer -L ROOT /dev/mapper/root

# Mount it
#
mount_hammer /dev/mapper/root /mnt
mkdir /mnt/boot
mount /dev/${disk}s1a /mnt/boot

# Create PFS mount points for nullfs.
#
# Do the mounts manually so we can install the system, setup
# the fstab later on.
mkdir /mnt/pfs

hammer pfs-master /mnt/pfs/usr
hammer pfs-master /mnt/pfs/usr.obj
hammer pfs-master /mnt/pfs/var
hammer pfs-master /mnt/pfs/var.crash
hammer pfs-master /mnt/pfs/var.tmp
hammer pfs-master /mnt/pfs/tmp
hammer pfs-master /mnt/pfs/home

mkdir /mnt/usr
mkdir /mnt/var
mkdir /mnt/tmp
mkdir /mnt/home

mount_null /mnt/pfs/usr /mnt/usr
mount_null /mnt/pfs/var /mnt/var
mount_null /mnt/pfs/tmp /mnt/tmp
mount_null /mnt/pfs/home /mnt/home

mkdir /mnt/usr/obj
mkdir /mnt/var/tmp
mkdir /mnt/var/crash

mount_null /mnt/pfs/var.tmp /mnt/var/tmp
mount_null /mnt/pfs/var.crash /mnt/var/crash
mount_null /mnt/pfs/usr.obj /mnt/usr/obj

chmod 1777 /mnt/tmp
chmod 1777 /mnt/var/tmp

# Install the system from the live CD
#
cpdup -o / /mnt
cpdup -o /boot /mnt/boot
cpdup -o /usr /mnt/usr
cpdup -o /var /mnt/var
cpdup -i0 /etc.hdd /mnt/etc

chflags -R nohistory /mnt/tmp
chflags -R nohistory /mnt/var/tmp
chflags -R nohistory /mnt/var/crash
chflags -R nohistory /mnt/usr/obj

# Create some directories to be used for NFS mounts later on.
# Edit as desired.
#
foreach i ( /proc /usr/doc /usr/src /repository /ftp /archive )
    if ( ! -d /mnt$i ) then
	mkdir /mnt$i
    endif
end

cat > /mnt/etc/fstab << EOF
# Device		Mountpoint	FStype	Options		Dump	Pass#
/dev/${disk}s1d		/		hammer	rw		1	1
/dev/${disk}s1a		/boot		ufs	rw		1	1
/dev/${disk}s1b		none		swap	sw		0	0
/pfs/usr		/usr		null	rw		0	0
/pfs/var		/var		null	rw		0	0
/pfs/tmp		/tmp		null	rw		0	0
/pfs/home		/home		null	rw		0	0
/pfs/var.tmp		/var/tmp	null	rw		0	0
/pfs/usr.obj		/usr/obj	null	rw		0	0
/pfs/var.crash		/var/crash	null	rw		0	0
proc			/proc		procfs	rw		0	0
# misc NFS mounts to get your test box access to 'stuff'
#crater:/repository	/repository	nfs	ro,intr,bg	0	0
#crater:/usr/doc	/usr/doc	nfs	ro,intr,bg	0	0
#crater:/ftp		/ftp		nfs	ro,intr,bg	0	0
#crater:/sources/HEAD	/usr/src	nfs	ro,intr,bg	0	0
#pkgbox:/archive	/archive	nfs	ro,intr,bg	0	0
EOF


# Mount devfs and create a new initrd
#
mount_devfs /mnt/dev
chroot /mnt mkinitrd

# Because root is not on the boot partition we have to tell the loader
# to tell the kernel where root is.
#
cat > /mnt/boot/loader.conf << EOF
dm_load="YES"
initrd.img_load="YES"
initrd.img_type="md_image"
vfs.root.mountfrom="ufs:md0s0"
vfs.root.realroot="crypt:hammer:/dev/${disk}s1d:root"
EOF

# Setup interface, configuration, sshd
#
set ifc = `route -n get default | fgrep interface | awk '{ print $2; }'`
set ip = `ifconfig $ifc | fgrep inet | fgrep -v inet6 | awk '{ print $2; }'`
set lip = `echo $ip | awk -F . '{ print $4; }'`

echo -n "ifconfig_$ifc=" >> /mnt/etc/rc.conf
echo '"DHCP"' >> /mnt/etc/rc.conf
cat >> /mnt/etc/rc.conf << EOF
sshd_enable="YES"
dntpd_enable="YES"
hostname="test$lip.MYDOMAIN.XXX"
dumpdev="/dev/${disk}s1b"
EOF

# Misc sysctls
#
cat >> /mnt/etc/sysctl.conf << EOF
#net.inet.ip.portrange.first=4000
EOF

# adjust work directory for pkgsrc in case we want
# to mount /usr/pkgsrc read-only.
#
cat >> /mnt/usr/pkg/etc/mk.conf << EOF
.ifdef BSD_PKG_MK       # begin pkgsrc settings
WRKOBJDIR=		/usr/obj/pkgsrc
.endif                  # end pkgsrc settings
EOF

# Allow sshd root logins via dsa key only
#
fgrep 'PermitRootLogin without-password' /mnt/etc/ssh/sshd_config >& /dev/null
if ( $?status ) then
    echo "PermitRootLogin without-password" >> /mnt/etc/ssh/sshd_config
endif

# additional loader.conf stuff
#cat >> /mnt/boot/loader.conf << EOF
#if_nfe_load="YES"
#EOF

# Get sshd working - auto install my key so I can login.
#
#mkdir -p /mnt/root/.ssh
#cat > /mnt/root/.ssh/authorized_keys << EOF
#ssh-dss ...
#EOF

if ( ! -f /mnt/etc/ssh/ssh_host_dsa_key ) then
    cd /mnt/etc/ssh
    ssh-keygen -t dsa -f ssh_host_dsa_key -N ""
endif

# take CD out and reboot
# 
