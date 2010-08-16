#!/bin/sh

#
# Copyright (c) 2008 Peter Holm <pho@FreeBSD.org>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#
# $FreeBSD$
#

[ `id -u ` -ne 0 ] && echo "Must be root!" && exit 1

[ ! -d /mnt2 ] && mkdir /mnt2
mount | grep "/dev/md0 on /mnt2" > /dev/null && umount /mnt2
mdconfig -l | grep md0 > /dev/null &&  mdconfig -d -u 0
rm -f /tmp/.snap/pho
trap "rm -f /tmp/.snap/pho" 0

for i in `jot 64`; do
   date '+%T'
   mksnap_ffs /tmp /tmp/.snap/pho
   mdconfig -a -t vnode -f /tmp/.snap/pho -u 0 -o readonly
   mount -o ro /dev/md0 /mnt2

   ls -l /mnt2 > /dev/null
   r=`head -c4 /dev/urandom | od -N2 -tu4 | sed -ne '1s/  *$//;1s/.* //p'`
   sleep $(( r % 120 ))

   umount /mnt2
   mdconfig -d -u 0
   rm -f /tmp/.snap/pho
done
