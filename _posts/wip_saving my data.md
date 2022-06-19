https://linuxconfig.org/howto-mount-usb-drive-in-linux
https://www.howtogeek.com/427480/how-to-back-up-your-linux-system/
https://stackoverflow.com/questions/33573028/chown-and-chmod-doesnt-work-raspberry-pi-2-jessie
https://wiki.archlinux.org/title/Rsync#Full_system_backup
https://askubuntu.com/questions/11840/how-do-i-use-chmod-on-an-ntfs-or-fat32-partition/956072#956072
https://www.youtube.com/watch?v=S0KZ5iXTkzg

```
proc            /proc           proc    defaults          0       0
PARTUUID=2486a029-01  /boot           vfat    defaults          0       2
PARTUUID=2486a029-02  /               ext4    defaults,noatime  0       1
# a swapfile is not a swap partition, no line here
#   use  dphys-swapfile swap[on|off]  for that
UUID=0540DB5E5B162C36 /mnt/backup_usb ntfs defaults,auto,users,rw,nofail,umask=000 0 0
UUID-A690548690545EBD /mnt/backup_hdd ntfs defaults,auto,users,rw,nofail,umask=000 0 0
```

```
proc            /proc           proc    defaults          0       0
PARTUUID=2486a029-01  /boot           vfat    defaults          0       2
PARTUUID=2486a029-02  /               ext4    defaults,noatime  0       1
# a swapfile is not a swap partition, no line here
#   use  dphys-swapfile swap[on|off]  for that
UUID=0540DB5E5B162C36 /mnt/backup_usb ntfs defaults,auto,users,permissionsrw,nofail,umask=000 0 0
UUID=A690548690545EBD /mnt/backup_hdd ntfs defaults,auto,users,permissions,uid=1000,rw,nofail,umask=000 0 0
```

lsblk
lsblk -o name,uuid
6CB26DC7B26D95FC
UUID=6CB26DC7B26D95FC /mnt/backup_hdd_2 ntfs defaults,auto,users,permissions, uid=1000,rw,nofail,umask=000 0 0
sudo mkdir /mnt/backup_hdd_2
sudo chown pi:pi /mnt/backup_hdd_2

groupadd sftp_users
useradd -g sftp_users -d /home/sftp_user -s /sbin/nologin sftp_user
passwd sftp_user
mkdir /mnt/backup_hdd_2/backups
chown -R sftp_user:sftp_users /mnt/backup_hdd_2/backups

nano /etc/ssh/sshd_config

```plaintext
Match Group sftp_users
ChrootDirectory /mnt/backup_hdd_2/backups
ForceCommand internal-sftp
```

systemctl restart sshd




sudo mkdir /mnt/backup_hdd_2/sftp
sudo mkdir /mnt/backup_hdd_2/sftp/sftp_user
sudo chown root:sftp_users /mnt/backup_hdd_2/sftp
sudo chown sftp_user:sftp_users /mnt/backup_hdd_2/sftp/sftp_user

nano /etc/ssh/sshd_config

```plaintext
Match Group sftp_users
ChrootDirectory /mnt/backup_hdd_2/sftp/%u
ForceCommand internal-sftp
```

systemctl restart sshd

https://freefilesync.org/
