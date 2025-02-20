### 安装SSH(dropbear)

mount -o remount,rw /system

adb push ssh /sdcard/ssh/

cp /sdcard/ssh/dropbear /system/xbin/dropbear
cp /sdcard/ssh/dropbearkey /system/xbin/dropbearkey
cp /sdcard/ssh/scp /system/xbin/scp
cp /sdcard/ssh/ssh /system/xbin/ssh

chmod 755 /system/xbin/dropbear
chmod 755 /system/xbin/dropbearkey
chmod 755 /system/xbin/scp
chmod 755 /system/xbin/ssh

mkdir -p /data/dropbear/.ssh 
chmod 644 /data/dropbear
chmod 644 /data/dropbear/.ssh
#生成密钥
dropbearkey -t rsa -f /data/dropbear/dropbear_rsa_host_key
#生成密钥
dropbearkey -t dss -f /data/dropbear/dropbear_dss_host_key
#建立用的环境变量
echo >> /data/dropbear/.profile  "PATH=/sbin:/vendor/bin:/system/sbin:/system/bin:/system/xbin"
#建立用的环境变量
echo >>/data/dropbear/.profile "export PATH" 
#做目录快捷方式
ln -s /data/dropbear /etc/dropbear

dropbear -V

# 公钥
cp /sdcard/ssh/keys/authorized_keys /data/dropbear/.ssh/authorized_keys
chmod 600 /data/dropbear/.ssh/authorized_keys

cp /system/bin/set_time.sh /system/bin/set_time.sh.bak 
vi /system/bin/set_time.sh
# 添加： /system/xbin/dropbear -v


mount -o remount,ro /system


