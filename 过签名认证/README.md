修改 `services.jar` 文件，使其不检查APK的签名信息。需要 TTL/SSH 连接设备

## 设备

- **设备**: KindleX 咪咕
- **系统版本**: Fire OS 5.7.2.8 (660655320)
- **Android版本**: 5.1.1

## 分析

在使用 `adb install -r apk` 安装APK时，会检查APK的签名信息，如果签名信息不匹配，则安装失败。
测试安装未签名的APK `adb install -r apk.apk`，用 `adb logcat` 抓取日志：

```bash
D/AndroidRuntime( 2440): >>>>>> START com.android.internal.os.RuntimeInit uid 2000 <<<<<<
D/AndroidRuntime( 2440): CheckJNI is OFF
E/AndroidRuntime( 2440): dexopt flags broken, ignoring value of m=y in dalvik.vm.dexopt-flags
I/art     ( 2440): Skinny Heap Starting Size = 2048KB
I/art     ( 2440): Skinny Heap Growth Limit = 20480KB
I/art     ( 2440): Skinny Heap Min Free = 128KB
I/art     ( 2440): Skinny Heap Max Free = 512KB
I/art     ( 2440): Skinny Heap Target Utilization = 0.95
E/memtrack( 2440): Couldn't load memtrack module (No such file or directory)
E/android.os.Debug( 2440): failed to load memtrack module: -2
E/ANDR-PERF-JNI( 2440): Couldn't load perfboost module (No such file or directory)
D/AndroidRuntime( 2440): Calling main entry com.android.commands.pm.Pm
E/cutils-trace( 2440): Error opening trace file: No such file or directory (2)
I/ProcessStatsService(  471): Prepared write state in 2ms
V/StorageManager( 2398): Full Threshold Bytes=209715200
D/DefContainer( 2398): Copying /data/local/tmp/apk.apk to base.apk
I/art     (  471): Background sticky concurrent mark sweep GC freed 211735(4MB) AllocSpace objects, 10(545KB) LOS objects, 25% free, 13MB/17MB, paused 2.071ms total 395.138ms
W/PackageManager(  471): Failed collect during installPackageLI
W/PackageManager(  471): android.content.pm.PackageParser$PackageParserException: Failed reading resources.arsc in java.util.jar.StrictJarFile@1c7b3825
W/PackageManager(  471):        at android.content.pm.PackageParser.loadCertificates(PackageParser.java:631)
W/PackageManager(  471):        at android.content.pm.PackageParser.collectCertificates(PackageParser.java:1146)
W/PackageManager(  471):        at android.content.pm.PackageParser.collectCertificates(PackageParser.java:1101)
W/PackageManager(  471):        at com.android.server.pm.PackageManagerService.installPackageLI(PackageManagerService.java:11414)
W/PackageManager(  471):        at com.android.server.pm.PackageManagerService.access$2300(PackageManagerService.java:261)
W/PackageManager(  471):        at com.android.server.pm.PackageManagerService$6.run(PackageManagerService.java:9364)
W/PackageManager(  471):        at android.os.Handler.handleCallback(Handler.java:739)
W/PackageManager(  471):        at android.os.Handler.dispatchMessage(Handler.java:95)
W/PackageManager(  471):        at android.os.Looper.loop(Looper.java:135)
W/PackageManager(  471):        at android.os.HandlerThread.run(HandlerThread.java:61)
W/PackageManager(  471):        at com.android.server.ServiceThread.run(ServiceThread.java:46)
W/PackageManager(  471): Caused by: java.lang.SecurityException: META-INF/MANIFEST.MF has invalid digest for resources.arsc in resources.arsc
W/PackageManager(  471):        at java.util.jar.JarVerifier.invalidDigest(JarVerifier.java:140)
W/PackageManager(  471):        at java.util.jar.JarVerifier.access$000(JarVerifier.java:51)
W/PackageManager(  471):        at java.util.jar.JarVerifier$VerifierEntry.verify(JarVerifier.java:132)
W/PackageManager(  471):        at java.util.jar.JarFile$JarFileInputStream.read(JarFile.java:117)
W/PackageManager(  471):        at android.content.pm.PackageParser.readFullyIgnoringContents(PackageParser.java:5231)
W/PackageManager(  471):        at android.content.pm.PackageParser.loadCertificates(PackageParser.java:628)
W/PackageManager(  471):        ... 10 more
I/art     (  471): Explicit concurrent mark sweep GC freed 356168(7MB) AllocSpace objects, 2(130KB) LOS objects, 19% free, 13MB/17MB, paused 2.364ms total 4.085s
I/art     ( 2440): System.exit called, status: 1
I/AndroidRuntime( 2440): VM exiting with result code 1.
I/art     (  471): Background sticky concurrent mark sweep GC freed 240521(4MB) AllocSpace objects, 0(0B) LOS objects, 28% free, 12MB/17MB, paused 1.728ms total 112.750ms
I/art     (  471): Background sticky concurrent mark sweep GC freed 239156(4MB) AllocSpace objects, 0(0B) LOS objects, 28% free, 12MB/17MB, paused 1.732ms total 104.660ms
I/Vlog    (  102): logd:performance:fgtracking=false;DV;1,key=TotalMessages;DV;1,Counter=71;CT;1,unit=count;DV;1:HI
I/Vlog    (  102): logd:performance:fgtracking=false;DV;1,key=DroppedMessages;DV;1,Counter=0;CT;1,unit=count;DV;1:HI
I/Vlog    (  102): logd:performance:fgtracking=false;DV;1,key=Throughput;DV;1,Counter=1.13;CT;1,unit=kbps;DV;1:HI
I/art     (  471): Background sticky concurrent mark sweep GC freed 239534(4MB) AllocSpace objects, 0(0B) LOS objects, 28% free, 12MB/17MB, paused 1.730ms total 100.499ms
```

可以看出`com.android.server.pm.PackageManagerService`类的`installPackageLI`方法是安装包的主要入口函数，负责处理安装过程。如果能够反编译修改使其不检查APK的签名信息，那么就可以安装未签名的APK。

`com.android.server.pm.PackageManagerService` 类 一般放在 `/system/framework/services.jar` 中

## 过程

1. 先把 `services.jar` 文件pull到电脑上
```bash
adb pull /system/framework/services.jar
```

2. 用MT管理器反编译 `services.jar` 文件，找到 `com.android.server.pm.PackageManagerService` 类, 需要修改`compareSignatures`与`verifySignaturesLP`方法, 修改后如下. 其实就是直接清空两个方法的代码.
```java
static int compareSignatures(Signature[] s1, Signature[] s2) {
        // TODO: 修改签名比较逻辑
        // if (s1 == null) {
        //     if (s2 == null) {
        //         return 1;
        //     }
        //     return DEX_OPT_FAILED;
        // }
        // if (s2 == null) {
        //     return -2;
        // }
        // if (s1.length != s2.length) {
        //     return -3;
        // }
        // if (s1.length == 1) {
        //     if (s1[DEX_OPT_SKIPPED].equals(s2[DEX_OPT_SKIPPED])) {
        //         return DEX_OPT_SKIPPED;
        //     }
        //     return -3;
        // }
        // ArraySet<Signature> set1 = new ArraySet<>();
        // int len$ = s1.length;
        // for (int i$ = DEX_OPT_SKIPPED; i$ < len$; i$++) {
        //     Signature sig = s1[i$];
        //     set1.add(sig);
        // }
        // ArraySet<Signature> set2 = new ArraySet<>();
        // int len$2 = s2.length;
        // for (int i$2 = DEX_OPT_SKIPPED; i$2 < len$2; i$2++) {
        //     Signature sig2 = s2[i$2];
        //     set2.add(sig2);
        // }
        // if (set1.equals(set2)) {
        //     return DEX_OPT_SKIPPED;
        // }
        // return -3;
        // 直接返回DEX_OPT_SKIPPED表示签名匹配
        return DEX_OPT_SKIPPED;
    }
```

```java
private void verifySignaturesLP(PackageSetting pkgSetting, PackageParser.Package pkg) throws PackageManagerException {
        // TODO: 修改签名比较逻辑
        // if (pkgSetting.signatures.mSignatures != null) {
        //     boolean match = compareSignatures(pkgSetting.signatures.mSignatures, pkg.mSignatures) == 0 ? true : DEX_OPT_SKIPPED;
        //     if (!match) {
        //         match = compareSignaturesCompat(pkgSetting.signatures, pkg) == 0 ? true : DEX_OPT_SKIPPED;
        //     }
        //     if (!match) {
        //         match = compareSignaturesRecover(pkgSetting.signatures, pkg) == 0 ? true : DEX_OPT_SKIPPED;
        //     }
        //     if (!match && (match = PackageHelper.checkMatchingSignature(PackageHelper.readCertificateAsSignature("/system/vendor/data/amz.rsa"), pkg.mSignatures))) {
        //         Slog.w(TAG, "Package sign doesn't match it's original signature, but new pkg sign is signed by Amazon, so letting it pass");
        //     }
        //     if (!match) {
        //         throw new PackageManagerException(-7, "Package " + pkg.packageName + " signatures do not match the previously installed version; ignoring!");
        //     }
        // }
        // if (pkgSetting.sharedUser != null && pkgSetting.sharedUser.signatures.mSignatures != null) {
        //     boolean match2 = compareSignatures(pkgSetting.sharedUser.signatures.mSignatures, pkg.mSignatures) == 0 ? true : DEX_OPT_SKIPPED;
        //     if (!match2) {
        //         match2 = compareSignaturesCompat(pkgSetting.sharedUser.signatures, pkg) == 0 ? true : DEX_OPT_SKIPPED;
        //     }
        //     if (!match2) {
        //         match2 = compareSignaturesRecover(pkgSetting.sharedUser.signatures, pkg) == 0 ? true : DEX_OPT_SKIPPED;
        //     }
        //     if (!match2) {
        //         throw new PackageManagerException(-8, "Package " + pkg.packageName + " has no signatures that match those in shared user " + pkgSetting.sharedUser.name + "; ignoring!");
        //     }
        // }
        // 直接返回表示签名验证通过
        return;
    }
```

3. 把修改后的 `services.jar` 文件push到设备上
```bash
adb push services.jar "/sdcard/MT2/services.jar.修改版"
```

4. 覆盖原文件
```bash
root@eanab:/system/framework # cp "/system/framework/services.jar" "/sdcard/MT2/services.jar.原版"
root@eanab:/system/framework # cp "/sdcard/MT2/services.jar.修改版" "/system/framework/services.jar"
root@eanab:/system/framework # chmod 644 "/system/framework/services.jar"
root@eanab:/system/framework # ls -l "/system/framework/services.jar"
__bionic_open_tzdata_path: ANDROID_ROOT not set!
__bionic_open_tzdata_path: ANDROID_ROOT not set!
__bionic_open_tzdata_path: ANDROID_ROOT not set!
-rw-r--r-- root     root      2090182 2025-02-21 08:31 services.jar
```

5. 重启设备

## 测试

安装不同签名的APK
```bash
adb install -r apk.apk
```

## 还原

```bash
root@eanab:/system/framework # cp "/sdcard/MT2/services.jar.原版" "/system/framework/services.jar"
root@eanab:/system/framework # chmod 644 "/system/framework/services.jar"
root@eanab:/system/framework # ls -l "/system/framework/services.jar"
__bionic_open_tzdata_path: ANDROID_ROOT not set!
__bionic_open_tzdata_path: ANDROID_ROOT not set!
__bionic_open_tzdata_path: ANDROID_ROOT not set!
-rw-r--r-- root     root      2090182 2025-02-21 08:31 services.jar
```
重启设备
