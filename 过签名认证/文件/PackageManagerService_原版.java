//
// Decompiled by Jadx - 5595ms
//
package com.android.server.pm;

import android.app.ActivityManager;
import android.app.ActivityManagerNative;
import android.app.AppGlobals;
import android.app.IActivityManager;
import android.app.IApplicationThread;
import android.app.PendingIntent;
import android.app.admin.IDevicePolicyManager;
import android.app.usage.UsageStats;
import android.app.usage.UsageStatsManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.IIntentReceiver;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.IntentSender;
import android.content.ServiceConnection;
import android.content.pm.ActivityInfo;
import android.content.pm.ApplicationInfo;
import android.content.pm.FeatureInfo;
import android.content.pm.IPackageDataObserver;
import android.content.pm.IPackageDeleteObserver;
import android.content.pm.IPackageDeleteObserver2;
import android.content.pm.IPackageInstallObserver2;
import android.content.pm.IPackageInstaller;
import android.content.pm.IPackageManager;
import android.content.pm.IPackageMoveObserver;
import android.content.pm.IPackageStatsObserver;
import android.content.pm.InstrumentationInfo;
import android.content.pm.KeySet;
import android.content.pm.ManifestDigest;
import android.content.pm.PackageCleanItem;
import android.content.pm.PackageInfo;
import android.content.pm.PackageInfoLite;
import android.content.pm.PackageInstaller;
import android.content.pm.PackageManager;
import android.content.pm.PackageParser;
import android.content.pm.PackageStats;
import android.content.pm.PackageUserState;
import android.content.pm.ParceledListSlice;
import android.content.pm.PermissionGroupInfo;
import android.content.pm.PermissionInfo;
import android.content.pm.ProviderInfo;
import android.content.pm.ResolveInfo;
import android.content.pm.ServiceInfo;
import android.content.pm.Signature;
import android.content.pm.UserInfo;
import android.content.pm.VerificationParams;
import android.content.pm.VerifierDeviceIdentity;
import android.content.pm.VerifierInfo;
import android.content.res.Resources;
import android.hardware.display.DisplayManager;
import android.net.Uri;
import android.os.Binder;
import android.os.Build;
import android.os.Bundle;
import android.os.Debug;
import android.os.Environment;
import android.os.FileUtils;
import android.os.IBinder;
import android.os.Message;
import android.os.Parcel;
import android.os.Process;
import android.os.RemoteException;
import android.os.ServiceManager;
import android.os.SystemClock;
import android.os.SystemProperties;
import android.os.UserHandle;
import android.os.storage.IMountService;
import android.os.storage.StorageManager;
import android.provider.Settings;
import android.security.KeyStore;
import android.security.SystemKeyStore;
import android.system.ErrnoException;
import android.system.Os;
import android.system.StructStat;
import android.text.TextUtils;
import android.util.ArrayMap;
import android.util.ArraySet;
import android.util.DisplayMetrics;
import android.util.EventLog;
import android.util.Log;
import android.util.LogPrinter;
import android.util.Slog;
import android.util.SparseArray;
import android.util.SparseBooleanArray;
import com.android.internal.FireOSInit;
import com.android.internal.app.IMediaContainerService;
import com.android.internal.app.IntentForwarderActivity;
import com.android.internal.app.ResolverActivity;
import com.android.internal.content.NativeLibraryHelper;
import com.android.internal.content.PackageHelper;
import com.android.internal.util.ArrayUtils;
import com.android.internal.util.FastPrintWriter;
import com.android.internal.util.FastXmlSerializer;
import com.android.internal.util.IndentingPrintWriter;
import com.android.server.EventLogTags;
import com.android.server.LocalServices;
import com.android.server.ServiceThread;
import com.android.server.SystemConfig;
import com.android.server.Watchdog;
import com.android.server.am.ActivityManagerService;
import com.android.server.storage.DeviceStorageMonitorInternal;
import dalvik.system.DexFile;
import dalvik.system.StaleDexCacheError;
import dalvik.system.VMRuntime;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileDescriptor;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FilenameFilter;
import java.io.IOException;
import java.io.PrintWriter;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import libcore.io.IoUtils;
import libcore.util.EmptyArray;

public class PackageManagerService extends IPackageManager.Stub {
    private static final String AMAZON_EXTRA_RESOURCE_LIST_ENVIRONMENT_VARIABLE = "AMAZON_EXTRA_RESOURCE_LIST";
    private static final int BLUETOOTH_UID = 1002;
    static final int BROADCAST_DELAY = 10000;
    static final int CHECK_PENDING_VERIFICATION = 16;
    private static final boolean DEBUG_ABI_SELECTION = true;
    private static final boolean DEBUG_BROADCASTS = false;
    private static final boolean DEBUG_DEXOPT = false;
    private static final boolean DEBUG_FILTERS = false;
    private static final boolean DEBUG_INSTALL = false;
    private static final boolean DEBUG_INTENT_MATCHING = false;
    private static final boolean DEBUG_PACKAGE_INFO = false;
    private static final boolean DEBUG_PACKAGE_SCANNING = false;
    static final boolean DEBUG_PREFERRED = false;
    private static final boolean DEBUG_REMOVE = false;
    static final boolean DEBUG_SD_INSTALL = false;
    static final boolean DEBUG_SETTINGS = false;
    private static final boolean DEBUG_SHOW_INFO = false;
    static final boolean DEBUG_UPGRADE = false;
    private static final boolean DEBUG_VERIFY = false;
    private static final long DEFAULT_MANDATORY_FSTRIM_INTERVAL = 0x0f731400;
    private static final int DEFAULT_VERIFICATION_RESPONSE = 1;
    private static final long DEFAULT_VERIFICATION_TIMEOUT = 10000;
    private static final boolean DEFAULT_VERIFY_ENABLE = true;
    static final int DEX_OPT_DEFERRED = 2;
    static final int DEX_OPT_FAILED = -1;
    static final int DEX_OPT_PERFORMED = 1;
    static final int DEX_OPT_SKIPPED = 0;
    private static final boolean ENABLE_FORCE_AMAZON_APPS_32BIT = false;
    static final int END_COPY = 4;
    static final int FIND_INSTALL_LOC = 8;
    private static final String IDMAP_PREFIX = "/data/resource-cache/";
    private static final String IDMAP_SUFFIX = "@idmap";
    static final int INIT_COPY = 5;
    private static final String INSTALL_PACKAGE_SUFFIX = "-";
    private static final int LOG_UID = 1007;
    private static final int MAX_PERMISSION_TREE_FOOTPRINT = 32768;
    static final int MCS_BOUND = 3;
    static final int MCS_GIVE_UP = 11;
    static final int MCS_RECONNECT = 10;
    static final int MCS_UNBIND = 6;
    private static final int NFC_UID = 1027;
    private static final String PACKAGE_MIME_TYPE = "application/vnd.android.package-archive";
    static final int PACKAGE_VERIFIED = 15;
    static final int POST_INSTALL = 9;
    private static final int RADIO_UID = 1001;
    static final int REMOVE_CHATTY = 65536;
    static final int SCAN_BOOTING = 256;
    static final int SCAN_DEFER_DEX = 128;
    static final int SCAN_DELETE_DATA_ON_FAILURES = 1024;
    static final int SCAN_FORCE_DEX = 4;
    static final int SCAN_NEW_INSTALL = 16;
    static final int SCAN_NO_DEX = 2;
    static final int SCAN_NO_PATHS = 32;
    static final int SCAN_REPLACING = 2048;
    static final int SCAN_REQUIRE_KNOWN = 4096;
    static final int SCAN_TRUSTED_OVERLAY = 512;
    static final int SCAN_UPDATE_SIGNATURE = 8;
    static final int SCAN_UPDATE_TIME = 64;
    private static final String SD_ENCRYPTION_ALGORITHM = "AES";
    private static final String SD_ENCRYPTION_KEYSTORE_NAME = "AppsOnSD";
    static final int SEND_PENDING_BROADCAST = 1;
    private static final int SHELL_UID = 2000;
    static final int START_CLEANING_PACKAGE = 7;
    static final String TAG = "PackageManager";
    private static final int UID_NET_ADMIN = 3005;
    private static final int UID_NET_RAW = 3004;
    static final int UPDATED_MEDIA_STATUS = 12;
    static final int UPDATE_PERMISSIONS_ALL = 1;
    static final int UPDATE_PERMISSIONS_REPLACE_ALL = 4;
    static final int UPDATE_PERMISSIONS_REPLACE_PKG = 2;
    private static final String VENDOR_OVERLAY_DIR = "/vendor/overlay";
    private static final long WATCHDOG_TIMEOUT = 900000;
    static final int WRITE_PACKAGE_RESTRICTIONS = 14;
    static final int WRITE_SETTINGS = 13;
    static final int WRITE_SETTINGS_DELAY = 10000;
    private static String sPreferredInstructionSet;
    static UserManagerService sUserManager;
    ApplicationInfo mAndroidApplication;
    final File mAppDataDir;
    final File mAppInstallDir;
    private File mAppLib32InstallDir;
    final String mAsecInternalPath;
    final ArrayMap<String, FeatureInfo> mAvailableFeatures;
    final Context mContext;
    ComponentName mCustomResolverComponentName;
    final int mDefParseFlags;
    final long mDexOptLRUThresholdInMills;
    final File mDrmAppPrivateInstallDir;
    final boolean mFactoryTest;
    boolean mFoundPolicyFile;
    final int[] mGlobalGids;
    final PackageHandler mHandler;
    final ServiceThread mHandlerThread;
    volatile boolean mHasSystemUidErrors;
    final Installer mInstaller;
    final PackageInstallerService mInstallerService;
    final boolean mIsUpgrade;
    final boolean mLazyDexOpt;
    final DisplayMetrics mMetrics;
    final boolean mOnlyCore;
    PackageParser.Package mPlatformPackage;
    private ArrayList<Message> mPostSystemReadyMessages;
    private final String mRequiredVerifierPackage;
    ComponentName mResolveComponentName;
    boolean mRestoredSettings;
    volatile boolean mSafeMode;
    final String[] mSeparateProcesses;
    final Settings mSettings;
    final SparseArray<ArraySet<String>> mSystemPermissions;
    volatile boolean mSystemReady;
    final File mUserAppDataDir;
    static final String DEFAULT_CONTAINER_PACKAGE = "com.android.defcontainer";
    static final ComponentName DEFAULT_CONTAINER_COMPONENT = new ComponentName(DEFAULT_CONTAINER_PACKAGE, "com.android.defcontainer.DefaultContainerService");
    private static final Comparator<ResolveInfo> mResolvePrioritySorter = new PackageManagerService$4();
    private static final Comparator<ProviderInfo> mProviderInitOrderSorter = new PackageManagerService$5();
    final int mSdkVersion = Build.VERSION.SDK_INT;
    final Object mInstallLock = new Object();
    final ArrayMap<String, PackageParser.Package> mPackages = new ArrayMap<>();
    final ArrayMap<String, ArrayMap<String, PackageParser.Package>> mOverlays = new ArrayMap<>();
    private boolean mShouldRestoreconData = SELinuxMMAC.shouldRestorecon();
    final ArrayMap<String, SharedLibraryEntry> mSharedLibraries = new ArrayMap<>();
    final ActivityIntentResolver mActivities = new ActivityIntentResolver(this);
    final ActivityIntentResolver mReceivers = new ActivityIntentResolver(this);
    final ServiceIntentResolver mServices = new ServiceIntentResolver(this);
    final ProviderIntentResolver mProviders = new ProviderIntentResolver(this, (PackageManagerService$1) null);
    final ArrayMap<String, PackageParser.Provider> mProvidersByAuthority = new ArrayMap<>();
    final ArrayMap<ComponentName, PackageParser.Instrumentation> mInstrumentation = new ArrayMap<>();
    final ArrayMap<String, PackageParser.PermissionGroup> mPermissionGroups = new ArrayMap<>();
    final ArraySet<String> mTransferedPackages = new ArraySet<>();
    final ArraySet<String> mProtectedBroadcasts = new ArraySet<>();
    final SparseArray<PackageVerificationState> mPendingVerification = new SparseArray<>();
    final ArrayMap<String, ArraySet<String>> mAppOpPermissionPackages = new ArrayMap<>();
    ArraySet<PackageParser.Package> mDeferredDexOpt = null;
    SparseBooleanArray mUserNeedsBadging = new SparseBooleanArray();
    private int mPendingVerificationToken = DEX_OPT_SKIPPED;
    final ActivityInfo mResolveActivity = new ActivityInfo();
    final ResolveInfo mResolveInfo = new ResolveInfo();
    boolean mResolverReplaced = false;
    final PendingPackageBroadcasts mPendingBroadcasts = new PendingPackageBroadcasts();
    private IMediaContainerService mContainerService = null;
    private VendorPackageManagerCallback[] mVendorCallbacks = VendorPackageManagerCallback.findCallbacks();
    private ArraySet<Integer> mDirtyUsers = new ArraySet<>();
    private final DefaultContainerConnection mDefContainerConn = new DefaultContainerConnection(this);
    final SparseArray<PostInstallData> mRunningInstalls = new SparseArray<>();
    int mNextInstallToken = 1;
    private final PackageUsage mPackageUsage = new PackageUsage(this, (PackageManagerService$1) null);
    private boolean mMediaMounted = false;

    static int access$3008(PackageManagerService x0) {
        int i = x0.mPendingVerificationToken;
        x0.mPendingVerificationToken = i + 1;
        return i;
    }

    Bundle extrasForInstallResult(PackageInstalledInfo res) {
        switch (res.returnCode) {
            case -112:
                Bundle extras = new Bundle();
                extras.putString("android.content.pm.extra.FAILURE_EXISTING_PERMISSION", res.origPermission);
                extras.putString("android.content.pm.extra.FAILURE_EXISTING_PACKAGE", res.origPackage);
                return extras;
            default:
                return null;
        }
    }

    void scheduleWriteSettingsLocked() {
        if (!this.mHandler.hasMessages(WRITE_SETTINGS)) {
            this.mHandler.sendEmptyMessageDelayed(WRITE_SETTINGS, DEFAULT_VERIFICATION_TIMEOUT);
        }
    }

    void scheduleWritePackageRestrictionsLocked(int userId) {
        if (sUserManager.exists(userId)) {
            this.mDirtyUsers.add(Integer.valueOf(userId));
            if (!this.mHandler.hasMessages(WRITE_PACKAGE_RESTRICTIONS)) {
                this.mHandler.sendEmptyMessageDelayed(WRITE_PACKAGE_RESTRICTIONS, DEFAULT_VERIFICATION_TIMEOUT);
            }
        }
    }

    /* JADX WARN: Type inference failed for: r0v0, types: [com.android.server.pm.PackageManagerService, android.os.IBinder] */
    public static final PackageManagerService main(Context context, Installer installer, boolean factoryTest, boolean onlyCore) {
        ?? packageManagerService = new PackageManagerService(context, installer, factoryTest, onlyCore);
        ServiceManager.addService("package", (IBinder) packageManagerService);
        return packageManagerService;
    }

    static String[] splitString(String str, char sep) {
        int count = 1;
        int i = DEX_OPT_SKIPPED;
        while (true) {
            int i2 = str.indexOf(sep, i);
            if (i2 < 0) {
                break;
            }
            count++;
            i = i2 + 1;
        }
        String[] res = new String[count];
        int i3 = DEX_OPT_SKIPPED;
        int count2 = DEX_OPT_SKIPPED;
        int lastI = DEX_OPT_SKIPPED;
        while (true) {
            int i4 = str.indexOf(sep, i3);
            if (i4 >= 0) {
                res[count2] = str.substring(lastI, i4);
                count2++;
                i3 = i4 + 1;
                lastI = i3;
            } else {
                res[count2] = str.substring(lastI, str.length());
                return res;
            }
        }
    }

    private static void getDefaultDisplayMetrics(Context context, DisplayMetrics metrics) {
        DisplayManager displayManager = (DisplayManager) context.getSystemService("display");
        displayManager.getDisplay(DEX_OPT_SKIPPED).getMetrics(metrics);
    }

    public PackageManagerService(Context context, Installer installer, boolean factoryTest, boolean onlyCore) {
        long dexOptLRUThresholdInMinutes;
        int reparseFlags;
        String msg;
        EventLog.writeEvent(3060, SystemClock.uptimeMillis());
        if (this.mSdkVersion <= 0) {
            Slog.w(TAG, "**** ro.build.version.sdk not set!");
        }
        this.mContext = context;
        this.mFactoryTest = factoryTest;
        this.mOnlyCore = onlyCore;
        this.mLazyDexOpt = "eng".equals(SystemProperties.get("ro.build.type"));
        this.mMetrics = new DisplayMetrics();
        this.mSettings = new Settings(context);
        this.mSettings.addSharedUserLPw("android.uid.system", 1000, 0x40000001);
        this.mSettings.addSharedUserLPw("android.uid.phone", RADIO_UID, 0x40000001, new int[]{UID_NET_RAW, UID_NET_ADMIN});
        this.mSettings.addSharedUserLPw("android.uid.log", LOG_UID, 0x40000001);
        this.mSettings.addSharedUserLPw("android.uid.nfc", NFC_UID, 0x40000001);
        this.mSettings.addSharedUserLPw("android.uid.bluetooth", BLUETOOTH_UID, 0x40000001, new int[]{BLUETOOTH_UID, RADIO_UID});
        this.mSettings.addSharedUserLPw("android.uid.shell", SHELL_UID, 0x40000001);
        if (this.mLazyDexOpt) {
            dexOptLRUThresholdInMinutes = 30;
        } else {
            dexOptLRUThresholdInMinutes = 10080;
        }
        this.mDexOptLRUThresholdInMills = 60 * dexOptLRUThresholdInMinutes * 1000;
        this.mSettings.setAmzSignature(PackageHelper.readCertificateAsSignature("/system/vendor/data/amz.rsa"));
        if (new File("/system/vendor/data/tl1.rsa").exists()) {
            this.mSettings.setTrustLevel1Signature(PackageHelper.readCertificateAsSignature("/system/vendor/data/tl1.rsa"));
        }
        VendorPackageManagerCallback.callOnInit(this.mVendorCallbacks, DEX_OPT_SKIPPED, this, (ArrayMap) null);
        File ttpCertsDir = new File("/system/vendor/data/ttp/");
        if (ttpCertsDir.exists() && ttpCertsDir.isDirectory()) {
            File[] arr$ = ttpCertsDir.listFiles();
            int len$ = arr$.length;
            for (int i$ = DEX_OPT_SKIPPED; i$ < len$; i$++) {
                File cert = arr$[i$];
                this.mSettings.addTrustedThirdPartySignature(PackageHelper.readCertificateAsSignature(cert.getAbsolutePath()));
            }
        }
        String separateProcesses = SystemProperties.get("debug.separate_processes");
        if (separateProcesses != null && separateProcesses.length() > 0) {
            if ("*".equals(separateProcesses)) {
                this.mDefParseFlags = 8;
                this.mSeparateProcesses = null;
                Slog.w(TAG, "Running with debug.separate_processes: * (ALL)");
            } else {
                this.mDefParseFlags = DEX_OPT_SKIPPED;
                this.mSeparateProcesses = separateProcesses.split(",");
                Slog.w(TAG, "Running with debug.separate_processes: " + separateProcesses);
            }
        } else {
            this.mDefParseFlags = DEX_OPT_SKIPPED;
            this.mSeparateProcesses = null;
        }
        this.mInstaller = installer;
        getDefaultDisplayMetrics(context, this.mMetrics);
        SystemConfig systemConfig = SystemConfig.getInstance();
        this.mGlobalGids = systemConfig.getGlobalGids();
        this.mSystemPermissions = systemConfig.getSystemPermissions();
        this.mAvailableFeatures = systemConfig.getAvailableFeatures();
        synchronized (this.mInstallLock) {
            synchronized (this.mPackages) {
                this.mHandlerThread = new ServiceThread(TAG, MCS_RECONNECT, true);
                this.mHandlerThread.start();
                this.mHandler = new PackageHandler(this, this.mHandlerThread.getLooper());
                Watchdog.getInstance().addThread(this.mHandler, WATCHDOG_TIMEOUT);
                File dataDir = Environment.getDataDirectory();
                this.mAppDataDir = new File(dataDir, "data");
                this.mAppInstallDir = new File(dataDir, "app");
                this.mAppLib32InstallDir = new File(dataDir, "app-lib");
                this.mAsecInternalPath = new File(dataDir, "app-asec").getPath();
                this.mUserAppDataDir = new File(dataDir, "user");
                this.mDrmAppPrivateInstallDir = new File(dataDir, "app-private");
                sUserManager = new UserManagerService(context, this, this.mInstallLock, this.mPackages);
                ArrayMap<String, SystemConfig.PermissionEntry> permConfig = systemConfig.getPermissions();
                for (int i = DEX_OPT_SKIPPED; i < permConfig.size(); i++) {
                    SystemConfig.PermissionEntry perm = permConfig.valueAt(i);
                    BasePermission bp = (BasePermission) this.mSettings.mPermissions.get(perm.name);
                    if (bp == null) {
                        bp = new BasePermission(perm.name, "android", 1);
                        this.mSettings.mPermissions.put(perm.name, bp);
                    }
                    if (perm.gids != null) {
                        bp.gids = appendInts(bp.gids, perm.gids);
                    }
                }
                ArrayMap<String, String> libConfig = systemConfig.getSharedLibraries();
                for (int i2 = DEX_OPT_SKIPPED; i2 < libConfig.size(); i2++) {
                    this.mSharedLibraries.put(libConfig.keyAt(i2), new SharedLibraryEntry(libConfig.valueAt(i2), (String) null));
                }
                this.mFoundPolicyFile = SELinuxMMAC.readInstallPolicy();
                this.mRestoredSettings = this.mSettings.readLPw(this, sUserManager.getUsers(false), this.mSdkVersion, this.mOnlyCore);
                String customResolverActivity = Resources.getSystem().getString(0x01040042);
                if (!TextUtils.isEmpty(customResolverActivity)) {
                    this.mCustomResolverComponentName = ComponentName.unflattenFromString(customResolverActivity);
                }
                long startTime = SystemClock.uptimeMillis();
                EventLog.writeEvent(3070, startTime);
                VendorPackageManagerCallback.callOnInit(this.mVendorCallbacks, 100, this, this.mPackages);
                if (isFirstBoot()) {
                    VendorPackageManagerCallback.callOnSystemOTA(this.mVendorCallbacks);
                }
                ArraySet<String> alreadyDexOpted = new ArraySet<>();
                String bootClassPath = System.getenv("BOOTCLASSPATH");
                String systemServerClassPath = System.getenv("SYSTEMSERVERCLASSPATH");
                if (bootClassPath != null) {
                    String[] bootClassPathElements = splitString(bootClassPath, ':');
                    int len$2 = bootClassPathElements.length;
                    for (int i$2 = DEX_OPT_SKIPPED; i$2 < len$2; i$2++) {
                        String element = bootClassPathElements[i$2];
                        alreadyDexOpted.add(element);
                    }
                } else {
                    Slog.w(TAG, "No BOOTCLASSPATH found!");
                }
                if (systemServerClassPath != null) {
                    String[] systemServerClassPathElements = splitString(systemServerClassPath, ':');
                    int len$3 = systemServerClassPathElements.length;
                    for (int i$3 = DEX_OPT_SKIPPED; i$3 < len$3; i$3++) {
                        String element2 = systemServerClassPathElements[i$3];
                        alreadyDexOpted.add(element2);
                    }
                } else {
                    Slog.w(TAG, "No SYSTEMSERVERCLASSPATH found!");
                }
                List<String> allInstructionSets = getAllInstructionSets();
                String[] dexCodeInstructionSets = getDexCodeInstructionSets((String[]) allInstructionSets.toArray(new String[allInstructionSets.size()]));
                if (this.mSharedLibraries.size() > 0) {
                    int len$4 = dexCodeInstructionSets.length;
                    int i$4 = DEX_OPT_SKIPPED;
                    while (true) {
                        int i$5 = i$4;
                        if (i$5 >= len$4) {
                            break;
                        }
                        String dexCodeInstructionSet = dexCodeInstructionSets[i$5];
                        for (SharedLibraryEntry libEntry : this.mSharedLibraries.values()) {
                            String lib = libEntry.path;
                            if (lib != null) {
                                try {
                                    try {
                                        byte dexoptRequired = DexFile.isDexOptNeededInternal(lib, null, dexCodeInstructionSet, false);
                                        if (dexoptRequired != 0) {
                                            alreadyDexOpted.add(lib);
                                            if (dexoptRequired == 2) {
                                                this.mInstaller.dexopt(lib, 1000, true, dexCodeInstructionSet);
                                            } else {
                                                this.mInstaller.patchoat(lib, 1000, true, dexCodeInstructionSet);
                                            }
                                        } else {
                                            this.mInstaller.updatePkgOwner(lib, 1000, dexCodeInstructionSet);
                                        }
                                    } catch (IOException e) {
                                        Slog.w(TAG, "Cannot dexopt " + lib + "; is it an APK or JAR? " + e.getMessage());
                                    }
                                } catch (FileNotFoundException e2) {
                                    Slog.w(TAG, "Library not found: " + lib);
                                }
                            }
                        }
                        i$4 = i$5 + 1;
                    }
                }
                File frameworkDir = new File(Environment.getRootDirectory(), "framework");
                alreadyDexOpted.add(frameworkDir.getPath() + "/framework-res.apk");
                alreadyDexOpted.add(frameworkDir.getPath() + "/core-libart.jar");
                alreadyDexOpted.add("vendor/amazon/framework/android.amazon.res/android.amazon.res.apk");
                String amazonExtraResourceListString = System.getenv(AMAZON_EXTRA_RESOURCE_LIST_ENVIRONMENT_VARIABLE);
                if (amazonExtraResourceListString != null) {
                    Slog.i(TAG, "amazonResourceList: " + amazonExtraResourceListString);
                    String[] resourceListArray = amazonExtraResourceListString.split(":");
                    int len$5 = resourceListArray.length;
                    for (int i$6 = DEX_OPT_SKIPPED; i$6 < len$5; i$6++) {
                        String resPath = resourceListArray[i$6];
                        alreadyDexOpted.add(resPath);
                    }
                }
                String[] frameworkFiles = frameworkDir.list();
                if (frameworkFiles != null) {
                    int len$6 = dexCodeInstructionSets.length;
                    for (int i$7 = DEX_OPT_SKIPPED; i$7 < len$6; i$7++) {
                        String dexCodeInstructionSet2 = dexCodeInstructionSets[i$7];
                        for (int i3 = DEX_OPT_SKIPPED; i3 < frameworkFiles.length; i3++) {
                            File libPath = new File(frameworkDir, frameworkFiles[i3]);
                            String path = libPath.getPath();
                            if (!alreadyDexOpted.contains(path) && (path.endsWith(".apk") || path.endsWith(".jar"))) {
                                try {
                                    byte dexoptRequired2 = DexFile.isDexOptNeededInternal(path, null, dexCodeInstructionSet2, false);
                                    if (dexoptRequired2 == 2) {
                                        this.mInstaller.dexopt(path, 1000, true, dexCodeInstructionSet2);
                                    } else if (dexoptRequired2 == 1) {
                                        this.mInstaller.patchoat(path, 1000, true, dexCodeInstructionSet2);
                                    } else {
                                        this.mInstaller.updatePkgOwner(path, 1000, dexCodeInstructionSet2);
                                    }
                                } catch (FileNotFoundException e3) {
                                    Slog.w(TAG, "Jar not found: " + path);
                                } catch (IOException e4) {
                                    Slog.w(TAG, "Exception reading jar: " + path, e4);
                                }
                            }
                        }
                    }
                }
                File vendorOverlayDir = new File(VENDOR_OVERLAY_DIR);
                scanDirLI(vendorOverlayDir, 65, 928, 0L);
                scanDirLI(frameworkDir, 193, 418, 0L);
                File privilegedAppDir = new File(Environment.getRootDirectory(), "priv-app");
                scanDirLI(privilegedAppDir, 193, 416, 0L);
                File systemAppDir = new File(Environment.getRootDirectory(), "app");
                scanDirLI(systemAppDir, 65, 416, 0L);
                File vendorAppDir = new File("/vendor/app");
                try {
                    vendorAppDir = vendorAppDir.getCanonicalFile();
                } catch (IOException e5) {
                }
                scanDirLI(vendorAppDir, 65, 416, 0L);
                File oemAppDir = new File(Environment.getOemDirectory(), "app");
                scanDirLI(oemAppDir, 65, 416, 0L);
                this.mInstaller.moveFiles();
                List<String> possiblyDeletedUpdatedSystemApps = new ArrayList<>();
                ArrayMap<String, File> expectingBetter = new ArrayMap<>();
                if (!this.mOnlyCore) {
                    Iterator<PackageSetting> psit = this.mSettings.mPackages.values().iterator();
                    while (psit.hasNext()) {
                        PackageSetting ps = psit.next();
                        if ((ps.pkgFlags & 1) != 0) {
                            PackageParser.Package scannedPkg = this.mPackages.get(ps.name);
                            if (scannedPkg != null) {
                                if (this.mSettings.isDisabledSystemPackageLPr(ps.name)) {
                                    logCriticalInfo(INIT_COPY, "Expecting better updated system app for " + ps.name + "; removing system app.  Last known codePath=" + ps.codePathString + ", installStatus=" + ps.installStatus + ", versionCode=" + ps.versionCode + "; scanned versionCode=" + scannedPkg.mVersionCode);
                                    removePackageLI(ps, true);
                                    expectingBetter.put(ps.name, ps.codePath);
                                }
                            } else if (!this.mSettings.isDisabledSystemPackageLPr(ps.name)) {
                                psit.remove();
                                logCriticalInfo(INIT_COPY, "System package " + ps.name + " no longer exists; wiping its data");
                                removeDataDirsLI(ps.name);
                            } else {
                                PackageSetting disabledPs = this.mSettings.getDisabledSystemPkgLPr(ps.name);
                                if (disabledPs.codePath == null || !disabledPs.codePath.exists()) {
                                    possiblyDeletedUpdatedSystemApps.add(ps.name);
                                }
                            }
                        }
                    }
                }
                ArrayList<PackageSetting> deletePkgsList = this.mSettings.getListOfIncompleteInstallPackagesLPr();
                for (int i4 = DEX_OPT_SKIPPED; i4 < deletePkgsList.size(); i4++) {
                    cleanupInstallFailedPackage(deletePkgsList.get(i4));
                }
                deleteTempPackageFiles();
                this.mSettings.pruneSharedUsersLPw();
                if (!this.mOnlyCore) {
                    EventLog.writeEvent(3080, SystemClock.uptimeMillis());
                    scanDirLI(this.mAppInstallDir, DEX_OPT_SKIPPED, 4512, 0L);
                    scanDirLI(this.mDrmAppPrivateInstallDir, 16, 4512, 0L);
                    for (String deletedAppName : possiblyDeletedUpdatedSystemApps) {
                        PackageParser.Package deletedPkg = this.mPackages.get(deletedAppName);
                        this.mSettings.removeDisabledSystemPackageLPw(deletedAppName);
                        if (deletedPkg == null) {
                            msg = "Updated system package " + deletedAppName + " no longer exists; wiping its data";
                            removeDataDirsLI(deletedAppName);
                        } else {
                            msg = "Updated system app + " + deletedAppName + " no longer present; removing system privileges for " + deletedAppName;
                            deletedPkg.applicationInfo.flags &= -2;
                            PackageSetting deletedPs = (PackageSetting) this.mSettings.mPackages.get(deletedAppName);
                            deletedPs.pkgFlags &= -2;
                        }
                        logCriticalInfo(INIT_COPY, msg);
                    }
                    for (int i5 = DEX_OPT_SKIPPED; i5 < expectingBetter.size(); i5++) {
                        String packageName = expectingBetter.keyAt(i5);
                        if (!this.mPackages.containsKey(packageName)) {
                            File scanFile = expectingBetter.valueAt(i5);
                            logCriticalInfo(INIT_COPY, "Expected better " + packageName + " but never showed up; reverting to system");
                            if (FileUtils.contains(privilegedAppDir, scanFile)) {
                                reparseFlags = 193;
                            } else if (FileUtils.contains(systemAppDir, scanFile)) {
                                reparseFlags = 65;
                            } else if (FileUtils.contains(vendorAppDir, scanFile)) {
                                reparseFlags = 65;
                            } else if (FileUtils.contains(oemAppDir, scanFile)) {
                                reparseFlags = 65;
                            } else {
                                Slog.e(TAG, "Ignoring unexpected fallback path " + scanFile);
                            }
                            this.mSettings.enableSystemPackageLPw(packageName);
                            try {
                                scanPackageLI(scanFile, reparseFlags, 416, 0L, (UserHandle) null);
                            } catch (PackageManagerException e6) {
                                Slog.e(TAG, "Failed to parse original system package: " + e6.getMessage());
                            }
                        }
                    }
                    VendorPackageManagerCallback.callOnInit(this.mVendorCallbacks, 200, this, this.mPackages);
                }
                updateAllSharedLibrariesLPw();
                for (SharedUserSetting setting : this.mSettings.getAllSharedUsersLPw()) {
                    adjustCpuAbisForSharedUserLPw(setting.packages, null, false, false);
                }
                this.mPackageUsage.readLP();
                EventLog.writeEvent(3090, SystemClock.uptimeMillis());
                Slog.i(TAG, "Time to scan packages: " + (((float) (SystemClock.uptimeMillis() - startTime)) / 1000.0f) + " seconds");
                boolean regrantPermissions = this.mSettings.mInternalSdkPlatform != this.mSdkVersion;
                if (regrantPermissions) {
                    Slog.i(TAG, "Platform changed from " + this.mSettings.mInternalSdkPlatform + " to " + this.mSdkVersion + "; regranting permissions for internal storage");
                }
                this.mSettings.mInternalSdkPlatform = this.mSdkVersion;
                updatePermissionsLPw(null, null, (regrantPermissions ? MCS_UNBIND : DEX_OPT_SKIPPED) | 1);
                if (!this.mRestoredSettings && !onlyCore) {
                    this.mSettings.readDefaultPreferredAppsLPw(this, DEX_OPT_SKIPPED);
                }
                this.mIsUpgrade = !Build.FINGERPRINT.equals(this.mSettings.mFingerprint);
                if (isUpgrade() && !isFirstBoot()) {
                    VendorPackageManagerCallback.callOnSystemOTA(this.mVendorCallbacks);
                }
                if (this.mIsUpgrade && !onlyCore) {
                    Slog.i(TAG, "Build fingerprint changed; clearing code caches");
                    for (String pkgName : this.mSettings.mPackages.keySet()) {
                        deleteCodeCacheDirsLI(pkgName);
                    }
                    this.mSettings.mFingerprint = Build.FINGERPRINT;
                }
                this.mSettings.updateInternalDatabaseVersion();
                this.mSettings.writeLPr();
                EventLog.writeEvent(3100, SystemClock.uptimeMillis());
                this.mRequiredVerifierPackage = getRequiredVerifierLPr();
                VendorPackageManagerCallback.callOnInit(this.mVendorCallbacks, 1000, this, (ArrayMap) null);
            }
        }
        this.mInstallerService = new PackageInstallerService(context, this, this.mAppInstallDir);
        Runtime.getRuntime().gc();
    }

    public boolean isFirstBoot() {
        return !this.mRestoredSettings;
    }

    public boolean isOnlyCoreApps() {
        return this.mOnlyCore;
    }

    public boolean isUpgrade() {
        return this.mIsUpgrade;
    }

    private String getRequiredVerifierLPr() {
        Intent verification = new Intent("android.intent.action.PACKAGE_NEEDS_VERIFICATION");
        List<ResolveInfo> receivers = queryIntentReceivers(verification, PACKAGE_MIME_TYPE, SCAN_TRUSTED_OVERLAY, DEX_OPT_SKIPPED);
        String requiredVerifier = null;
        int N = receivers.size();
        for (int i = DEX_OPT_SKIPPED; i < N; i++) {
            ResolveInfo info = receivers.get(i);
            if (info.activityInfo != null) {
                String packageName = info.activityInfo.packageName;
                SharedUserSetting sharedUserSetting = (PackageSetting) this.mSettings.mPackages.get(packageName);
                if (sharedUserSetting == null) {
                    continue;
                } else if (!((GrantedPermissions) (((PackageSetting) sharedUserSetting).sharedUser != null ? ((PackageSetting) sharedUserSetting).sharedUser : sharedUserSetting)).grantedPermissions.contains("android.permission.PACKAGE_VERIFICATION_AGENT")) {
                    continue;
                } else {
                    if (requiredVerifier != null) {
                        throw new RuntimeException("There can be only one required verifier");
                    }
                    requiredVerifier = packageName;
                }
            }
        }
        return requiredVerifier;
    }

    public boolean onTransact(int code, Parcel data, Parcel reply, int flags) throws RemoteException {
        try {
            return super.onTransact(code, data, reply, flags);
        } catch (RuntimeException e) {
            if (!(e instanceof SecurityException) && !(e instanceof IllegalArgumentException)) {
                Slog.wtf(TAG, "Package Manager Crash", e);
            }
            throw e;
        }
    }

    void cleanupInstallFailedPackage(PackageSetting ps) {
        logCriticalInfo(INIT_COPY, "Cleaning up incompletely installed app: " + ps.name);
        removeDataDirsLI(ps.name);
        if (ps.codePath != null) {
            if (ps.codePath.isDirectory()) {
                FileUtils.deleteContents(ps.codePath);
            }
            ps.codePath.delete();
        }
        if (ps.resourcePath != null && !ps.resourcePath.equals(ps.codePath)) {
            if (ps.resourcePath.isDirectory()) {
                FileUtils.deleteContents(ps.resourcePath);
            }
            ps.resourcePath.delete();
        }
        this.mSettings.removePackageLPw(ps.name);
    }

    static int[] appendInts(int[] cur, int[] add) {
        if (add != null) {
            if (cur == null) {
                return add;
            }
            int N = add.length;
            for (int i = DEX_OPT_SKIPPED; i < N; i++) {
                cur = ArrayUtils.appendInt(cur, add[i]);
            }
            return cur;
        }
        return cur;
    }

    static int[] removeInts(int[] cur, int[] rem) {
        if (rem != null && cur != null) {
            int N = rem.length;
            for (int i = DEX_OPT_SKIPPED; i < N; i++) {
                cur = ArrayUtils.removeInt(cur, rem[i]);
            }
        }
        return cur;
    }

    PackageInfo generatePackageInfo(PackageParser.Package p, int flags, int userId) {
        SharedUserSetting sharedUserSetting;
        if (!sUserManager.exists(userId) || (sharedUserSetting = (PackageSetting) p.mExtras) == null) {
            return null;
        }
        SharedUserSetting sharedUserSetting2 = ((PackageSetting) sharedUserSetting).sharedUser != null ? ((PackageSetting) sharedUserSetting).sharedUser : sharedUserSetting;
        PackageUserState state = sharedUserSetting.readUserState(userId);
        return PackageParser.generatePackageInfo(p, ((GrantedPermissions) sharedUserSetting2).gids, flags, ((PackageSetting) sharedUserSetting).firstInstallTime, ((PackageSetting) sharedUserSetting).lastUpdateTime, ((GrantedPermissions) sharedUserSetting2).grantedPermissions, state, userId);
    }

    public boolean isPackageFrozen(String packageName) {
        synchronized (this.mPackages) {
            PackageSetting ps = (PackageSetting) this.mSettings.mPackages.get(packageName);
            if (ps != null) {
                return ps.frozen;
            }
            Slog.w(TAG, "Package " + packageName + " is missing; assuming frozen");
            return true;
        }
    }

    public boolean isPackageAvailable(String packageName, int userId) {
        PackageSetting ps;
        PackageUserState state;
        boolean z = false;
        if (sUserManager.exists(userId)) {
            enforceCrossUserPermission(Binder.getCallingUid(), userId, false, false, "is package available");
            synchronized (this.mPackages) {
                PackageParser.Package p = this.mPackages.get(packageName);
                if (p != null && (ps = (PackageSetting) p.mExtras) != null && (state = ps.readUserState(userId)) != null) {
                    z = PackageParser.isAvailable(state);
                }
            }
        }
        return z;
    }

    public PackageInfo getPackageInfo(String packageName, int flags, int userId) {
        PackageInfo generatePackageInfoFromSettingsLPw;
        if (!sUserManager.exists(userId)) {
            return null;
        }
        enforceCrossUserPermission(Binder.getCallingUid(), userId, false, false, "get package info");
        synchronized (this.mPackages) {
            PackageParser.Package p = this.mPackages.get(packageName);
            if (p != null) {
                generatePackageInfoFromSettingsLPw = generatePackageInfo(p, flags, userId);
            } else {
                generatePackageInfoFromSettingsLPw = (flags & 8192) != 0 ? generatePackageInfoFromSettingsLPw(packageName, flags, userId) : null;
            }
        }
        return generatePackageInfoFromSettingsLPw;
    }

    public String[] currentToCanonicalPackageNames(String[] names) {
        String[] out = new String[names.length];
        synchronized (this.mPackages) {
            for (int i = names.length + DEX_OPT_FAILED; i >= 0; i += DEX_OPT_FAILED) {
                PackageSetting ps = (PackageSetting) this.mSettings.mPackages.get(names[i]);
                out[i] = (ps == null || ps.realName == null) ? names[i] : ps.realName;
            }
        }
        return out;
    }

    public String[] canonicalToCurrentPackageNames(String[] names) {
        String[] out = new String[names.length];
        synchronized (this.mPackages) {
            for (int i = names.length + DEX_OPT_FAILED; i >= 0; i += DEX_OPT_FAILED) {
                String cur = (String) this.mSettings.mRenamedPackages.get(names[i]);
                if (cur == null) {
                    cur = names[i];
                }
                out[i] = cur;
            }
        }
        return out;
    }

    public int getPackageUid(String packageName, int userId) {
        if (!sUserManager.exists(userId)) {
            return DEX_OPT_FAILED;
        }
        enforceCrossUserPermission(Binder.getCallingUid(), userId, false, false, "get package uid");
        synchronized (this.mPackages) {
            PackageParser.Package p = this.mPackages.get(packageName);
            if (p != null) {
                return UserHandle.getUid(userId, p.applicationInfo.uid);
            }
            PackageSetting ps = (PackageSetting) this.mSettings.mPackages.get(packageName);
            if (ps == null || ps.pkg == null || ps.pkg.applicationInfo == null) {
                return DEX_OPT_FAILED;
            }
            PackageParser.Package p2 = ps.pkg;
            return p2 != null ? UserHandle.getUid(userId, p2.applicationInfo.uid) : DEX_OPT_FAILED;
        }
    }

    public int[] getPackageGids(String packageName) {
        synchronized (this.mPackages) {
            PackageParser.Package p = this.mPackages.get(packageName);
            if (p != null) {
                PackageSetting ps = (PackageSetting) p.mExtras;
                int[] vpGids = VendorPackageManagerCallback.callAddPackageGids(this.mVendorCallbacks, packageName);
                return (vpGids == null || vpGids.length != 0) ? appendInts(ps.getGids(), vpGids) : ps.getGids();
            }
            return new int[DEX_OPT_SKIPPED];
        }
    }

    static final PermissionInfo generatePermissionInfo(BasePermission bp, int flags) {
        if (bp.perm != null) {
            return PackageParser.generatePermissionInfo(bp.perm, flags);
        }
        PermissionInfo pi = new PermissionInfo();
        pi.name = bp.name;
        pi.packageName = bp.sourcePackage;
        pi.nonLocalizedLabel = bp.name;
        pi.protectionLevel = bp.protectionLevel;
        return pi;
    }

    public PermissionInfo getPermissionInfo(String name, int flags) {
        PermissionInfo generatePermissionInfo;
        synchronized (this.mPackages) {
            BasePermission p = (BasePermission) this.mSettings.mPermissions.get(name);
            generatePermissionInfo = p != null ? generatePermissionInfo(p, flags) : null;
        }
        return generatePermissionInfo;
    }

    public List<PermissionInfo> queryPermissionsByGroup(String group, int flags) {
        ArrayList<PermissionInfo> out;
        synchronized (this.mPackages) {
            out = new ArrayList<>(MCS_RECONNECT);
            for (BasePermission p : this.mSettings.mPermissions.values()) {
                if (group == null) {
                    if (p.perm == null || p.perm.info.group == null) {
                        out.add(generatePermissionInfo(p, flags));
                    }
                } else if (p.perm != null && group.equals(p.perm.info.group)) {
                    out.add(PackageParser.generatePermissionInfo(p.perm, flags));
                }
            }
            if (out.size() <= 0) {
                if (!this.mPermissionGroups.containsKey(group)) {
                    out = null;
                }
            }
        }
        return out;
    }

    public PermissionGroupInfo getPermissionGroupInfo(String name, int flags) {
        PermissionGroupInfo generatePermissionGroupInfo;
        synchronized (this.mPackages) {
            generatePermissionGroupInfo = PackageParser.generatePermissionGroupInfo(this.mPermissionGroups.get(name), flags);
        }
        return generatePermissionGroupInfo;
    }

    public List<PermissionGroupInfo> getAllPermissionGroups(int flags) {
        ArrayList<PermissionGroupInfo> out;
        synchronized (this.mPackages) {
            int N = this.mPermissionGroups.size();
            out = new ArrayList<>(N);
            for (PackageParser.PermissionGroup pg : this.mPermissionGroups.values()) {
                out.add(PackageParser.generatePermissionGroupInfo(pg, flags));
            }
        }
        return out;
    }

    private ApplicationInfo generateApplicationInfoFromSettingsLPw(String packageName, int flags, int userId) {
        PackageSetting ps;
        if (!sUserManager.exists(userId) || (ps = (PackageSetting) this.mSettings.mPackages.get(packageName)) == null) {
            return null;
        }
        if (ps.pkg == null) {
            PackageInfo pInfo = generatePackageInfoFromSettingsLPw(packageName, flags, userId);
            if (pInfo != null) {
                return pInfo.applicationInfo;
            }
            return null;
        }
        return PackageParser.generateApplicationInfo(ps.pkg, flags, ps.readUserState(userId), userId);
    }

    private PackageInfo generatePackageInfoFromSettingsLPw(String packageName, int flags, int userId) {
        PackageSetting ps;
        if (!sUserManager.exists(userId) || (ps = (PackageSetting) this.mSettings.mPackages.get(packageName)) == null) {
            return null;
        }
        PackageParser.Package pkg = ps.pkg;
        if (pkg == null) {
            if ((flags & 8192) == 0) {
                return null;
            }
            pkg = new PackageParser.Package(packageName);
            pkg.applicationInfo.packageName = packageName;
            pkg.applicationInfo.flags = ps.pkgFlags | 0x01000000;
            pkg.applicationInfo.dataDir = getDataPathForPackage(packageName, DEX_OPT_SKIPPED).getPath();
            pkg.applicationInfo.primaryCpuAbi = ps.primaryCpuAbiString;
            pkg.applicationInfo.secondaryCpuAbi = ps.secondaryCpuAbiString;
            if ((flags & 8192) != 0) {
                pkg.mExtras = ps;
            }
        }
        return generatePackageInfo(pkg, flags, userId);
    }

    public ApplicationInfo getApplicationInfo(String packageName, int flags, int userId) {
        ApplicationInfo applicationInfo;
        if (!sUserManager.exists(userId)) {
            return null;
        }
        enforceCrossUserPermission(Binder.getCallingUid(), userId, false, false, "get application info");
        synchronized (this.mPackages) {
            PackageParser.Package p = this.mPackages.get(packageName);
            if (p != null) {
                PackageSetting ps = (PackageSetting) this.mSettings.mPackages.get(packageName);
                applicationInfo = ps == null ? null : PackageParser.generateApplicationInfo(p, flags, ps.readUserState(userId), userId);
            } else if ("android".equals(packageName) || "system".equals(packageName)) {
                applicationInfo = this.mAndroidApplication;
            } else if ((flags & 8192) != 0) {
                applicationInfo = generateApplicationInfoFromSettingsLPw(packageName, flags, userId);
            } else {
                Log.w(TAG, packageName + " is not installed for user " + userId);
                applicationInfo = null;
            }
        }
        return applicationInfo;
    }

    public void freeStorageAndNotify(long freeStorageSize, IPackageDataObserver observer) {
        this.mContext.enforceCallingOrSelfPermission("android.permission.CLEAR_APP_CACHE", null);
        this.mHandler.post(new PackageManagerService$1(this, freeStorageSize, observer));
    }

    public void freeStorage(long freeStorageSize, IntentSender pi) {
        this.mContext.enforceCallingOrSelfPermission("android.permission.CLEAR_APP_CACHE", null);
        this.mHandler.post(new PackageManagerService$2(this, freeStorageSize, pi));
    }

    void freeStorage(long freeStorageSize) throws IOException {
        synchronized (this.mInstallLock) {
            if (this.mInstaller.freeCache(freeStorageSize) < 0) {
                throw new IOException("Failed to free enough space");
            }
        }
    }

    public ActivityInfo getActivityInfo(ComponentName component, int flags, int userId) {
        ActivityInfo generateActivityInfo;
        if (!sUserManager.exists(userId)) {
            return null;
        }
        enforceCrossUserPermission(Binder.getCallingUid(), userId, false, false, "get activity info");
        synchronized (this.mPackages) {
            PackageParser.Activity a = (PackageParser.Activity) ActivityIntentResolver.access$1700(this.mActivities).get(component);
            if (a != null && this.mSettings.isEnabledLPr(a.info, flags, userId)) {
                PackageSetting ps = (PackageSetting) this.mSettings.mPackages.get(component.getPackageName());
                generateActivityInfo = ps == null ? null : PackageParser.generateActivityInfo(a, flags, ps.readUserState(userId), userId);
            } else {
                generateActivityInfo = this.mResolveComponentName.equals(component) ? PackageParser.generateActivityInfo(this.mResolveActivity, flags, new PackageUserState(), userId) : null;
            }
        }
        return generateActivityInfo;
    }

    public boolean activitySupportsIntent(ComponentName component, Intent intent, String resolvedType) {
        synchronized (this.mPackages) {
            PackageParser.Activity a = (PackageParser.Activity) ActivityIntentResolver.access$1700(this.mActivities).get(component);
            if (a == null) {
                return false;
            }
            for (int i = DEX_OPT_SKIPPED; i < a.intents.size(); i++) {
                if (((PackageParser.ActivityIntentInfo) a.intents.get(i)).match(intent.getAction(), resolvedType, intent.getScheme(), intent.getData(), intent.getCategories(), TAG) >= 0) {
                    return true;
                }
            }
            return false;
        }
    }

    public ActivityInfo getReceiverInfo(ComponentName component, int flags, int userId) {
        ActivityInfo activityInfo;
        if (!sUserManager.exists(userId)) {
            return null;
        }
        enforceCrossUserPermission(Binder.getCallingUid(), userId, false, false, "get receiver info");
        synchronized (this.mPackages) {
            PackageParser.Activity a = (PackageParser.Activity) ActivityIntentResolver.access$1700(this.mReceivers).get(component);
            if (a == null || !this.mSettings.isEnabledLPr(a.info, flags, userId)) {
                activityInfo = null;
            } else {
                PackageSetting ps = (PackageSetting) this.mSettings.mPackages.get(component.getPackageName());
                activityInfo = ps == null ? null : PackageParser.generateActivityInfo(a, flags, ps.readUserState(userId), userId);
            }
        }
        return activityInfo;
    }

    public ServiceInfo getServiceInfo(ComponentName component, int flags, int userId) {
        ServiceInfo serviceInfo;
        if (!sUserManager.exists(userId)) {
            return null;
        }
        enforceCrossUserPermission(Binder.getCallingUid(), userId, false, false, "get service info");
        synchronized (this.mPackages) {
            PackageParser.Service s = (PackageParser.Service) ServiceIntentResolver.access$1800(this.mServices).get(component);
            if (s == null || !this.mSettings.isEnabledLPr(s.info, flags, userId)) {
                serviceInfo = null;
            } else {
                PackageSetting ps = (PackageSetting) this.mSettings.mPackages.get(component.getPackageName());
                serviceInfo = ps == null ? null : PackageParser.generateServiceInfo(s, flags, ps.readUserState(userId), userId);
            }
        }
        return serviceInfo;
    }

    public ProviderInfo getProviderInfo(ComponentName component, int flags, int userId) {
        ProviderInfo providerInfo;
        if (!sUserManager.exists(userId)) {
            return null;
        }
        enforceCrossUserPermission(Binder.getCallingUid(), userId, false, false, "get provider info");
        synchronized (this.mPackages) {
            PackageParser.Provider p = (PackageParser.Provider) ProviderIntentResolver.access$1900(this.mProviders).get(component);
            if (p == null || !this.mSettings.isEnabledLPr(p.info, flags, userId)) {
                providerInfo = null;
            } else {
                PackageSetting ps = (PackageSetting) this.mSettings.mPackages.get(component.getPackageName());
                providerInfo = ps == null ? null : PackageParser.generateProviderInfo(p, flags, ps.readUserState(userId), userId);
            }
        }
        return providerInfo;
    }

    public String[] getSystemSharedLibraryNames() {
        synchronized (this.mPackages) {
            Set<String> libSet = this.mSharedLibraries.keySet();
            int size = libSet.size();
            if (size > 0) {
                String[] libs = new String[size];
                libSet.toArray(libs);
                return libs;
            }
            return null;
        }
    }

    public FeatureInfo[] getSystemAvailableFeatures() {
        synchronized (this.mPackages) {
            Collection<? extends FeatureInfo> featSet = this.mAvailableFeatures.values();
            List<FeatureInfo> vendorFeatures = VendorPackageManagerCallback.callGetAvailableFeatures(this.mVendorCallbacks, this.mPackages);
            int size = featSet.size() + vendorFeatures.size();
            if (size > 0) {
                ArrayList<FeatureInfo> featureList = new ArrayList<>();
                featureList.addAll(featSet);
                featureList.addAll(vendorFeatures);
                FeatureInfo[] features = new FeatureInfo[size + 1];
                featureList.toArray(features);
                FeatureInfo fi = new FeatureInfo();
                fi.reqGlEsVersion = SystemProperties.getInt("ro.opengles.version", DEX_OPT_SKIPPED);
                features[size] = fi;
                return features;
            }
            return null;
        }
    }

    public boolean hasSystemFeature(String name, int version) {
        boolean z;
        synchronized (this.mPackages) {
            FeatureInfo feat = this.mAvailableFeatures.get(name);
            if (feat == null) {
                z = VendorPackageManagerCallback.callHasFeature(this.mVendorCallbacks, name, version, this.mPackages);
            } else {
                z = feat.version >= version;
            }
        }
        return z;
    }

    private void checkValidCaller(int uid, int userId) {
        if (UserHandle.getUserId(uid) == userId || uid == 1000 || uid == 0) {
        } else {
            throw new SecurityException("Caller uid=" + uid + " is not privileged to communicate with user=" + userId);
        }
    }

    public int checkPermission(String permName, String pkgName) {
        synchronized (this.mPackages) {
            PackageParser.Package p = this.mPackages.get(pkgName);
            if (p != null && p.mExtras != null) {
                PackageSetting ps = (PackageSetting) p.mExtras;
                if (ps.sharedUser != null) {
                    if (ps.sharedUser.grantedPermissions.contains(permName)) {
                        return DEX_OPT_SKIPPED;
                    }
                } else if (ps.grantedPermissions.contains(permName)) {
                    return DEX_OPT_SKIPPED;
                }
            }
            return DEX_OPT_FAILED;
        }
    }

    public int checkUidPermission(String permName, int uid) {
        synchronized (this.mPackages) {
            Object obj = this.mSettings.getUserIdLPw(UserHandle.getAppId(uid));
            if (obj != null) {
                GrantedPermissions gp = (GrantedPermissions) obj;
                if (gp.grantedPermissions.contains(permName)) {
                    return DEX_OPT_SKIPPED;
                }
            } else {
                ArraySet<String> perms = this.mSystemPermissions.get(uid);
                if (perms != null && perms.contains(permName)) {
                    return DEX_OPT_SKIPPED;
                }
            }
            return DEX_OPT_FAILED;
        }
    }

    void enforceCrossUserPermission(int callingUid, int userId, boolean requireFullPermission, boolean checkShell, String message) {
        if (userId < 0) {
            throw new IllegalArgumentException("Invalid userId " + userId);
        }
        if (checkShell) {
            enforceShellRestriction("no_debugging_features", callingUid, userId);
        }
        if (userId != UserHandle.getUserId(callingUid) && callingUid != 1000 && callingUid != 0) {
            try {
                if (requireFullPermission) {
                    this.mContext.enforceCallingOrSelfPermission("android.permission.INTERACT_ACROSS_USERS_FULL", message);
                } else {
                    try {
                        this.mContext.enforceCallingOrSelfPermission("android.permission.INTERACT_ACROSS_USERS_FULL", message);
                    } catch (SecurityException e) {
                        this.mContext.enforceCallingOrSelfPermission("android.permission.INTERACT_ACROSS_USERS", message);
                    }
                }
            } catch (Exception e2) {
                Log.e(TAG, "enforceCrossUserPermission caught Exception:", e2);
                throw new SecurityException("logged stack trace, throwing a new SecurityException to apps", e2);
            }
        }
    }

    void enforceShellRestriction(String restriction, int callingUid, int userHandle) {
        if (callingUid == SHELL_UID) {
            if (userHandle >= 0 && sUserManager.hasUserRestriction(restriction, userHandle)) {
                throw new SecurityException("Shell does not have permission to access user " + userHandle);
            }
            if (userHandle < 0) {
                Slog.e(TAG, "Unable to check shell permission for user " + userHandle + "\n\t" + Debug.getCallers(MCS_BOUND));
            }
        }
    }

    private BasePermission findPermissionTreeLP(String permName) {
        for (BasePermission bp : this.mSettings.mPermissionTrees.values()) {
            if (permName.startsWith(bp.name) && permName.length() > bp.name.length() && permName.charAt(bp.name.length()) == '.') {
                return bp;
            }
        }
        return null;
    }

    private BasePermission checkPermissionTreeLP(String permName) {
        BasePermission bp;
        if (permName != null && (bp = findPermissionTreeLP(permName)) != null) {
            if (bp.uid == UserHandle.getAppId(Binder.getCallingUid())) {
                return bp;
            }
            throw new SecurityException("Calling uid " + Binder.getCallingUid() + " is not allowed to add to permission tree " + bp.name + " owned by uid " + bp.uid);
        }
        throw new SecurityException("No permission tree found for " + permName);
    }

    static boolean compareStrings(CharSequence s1, CharSequence s2) {
        if (s1 == null) {
            return s2 == null;
        }
        if (s2 == null || s1.getClass() != s2.getClass()) {
            return false;
        }
        return s1.equals(s2);
    }

    static boolean comparePermissionInfos(PermissionInfo pi1, PermissionInfo pi2) {
        return pi1.icon == pi2.icon && pi1.logo == pi2.logo && pi1.protectionLevel == pi2.protectionLevel && compareStrings(pi1.name, pi2.name) && compareStrings(pi1.nonLocalizedLabel, pi2.nonLocalizedLabel) && compareStrings(pi1.packageName, pi2.packageName);
    }

    int permissionInfoFootprint(PermissionInfo info) {
        int size = info.name.length();
        if (info.nonLocalizedLabel != null) {
            size += info.nonLocalizedLabel.length();
        }
        return info.nonLocalizedDescription != null ? size + info.nonLocalizedDescription.length() : size;
    }

    int calculateCurrentPermissionFootprintLocked(BasePermission tree) {
        int size = DEX_OPT_SKIPPED;
        for (BasePermission perm : this.mSettings.mPermissions.values()) {
            if (perm.uid == tree.uid) {
                size += perm.name.length() + permissionInfoFootprint(perm.perm.info);
            }
        }
        return size;
    }

    void enforcePermissionCapLocked(PermissionInfo info, BasePermission tree) {
        if (tree.uid != 1000) {
            int curTreeSize = calculateCurrentPermissionFootprintLocked(tree);
            if (permissionInfoFootprint(info) + curTreeSize > MAX_PERMISSION_TREE_FOOTPRINT) {
                throw new SecurityException("Permission tree size cap exceeded");
            }
        }
    }

    boolean addPermissionLocked(PermissionInfo info, boolean async) {
        if (info.labelRes == 0 && info.nonLocalizedLabel == null) {
            throw new SecurityException("Label must be specified in permission");
        }
        BasePermission tree = checkPermissionTreeLP(info.name);
        BasePermission bp = (BasePermission) this.mSettings.mPermissions.get(info.name);
        boolean added = bp == null;
        boolean changed = true;
        int fixedLevel = PermissionInfo.fixProtectionLevel(info.protectionLevel);
        if (added) {
            enforcePermissionCapLocked(info, tree);
            bp = new BasePermission(info.name, tree.sourcePackage, 2);
        } else {
            if (bp.type != 2) {
                throw new SecurityException("Not allowed to modify non-dynamic permission " + info.name);
            }
            if (bp.protectionLevel == fixedLevel && bp.perm.owner.equals(tree.perm.owner) && bp.uid == tree.uid && comparePermissionInfos(bp.perm.info, info)) {
                changed = false;
            }
        }
        bp.protectionLevel = fixedLevel;
        PermissionInfo info2 = new PermissionInfo(info);
        info2.protectionLevel = fixedLevel;
        bp.perm = new PackageParser.Permission(tree.perm.owner, info2);
        bp.perm.info.packageName = tree.perm.info.packageName;
        bp.uid = tree.uid;
        if (added) {
            this.mSettings.mPermissions.put(info2.name, bp);
        }
        if (changed) {
            if (!async) {
                this.mSettings.writeLPr();
            } else {
                scheduleWriteSettingsLocked();
            }
        }
        return added;
    }

    public boolean addPermission(PermissionInfo info) {
        boolean addPermissionLocked;
        synchronized (this.mPackages) {
            addPermissionLocked = addPermissionLocked(info, false);
        }
        return addPermissionLocked;
    }

    public boolean addPermissionAsync(PermissionInfo info) {
        boolean addPermissionLocked;
        synchronized (this.mPackages) {
            addPermissionLocked = addPermissionLocked(info, true);
        }
        return addPermissionLocked;
    }

    public void removePermission(String name) {
        synchronized (this.mPackages) {
            checkPermissionTreeLP(name);
            BasePermission bp = (BasePermission) this.mSettings.mPermissions.get(name);
            if (bp != null) {
                if (bp.type != 2) {
                    throw new SecurityException("Not allowed to modify non-dynamic permission " + name);
                }
                this.mSettings.mPermissions.remove(name);
                this.mSettings.writeLPr();
            }
        }
    }

    private static void checkGrantRevokePermissions(PackageParser.Package pkg, BasePermission bp) {
        int index = pkg.requestedPermissions.indexOf(bp.name);
        if (index == DEX_OPT_FAILED) {
            throw new SecurityException("Package " + pkg.packageName + " has not requested permission " + bp.name);
        }
        boolean isNormal = (bp.protectionLevel & PACKAGE_VERIFIED) == 0 ? true : DEX_OPT_SKIPPED;
        boolean isDangerous = (bp.protectionLevel & PACKAGE_VERIFIED) == 1 ? true : DEX_OPT_SKIPPED;
        boolean isDevelopment = (bp.protectionLevel & SCAN_NO_PATHS) != 0 ? true : DEX_OPT_SKIPPED;
        if (!isNormal && !isDangerous && !isDevelopment) {
            throw new SecurityException("Permission " + bp.name + " is not a changeable permission type");
        }
        if ((isNormal || isDangerous) && ((Boolean) pkg.requestedPermissionsRequired.get(index)).booleanValue()) {
            throw new SecurityException("Can't change " + bp.name + ". It is required by the application");
        }
    }

    public void grantPermission(String packageName, String permissionName) {
        this.mContext.enforceCallingOrSelfPermission("android.permission.GRANT_REVOKE_PERMISSIONS", null);
        synchronized (this.mPackages) {
            PackageParser.Package pkg = this.mPackages.get(packageName);
            if (pkg == null) {
                throw new IllegalArgumentException("Unknown package: " + packageName);
            }
            BasePermission bp = (BasePermission) this.mSettings.mPermissions.get(permissionName);
            if (bp == null) {
                throw new IllegalArgumentException("Unknown permission: " + permissionName);
            }
            checkGrantRevokePermissions(pkg, bp);
            SharedUserSetting sharedUserSetting = (PackageSetting) pkg.mExtras;
            if (sharedUserSetting != null) {
                SharedUserSetting sharedUserSetting2 = ((PackageSetting) sharedUserSetting).sharedUser != null ? ((PackageSetting) sharedUserSetting).sharedUser : sharedUserSetting;
                if (((GrantedPermissions) sharedUserSetting2).grantedPermissions.add(permissionName) && !VendorPackageManagerCallback.callBlockDevelopmentPermPersist(this.mVendorCallbacks, packageName, bp.name)) {
                    if (((PackageSetting) sharedUserSetting).haveGids) {
                        ((GrantedPermissions) sharedUserSetting2).gids = appendInts(((GrantedPermissions) sharedUserSetting2).gids, bp.gids);
                    }
                    this.mSettings.writeLPr();
                }
            }
        }
    }

    public void revokePermission(String packageName, String permissionName) {
        IActivityManager am;
        int changedAppId = DEX_OPT_FAILED;
        synchronized (this.mPackages) {
            PackageParser.Package pkg = this.mPackages.get(packageName);
            if (pkg == null) {
                throw new IllegalArgumentException("Unknown package: " + packageName);
            }
            if (pkg.applicationInfo.uid != Binder.getCallingUid()) {
                this.mContext.enforceCallingOrSelfPermission("android.permission.GRANT_REVOKE_PERMISSIONS", null);
            }
            BasePermission bp = (BasePermission) this.mSettings.mPermissions.get(permissionName);
            if (bp == null) {
                throw new IllegalArgumentException("Unknown permission: " + permissionName);
            }
            checkGrantRevokePermissions(pkg, bp);
            SharedUserSetting sharedUserSetting = (PackageSetting) pkg.mExtras;
            if (sharedUserSetting != null) {
                SharedUserSetting sharedUserSetting2 = ((PackageSetting) sharedUserSetting).sharedUser != null ? ((PackageSetting) sharedUserSetting).sharedUser : sharedUserSetting;
                if (((GrantedPermissions) sharedUserSetting2).grantedPermissions.remove(permissionName)) {
                    ((GrantedPermissions) sharedUserSetting2).grantedPermissions.remove(permissionName);
                    if (((PackageSetting) sharedUserSetting).haveGids) {
                        ((GrantedPermissions) sharedUserSetting2).gids = removeInts(((GrantedPermissions) sharedUserSetting2).gids, bp.gids);
                    }
                    this.mSettings.writeLPr();
                    changedAppId = ((PackageSetting) sharedUserSetting).appId;
                }
                if (changedAppId >= 0 && (am = ActivityManagerNative.getDefault()) != null) {
                    UserHandle.getCallingUserId();
                    long ident = Binder.clearCallingIdentity();
                    try {
                        int[] users = sUserManager.getUserIds();
                        int len$ = users.length;
                        for (int i$ = DEX_OPT_SKIPPED; i$ < len$; i$++) {
                            int user = users[i$];
                            am.killUid(UserHandle.getUid(user, changedAppId), "revoke " + permissionName);
                        }
                    } catch (RemoteException e) {
                    } finally {
                        Binder.restoreCallingIdentity(ident);
                    }
                }
            }
        }
    }

    public boolean isProtectedBroadcast(String actionName) {
        boolean contains;
        synchronized (this.mPackages) {
            contains = this.mProtectedBroadcasts.contains(actionName);
        }
        return contains;
    }

    public int checkSignatures(String pkg1, String pkg2) {
        int compareSignatures;
        synchronized (this.mPackages) {
            PackageParser.Package p1 = this.mPackages.get(pkg1);
            PackageParser.Package p2 = this.mPackages.get(pkg2);
            compareSignatures = (p1 == null || p1.mExtras == null || p2 == null || p2.mExtras == null) ? -4 : compareSignatures(p1.mSignatures, p2.mSignatures);
        }
        return compareSignatures;
    }

    public int checkUidSignatures(int uid1, int uid2) {
        Signature[] s1;
        Signature[] s2;
        int i = -4;
        int uid12 = UserHandle.getAppId(uid1);
        int uid22 = UserHandle.getAppId(uid2);
        synchronized (this.mPackages) {
            Object obj = this.mSettings.getUserIdLPw(uid12);
            if (obj != null) {
                if (obj instanceof SharedUserSetting) {
                    s1 = ((SharedUserSetting) obj).signatures.mSignatures;
                } else if (obj instanceof PackageSetting) {
                    s1 = ((PackageSetting) obj).signatures.mSignatures;
                }
                Object obj2 = this.mSettings.getUserIdLPw(uid22);
                if (obj2 != null) {
                    if (obj2 instanceof SharedUserSetting) {
                        s2 = ((SharedUserSetting) obj2).signatures.mSignatures;
                    } else if (obj2 instanceof PackageSetting) {
                        s2 = ((PackageSetting) obj2).signatures.mSignatures;
                    }
                    i = compareSignatures(s1, s2);
                }
            }
        }
        return i;
    }

    static int compareSignatures(Signature[] s1, Signature[] s2) {
        if (s1 == null) {
            if (s2 == null) {
                return 1;
            }
            return DEX_OPT_FAILED;
        }
        if (s2 == null) {
            return -2;
        }
        if (s1.length != s2.length) {
            return -3;
        }
        if (s1.length == 1) {
            if (s1[DEX_OPT_SKIPPED].equals(s2[DEX_OPT_SKIPPED])) {
                return DEX_OPT_SKIPPED;
            }
            return -3;
        }
        ArraySet<Signature> set1 = new ArraySet<>();
        int len$ = s1.length;
        for (int i$ = DEX_OPT_SKIPPED; i$ < len$; i$++) {
            Signature sig = s1[i$];
            set1.add(sig);
        }
        ArraySet<Signature> set2 = new ArraySet<>();
        int len$2 = s2.length;
        for (int i$2 = DEX_OPT_SKIPPED; i$2 < len$2; i$2++) {
            Signature sig2 = s2[i$2];
            set2.add(sig2);
        }
        if (set1.equals(set2)) {
            return DEX_OPT_SKIPPED;
        }
        return -3;
    }

    private boolean isCompatSignatureUpdateNeeded(PackageParser.Package scannedPkg) {
        return (isExternal(scannedPkg) && this.mSettings.isExternalDatabaseVersionOlderThan(2)) || (!isExternal(scannedPkg) && this.mSettings.isInternalDatabaseVersionOlderThan(2));
    }

    private int compareSignaturesCompat(PackageSignatures existingSigs, PackageParser.Package scannedPkg) {
        if (!isCompatSignatureUpdateNeeded(scannedPkg)) {
            return -3;
        }
        ArraySet<Signature> existingSet = new ArraySet<>();
        Signature[] arr$ = existingSigs.mSignatures;
        int len$ = arr$.length;
        for (int i$ = DEX_OPT_SKIPPED; i$ < len$; i$++) {
            existingSet.add(arr$[i$]);
        }
        ArraySet<Signature> scannedCompatSet = new ArraySet<>();
        Signature[] arr$2 = scannedPkg.mSignatures;
        int len$2 = arr$2.length;
        for (int i$2 = DEX_OPT_SKIPPED; i$2 < len$2; i$2++) {
            Signature sig = arr$2[i$2];
            try {
                Signature[] chainSignatures = sig.getChainSignatures();
                int len$3 = chainSignatures.length;
                for (int i$3 = DEX_OPT_SKIPPED; i$3 < len$3; i$3++) {
                    Signature chainSig = chainSignatures[i$3];
                    scannedCompatSet.add(chainSig);
                }
            } catch (CertificateEncodingException e) {
                scannedCompatSet.add(sig);
            }
        }
        if (scannedCompatSet.equals(existingSet)) {
            existingSigs.assignSignatures(scannedPkg.mSignatures);
            synchronized (this.mPackages) {
                this.mSettings.mKeySetManagerService.removeAppKeySetDataLPw(scannedPkg.packageName);
            }
            return DEX_OPT_SKIPPED;
        }
        return -3;
    }

    private boolean isRecoverSignatureUpdateNeeded(PackageParser.Package scannedPkg) {
        return isExternal(scannedPkg) ? this.mSettings.isExternalDatabaseVersionOlderThan(MCS_BOUND) : this.mSettings.isInternalDatabaseVersionOlderThan(MCS_BOUND);
    }

    private int compareSignaturesRecover(PackageSignatures existingSigs, PackageParser.Package scannedPkg) {
        if (!isRecoverSignatureUpdateNeeded(scannedPkg)) {
            return -3;
        }
        String msg = null;
        try {
            if (Signature.areEffectiveMatch(existingSigs.mSignatures, scannedPkg.mSignatures)) {
                logCriticalInfo(4, "Recovered effectively matching certificates for " + scannedPkg.packageName);
                return DEX_OPT_SKIPPED;
            }
        } catch (CertificateException e) {
            msg = e.getMessage();
        }
        logCriticalInfo(4, "Failed to recover certificates for " + scannedPkg.packageName + ": " + msg);
        return -3;
    }

    static boolean allowedOnTrust(String perm, PackageParser.Package pkg) {
        PackageParser.Package.TrustLevel trustLevel;
        if (pkg == null || perm == null || (trustLevel = (PackageParser.Package.TrustLevel) PackageParser.TRUSTED_PERMISSIONS.get(perm)) == null || trustLevel.getIntValue() != pkg.mTrustLevel.getIntValue()) {
            return false;
        }
        Log.i(TAG, "Trust " + pkg.packageName + ". Grant " + perm);
        return true;
    }

    public String[] getPackagesForUid(int uid) {
        int uid2 = UserHandle.getAppId(uid);
        synchronized (this.mPackages) {
            Object obj = this.mSettings.getUserIdLPw(uid2);
            if (obj instanceof SharedUserSetting) {
                SharedUserSetting sus = (SharedUserSetting) obj;
                int N = sus.packages.size();
                String[] res = new String[N];
                Iterator<PackageSetting> it = sus.packages.iterator();
                int i = DEX_OPT_SKIPPED;
                while (it.hasNext()) {
                    res[i] = it.next().name;
                    i++;
                }
                return res;
            }
            if (obj instanceof PackageSetting) {
                PackageSetting ps = (PackageSetting) obj;
                return new String[]{ps.name};
            }
            return null;
        }
    }

    public String getNameForUid(int uid) {
        synchronized (this.mPackages) {
            Object obj = this.mSettings.getUserIdLPw(UserHandle.getAppId(uid));
            if (obj instanceof SharedUserSetting) {
                SharedUserSetting sus = (SharedUserSetting) obj;
                return sus.name + ":" + sus.userId;
            }
            if (obj instanceof PackageSetting) {
                PackageSetting ps = (PackageSetting) obj;
                return ps.name;
            }
            return null;
        }
    }

    public int getUidForSharedUser(String sharedUserName) {
        int i = DEX_OPT_FAILED;
        if (sharedUserName != null) {
            synchronized (this.mPackages) {
                SharedUserSetting suid = this.mSettings.getSharedUserLPw(sharedUserName, (Signature[]) null, DEX_OPT_SKIPPED, false);
                if (suid != null) {
                    i = suid.userId;
                }
            }
        }
        return i;
    }

    public int getFlagsForUid(int uid) {
        synchronized (this.mPackages) {
            Object obj = this.mSettings.getUserIdLPr(UserHandle.getAppId(uid));
            if (obj instanceof SharedUserSetting) {
                SharedUserSetting sus = (SharedUserSetting) obj;
                return sus.pkgFlags;
            }
            if (obj instanceof PackageSetting) {
                PackageSetting ps = (PackageSetting) obj;
                return ps.pkgFlags;
            }
            return DEX_OPT_SKIPPED;
        }
    }

    public boolean isUidPrivileged(int uid) {
        int uid2 = UserHandle.getAppId(uid);
        synchronized (this.mPackages) {
            Object obj = this.mSettings.getUserIdLPr(uid2);
            if (obj instanceof SharedUserSetting) {
                SharedUserSetting sus = (SharedUserSetting) obj;
                Iterator<PackageSetting> it = sus.packages.iterator();
                while (it.hasNext()) {
                    if (it.next().isPrivileged()) {
                        return true;
                    }
                }
            } else if (obj instanceof PackageSetting) {
                PackageSetting ps = (PackageSetting) obj;
                return ps.isPrivileged();
            }
            return false;
        }
    }

    public String[] getAppOpPermissionPackages(String permissionName) {
        String[] strArr;
        synchronized (this.mPackages) {
            ArraySet<String> pkgs = this.mAppOpPermissionPackages.get(permissionName);
            strArr = pkgs == null ? null : (String[]) pkgs.toArray(new String[pkgs.size()]);
        }
        return strArr;
    }

    public ResolveInfo resolveIntent(Intent intent, String resolvedType, int flags, int userId) {
        if (!sUserManager.exists(userId)) {
            return null;
        }
        enforceCrossUserPermission(Binder.getCallingUid(), userId, false, false, "resolve intent");
        List<ResolveInfo> query = queryIntentActivities(intent, resolvedType, flags, userId);
        return chooseBestActivity(intent, resolvedType, flags, query, userId);
    }

    public void setLastChosenActivity(Intent intent, String resolvedType, int flags, IntentFilter filter, int match, ComponentName activity) {
        int userId = UserHandle.getCallingUserId();
        intent.setComponent(null);
        List<ResolveInfo> query = queryIntentActivities(intent, resolvedType, flags, userId);
        findPreferredActivity(intent, resolvedType, flags, query, DEX_OPT_SKIPPED, false, true, false, userId);
        addPreferredActivityInternal(filter, match, null, activity, false, userId, "Setting last chosen");
    }

    public ResolveInfo getLastChosenActivity(Intent intent, String resolvedType, int flags) {
        int userId = UserHandle.getCallingUserId();
        List<ResolveInfo> query = queryIntentActivities(intent, resolvedType, flags, userId);
        return findPreferredActivity(intent, resolvedType, flags, query, DEX_OPT_SKIPPED, false, false, false, userId);
    }

    private ResolveInfo chooseBestActivity(Intent intent, String resolvedType, int flags, List<ResolveInfo> query, int userId) {
        if (query != null) {
            int N = query.size();
            if (N == 1) {
                return query.get(DEX_OPT_SKIPPED);
            }
            if (N > 1) {
                boolean debug = (intent.getFlags() & 8) != 0;
                ResolveInfo r0 = query.get(DEX_OPT_SKIPPED);
                ResolveInfo r1 = query.get(1);
                if (debug) {
                    Slog.v(TAG, r0.activityInfo.name + "=" + r0.priority + " vs " + r1.activityInfo.name + "=" + r1.priority);
                }
                if (r0.priority != r1.priority || r0.preferredOrder != r1.preferredOrder || r0.isDefault != r1.isDefault) {
                    return query.get(DEX_OPT_SKIPPED);
                }
                ResolveInfo ri = findPreferredActivity(intent, resolvedType, flags, query, r0.priority, true, false, debug, userId);
                if (ri != null) {
                    return ri;
                }
                if (userId != 0) {
                    ResolveInfo ri2 = new ResolveInfo(this.mResolveInfo);
                    ri2.activityInfo = new ActivityInfo(ri2.activityInfo);
                    ri2.activityInfo.applicationInfo = new ApplicationInfo(ri2.activityInfo.applicationInfo);
                    ri2.activityInfo.applicationInfo.uid = UserHandle.getUid(userId, UserHandle.getAppId(ri2.activityInfo.applicationInfo.uid));
                    return ri2;
                }
                return this.mResolveInfo;
            }
        }
        return null;
    }

    private ResolveInfo findPersistentPreferredActivityLP(Intent intent, String resolvedType, int flags, List<ResolveInfo> query, boolean debug, int userId) {
        List<PersistentPreferredActivity> pprefs;
        int N = query.size();
        PersistentPreferredIntentResolver ppir = (PersistentPreferredIntentResolver) this.mSettings.mPersistentPreferredActivities.get(userId);
        if (debug) {
            Slog.v(TAG, "Looking for presistent preferred activities...");
        }
        if (ppir != null) {
            pprefs = ppir.queryIntent(intent, resolvedType, (REMOVE_CHATTY & flags) != 0, userId);
        } else {
            pprefs = null;
        }
        if (pprefs != null && pprefs.size() > 0) {
            int M = pprefs.size();
            for (int i = DEX_OPT_SKIPPED; i < M; i++) {
                PersistentPreferredActivity ppa = pprefs.get(i);
                if (debug) {
                    Slog.v(TAG, "Checking PersistentPreferredActivity ds=" + (ppa.countDataSchemes() > 0 ? ppa.getDataScheme(DEX_OPT_SKIPPED) : "<none>") + "\n  component=" + ppa.mComponent);
                    ppa.dump(new LogPrinter(2, TAG, MCS_BOUND), "  ");
                }
                ActivityInfo ai = getActivityInfo(ppa.mComponent, flags | SCAN_TRUSTED_OVERLAY, userId);
                if (debug) {
                    Slog.v(TAG, "Found persistent preferred activity:");
                    if (ai != null) {
                        ai.dump(new LogPrinter(2, TAG, MCS_BOUND), "  ");
                    } else {
                        Slog.v(TAG, "  null");
                    }
                }
                if (ai != null) {
                    for (int j = DEX_OPT_SKIPPED; j < N; j++) {
                        ResolveInfo ri = query.get(j);
                        if (ri.activityInfo.applicationInfo.packageName.equals(ai.applicationInfo.packageName) && ri.activityInfo.name.equals(ai.name)) {
                            if (debug) {
                                Slog.v(TAG, "Returning persistent preferred activity: " + ri.activityInfo.packageName + "/" + ri.activityInfo.name);
                                return ri;
                            }
                            return ri;
                        }
                    }
                }
            }
        }
        return null;
    }

    /* JADX WARN: Code restructure failed: missing block: B:107:0x0169, code lost:
    
        continue;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
    */
    ResolveInfo findPreferredActivity(Intent intent, String resolvedType, int flags, List<ResolveInfo> query, int priority, boolean always, boolean removeMatches, boolean debug, int userId) {
        if (!sUserManager.exists(userId)) {
            return null;
        }
        synchronized (this.mPackages) {
            if (intent.getSelector() != null) {
                intent = intent.getSelector();
            }
            ResolveInfo pri = findPersistentPreferredActivityLP(intent, resolvedType, flags, query, debug, userId);
            if (pri != null) {
                return pri;
            }
            PreferredIntentResolver pir = (PreferredIntentResolver) this.mSettings.mPreferredActivities.get(userId);
            if (debug) {
                Slog.v(TAG, "Looking for preferred activities...");
            }
            List<PreferredActivity> prefs = pir != null ? pir.queryIntent(intent, resolvedType, (REMOVE_CHATTY & flags) != 0, userId) : null;
            if (prefs != null && prefs.size() > 0) {
                boolean changed = false;
                int match = DEX_OPT_SKIPPED;
                if (debug) {
                    try {
                        Slog.v(TAG, "Figuring out best match...");
                    } finally {
                        if (DEX_OPT_SKIPPED != 0) {
                            scheduleWritePackageRestrictionsLocked(userId);
                        }
                    }
                }
                int N = query.size();
                for (int j = DEX_OPT_SKIPPED; j < N; j++) {
                    ResolveInfo ri = query.get(j);
                    if (debug) {
                        Slog.v(TAG, "Match for " + ri.activityInfo + ": 0x" + Integer.toHexString(match));
                    }
                    if (ri.match > match) {
                        match = ri.match;
                    }
                }
                if (debug) {
                    Slog.v(TAG, "Best match: 0x" + Integer.toHexString(match));
                }
                int match2 = match & 0x0fff0000;
                int M = prefs.size();
                for (int i = DEX_OPT_SKIPPED; i < M; i++) {
                    PreferredActivity pa = prefs.get(i);
                    if (debug) {
                        Slog.v(TAG, "Checking PreferredActivity ds=" + (pa.countDataSchemes() > 0 ? pa.getDataScheme(DEX_OPT_SKIPPED) : "<none>") + "\n  component=" + pa.mPref.mComponent);
                        pa.dump(new LogPrinter(2, TAG, MCS_BOUND), "  ");
                    }
                    if (pa.mPref.mMatch != match2) {
                        if (debug) {
                            Slog.v(TAG, "Skipping bad match " + Integer.toHexString(pa.mPref.mMatch));
                        }
                    } else if (!always || pa.mPref.mAlways) {
                        ActivityInfo ai = getActivityInfo(pa.mPref.mComponent, flags | SCAN_TRUSTED_OVERLAY, userId);
                        if (debug) {
                            Slog.v(TAG, "Found preferred activity:");
                            if (ai != null) {
                                ai.dump(new LogPrinter(2, TAG, MCS_BOUND), "  ");
                            } else {
                                Slog.v(TAG, "  null");
                            }
                        }
                        if (ai == null) {
                            Slog.w(TAG, "Removing dangling preferred activity: " + pa.mPref.mComponent);
                            pir.removeFilter(pa);
                            changed = true;
                        } else {
                            int j2 = DEX_OPT_SKIPPED;
                            while (true) {
                                if (j2 < N) {
                                    ResolveInfo ri2 = query.get(j2);
                                    if (ri2.activityInfo.applicationInfo.packageName.equals(ai.applicationInfo.packageName) && ri2.activityInfo.name.equals(ai.name)) {
                                        if (!removeMatches) {
                                            if (!always || pa.mPref.sameSet(query)) {
                                                if (debug) {
                                                    Slog.v(TAG, "Returning preferred activity: " + ri2.activityInfo.packageName + "/" + ri2.activityInfo.name);
                                                }
                                                return ri2;
                                            }
                                            Slog.i(TAG, "Result set changed, dropping preferred activity for " + intent + " type " + resolvedType);
                                            pir.removeFilter(pa);
                                            PreferredActivity lastChosen = new PreferredActivity(pa, pa.mPref.mMatch, (ComponentName[]) null, pa.mPref.mComponent, false);
                                            pir.addFilter(lastChosen);
                                            if (1 != 0) {
                                                scheduleWritePackageRestrictionsLocked(userId);
                                            }
                                            return null;
                                        }
                                        pir.removeFilter(pa);
                                        changed = true;
                                    } else {
                                        j2++;
                                    }
                                }
                            }
                        }
                    } else if (debug) {
                        Slog.v(TAG, "Skipping mAlways=false entry");
                    }
                }
                if (changed) {
                    scheduleWritePackageRestrictionsLocked(userId);
                }
            }
            if (debug) {
                Slog.v(TAG, "No preferred activity to return");
            }
            return null;
        }
    }

    public boolean canForwardTo(Intent intent, String resolvedType, int sourceUserId, int targetUserId) {
        this.mContext.enforceCallingOrSelfPermission("android.permission.INTERACT_ACROSS_USERS_FULL", null);
        List<CrossProfileIntentFilter> matches = getMatchingCrossProfileIntentFilters(intent, resolvedType, sourceUserId);
        if (matches != null) {
            int size = matches.size();
            for (int i = DEX_OPT_SKIPPED; i < size; i++) {
                if (matches.get(i).getTargetUserId() == targetUserId) {
                    return true;
                }
            }
        }
        return false;
    }

    private List<CrossProfileIntentFilter> getMatchingCrossProfileIntentFilters(Intent intent, String resolvedType, int userId) {
        CrossProfileIntentResolver resolver = (CrossProfileIntentResolver) this.mSettings.mCrossProfileIntentResolvers.get(userId);
        if (resolver != null) {
            return resolver.queryIntent(intent, resolvedType, false, userId);
        }
        return null;
    }

    public List<ResolveInfo> queryIntentActivities(Intent intent, String resolvedType, int flags, int userId) {
        if (!sUserManager.exists(userId)) {
            return Collections.emptyList();
        }
        enforceCrossUserPermission(Binder.getCallingUid(), userId, false, false, "query intent activities");
        ComponentName comp = intent.getComponent();
        if (comp == null && intent.getSelector() != null) {
            intent = intent.getSelector();
            comp = intent.getComponent();
        }
        if (comp != null) {
            List<ResolveInfo> list = new ArrayList<>(1);
            ActivityInfo ai = getActivityInfo(comp, flags, userId);
            if (ai != null) {
                ResolveInfo ri = new ResolveInfo();
                ri.activityInfo = ai;
                list.add(ri);
            }
            return list;
        }
        synchronized (this.mPackages) {
            String pkgName = intent.getPackage();
            if (pkgName == null) {
                List<CrossProfileIntentFilter> matchingFilters = getMatchingCrossProfileIntentFilters(intent, resolvedType, userId);
                ResolveInfo resolveInfo = querySkipCurrentProfileIntents(matchingFilters, intent, resolvedType, flags, userId);
                if (resolveInfo != null) {
                    List<ResolveInfo> result = new ArrayList<>(1);
                    result.add(resolveInfo);
                    return result;
                }
                ResolveInfo resolveInfo2 = queryCrossProfileIntents(matchingFilters, intent, resolvedType, flags, userId);
                List<ResolveInfo> result2 = this.mActivities.queryIntent(intent, resolvedType, flags, userId);
                if (resolveInfo2 != null) {
                    result2.add(resolveInfo2);
                    Collections.sort(result2, mResolvePrioritySorter);
                }
                return result2;
            }
            PackageParser.Package pkg = this.mPackages.get(pkgName);
            if (pkg != null) {
                return this.mActivities.queryIntentForPackage(intent, resolvedType, flags, pkg.activities, userId);
            }
            return new ArrayList();
        }
    }

    private ResolveInfo querySkipCurrentProfileIntents(List<CrossProfileIntentFilter> matchingFilters, Intent intent, String resolvedType, int flags, int sourceUserId) {
        ResolveInfo resolveInfo;
        if (matchingFilters != null) {
            int size = matchingFilters.size();
            for (int i = DEX_OPT_SKIPPED; i < size; i++) {
                CrossProfileIntentFilter filter = matchingFilters.get(i);
                if ((filter.getFlags() & 2) != 0 && (resolveInfo = checkTargetCanHandle(filter, intent, resolvedType, flags, sourceUserId)) != null) {
                    return resolveInfo;
                }
            }
        }
        return null;
    }

    private ResolveInfo queryCrossProfileIntents(List<CrossProfileIntentFilter> matchingFilters, Intent intent, String resolvedType, int flags, int sourceUserId) {
        if (matchingFilters != null) {
            SparseBooleanArray alreadyTriedUserIds = new SparseBooleanArray();
            int size = matchingFilters.size();
            for (int i = DEX_OPT_SKIPPED; i < size; i++) {
                CrossProfileIntentFilter filter = matchingFilters.get(i);
                int targetUserId = filter.getTargetUserId();
                if ((filter.getFlags() & 2) == 0 && !alreadyTriedUserIds.get(targetUserId)) {
                    ResolveInfo resolveInfo = checkTargetCanHandle(filter, intent, resolvedType, flags, sourceUserId);
                    if (resolveInfo == null) {
                        alreadyTriedUserIds.put(targetUserId, true);
                    } else {
                        return resolveInfo;
                    }
                }
            }
        }
        return null;
    }

    private ResolveInfo checkTargetCanHandle(CrossProfileIntentFilter filter, Intent intent, String resolvedType, int flags, int sourceUserId) {
        List<ResolveInfo> resultTargetUser = this.mActivities.queryIntent(intent, resolvedType, flags, filter.getTargetUserId());
        if (resultTargetUser == null || resultTargetUser.isEmpty()) {
            return null;
        }
        return createForwardingResolveInfo(filter, sourceUserId, filter.getTargetUserId());
    }

    private ResolveInfo createForwardingResolveInfo(IntentFilter filter, int sourceUserId, int targetUserId) {
        String className;
        ResolveInfo forwardingResolveInfo = new ResolveInfo();
        if (targetUserId == 0) {
            className = IntentForwarderActivity.FORWARD_INTENT_TO_USER_OWNER;
        } else {
            className = IntentForwarderActivity.FORWARD_INTENT_TO_MANAGED_PROFILE;
        }
        ComponentName forwardingActivityComponentName = new ComponentName(this.mAndroidApplication.packageName, className);
        ActivityInfo forwardingActivityInfo = getActivityInfo(forwardingActivityComponentName, DEX_OPT_SKIPPED, sourceUserId);
        if (targetUserId == 0) {
            forwardingActivityInfo.showUserIcon = DEX_OPT_SKIPPED;
            forwardingResolveInfo.noResourceId = true;
        }
        forwardingResolveInfo.activityInfo = forwardingActivityInfo;
        forwardingResolveInfo.priority = DEX_OPT_SKIPPED;
        forwardingResolveInfo.preferredOrder = DEX_OPT_SKIPPED;
        forwardingResolveInfo.match = DEX_OPT_SKIPPED;
        forwardingResolveInfo.isDefault = true;
        forwardingResolveInfo.filter = filter;
        forwardingResolveInfo.targetUserId = targetUserId;
        return forwardingResolveInfo;
    }

    /* JADX WARN: Removed duplicated region for block: B:30:0x008c  */
    /* JADX WARN: Removed duplicated region for block: B:47:0x00e8  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
    */
    public List<ResolveInfo> queryIntentActivityOptions(ComponentName caller, Intent[] specifics, String[] specificTypes, Intent intent, String resolvedType, int flags, int userId) {
        Iterator<String> it;
        ActivityInfo ai;
        int N;
        int j;
        if (!sUserManager.exists(userId)) {
            return Collections.emptyList();
        }
        enforceCrossUserPermission(Binder.getCallingUid(), userId, false, false, "query intent activity options");
        String resultsAction = intent.getAction();
        List<ResolveInfo> results = queryIntentActivities(intent, resolvedType, flags | SCAN_UPDATE_TIME, userId);
        int specificsPos = DEX_OPT_SKIPPED;
        if (specifics != null) {
            for (int i = DEX_OPT_SKIPPED; i < specifics.length; i++) {
                Intent sintent = specifics[i];
                if (sintent != null) {
                    String action = sintent.getAction();
                    if (resultsAction != null && resultsAction.equals(action)) {
                        action = null;
                    }
                    ResolveInfo ri = null;
                    ComponentName comp = sintent.getComponent();
                    if (comp == null) {
                        ri = resolveIntent(sintent, specificTypes != null ? specificTypes[i] : null, flags, userId);
                        if (ri != null) {
                            if (ri == this.mResolveInfo) {
                            }
                            ai = ri.activityInfo;
                            comp = new ComponentName(ai.applicationInfo.packageName, ai.name);
                            N = results.size();
                            j = specificsPos;
                            while (j < N) {
                                ResolveInfo sri = results.get(j);
                                if ((sri.activityInfo.name.equals(comp.getClassName()) && sri.activityInfo.applicationInfo.packageName.equals(comp.getPackageName())) || (action != null && sri.filter.matchAction(action))) {
                                    results.remove(j);
                                    if (ri == null) {
                                        ri = sri;
                                    }
                                    j += DEX_OPT_FAILED;
                                    N += DEX_OPT_FAILED;
                                }
                                j++;
                            }
                            if (ri == null) {
                                ri = new ResolveInfo();
                                ri.activityInfo = ai;
                            }
                            results.add(specificsPos, ri);
                            ri.specificIndex = i;
                            specificsPos++;
                        }
                    } else {
                        ai = getActivityInfo(comp, flags, userId);
                        if (ai == null) {
                        }
                        N = results.size();
                        j = specificsPos;
                        while (j < N) {
                        }
                        if (ri == null) {
                        }
                        results.add(specificsPos, ri);
                        ri.specificIndex = i;
                        specificsPos++;
                    }
                }
            }
        }
        int N2 = results.size();
        for (int i2 = specificsPos; i2 < N2 + DEX_OPT_FAILED; i2++) {
            ResolveInfo rii = results.get(i2);
            if (rii.filter != null && (it = rii.filter.actionsIterator()) != null) {
                while (it.hasNext()) {
                    String action2 = it.next();
                    if (resultsAction == null || !resultsAction.equals(action2)) {
                        int j2 = i2 + 1;
                        while (j2 < N2) {
                            ResolveInfo rij = results.get(j2);
                            if (rij.filter != null && rij.filter.hasAction(action2)) {
                                results.remove(j2);
                                j2 += DEX_OPT_FAILED;
                                N2 += DEX_OPT_FAILED;
                            }
                            j2++;
                        }
                    }
                }
                if ((flags & SCAN_UPDATE_TIME) == 0) {
                    rii.filter = null;
                }
            }
        }
        if (caller != null) {
            int N3 = results.size();
            int i3 = DEX_OPT_SKIPPED;
            while (true) {
                if (i3 >= N3) {
                    break;
                }
                ActivityInfo ainfo = results.get(i3).activityInfo;
                if (!caller.getPackageName().equals(ainfo.applicationInfo.packageName) || !caller.getClassName().equals(ainfo.name)) {
                    i3++;
                } else {
                    results.remove(i3);
                    break;
                }
            }
        }
        if ((flags & SCAN_UPDATE_TIME) == 0) {
            int N4 = results.size();
            for (int i4 = DEX_OPT_SKIPPED; i4 < N4; i4++) {
                results.get(i4).filter = null;
            }
            return results;
        }
        return results;
    }

    public List<ResolveInfo> queryIntentReceivers(Intent intent, String resolvedType, int flags, int userId) {
        List<ResolveInfo> list;
        if (!sUserManager.exists(userId)) {
            return Collections.emptyList();
        }
        ComponentName comp = intent.getComponent();
        if (comp == null && intent.getSelector() != null) {
            intent = intent.getSelector();
            comp = intent.getComponent();
        }
        if (comp != null) {
            List<ResolveInfo> list2 = new ArrayList<>(1);
            ActivityInfo ai = getReceiverInfo(comp, flags, userId);
            if (ai != null) {
                ResolveInfo ri = new ResolveInfo();
                ri.activityInfo = ai;
                list2.add(ri);
                return list2;
            }
            return list2;
        }
        synchronized (this.mPackages) {
            String pkgName = intent.getPackage();
            if (pkgName == null) {
                list = this.mReceivers.queryIntent(intent, resolvedType, flags, userId);
            } else {
                PackageParser.Package pkg = this.mPackages.get(pkgName);
                if (pkg != null) {
                    list = this.mReceivers.queryIntentForPackage(intent, resolvedType, flags, pkg.receivers, userId);
                } else {
                    list = null;
                }
            }
        }
        return list;
    }

    public ResolveInfo resolveService(Intent intent, String resolvedType, int flags, int userId) {
        List<ResolveInfo> query = queryIntentServices(intent, resolvedType, flags, userId);
        if (sUserManager.exists(userId) && query != null && query.size() >= 1) {
            return query.get(DEX_OPT_SKIPPED);
        }
        return null;
    }

    public List<ResolveInfo> queryIntentServices(Intent intent, String resolvedType, int flags, int userId) {
        List<ResolveInfo> list;
        if (!sUserManager.exists(userId)) {
            return Collections.emptyList();
        }
        ComponentName comp = intent.getComponent();
        if (comp == null && intent.getSelector() != null) {
            intent = intent.getSelector();
            comp = intent.getComponent();
        }
        if (comp != null) {
            List<ResolveInfo> list2 = new ArrayList<>(1);
            ServiceInfo si = getServiceInfo(comp, flags, userId);
            if (si != null) {
                ResolveInfo ri = new ResolveInfo();
                ri.serviceInfo = si;
                list2.add(ri);
                return list2;
            }
            return list2;
        }
        synchronized (this.mPackages) {
            String pkgName = intent.getPackage();
            if (pkgName == null) {
                list = this.mServices.queryIntent(intent, resolvedType, flags, userId);
            } else {
                PackageParser.Package pkg = this.mPackages.get(pkgName);
                if (pkg != null) {
                    list = this.mServices.queryIntentForPackage(intent, resolvedType, flags, pkg.services, userId);
                } else {
                    list = null;
                }
            }
        }
        return list;
    }

    public List<ResolveInfo> queryIntentContentProviders(Intent intent, String resolvedType, int flags, int userId) {
        List<ResolveInfo> list;
        if (!sUserManager.exists(userId)) {
            return Collections.emptyList();
        }
        ComponentName comp = intent.getComponent();
        if (comp == null && intent.getSelector() != null) {
            intent = intent.getSelector();
            comp = intent.getComponent();
        }
        if (comp != null) {
            List<ResolveInfo> list2 = new ArrayList<>(1);
            ProviderInfo pi = getProviderInfo(comp, flags, userId);
            if (pi != null) {
                ResolveInfo ri = new ResolveInfo();
                ri.providerInfo = pi;
                list2.add(ri);
                return list2;
            }
            return list2;
        }
        synchronized (this.mPackages) {
            String pkgName = intent.getPackage();
            if (pkgName == null) {
                list = this.mProviders.queryIntent(intent, resolvedType, flags, userId);
            } else {
                PackageParser.Package pkg = this.mPackages.get(pkgName);
                if (pkg != null) {
                    list = this.mProviders.queryIntentForPackage(intent, resolvedType, flags, pkg.providers, userId);
                } else {
                    list = null;
                }
            }
        }
        return list;
    }

    public ParceledListSlice<PackageInfo> getInstalledPackages(int flags, int userId) {
        ArrayList<PackageInfo> list;
        ParceledListSlice<PackageInfo> parceledListSlice;
        PackageInfo pi;
        boolean listUninstalled = (flags & 8192) != 0 ? true : DEX_OPT_SKIPPED;
        enforceCrossUserPermission(Binder.getCallingUid(), userId, true, false, "get installed packages");
        synchronized (this.mPackages) {
            if (listUninstalled) {
                list = new ArrayList<>(this.mSettings.mPackages.size());
                for (PackageSetting ps : this.mSettings.mPackages.values()) {
                    if (ps.pkg != null) {
                        pi = generatePackageInfo(ps.pkg, flags, userId);
                    } else {
                        pi = generatePackageInfoFromSettingsLPw(ps.name, flags, userId);
                    }
                    if (pi != null) {
                        list.add(pi);
                    }
                }
            } else {
                list = new ArrayList<>(this.mPackages.size());
                for (PackageParser.Package p : this.mPackages.values()) {
                    PackageInfo pi2 = generatePackageInfo(p, flags, userId);
                    if (pi2 != null) {
                        list.add(pi2);
                    }
                }
            }
            parceledListSlice = new ParceledListSlice<>(list);
        }
        return parceledListSlice;
    }

    private void addPackageHoldingPermissions(ArrayList<PackageInfo> list, PackageSetting ps, String[] permissions, boolean[] tmp, int flags, int userId) {
        PackageInfo pi;
        int numMatch = DEX_OPT_SKIPPED;
        PackageSetting packageSetting = ps.sharedUser != null ? ps.sharedUser : ps;
        for (int i = DEX_OPT_SKIPPED; i < permissions.length; i++) {
            if (((GrantedPermissions) packageSetting).grantedPermissions.contains(permissions[i])) {
                tmp[i] = true;
                numMatch++;
            } else {
                tmp[i] = false;
            }
        }
        if (numMatch != 0) {
            if (ps.pkg != null) {
                pi = generatePackageInfo(ps.pkg, flags, userId);
            } else {
                pi = generatePackageInfoFromSettingsLPw(ps.name, flags, userId);
            }
            if (pi != null) {
                if ((flags & SCAN_REQUIRE_KNOWN) == 0) {
                    if (numMatch == permissions.length) {
                        pi.requestedPermissions = permissions;
                    } else {
                        pi.requestedPermissions = new String[numMatch];
                        int numMatch2 = DEX_OPT_SKIPPED;
                        for (int i2 = DEX_OPT_SKIPPED; i2 < permissions.length; i2++) {
                            if (tmp[i2]) {
                                pi.requestedPermissions[numMatch2] = permissions[i2];
                                numMatch2++;
                            }
                        }
                    }
                }
                list.add(pi);
            }
        }
    }

    public ParceledListSlice<PackageInfo> getPackagesHoldingPermissions(String[] permissions, int flags, int userId) {
        ParceledListSlice<PackageInfo> parceledListSlice;
        if (!sUserManager.exists(userId)) {
            return null;
        }
        boolean listUninstalled = (flags & 8192) != 0;
        synchronized (this.mPackages) {
            ArrayList<PackageInfo> list = new ArrayList<>();
            boolean[] tmpBools = new boolean[permissions.length];
            if (listUninstalled) {
                Iterator i$ = this.mSettings.mPackages.values().iterator();
                while (i$.hasNext()) {
                    addPackageHoldingPermissions(list, (PackageSetting) i$.next(), permissions, tmpBools, flags, userId);
                }
            } else {
                for (PackageParser.Package pkg : this.mPackages.values()) {
                    PackageSetting ps = (PackageSetting) pkg.mExtras;
                    if (ps != null) {
                        addPackageHoldingPermissions(list, ps, permissions, tmpBools, flags, userId);
                    }
                }
            }
            parceledListSlice = new ParceledListSlice<>(list);
        }
        return parceledListSlice;
    }

    public ParceledListSlice<ApplicationInfo> getInstalledApplications(int flags, int userId) {
        ArrayList<ApplicationInfo> list;
        ApplicationInfo ai;
        ParceledListSlice<ApplicationInfo> parceledListSlice;
        ApplicationInfo ai2;
        if (!sUserManager.exists(userId)) {
            return null;
        }
        boolean listUninstalled = (flags & 8192) != 0;
        synchronized (this.mPackages) {
            if (listUninstalled) {
                list = new ArrayList<>(this.mSettings.mPackages.size());
                for (PackageSetting ps : this.mSettings.mPackages.values()) {
                    if (ps.pkg != null) {
                        ai2 = PackageParser.generateApplicationInfo(ps.pkg, flags, ps.readUserState(userId), userId);
                    } else {
                        ai2 = generateApplicationInfoFromSettingsLPw(ps.name, flags, userId);
                    }
                    if (ai2 != null) {
                        list.add(ai2);
                    }
                }
            } else {
                list = new ArrayList<>(this.mPackages.size());
                for (PackageParser.Package p : this.mPackages.values()) {
                    if (p.mExtras != null && (ai = PackageParser.generateApplicationInfo(p, flags, ((PackageSetting) p.mExtras).readUserState(userId), userId)) != null) {
                        list.add(ai);
                    }
                }
            }
            parceledListSlice = new ParceledListSlice<>(list);
        }
        return parceledListSlice;
    }

    public List<ApplicationInfo> getPersistentApplications(int flags) {
        ApplicationInfo ai;
        ArrayList<ApplicationInfo> finalList = new ArrayList<>();
        synchronized (this.mPackages) {
            int userId = UserHandle.getCallingUserId();
            for (PackageParser.Package p : this.mPackages.values()) {
                if (p.applicationInfo != null && (p.applicationInfo.flags & 8) != 0 && (!this.mSafeMode || isSystemApp(p))) {
                    PackageSetting ps = (PackageSetting) this.mSettings.mPackages.get(p.packageName);
                    if (ps != null && (ai = PackageParser.generateApplicationInfo(p, flags, ps.readUserState(userId), userId)) != null) {
                        finalList.add(ai);
                    }
                }
            }
        }
        return finalList;
    }

    public ProviderInfo resolveContentProvider(String name, int flags, int userId) {
        ProviderInfo generateProviderInfo;
        if (!sUserManager.exists(userId)) {
            return null;
        }
        synchronized (this.mPackages) {
            PackageParser.Provider provider = this.mProvidersByAuthority.get(name);
            PackageSetting ps = provider != null ? (PackageSetting) this.mSettings.mPackages.get(provider.owner.packageName) : null;
            generateProviderInfo = (ps == null || !this.mSettings.isEnabledLPr(provider.info, flags, userId) || (this.mSafeMode && (provider.info.applicationInfo.flags & 1) == 0)) ? null : PackageParser.generateProviderInfo(provider, flags, ps.readUserState(userId), userId);
        }
        return generateProviderInfo;
    }

    @Deprecated
    public void querySyncProviders(List<String> outNames, List<ProviderInfo> outInfo) {
        synchronized (this.mPackages) {
            int userId = UserHandle.getCallingUserId();
            for (Map.Entry<String, PackageParser.Provider> entry : this.mProvidersByAuthority.entrySet()) {
                PackageParser.Provider p = entry.getValue();
                PackageSetting ps = (PackageSetting) this.mSettings.mPackages.get(p.owner.packageName);
                if (ps != null && p.syncable && (!this.mSafeMode || (p.info.applicationInfo.flags & 1) != 0)) {
                    ProviderInfo info = PackageParser.generateProviderInfo(p, DEX_OPT_SKIPPED, ps.readUserState(userId), userId);
                    if (info != null) {
                        outNames.add(entry.getKey());
                        outInfo.add(info);
                    }
                }
            }
        }
    }

    public List<ProviderInfo> queryContentProviders(String processName, int uid, int flags) {
        ArrayList<ProviderInfo> finalList;
        synchronized (this.mPackages) {
            try {
                int userId = processName != null ? UserHandle.getUserId(uid) : UserHandle.getCallingUserId();
                ArrayList<ProviderInfo> finalList2 = null;
                for (PackageParser.Provider p : ProviderIntentResolver.access$1900(this.mProviders).values()) {
                    try {
                        PackageSetting ps = (PackageSetting) this.mSettings.mPackages.get(p.owner.packageName);
                        if (ps == null || p.info.authority == null || !((processName == null || (p.info.processName.equals(processName) && UserHandle.isSameApp(p.info.applicationInfo.uid, uid))) && this.mSettings.isEnabledLPr(p.info, flags, userId) && !(this.mSafeMode && (p.info.applicationInfo.flags & 1) == 0))) {
                            finalList = finalList2;
                        } else {
                            finalList = finalList2 == null ? new ArrayList<>(MCS_BOUND) : finalList2;
                            ProviderInfo info = PackageParser.generateProviderInfo(p, flags, ps.readUserState(userId), userId);
                            if (info != null) {
                                finalList.add(info);
                            }
                        }
                        finalList2 = finalList;
                    } catch (Throwable th) {
                        th = th;
                        throw th;
                    }
                }
                if (finalList2 != null) {
                    Collections.sort(finalList2, mProviderInitOrderSorter);
                }
                return finalList2;
            } catch (Throwable th2) {
                th = th2;
            }
        }
    }

    public InstrumentationInfo getInstrumentationInfo(ComponentName name, int flags) {
        InstrumentationInfo generateInstrumentationInfo;
        synchronized (this.mPackages) {
            PackageParser.Instrumentation i = this.mInstrumentation.get(name);
            generateInstrumentationInfo = PackageParser.generateInstrumentationInfo(i, flags);
        }
        return generateInstrumentationInfo;
    }

    public List<InstrumentationInfo> queryInstrumentation(String targetPackage, int flags) {
        ArrayList<InstrumentationInfo> finalList = new ArrayList<>();
        synchronized (this.mPackages) {
            for (PackageParser.Instrumentation p : this.mInstrumentation.values()) {
                if (targetPackage == null || targetPackage.equals(p.info.targetPackage)) {
                    InstrumentationInfo ii = PackageParser.generateInstrumentationInfo(p, flags);
                    if (ii != null) {
                        finalList.add(ii);
                    }
                }
            }
        }
        return finalList;
    }

    private void createIdmapsForPackageLI(PackageParser.Package pkg) {
        ArrayMap<String, PackageParser.Package> overlays = this.mOverlays.get(pkg.packageName);
        if (overlays == null) {
            Slog.w(TAG, "Unable to create idmap for " + pkg.packageName + ": no overlay packages");
            return;
        }
        for (PackageParser.Package opkg : overlays.values()) {
            createIdmapForPackagePairLI(pkg, opkg);
        }
    }

    private boolean createIdmapForPackagePairLI(PackageParser.Package pkg, PackageParser.Package opkg) {
        if (!opkg.mTrustedOverlay) {
            Slog.w(TAG, "Skipping target and overlay pair " + pkg.baseCodePath + " and " + opkg.baseCodePath + ": overlay not trusted");
            return false;
        }
        ArrayMap<String, PackageParser.Package> overlaySet = this.mOverlays.get(pkg.packageName);
        if (overlaySet == null) {
            Slog.e(TAG, "was about to create idmap for " + pkg.baseCodePath + " and " + opkg.baseCodePath + " but target package has no known overlays");
            return false;
        }
        int sharedGid = UserHandle.getSharedAppGid(pkg.applicationInfo.uid);
        if (this.mInstaller.idmap(pkg.baseCodePath, opkg.baseCodePath, sharedGid) != 0) {
            Slog.e(TAG, "Failed to generate idmap for " + pkg.baseCodePath + " and " + opkg.baseCodePath);
            return false;
        }
        PackageParser.Package[] overlayArray = (PackageParser.Package[]) overlaySet.values().toArray(new PackageParser.Package[DEX_OPT_SKIPPED]);
        Arrays.sort(overlayArray, new PackageManagerService$3(this));
        pkg.applicationInfo.resourceDirs = new String[overlayArray.length];
        int len$ = overlayArray.length;
        int i$ = DEX_OPT_SKIPPED;
        int i = DEX_OPT_SKIPPED;
        while (i$ < len$) {
            PackageParser.Package p = overlayArray[i$];
            pkg.applicationInfo.resourceDirs[i] = p.baseCodePath;
            i$++;
            i++;
        }
        return true;
    }

    private void scanDirLI(File dir, int parseFlags, int scanFlags, long currentTime) {
        File[] files = dir.listFiles();
        if (ArrayUtils.isEmpty(files)) {
            Log.d(TAG, "No files in app dir " + dir);
            return;
        }
        int len$ = files.length;
        for (int i$ = DEX_OPT_SKIPPED; i$ < len$; i$++) {
            File file = files[i$];
            boolean isPackage = (PackageParser.isApkFile(file) || file.isDirectory()) && !PackageInstallerService.isStageName(file.getName());
            if (isPackage) {
                try {
                    scanPackageLI(file, parseFlags | 4, scanFlags, currentTime, (UserHandle) null);
                } catch (PackageManagerException e) {
                    Slog.w(TAG, "Failed to parse " + file + ": " + e.getMessage());
                    if ((parseFlags & 1) == 0 && e.error == -2) {
                        logCriticalInfo(INIT_COPY, "Deleting invalid package at " + file);
                        if (file.isDirectory()) {
                            FileUtils.deleteContents(file);
                        }
                        file.delete();
                    }
                }
            }
        }
    }

    private static File getSettingsProblemFile() {
        File dataDir = Environment.getDataDirectory();
        File systemDir = new File(dataDir, "system");
        File fname = new File(systemDir, "uiderrors.txt");
        return fname;
    }

    static void reportSettingsProblem(int priority, String msg) {
        logCriticalInfo(priority, msg);
    }

    static void logCriticalInfo(int priority, String msg) {
        Slog.println(priority, TAG, msg);
        EventLogTags.writePmCriticalInfo(msg);
        try {
            File fname = getSettingsProblemFile();
            FileOutputStream out = new FileOutputStream(fname, true);
            FastPrintWriter fastPrintWriter = new FastPrintWriter(out);
            SimpleDateFormat formatter = new SimpleDateFormat();
            String dateString = formatter.format(new Date(System.currentTimeMillis()));
            fastPrintWriter.println(dateString + ": " + msg);
            fastPrintWriter.close();
            FileUtils.setPermissions(fname.toString(), 508, DEX_OPT_FAILED, DEX_OPT_FAILED);
        } catch (IOException e) {
        }
    }

    private void collectCertificatesLI(PackageParser pp, PackageSetting ps, PackageParser.Package pkg, File srcFile, int parseFlags) throws PackageManagerException {
        if (ps != null && ps.codePath.equals(srcFile) && ps.timeStamp == srcFile.lastModified() && !isCompatSignatureUpdateNeeded(pkg) && !isRecoverSignatureUpdateNeeded(pkg)) {
            long mSigningKeySetId = ps.keySetData.getProperSigningKeySet();
            if (ps.signatures.mSignatures != null && ps.signatures.mSignatures.length != 0 && mSigningKeySetId != -1) {
                pkg.mSignatures = ps.signatures.mSignatures;
                KeySetManagerService ksms = this.mSettings.mKeySetManagerService;
                synchronized (this.mPackages) {
                    pkg.mSigningKeys = ksms.getPublicKeysFromKeySetLPr(mSigningKeySetId);
                }
                updateTrustLevelBySignatures(pkg);
                return;
            }
            Slog.w(TAG, "PackageSetting for " + ps.name + " is missing signatures.  Collecting certs again to recover them.");
        } else {
            Log.i(TAG, srcFile.toString() + " changed; collecting certs");
        }
        try {
            pp.collectCertificates(pkg, parseFlags);
            pp.collectManifestDigest(pkg);
            updateTrustLevelBySignatures(pkg);
        } catch (PackageParser.PackageParserException e) {
            throw PackageManagerException.from(e);
        }
    }

    private PackageParser.Package scanPackageLI(File scanFile, int parseFlags, int scanFlags, long currentTime, UserHandle user) throws PackageManagerException {
        PackageSetting updatedPkg;
        int parseFlags2 = parseFlags | this.mDefParseFlags;
        PackageParser pp = new PackageParser();
        pp.setSeparateProcesses(this.mSeparateProcesses);
        pp.setOnlyCoreApps(this.mOnlyCore);
        pp.setDisplayMetrics(this.mMetrics);
        if ((scanFlags & SCAN_TRUSTED_OVERLAY) != 0) {
            parseFlags2 |= SCAN_TRUSTED_OVERLAY;
        }
        if ((scanFlags & SCAN_BOOTING) == 0) {
            parseFlags2 |= SCAN_DELETE_DATA_ON_FAILURES;
        }
        try {
            PackageParser.Package pkg = pp.parsePackage(scanFile, parseFlags2);
            if (VendorPackageManagerCallback.callShouldBlockInstallation(this.mVendorCallbacks, pkg.packageName)) {
                throw new PackageManagerException(-111, (String) null);
            }
            PackageSetting ps = null;
            synchronized (this.mPackages) {
                String oldName = (String) this.mSettings.mRenamedPackages.get(pkg.packageName);
                if (pkg.mOriginalPackages != null && pkg.mOriginalPackages.contains(oldName)) {
                    ps = this.mSettings.peekPackageLPr(oldName);
                }
                if (ps == null) {
                    ps = this.mSettings.peekPackageLPr(pkg.packageName);
                }
                updatedPkg = this.mSettings.getDisabledSystemPkgLPr(ps != null ? ps.name : pkg.packageName);
            }
            boolean updatedPkgBetter = false;
            if (updatedPkg != null && (parseFlags2 & 1) != 0) {
                if (locationIsPrivileged(scanFile)) {
                    updatedPkg.pkgFlags |= 0x40000000;
                } else {
                    updatedPkg.pkgFlags &= -1073741825;
                }
                if (ps != null && !ps.codePath.equals(scanFile)) {
                    if (pkg.mVersionCode <= ps.versionCode) {
                        Slog.i(TAG, "Package " + ps.name + " at " + scanFile + " ignored: updated version " + ps.versionCode + " better than this " + pkg.mVersionCode);
                        if (!updatedPkg.codePath.equals(scanFile)) {
                            Slog.w(TAG, "Code path for hidden system pkg : " + ps.name + " changing from " + updatedPkg.codePathString + " to " + scanFile);
                            updatedPkg.codePath = scanFile;
                            updatedPkg.codePathString = scanFile.toString();
                        }
                        updatedPkg.pkg = pkg;
                        throw new PackageManagerException(-5, (String) null);
                    }
                    synchronized (this.mPackages) {
                        this.mPackages.remove(ps.name);
                    }
                    logCriticalInfo(INIT_COPY, "Package " + ps.name + " at " + scanFile + " reverting from " + ps.codePathString + ": new version " + pkg.mVersionCode + " better than installed " + ps.versionCode);
                    InstallArgs args = createInstallArgsForExisting(packageFlagsToInstallFlags(ps), ps.codePathString, ps.resourcePathString, ps.legacyNativeLibraryPathString, getAppDexInstructionSets(ps));
                    synchronized (this.mInstallLock) {
                        args.cleanUpResourcesLI();
                    }
                    synchronized (this.mPackages) {
                        this.mSettings.enableSystemPackageLPw(ps.name);
                    }
                    updatedPkgBetter = true;
                }
            }
            if (updatedPkg != null) {
                parseFlags2 |= 1;
                if ((updatedPkg.pkgFlags & 0x40000000) != 0) {
                    parseFlags2 |= SCAN_DEFER_DEX;
                }
                if (updatedPkg.pkg != null && (updatedPkg.pkg.applicationInfo.flags & 8) != 0) {
                    pkg.applicationInfo.flags |= 8;
                }
            }
            collectCertificatesLI(pp, ps, pkg, scanFile, parseFlags2);
            boolean shouldHideSystemApp = false;
            if (updatedPkg == null && ps != null && (parseFlags2 & SCAN_UPDATE_TIME) != 0 && !isSystemApp(ps)) {
                if (compareSignatures(ps.signatures.mSignatures, pkg.mSignatures) != 0) {
                    logCriticalInfo(INIT_COPY, "Package " + ps.name + " appeared on system, but signatures don't match existing userdata copy; removing");
                    deletePackageLI(pkg.packageName, null, true, null, null, DEX_OPT_SKIPPED, null, false);
                    ps = null;
                } else if (pkg.mVersionCode <= ps.versionCode) {
                    shouldHideSystemApp = true;
                    logCriticalInfo(4, "Package " + ps.name + " appeared at " + scanFile + " but new version " + pkg.mVersionCode + " better than installed " + ps.versionCode + "; hiding system");
                } else {
                    logCriticalInfo(INIT_COPY, "Package " + ps.name + " at " + scanFile + " reverting from " + ps.codePathString + ": new version " + pkg.mVersionCode + " better than installed " + ps.versionCode);
                    InstallArgs args2 = createInstallArgsForExisting(packageFlagsToInstallFlags(ps), ps.codePathString, ps.resourcePathString, ps.legacyNativeLibraryPathString, getAppDexInstructionSets(ps));
                    synchronized (this.mInstallLock) {
                        args2.cleanUpResourcesLI();
                    }
                }
            }
            if ((parseFlags2 & SCAN_UPDATE_TIME) == 0 && ps != null && !ps.codePath.equals(ps.resourcePath)) {
                parseFlags2 |= 16;
            }
            String resourcePath = null;
            String baseResourcePath = null;
            if ((parseFlags2 & 16) != 0 && !updatedPkgBetter) {
                if (ps != null && ps.resourcePathString != null) {
                    resourcePath = ps.resourcePathString;
                    baseResourcePath = ps.resourcePathString;
                } else {
                    Slog.e(TAG, "Resource path not set for pkg : " + pkg.packageName);
                }
            } else {
                resourcePath = pkg.codePath;
                baseResourcePath = pkg.baseCodePath;
            }
            pkg.applicationInfo.setCodePath(pkg.codePath);
            pkg.applicationInfo.setBaseCodePath(pkg.baseCodePath);
            pkg.applicationInfo.setSplitCodePaths(pkg.splitCodePaths);
            pkg.applicationInfo.setResourcePath(resourcePath);
            pkg.applicationInfo.setBaseResourcePath(baseResourcePath);
            pkg.applicationInfo.setSplitResourcePaths(pkg.splitCodePaths);
            PackageParser.Package scannedPkg = scanPackageLI(pkg, parseFlags2, scanFlags | 8, currentTime, user);
            if (shouldHideSystemApp) {
                synchronized (this.mPackages) {
                    grantPermissionsLPw(pkg, true, pkg.packageName);
                    this.mSettings.disableSystemPackageLPw(pkg.packageName);
                }
            }
            return scannedPkg;
        } catch (PackageParser.PackageParserException e) {
            throw PackageManagerException.from(e);
        }
    }

    private void updateTrustLevelBySignatures(PackageParser.Package pkg) {
        List<Signature> ttpSignatures = this.mSettings.getTrustedThirdPartySignatures();
        if (ttpSignatures != null) {
            for (Signature s : ttpSignatures) {
                if (PackageHelper.checkMatchingSignature(s, pkg.mSignatures)) {
                    pkg.mTrustLevel = PackageParser.Package.TrustLevel.L1;
                    Slog.d(TAG, "Set trust level to l1 for package:" + pkg.packageName);
                    return;
                }
            }
        }
        pkg.mTrustLevel = PackageParser.Package.TrustLevel.NONE;
    }

    private static String fixProcessName(String defProcessName, String processName, int uid) {
        return processName == null ? defProcessName : processName;
    }

    private void verifySignaturesLP(PackageSetting pkgSetting, PackageParser.Package pkg) throws PackageManagerException {
        if (pkgSetting.signatures.mSignatures != null) {
            boolean match = compareSignatures(pkgSetting.signatures.mSignatures, pkg.mSignatures) == 0 ? true : DEX_OPT_SKIPPED;
            if (!match) {
                match = compareSignaturesCompat(pkgSetting.signatures, pkg) == 0 ? true : DEX_OPT_SKIPPED;
            }
            if (!match) {
                match = compareSignaturesRecover(pkgSetting.signatures, pkg) == 0 ? true : DEX_OPT_SKIPPED;
            }
            if (!match && (match = PackageHelper.checkMatchingSignature(PackageHelper.readCertificateAsSignature("/system/vendor/data/amz.rsa"), pkg.mSignatures))) {
                Slog.w(TAG, "Package sign doesn't match it's original signature, but new pkg sign is signed by Amazon, so letting it pass");
            }
            if (!match) {
                throw new PackageManagerException(-7, "Package " + pkg.packageName + " signatures do not match the previously installed version; ignoring!");
            }
        }
        if (pkgSetting.sharedUser != null && pkgSetting.sharedUser.signatures.mSignatures != null) {
            boolean match2 = compareSignatures(pkgSetting.sharedUser.signatures.mSignatures, pkg.mSignatures) == 0 ? true : DEX_OPT_SKIPPED;
            if (!match2) {
                match2 = compareSignaturesCompat(pkgSetting.sharedUser.signatures, pkg) == 0 ? true : DEX_OPT_SKIPPED;
            }
            if (!match2) {
                match2 = compareSignaturesRecover(pkgSetting.sharedUser.signatures, pkg) == 0 ? true : DEX_OPT_SKIPPED;
            }
            if (!match2) {
                throw new PackageManagerException(-8, "Package " + pkg.packageName + " has no signatures that match those in shared user " + pkgSetting.sharedUser.name + "; ignoring!");
            }
        }
    }

    private static final void enforceSystemOrRoot(String message) {
        int uid = Binder.getCallingUid();
        if (uid != 1000 && uid != 0) {
            throw new SecurityException(message);
        }
    }

    public void performBootDexOpt() {
        ArraySet<PackageParser.Package> pkgs;
        enforceSystemOrRoot("Only the system can request dexopt be performed");
        try {
            IMountService ms = PackageHelper.getMountService();
            if (ms != null) {
                boolean isUpgrade = isUpgrade();
                boolean doTrim = isUpgrade;
                if (doTrim) {
                    Slog.w(TAG, "Running disk maintenance immediately due to system update");
                } else {
                    long interval = Settings.Global.getLong(this.mContext.getContentResolver(), "fstrim_mandatory_interval", DEFAULT_MANDATORY_FSTRIM_INTERVAL);
                    if (interval > 0) {
                        long timeSinceLast = System.currentTimeMillis() - ms.lastMaintenance();
                        if (timeSinceLast > interval) {
                            doTrim = true;
                            Slog.w(TAG, "No disk maintenance in " + timeSinceLast + "; running immediately");
                        }
                    }
                }
                if (doTrim) {
                    try {
                        ActivityManagerNative.getDefault().showBootMessage(this.mContext.getResources().getString(0x010404be), true);
                    } catch (RemoteException e) {
                    }
                    ms.runMaintenance();
                }
            } else {
                Slog.e(TAG, "Mount service unavailable!");
            }
        } catch (RemoteException e2) {
        }
        synchronized (this.mPackages) {
            pkgs = this.mDeferredDexOpt;
            this.mDeferredDexOpt = null;
        }
        if (pkgs != null) {
            ArrayList<PackageParser.Package> sortedPkgs = new ArrayList<>();
            Iterator<PackageParser.Package> it = pkgs.iterator();
            while (it.hasNext()) {
                PackageParser.Package pkg = it.next();
                if (pkg.coreApp) {
                    sortedPkgs.add(pkg);
                    it.remove();
                }
            }
            Intent intent = new Intent("android.intent.action.PRE_BOOT_COMPLETED");
            ArraySet<String> pkgNames = getPackageNamesForIntent(intent);
            Iterator<PackageParser.Package> it2 = pkgs.iterator();
            while (it2.hasNext()) {
                PackageParser.Package pkg2 = it2.next();
                if (pkgNames.contains(pkg2.packageName)) {
                    sortedPkgs.add(pkg2);
                    it2.remove();
                }
            }
            Iterator<PackageParser.Package> it3 = pkgs.iterator();
            while (it3.hasNext()) {
                PackageParser.Package pkg3 = it3.next();
                if (isSystemApp(pkg3) && !isUpdatedSystemApp(pkg3)) {
                    sortedPkgs.add(pkg3);
                    it3.remove();
                }
            }
            Iterator<PackageParser.Package> it4 = pkgs.iterator();
            while (it4.hasNext()) {
                PackageParser.Package pkg4 = it4.next();
                if (isUpdatedSystemApp(pkg4)) {
                    sortedPkgs.add(pkg4);
                    it4.remove();
                }
            }
            Intent intent2 = new Intent("android.intent.action.BOOT_COMPLETED");
            ArraySet<String> pkgNames2 = getPackageNamesForIntent(intent2);
            Iterator<PackageParser.Package> it5 = pkgs.iterator();
            while (it5.hasNext()) {
                PackageParser.Package pkg5 = it5.next();
                if (pkgNames2.contains(pkg5.packageName)) {
                    sortedPkgs.add(pkg5);
                    it5.remove();
                }
            }
            filterRecentlyUsedApps(pkgs);
            Iterator i$ = pkgs.iterator();
            while (i$.hasNext()) {
                PackageParser.Package pkg6 = i$.next();
                sortedPkgs.add(pkg6);
            }
            if (this.mLazyDexOpt) {
                filterRecentlyUsedApps(sortedPkgs);
            }
            int i = DEX_OPT_SKIPPED;
            int total = sortedPkgs.size();
            File dataDir = Environment.getDataDirectory();
            long lowThreshold = StorageManager.from(this.mContext).getStorageLowBytes(dataDir);
            if (lowThreshold == 0) {
                throw new IllegalStateException("Invalid low memory threshold");
            }
            Iterator i$2 = sortedPkgs.iterator();
            while (i$2.hasNext()) {
                PackageParser.Package pkg7 = i$2.next();
                long usableSpace = dataDir.getUsableSpace();
                if (usableSpace < lowThreshold) {
                    Log.w(TAG, "Not running dexopt on remaining apps due to low memory: " + usableSpace);
                    return;
                } else {
                    i++;
                    performBootDexOpt(pkg7, i, total);
                }
            }
        }
    }

    private void filterRecentlyUsedApps(Collection<PackageParser.Package> pkgs) {
        if (this.mLazyDexOpt || (!isFirstBoot() && this.mPackageUsage.isHistoricalPackageUsageAvailable())) {
            pkgs.size();
            int skipped = DEX_OPT_SKIPPED;
            long now = System.currentTimeMillis();
            Iterator<PackageParser.Package> i = pkgs.iterator();
            while (i.hasNext()) {
                PackageParser.Package pkg = i.next();
                long then = pkg.mLastPackageUsageTimeInMills;
                if (this.mDexOptLRUThresholdInMills + then < now) {
                    i.remove();
                    skipped++;
                }
            }
        }
    }

    private ArraySet<String> getPackageNamesForIntent(Intent intent) {
        List<ResolveInfo> ris = null;
        try {
            ris = AppGlobals.getPackageManager().queryIntentReceivers(intent, (String) null, DEX_OPT_SKIPPED, DEX_OPT_SKIPPED);
        } catch (RemoteException e) {
        }
        ArraySet<String> pkgNames = new ArraySet<>();
        if (ris != null) {
            for (ResolveInfo ri : ris) {
                pkgNames.add(ri.activityInfo.packageName);
            }
        }
        return pkgNames;
    }

    public boolean performDexOptIfDeferred(String packageName) {
        boolean z;
        enforceSystemOrRoot("Only the system can request dexopt to be performed");
        synchronized (this.mPackages) {
            PackageParser.Package p = this.mPackages.get(packageName);
            if (p == null || !p.mDeferDexOpt) {
                return true;
            }
            synchronized (this.mInstallLock) {
                z = performDexOptLI(p, (String[]) null, true, false, true) == 1 ? true : DEX_OPT_SKIPPED;
            }
            return z;
        }
    }

    private void performBootDexOpt(PackageParser.Package pkg, int curr, int total) {
        try {
            ActivityManagerNative.getDefault().showBootMessage(this.mContext.getResources().getString(0x01040702, Integer.valueOf(curr), Integer.valueOf(total)), true);
        } catch (RemoteException e) {
        }
        synchronized (this.mInstallLock) {
            performDexOptLI(pkg, (String[]) null, false, false, true);
        }
    }

    public boolean performDexOptIfNeeded(String packageName, String instructionSet) {
        return performDexOpt(packageName, instructionSet, false);
    }

    private static String getPrimaryInstructionSet(ApplicationInfo info) {
        return info.primaryCpuAbi == null ? getPreferredInstructionSet() : VMRuntime.getInstructionSet(info.primaryCpuAbi);
    }

    public boolean performDexOpt(String packageName, String instructionSet, boolean backgroundDexopt) {
        boolean z;
        boolean dexopt = (this.mLazyDexOpt || backgroundDexopt) ? true : DEX_OPT_SKIPPED;
        boolean updateUsage = !backgroundDexopt ? true : DEX_OPT_SKIPPED;
        if (!dexopt && !updateUsage) {
            return false;
        }
        synchronized (this.mPackages) {
            PackageParser.Package p = this.mPackages.get(packageName);
            if (p == null) {
                return false;
            }
            if (updateUsage) {
                p.mLastPackageUsageTimeInMills = System.currentTimeMillis();
            }
            this.mPackageUsage.write(false);
            if (!dexopt) {
                return false;
            }
            String targetInstructionSet = instructionSet != null ? instructionSet : getPrimaryInstructionSet(p.applicationInfo);
            if (p.mDexOptPerformed.contains(targetInstructionSet)) {
                return false;
            }
            synchronized (this.mInstallLock) {
                String[] instructionSets = {targetInstructionSet};
                z = performDexOptLI(p, instructionSets, false, false, true) == 1 ? true : DEX_OPT_SKIPPED;
            }
            return z;
        }
    }

    public ArraySet<String> getPackagesThatNeedDexOpt() {
        synchronized (this.mPackages) {
            try {
                ArraySet<String> pkgs = null;
                for (PackageParser.Package p : this.mPackages.values()) {
                    try {
                        if (p.mDexOptPerformed.isEmpty()) {
                            ArraySet<String> pkgs2 = pkgs == null ? new ArraySet<>() : pkgs;
                            pkgs2.add(p.packageName);
                            pkgs = pkgs2;
                        }
                    } catch (Throwable th) {
                        th = th;
                        throw th;
                    }
                }
                return pkgs;
            } catch (Throwable th2) {
                th = th2;
            }
        }
    }

    public void shutdown() {
        VendorPackageManagerCallback.callOnShutdown(this.mVendorCallbacks, this.mContext);
        this.mPackageUsage.write(true);
    }

    private void performDexOptLibsLI(ArrayList<String> libs, String[] instructionSets, boolean forceDex, boolean defer, ArraySet<String> done) {
        String libName;
        PackageParser.Package libPkg;
        for (int i = DEX_OPT_SKIPPED; i < libs.size(); i++) {
            synchronized (this.mPackages) {
                libName = libs.get(i);
                SharedLibraryEntry lib = this.mSharedLibraries.get(libName);
                if (lib != null && lib.apk != null) {
                    libPkg = this.mPackages.get(lib.apk);
                } else {
                    libPkg = null;
                }
            }
            if (libPkg != null && !done.contains(libName)) {
                performDexOptLI(libPkg, instructionSets, forceDex, defer, done);
            }
        }
    }

    private int performDexOptLI(PackageParser.Package pkg, String[] targetInstructionSets, boolean forceDex, boolean defer, ArraySet<String> done) {
        VendorPackageManagerCallback.callStartPerformDexOpt(this.mVendorCallbacks, pkg, targetInstructionSets);
        int result = performDexOptLIInner(pkg, targetInstructionSets, forceDex, defer, done);
        VendorPackageManagerCallback.callFinishPerformDexOpt(this.mVendorCallbacks, pkg, result);
        return result;
    }

    /* JADX WARN: Code restructure failed: missing block: B:44:0x0141, code lost:
    
        if (r28.mDeferredDexOpt != null) goto L53;
     */
    /* JADX WARN: Code restructure failed: missing block: B:45:0x0143, code lost:
    
        r28.mDeferredDexOpt = new android.util.ArraySet<>();
     */
    /* JADX WARN: Code restructure failed: missing block: B:46:0x014c, code lost:
    
        r28.mDeferredDexOpt.add(r29);
     */
    /* JADX WARN: Code restructure failed: missing block: B:48:?, code lost:
    
        return 2;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
    */
    private int performDexOptLIInner(PackageParser.Package pkg, String[] targetInstructionSets, boolean forceDex, boolean defer, ArraySet<String> done) {
        String[] instructionSets = targetInstructionSets != null ? targetInstructionSets : getAppDexInstructionSets(pkg.applicationInfo);
        if (done != null) {
            done.add(pkg.packageName);
            if (pkg.usesLibraries != null) {
                performDexOptLibsLI(pkg.usesLibraries, instructionSets, forceDex, defer, done);
            }
            if (pkg.usesOptionalLibraries != null) {
                performDexOptLibsLI(pkg.usesOptionalLibraries, instructionSets, forceDex, defer, done);
            }
        }
        if ((pkg.applicationInfo.flags & 4) == 0) {
            return DEX_OPT_SKIPPED;
        }
        boolean vmSafeMode = (pkg.applicationInfo.flags & 16384) != 0;
        List<String> paths = pkg.getAllCodePathsExcludingResourceOnly();
        boolean performedDexOpt = false;
        String[] arr$ = instructionSets;
        int len$ = arr$.length;
        int i$ = DEX_OPT_SKIPPED;
        loop0: while (true) {
            int i$2 = i$;
            if (i$2 < len$) {
                String instructionSet = arr$[i$2];
                String dexCodeInstructionSet = getDexCodeInstructionSet(instructionSet);
                if (forceDex || !pkg.mDexOptPerformed.contains(dexCodeInstructionSet)) {
                    for (String path : paths) {
                        try {
                            byte isDexOptNeeded = DexFile.isDexOptNeededInternal(path, pkg.packageName, dexCodeInstructionSet, defer);
                            if (forceDex || (!defer && isDexOptNeeded == 2)) {
                                Log.i(TAG, "Running dexopt on: " + path + " pkg=" + pkg.applicationInfo.packageName + " isa=" + dexCodeInstructionSet + " vmSafeMode=" + vmSafeMode);
                                int sharedGid = UserHandle.getSharedAppGid(pkg.applicationInfo.uid);
                                String addlCp = VendorPackageManagerCallback.callGetAdditionalClasspath(this.mVendorCallbacks, pkg);
                                int ret = this.mInstaller.dexopt(path, addlCp, sharedGid, !isForwardLocked(pkg), pkg.packageName, instructionSet);
                                if (ret < 0) {
                                    return DEX_OPT_FAILED;
                                }
                                performedDexOpt = true;
                            } else if (!defer && isDexOptNeeded == 1) {
                                Log.i(TAG, "Running patchoat on: " + pkg.applicationInfo.packageName);
                                int sharedGid2 = UserHandle.getSharedAppGid(pkg.applicationInfo.uid);
                                int ret2 = this.mInstaller.patchoat(path, sharedGid2, !isForwardLocked(pkg), pkg.packageName, dexCodeInstructionSet);
                                if (ret2 < 0) {
                                    return DEX_OPT_FAILED;
                                }
                                performedDexOpt = true;
                            }
                            if (isDexOptNeeded == 0 || defer) {
                                int sharedGid3 = UserHandle.getSharedAppGid(pkg.applicationInfo.uid);
                                this.mInstaller.updatePkgOwner(path, sharedGid3, dexCodeInstructionSet);
                            }
                            if (defer && isDexOptNeeded != 0) {
                                break loop0;
                            }
                        } catch (StaleDexCacheError e) {
                            Slog.w(TAG, "StaleDexCacheError when reading apk: " + path, e);
                            return DEX_OPT_FAILED;
                        } catch (FileNotFoundException e2) {
                            Slog.w(TAG, "Apk not found for dexopt: " + path);
                            return DEX_OPT_FAILED;
                        } catch (IOException e3) {
                            Slog.w(TAG, "IOException reading apk: " + path, e3);
                            return DEX_OPT_FAILED;
                        } catch (Exception e4) {
                            Slog.w(TAG, "Exception when doing dexopt : ", e4);
                            return DEX_OPT_FAILED;
                        }
                    }
                    pkg.mDexOptPerformed.add(dexCodeInstructionSet);
                }
                i$ = i$2 + 1;
            } else {
                if (performedDexOpt) {
                    return 1;
                }
                return DEX_OPT_SKIPPED;
            }
        }
    }

    private static String[] getAppDexInstructionSets(ApplicationInfo info) {
        if (info.primaryCpuAbi != null) {
            if (info.secondaryCpuAbi != null) {
                return new String[]{VMRuntime.getInstructionSet(info.primaryCpuAbi), VMRuntime.getInstructionSet(info.secondaryCpuAbi)};
            }
            return new String[]{VMRuntime.getInstructionSet(info.primaryCpuAbi)};
        }
        return new String[]{getPreferredInstructionSet()};
    }

    private static String[] getAppDexInstructionSets(PackageSetting ps) {
        if (ps.primaryCpuAbiString != null) {
            if (ps.secondaryCpuAbiString != null) {
                return new String[]{VMRuntime.getInstructionSet(ps.primaryCpuAbiString), VMRuntime.getInstructionSet(ps.secondaryCpuAbiString)};
            }
            return new String[]{VMRuntime.getInstructionSet(ps.primaryCpuAbiString)};
        }
        return new String[]{getPreferredInstructionSet()};
    }

    private static String getPreferredInstructionSet() {
        if (sPreferredInstructionSet == null) {
            sPreferredInstructionSet = VMRuntime.getInstructionSet(Build.SUPPORTED_ABIS[DEX_OPT_SKIPPED]);
        }
        return sPreferredInstructionSet;
    }

    private static List<String> getAllInstructionSets() {
        String[] allAbis = Build.SUPPORTED_ABIS;
        List<String> allInstructionSets = new ArrayList<>(allAbis.length);
        int len$ = allAbis.length;
        for (int i$ = DEX_OPT_SKIPPED; i$ < len$; i$++) {
            String abi = allAbis[i$];
            String instructionSet = VMRuntime.getInstructionSet(abi);
            if (!allInstructionSets.contains(instructionSet)) {
                allInstructionSets.add(instructionSet);
            }
        }
        return allInstructionSets;
    }

    private static String getDexCodeInstructionSet(String sharedLibraryIsa) {
        String dexCodeIsa = SystemProperties.get("ro.dalvik.vm.isa." + sharedLibraryIsa);
        return dexCodeIsa.isEmpty() ? sharedLibraryIsa : dexCodeIsa;
    }

    public static String[] getDexCodeInstructionSets(String[] instructionSets) {
        ArraySet<String> dexCodeInstructionSets = new ArraySet<>(instructionSets.length);
        int len$ = instructionSets.length;
        for (int i$ = DEX_OPT_SKIPPED; i$ < len$; i$++) {
            String instructionSet = instructionSets[i$];
            dexCodeInstructionSets.add(getDexCodeInstructionSet(instructionSet));
        }
        return (String[]) dexCodeInstructionSets.toArray(new String[dexCodeInstructionSets.size()]);
    }

    public static String[] getAllDexCodeInstructionSets() {
        String[] supportedInstructionSets = new String[Build.SUPPORTED_ABIS.length];
        for (int i = DEX_OPT_SKIPPED; i < supportedInstructionSets.length; i++) {
            String abi = Build.SUPPORTED_ABIS[i];
            supportedInstructionSets[i] = VMRuntime.getInstructionSet(abi);
        }
        return getDexCodeInstructionSets(supportedInstructionSets);
    }

    public void forceDexOpt(String packageName) {
        PackageParser.Package pkg;
        enforceSystemOrRoot("forceDexOpt");
        synchronized (this.mPackages) {
            pkg = this.mPackages.get(packageName);
            if (pkg == null) {
                throw new IllegalArgumentException("Missing package: " + packageName);
            }
        }
        synchronized (this.mInstallLock) {
            String[] instructionSets = {getPrimaryInstructionSet(pkg.applicationInfo)};
            int res = performDexOptLI(pkg, instructionSets, true, false, true);
            if (res != 1) {
                throw new IllegalStateException("Failed to dexopt: " + res);
            }
        }
    }

    private int performDexOptLI(PackageParser.Package pkg, String[] instructionSets, boolean forceDex, boolean defer, boolean inclDependencies) {
        ArraySet<String> done;
        if (inclDependencies && (pkg.usesLibraries != null || pkg.usesOptionalLibraries != null)) {
            done = new ArraySet<>();
            done.add(pkg.packageName);
        } else {
            done = null;
        }
        return performDexOptLI(pkg, instructionSets, forceDex, defer, done);
    }

    private boolean verifyPackageUpdateLPr(PackageSetting oldPkg, PackageParser.Package newPkg) {
        if ((oldPkg.pkgFlags & 1) == 0) {
            Slog.w(TAG, "Unable to update from " + oldPkg.name + " to " + newPkg.packageName + ": old package not in system partition");
            return false;
        }
        if (this.mPackages.get(oldPkg.name) != null) {
            Slog.w(TAG, "Unable to update from " + oldPkg.name + " to " + newPkg.packageName + ": old package still exists");
            return false;
        }
        return true;
    }

    File getDataPathForUser(int userId) {
        return new File(this.mUserAppDataDir.getAbsolutePath() + File.separator + userId);
    }

    private File getDataPathForPackage(String packageName, int userId) {
        return userId == 0 ? new File(this.mAppDataDir, packageName) : new File(this.mUserAppDataDir.getAbsolutePath() + File.separator + userId + File.separator + packageName);
    }

    private int createDataDirsLI(String packageName, int uid, String seinfo) {
        int[] users = sUserManager.getUserIds();
        int res = this.mInstaller.install(packageName, uid, uid, seinfo);
        if (res < 0) {
            return res;
        }
        int len$ = users.length;
        for (int i$ = DEX_OPT_SKIPPED; i$ < len$; i$++) {
            int user = users[i$];
            if (user != 0 && (res = this.mInstaller.createUserData(packageName, UserHandle.getUid(user, uid), user, seinfo)) < 0) {
                return res;
            }
        }
        return res;
    }

    private int removeDataDirsLI(String packageName) {
        int[] users = sUserManager.getUserIds();
        int res = DEX_OPT_SKIPPED;
        int len$ = users.length;
        for (int i$ = DEX_OPT_SKIPPED; i$ < len$; i$++) {
            int user = users[i$];
            int resInner = this.mInstaller.remove(packageName, user);
            if (resInner < 0) {
                res = resInner;
            }
        }
        return res;
    }

    private int deleteCodeCacheDirsLI(String packageName) {
        int[] users = sUserManager.getUserIds();
        int res = DEX_OPT_SKIPPED;
        int len$ = users.length;
        for (int i$ = DEX_OPT_SKIPPED; i$ < len$; i$++) {
            int user = users[i$];
            int resInner = this.mInstaller.deleteCodeCacheFiles(packageName, user);
            if (resInner < 0) {
                res = resInner;
            }
        }
        return res;
    }

    private void addSharedLibraryLPw(ArraySet<String> usesLibraryFiles, SharedLibraryEntry file, PackageParser.Package changingLib) {
        if (file.path != null) {
            usesLibraryFiles.add(file.path);
            return;
        }
        PackageParser.Package p = this.mPackages.get(file.apk);
        if (changingLib != null && changingLib.packageName.equals(file.apk) && (p == null || p.packageName.equals(changingLib.packageName))) {
            p = changingLib;
        }
        if (p != null) {
            usesLibraryFiles.addAll(p.getAllCodePaths());
        }
    }

    private void updateSharedLibrariesLPw(PackageParser.Package pkg, PackageParser.Package changingLib) throws PackageManagerException {
        if (pkg.usesLibraries != null || pkg.usesOptionalLibraries != null) {
            ArraySet<String> usesLibraryFiles = new ArraySet<>();
            int N = pkg.usesLibraries != null ? pkg.usesLibraries.size() : DEX_OPT_SKIPPED;
            for (int i = DEX_OPT_SKIPPED; i < N; i++) {
                SharedLibraryEntry file = this.mSharedLibraries.get(pkg.usesLibraries.get(i));
                if (file == null && !VendorPackageManagerCallback.callIsLibraryInstalled(this.mVendorCallbacks, (String) pkg.usesLibraries.get(i))) {
                    throw new PackageManagerException(-9, "Package " + pkg.packageName + " requires unavailable shared library " + ((String) pkg.usesLibraries.get(i)) + "; failing!");
                }
                if (file != null) {
                    addSharedLibraryLPw(usesLibraryFiles, file, changingLib);
                }
            }
            int N2 = pkg.usesOptionalLibraries != null ? pkg.usesOptionalLibraries.size() : DEX_OPT_SKIPPED;
            for (int i2 = DEX_OPT_SKIPPED; i2 < N2; i2++) {
                SharedLibraryEntry file2 = this.mSharedLibraries.get(pkg.usesOptionalLibraries.get(i2));
                if (file2 == null) {
                    if (!VendorPackageManagerCallback.callIsLibraryInstalled(this.mVendorCallbacks, (String) pkg.usesOptionalLibraries.get(i2))) {
                        Slog.w(TAG, "Package " + pkg.packageName + " desires unavailable shared library " + ((String) pkg.usesOptionalLibraries.get(i2)) + "; ignoring!");
                    }
                } else {
                    addSharedLibraryLPw(usesLibraryFiles, file2, changingLib);
                }
            }
            int N3 = usesLibraryFiles.size();
            if (N3 > 0) {
                pkg.usesLibraryFiles = (String[]) usesLibraryFiles.toArray(new String[N3]);
            } else {
                pkg.usesLibraryFiles = null;
            }
        }
    }

    private static boolean hasString(List<String> list, List<String> which) {
        if (list == null) {
            return false;
        }
        for (int i = list.size() + DEX_OPT_FAILED; i >= 0; i += DEX_OPT_FAILED) {
            for (int j = which.size() + DEX_OPT_FAILED; j >= 0; j += DEX_OPT_FAILED) {
                if (which.get(j).equals(list.get(i))) {
                    return true;
                }
            }
        }
        return false;
    }

    private void updateAllSharedLibrariesLPw() {
        for (PackageParser.Package pkg : this.mPackages.values()) {
            try {
                updateSharedLibrariesLPw(pkg, null);
            } catch (PackageManagerException e) {
                Slog.e(TAG, "updateAllSharedLibrariesLPw failed: " + e.getMessage());
            }
        }
    }

    private ArrayList<PackageParser.Package> updateAllSharedLibrariesLPw(PackageParser.Package changingPkg) {
        ArrayList<PackageParser.Package> res = null;
        for (PackageParser.Package pkg : this.mPackages.values()) {
            if (hasString(pkg.usesLibraries, changingPkg.libraryNames) || hasString(pkg.usesOptionalLibraries, changingPkg.libraryNames)) {
                if (res == null) {
                    res = new ArrayList<>();
                }
                res.add(pkg);
                try {
                    updateSharedLibrariesLPw(pkg, changingPkg);
                } catch (PackageManagerException e) {
                    Slog.e(TAG, "updateAllSharedLibrariesLPw failed: " + e.getMessage());
                }
            }
        }
        return res;
    }

    public static String deriveAbiOverride(String abiOverride, PackageSetting settings) {
        if (INSTALL_PACKAGE_SUFFIX.equals(abiOverride)) {
            return null;
        }
        if (abiOverride != null) {
            return abiOverride;
        }
        if (settings == null) {
            return null;
        }
        String cpuAbiOverride = settings.cpuAbiOverrideString;
        return cpuAbiOverride;
    }

    private PackageParser.Package scanPackageLI(PackageParser.Package pkg, int parseFlags, int scanFlags, long currentTime, UserHandle user) throws PackageManagerException {
        boolean success = false;
        try {
            PackageParser.Package res = scanPackageDirtyLI(pkg, parseFlags, scanFlags, currentTime, user);
            success = true;
            return res;
        } finally {
            if (!success && (scanFlags & SCAN_DELETE_DATA_ON_FAILURES) != 0) {
                removeDataDirsLI(pkg.packageName);
            }
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    private PackageParser.Package scanPackageDirtyLI(PackageParser.Package pkg, int parseFlags, int scanFlags, long currentTime, UserHandle user) throws PackageManagerException {
        PackageSetting pkgSetting;
        NativeLibraryHelper.Handle handle;
        int copyRet;
        PackageParser.Provider p;
        PackageSetting known;
        File scanFile = new File(pkg.codePath);
        if (pkg.applicationInfo.getCodePath() == null || pkg.applicationInfo.getResourcePath() == null) {
            throw new PackageManagerException(-2, "Code and resource paths haven't been set correctly");
        }
        int vendorScanError = VendorPackageManagerCallback.callScanPackageLI(this.mVendorCallbacks, DEX_OPT_SKIPPED, pkg, (ArrayMap) null, false);
        if (vendorScanError != 1) {
            throw new PackageManagerException(-2, "Install failed");
        }
        if ((parseFlags & 1) != 0) {
            pkg.applicationInfo.flags |= 1;
        } else {
            pkg.coreApp = false;
        }
        if ((parseFlags & SCAN_DEFER_DEX) != 0) {
            pkg.applicationInfo.flags |= 0x40000000;
        }
        if (this.mCustomResolverComponentName != null && this.mCustomResolverComponentName.getPackageName().equals(pkg.packageName)) {
            setUpCustomResolverActivity(pkg);
        }
        if (pkg.packageName.equals("android")) {
            synchronized (this.mPackages) {
                if (this.mAndroidApplication != null) {
                    Slog.w(TAG, "*************************************************");
                    Slog.w(TAG, "Core android package being redefined.  Skipping.");
                    Slog.w(TAG, " file=" + scanFile);
                    Slog.w(TAG, "*************************************************");
                    throw new PackageManagerException(-5, "Core android package being redefined.  Skipping.");
                }
                this.mPlatformPackage = pkg;
                pkg.mVersionCode = this.mSdkVersion;
                this.mAndroidApplication = pkg.applicationInfo;
                if (!this.mResolverReplaced) {
                    this.mResolveActivity.applicationInfo = this.mAndroidApplication;
                    this.mResolveActivity.name = ResolverActivity.class.getName();
                    this.mResolveActivity.packageName = this.mAndroidApplication.packageName;
                    this.mResolveActivity.processName = "system:ui";
                    this.mResolveActivity.launchMode = DEX_OPT_SKIPPED;
                    this.mResolveActivity.documentLaunchMode = MCS_BOUND;
                    this.mResolveActivity.flags = SCAN_NO_PATHS;
                    this.mResolveActivity.theme = 0x01030489;
                    this.mResolveActivity.exported = true;
                    this.mResolveActivity.enabled = true;
                    this.mResolveInfo.activityInfo = this.mResolveActivity;
                    this.mResolveInfo.priority = DEX_OPT_SKIPPED;
                    this.mResolveInfo.preferredOrder = DEX_OPT_SKIPPED;
                    this.mResolveInfo.match = DEX_OPT_SKIPPED;
                    this.mResolveComponentName = new ComponentName(this.mAndroidApplication.packageName, this.mResolveActivity.name);
                }
            }
        }
        int vendorScanError2 = VendorPackageManagerCallback.callScanPackageLI(this.mVendorCallbacks, 400, pkg, (ArrayMap) null, false);
        if (vendorScanError2 != 1) {
            throw new PackageManagerException(-2, "Install failed");
        }
        if (this.mPackages.containsKey(pkg.packageName) || this.mSharedLibraries.containsKey(pkg.packageName)) {
            if (isFirstBoot()) {
                VendorPackageManagerCallback.callReplacePackageLI(this.mVendorCallbacks, this, pkg, parseFlags, scanFlags, user);
                return pkg;
            }
            throw new PackageManagerException(-5, "Application package " + pkg.packageName + " already installed.  Skipping duplicate.");
        }
        if ((scanFlags & SCAN_REQUIRE_KNOWN) != 0 && (known = this.mSettings.peekPackageLPr(pkg.packageName)) != null && (!pkg.applicationInfo.getCodePath().equals(known.codePathString) || !pkg.applicationInfo.getResourcePath().equals(known.resourcePathString))) {
            throw new PackageManagerException(-23, "Application package " + pkg.packageName + " found at " + pkg.applicationInfo.getCodePath() + " but expected at " + known.codePathString + "; ignoring.");
        }
        File destCodeFile = new File(pkg.applicationInfo.getCodePath());
        File destResourceFile = new File(pkg.applicationInfo.getResourcePath());
        SharedUserSetting suid = null;
        if (!isSystemApp(pkg)) {
            pkg.mOriginalPackages = null;
            pkg.mRealPackage = null;
            pkg.mAdoptPermissions = null;
        }
        synchronized (this.mPackages) {
            if (pkg.mSharedUserId != null && (suid = this.mSettings.getSharedUserLPw(pkg.mSharedUserId, pkg.mSignatures, pkg.applicationInfo.flags, true)) == null) {
                throw new PackageManagerException(-4, "Creating application package " + pkg.packageName + " for shared user failed");
            }
            PackageSetting origPackage = null;
            String realName = null;
            if (pkg.mOriginalPackages != null) {
                String renamed = (String) this.mSettings.mRenamedPackages.get(pkg.mRealPackage);
                if (pkg.mOriginalPackages.contains(renamed)) {
                    realName = pkg.mRealPackage;
                    if (!pkg.packageName.equals(renamed)) {
                        pkg.setPackageName(renamed);
                    }
                } else {
                    for (int i = pkg.mOriginalPackages.size() + DEX_OPT_FAILED; i >= 0; i += DEX_OPT_FAILED) {
                        origPackage = this.mSettings.peekPackageLPr((String) pkg.mOriginalPackages.get(i));
                        if (origPackage != null) {
                            if (!verifyPackageUpdateLPr(origPackage, pkg)) {
                                origPackage = null;
                            } else {
                                if (origPackage.sharedUser == null || origPackage.sharedUser.name.equals(pkg.mSharedUserId)) {
                                    break;
                                }
                                Slog.w(TAG, "Unable to migrate data from " + origPackage.name + " to " + pkg.packageName + ": old uid " + origPackage.sharedUser.name + " differs from " + pkg.mSharedUserId);
                                origPackage = null;
                            }
                        }
                    }
                }
            }
            if (this.mTransferedPackages.contains(pkg.packageName)) {
                Slog.w(TAG, "Package " + pkg.packageName + " was transferred to another, but its .apk remains");
            }
            pkgSetting = this.mSettings.getPackageLPw(pkg, origPackage, realName, suid, destCodeFile, destResourceFile, pkg.applicationInfo.nativeLibraryRootDir, pkg.applicationInfo.primaryCpuAbi, pkg.applicationInfo.secondaryCpuAbi, pkg.applicationInfo.flags, user, false);
            if (pkgSetting == null) {
                throw new PackageManagerException(-4, "Creating application package " + pkg.packageName + " failed");
            }
            if (pkgSetting.origPackage != null) {
                pkg.setPackageName(origPackage.name);
                reportSettingsProblem(INIT_COPY, "New package " + pkgSetting.realName + " renamed to replace old package " + pkgSetting.name);
                this.mTransferedPackages.add(origPackage.name);
                pkgSetting.origPackage = null;
            }
            if (realName != null) {
                this.mTransferedPackages.add(pkg.packageName);
            }
            if (this.mSettings.isDisabledSystemPackageLPr(pkg.packageName)) {
                pkg.applicationInfo.flags |= SCAN_DEFER_DEX;
            }
            if ((parseFlags & SCAN_UPDATE_TIME) == 0) {
                updateSharedLibrariesLPw(pkg, null);
            }
            if (this.mFoundPolicyFile) {
                SELinuxMMAC.assignSeinfoValue(pkg);
            }
            pkg.applicationInfo.uid = pkgSetting.appId;
            pkg.mExtras = pkgSetting;
            if (!pkgSetting.keySetData.isUsingUpgradeKeySets() || pkgSetting.sharedUser != null) {
                try {
                    verifySignaturesLP(pkgSetting, pkg);
                    pkgSetting.signatures.mSignatures = pkg.mSignatures;
                } catch (PackageManagerException e) {
                    if ((parseFlags & SCAN_UPDATE_TIME) == 0) {
                        throw e;
                    }
                    pkgSetting.signatures.mSignatures = pkg.mSignatures;
                    if (pkgSetting.sharedUser != null && compareSignatures(pkgSetting.sharedUser.signatures.mSignatures, pkg.mSignatures) != 0) {
                        throw new PackageManagerException(-104, "Signature mismatch for shared user : " + pkgSetting.sharedUser);
                    }
                    reportSettingsProblem(INIT_COPY, "System package " + pkg.packageName + " signature changed; retaining data.");
                }
            } else {
                if (!checkUpgradeKeySetLP(pkgSetting, pkg)) {
                    throw new PackageManagerException(-7, "Package " + pkg.packageName + " upgrade keys do not match the previously installed version");
                }
                pkgSetting.signatures.mSignatures = pkg.mSignatures;
            }
            if ((scanFlags & 16) != 0) {
                int N = pkg.providers.size();
                for (int i2 = DEX_OPT_SKIPPED; i2 < N; i2++) {
                    PackageParser.Provider p2 = (PackageParser.Provider) pkg.providers.get(i2);
                    if (p2.info.authority != null) {
                        String[] names = p2.info.authority.split(";");
                        for (int j = DEX_OPT_SKIPPED; j < names.length; j++) {
                            if (this.mProvidersByAuthority.containsKey(names[j])) {
                                PackageParser.Provider other = this.mProvidersByAuthority.get(names[j]);
                                String otherPackageName = (other == null || other.getComponentName() == null) ? "?" : other.getComponentName().getPackageName();
                                throw new PackageManagerException(-13, "Can't install because provider name " + names[j] + " (in package " + pkg.applicationInfo.packageName + ") is already used by " + otherPackageName);
                            }
                        }
                    }
                }
            }
            if (pkg.mAdoptPermissions != null) {
                for (int i3 = pkg.mAdoptPermissions.size() + DEX_OPT_FAILED; i3 >= 0; i3 += DEX_OPT_FAILED) {
                    String origName = (String) pkg.mAdoptPermissions.get(i3);
                    PackageSetting orig = this.mSettings.peekPackageLPr(origName);
                    if (orig != null && verifyPackageUpdateLPr(orig, pkg)) {
                        Slog.i(TAG, "Adopting permissions from " + origName + " to " + pkg.packageName);
                        this.mSettings.transferPermissionsLPw(origName, pkg.packageName);
                    }
                }
            }
        }
        String pkgName = pkg.packageName;
        long scanFileTime = scanFile.lastModified();
        boolean forceDex = (scanFlags & 4) != 0;
        pkg.applicationInfo.processName = fixProcessName(pkg.applicationInfo.packageName, pkg.applicationInfo.processName, pkg.applicationInfo.uid);
        int vendorScanError3 = VendorPackageManagerCallback.callScanPackageLI(this.mVendorCallbacks, 200, pkg, (ArrayMap) null, false);
        if (vendorScanError3 != 1) {
            return null;
        }
        if (this.mPlatformPackage == pkg) {
            pkg.applicationInfo.dataDir = new File(Environment.getDataDirectory(), "system").getPath();
        } else {
            File dataPath = getDataPathForPackage(pkg.packageName, DEX_OPT_SKIPPED);
            boolean uidError = false;
            if (dataPath.exists()) {
                int currentUid = DEX_OPT_SKIPPED;
                try {
                    StructStat stat = Os.stat(dataPath.getPath());
                    currentUid = stat.st_uid;
                } catch (ErrnoException e2) {
                    Slog.e(TAG, "Couldn't stat path " + dataPath.getPath(), e2);
                }
                if (currentUid != pkg.applicationInfo.uid) {
                    boolean recovered = false;
                    if (currentUid == 0 && this.mInstaller.fixUid(pkgName, pkg.applicationInfo.uid, pkg.applicationInfo.uid) >= 0) {
                        recovered = true;
                        reportSettingsProblem(INIT_COPY, "Package " + pkg.packageName + " unexpectedly changed to uid 0; recovered to " + pkg.applicationInfo.uid);
                    }
                    if (!recovered && ((parseFlags & 1) != 0 || (scanFlags & SCAN_BOOTING) != 0)) {
                        if (removeDataDirsLI(pkgName) >= 0) {
                            String prefix = (parseFlags & 1) != 0 ? "System package " : "Third party package ";
                            reportSettingsProblem(INIT_COPY, prefix + pkg.packageName + " has changed from uid: " + currentUid + " to " + pkg.applicationInfo.uid + "; old data erased");
                            recovered = true;
                            if (createDataDirsLI(pkgName, pkg.applicationInfo.uid, pkg.applicationInfo.seinfo) == DEX_OPT_FAILED) {
                                String msg = prefix + pkg.packageName + " could not have data directory re-created after delete.";
                                reportSettingsProblem(INIT_COPY, msg);
                                throw new PackageManagerException(-4, msg);
                            }
                        }
                        if (!recovered) {
                            this.mHasSystemUidErrors = true;
                        }
                    } else if (!recovered) {
                        throw new PackageManagerException(-24, "scanPackageLI");
                    }
                    if (!recovered) {
                        pkg.applicationInfo.dataDir = "/mismatched_uid/settings_" + pkg.applicationInfo.uid + "/fs_" + currentUid;
                        pkg.applicationInfo.nativeLibraryDir = pkg.applicationInfo.dataDir;
                        pkg.applicationInfo.nativeLibraryRootDir = pkg.applicationInfo.dataDir;
                        String msg2 = "Package " + pkg.packageName + " has mismatched uid: " + currentUid + " on disk, " + pkg.applicationInfo.uid + " in settings";
                        synchronized (this.mPackages) {
                            this.mSettings.mReadMessages.append(msg2);
                            this.mSettings.mReadMessages.append('\n');
                            uidError = true;
                            if (!pkgSetting.uidError) {
                                reportSettingsProblem(MCS_UNBIND, msg2);
                            }
                        }
                    }
                }
                pkg.applicationInfo.dataDir = dataPath.getPath();
                if (this.mShouldRestoreconData || isExternal(pkg)) {
                    Slog.i(TAG, "SELinux relabeling of " + pkg.packageName + " issued.");
                    this.mInstaller.restoreconData(pkg.packageName, pkg.applicationInfo.seinfo, pkg.applicationInfo.uid);
                }
            } else {
                int ret = createDataDirsLI(pkgName, pkg.applicationInfo.uid, pkg.applicationInfo.seinfo);
                if (ret < 0) {
                    throw new PackageManagerException(-4, "Unable to create data dirs [errorCode=" + ret + "]");
                }
                if (dataPath.exists()) {
                    pkg.applicationInfo.dataDir = dataPath.getPath();
                } else {
                    Slog.w(TAG, "Unable to create data directory: " + dataPath);
                    pkg.applicationInfo.dataDir = null;
                }
            }
            pkgSetting.uidError = uidError;
        }
        scanFile.getPath();
        pkg.applicationInfo.getCodePath();
        String amazonForcedAbi = null;
        if (amazonShouldForceAbi(pkg)) {
            amazonForcedAbi = Build.SUPPORTED_32_BIT_ABIS[DEX_OPT_SKIPPED];
            Log.i(TAG, "Forcing package=" + pkg + " to 32bit ABI " + amazonForcedAbi);
        }
        String cpuAbiOverride = deriveAbiOverride(pkg.cpuAbiOverride, pkgSetting);
        Log.i(TAG, "Derived cpuAbiOverride=" + cpuAbiOverride);
        if (isSystemApp(pkg) && !isUpdatedSystemApp(pkg)) {
            setBundledAppAbisAndRoots(pkg, pkgSetting);
            if (pkg.applicationInfo.primaryCpuAbi == null && pkg.applicationInfo.secondaryCpuAbi == null && Build.SUPPORTED_64_BIT_ABIS.length > 0) {
                NativeLibraryHelper.Handle handle2 = null;
                try {
                    handle = NativeLibraryHelper.Handle.create(scanFile);
                    if (NativeLibraryHelper.hasRenderscriptBitcode(handle)) {
                        pkg.applicationInfo.primaryCpuAbi = Build.SUPPORTED_32_BIT_ABIS[DEX_OPT_SKIPPED];
                    }
                } catch (IOException ioe) {
                    Slog.w(TAG, "Error scanning system app : " + ioe);
                } finally {
                }
            }
            setNativeLibraryPaths(pkg);
            VendorPackageManagerCallback.callExtractBundledPackage(this.mVendorCallbacks, pkg, cpuAbiOverride);
        } else {
            setNativeLibraryPaths(pkg);
            boolean isAsec = isForwardLocked(pkg) || isExternal(pkg);
            String nativeLibraryRootStr = pkg.applicationInfo.nativeLibraryRootDir;
            boolean useIsaSpecificSubdirs = pkg.applicationInfo.nativeLibraryRootRequiresIsa;
            handle = null;
            try {
                handle = NativeLibraryHelper.Handle.create(scanFile);
                File nativeLibraryRoot = new File(nativeLibraryRootStr);
                pkg.applicationInfo.primaryCpuAbi = null;
                pkg.applicationInfo.secondaryCpuAbi = null;
                if (isMultiArch(pkg.applicationInfo)) {
                    if (pkg.cpuAbiOverride != null && !INSTALL_PACKAGE_SUFFIX.equals(pkg.cpuAbiOverride)) {
                        Slog.w(TAG, "Ignoring abiOverride for multi arch application.");
                    }
                    int abi32 = -114;
                    int abi64 = -114;
                    if (Build.SUPPORTED_32_BIT_ABIS.length > 0) {
                        if (isAsec) {
                            abi32 = NativeLibraryHelper.findSupportedAbi(handle, Build.SUPPORTED_32_BIT_ABIS);
                        } else {
                            abi32 = NativeLibraryHelper.copyNativeBinariesForSupportedAbi(handle, nativeLibraryRoot, Build.SUPPORTED_32_BIT_ABIS, useIsaSpecificSubdirs);
                        }
                    }
                    maybeThrowExceptionForMultiArchCopy("Error unpackaging 32 bit native libs for multiarch app.", abi32);
                    if (Build.SUPPORTED_64_BIT_ABIS.length > 0) {
                        if (isAsec) {
                            abi64 = NativeLibraryHelper.findSupportedAbi(handle, Build.SUPPORTED_64_BIT_ABIS);
                        } else {
                            abi64 = NativeLibraryHelper.copyNativeBinariesForSupportedAbi(handle, nativeLibraryRoot, Build.SUPPORTED_64_BIT_ABIS, useIsaSpecificSubdirs);
                        }
                    }
                    maybeThrowExceptionForMultiArchCopy("Error unpackaging 64 bit native libs for multiarch app.", abi64);
                    if (abi64 >= 0) {
                        pkg.applicationInfo.primaryCpuAbi = Build.SUPPORTED_64_BIT_ABIS[abi64];
                    }
                    if (abi32 >= 0) {
                        String abi = Build.SUPPORTED_32_BIT_ABIS[abi32];
                        if (abi64 >= 0) {
                            pkg.applicationInfo.secondaryCpuAbi = abi;
                        } else {
                            pkg.applicationInfo.primaryCpuAbi = abi;
                        }
                    }
                } else {
                    String[] abiList = cpuAbiOverride != null ? new String[]{cpuAbiOverride} : Build.SUPPORTED_ABIS;
                    boolean needsRenderScriptOverride = false;
                    if (Build.SUPPORTED_64_BIT_ABIS.length > 0 && cpuAbiOverride == null && NativeLibraryHelper.hasRenderscriptBitcode(handle)) {
                        abiList = Build.SUPPORTED_32_BIT_ABIS;
                        needsRenderScriptOverride = true;
                    }
                    if (isAsec) {
                        copyRet = NativeLibraryHelper.findSupportedAbi(handle, abiList);
                    } else {
                        copyRet = NativeLibraryHelper.copyNativeBinariesForSupportedAbi(handle, nativeLibraryRoot, abiList, useIsaSpecificSubdirs);
                    }
                    if (copyRet < 0 && copyRet != -114) {
                        throw new PackageManagerException(-110, "Error unpackaging native libs for app, errorCode=" + copyRet);
                    }
                    if (copyRet >= 0) {
                        pkg.applicationInfo.primaryCpuAbi = abiList[copyRet];
                    } else if (amazonForcedAbi != null) {
                        pkg.applicationInfo.primaryCpuAbi = amazonForcedAbi;
                    } else if (copyRet == -114 && cpuAbiOverride != null) {
                        pkg.applicationInfo.primaryCpuAbi = cpuAbiOverride;
                    } else if (copyRet == -114 && pkg.cpuAbiHint != null) {
                        pkg.applicationInfo.primaryCpuAbi = pkg.cpuAbiHint;
                    } else if (needsRenderScriptOverride) {
                        pkg.applicationInfo.primaryCpuAbi = abiList[DEX_OPT_SKIPPED];
                    }
                }
            } catch (IOException ioe2) {
                Slog.e(TAG, "Unable to get canonical file " + ioe2.toString());
            } finally {
            }
            setNativeLibraryPaths(pkg);
            int[] userIds = sUserManager.getUserIds();
            synchronized (this.mInstallLock) {
                if (pkg.applicationInfo.primaryCpuAbi != null && !VMRuntime.is64BitAbi(pkg.applicationInfo.primaryCpuAbi)) {
                    String nativeLibPath = pkg.applicationInfo.nativeLibraryDir;
                    int len$ = userIds.length;
                    for (int i$ = DEX_OPT_SKIPPED; i$ < len$; i$++) {
                        int userId = userIds[i$];
                        if (this.mInstaller.linkNativeLibraryDirectory(pkg.packageName, nativeLibPath, userId) < 0) {
                            throw new PackageManagerException(-110, "Failed linking native library dir (user=" + userId + ")");
                        }
                    }
                }
            }
        }
        if (this.mPlatformPackage == pkg) {
            pkg.applicationInfo.primaryCpuAbi = VMRuntime.getRuntime().is64Bit() ? Build.SUPPORTED_64_BIT_ABIS[DEX_OPT_SKIPPED] : Build.SUPPORTED_32_BIT_ABIS[DEX_OPT_SKIPPED];
        }
        pkgSetting.primaryCpuAbiString = pkg.applicationInfo.primaryCpuAbi;
        pkgSetting.secondaryCpuAbiString = pkg.applicationInfo.secondaryCpuAbi;
        pkgSetting.cpuAbiOverrideString = cpuAbiOverride;
        pkg.cpuAbiOverride = cpuAbiOverride;
        Slog.d(TAG, "Resolved nativeLibraryRoot for " + pkg.applicationInfo.packageName + " to root=" + pkg.applicationInfo.nativeLibraryRootDir + ", isa=" + pkg.applicationInfo.nativeLibraryRootRequiresIsa);
        pkgSetting.legacyNativeLibraryPathString = pkg.applicationInfo.nativeLibraryRootDir;
        Log.d(TAG, "Abis for package[" + pkg.packageName + "] are primary=" + pkg.applicationInfo.primaryCpuAbi + " secondary=" + pkg.applicationInfo.secondaryCpuAbi);
        if ((scanFlags & SCAN_BOOTING) == 0 && pkgSetting.sharedUser != null) {
            adjustCpuAbisForSharedUserLPw(pkgSetting.sharedUser.packages, pkg, forceDex, (scanFlags & SCAN_DEFER_DEX) != 0);
        }
        if ((scanFlags & 2) == 0) {
            if (performDexOptLI(pkg, (String[]) null, forceDex, (scanFlags & SCAN_DEFER_DEX) != 0, false) == DEX_OPT_FAILED) {
                throw new PackageManagerException(-11, "scanPackageLI");
            }
        }
        if (this.mFactoryTest && pkg.requestedPermissions.contains("android.permission.FACTORY_TEST")) {
            pkg.applicationInfo.flags |= 16;
        }
        ArrayList<PackageParser.Package> clientLibPkgs = null;
        synchronized (this.mPackages) {
            if ((pkg.applicationInfo.flags & 1) != 0 && pkg.libraryNames != null) {
                for (int i4 = DEX_OPT_SKIPPED; i4 < pkg.libraryNames.size(); i4++) {
                    String name = (String) pkg.libraryNames.get(i4);
                    boolean allowed = false;
                    if (isUpdatedSystemApp(pkg)) {
                        PackageSetting sysPs = this.mSettings.getDisabledSystemPkgLPr(pkg.packageName);
                        if (sysPs.pkg != null && sysPs.pkg.libraryNames != null) {
                            int j2 = DEX_OPT_SKIPPED;
                            while (true) {
                                if (j2 >= sysPs.pkg.libraryNames.size()) {
                                    break;
                                }
                                if (!name.equals(sysPs.pkg.libraryNames.get(j2))) {
                                    j2++;
                                } else {
                                    allowed = true;
                                    break;
                                }
                            }
                        }
                    } else {
                        allowed = true;
                    }
                    if (allowed) {
                        if (!this.mSharedLibraries.containsKey(name)) {
                            this.mSharedLibraries.put(name, new SharedLibraryEntry((String) null, pkg.packageName));
                        } else if (!name.equals(pkg.packageName)) {
                            Slog.w(TAG, "Package " + pkg.packageName + " library " + name + " already exists; skipping");
                        }
                    } else {
                        Slog.w(TAG, "Package " + pkg.packageName + " declares lib " + name + " that is not declared on system image; skipping");
                    }
                }
                if ((scanFlags & SCAN_BOOTING) == 0) {
                    clientLibPkgs = updateAllSharedLibrariesLPw(pkg);
                }
            }
        }
        if (clientLibPkgs != null && (scanFlags & 2) == 0) {
            for (int i5 = DEX_OPT_SKIPPED; i5 < clientLibPkgs.size(); i5++) {
                if (performDexOptLI(clientLibPkgs.get(i5), (String[]) null, forceDex, (scanFlags & SCAN_DEFER_DEX) != 0, false) == DEX_OPT_FAILED) {
                    throw new PackageManagerException(-11, "scanPackageLI failed to dexopt clientLibPkgs");
                }
            }
        }
        if (clientLibPkgs != null) {
            for (int i6 = DEX_OPT_SKIPPED; i6 < clientLibPkgs.size(); i6++) {
                PackageParser.Package clientPkg = clientLibPkgs.get(i6);
                killApplication(clientPkg.applicationInfo.packageName, clientPkg.applicationInfo.uid, "update lib");
            }
        }
        synchronized (this.mPackages) {
            this.mSettings.insertPackageSettingLPw(pkgSetting, pkg);
            this.mPackages.put(pkg.applicationInfo.packageName, pkg);
            Iterator<PackageCleanItem> iter = this.mSettings.mPackagesToBeCleaned.iterator();
            while (iter.hasNext()) {
                PackageCleanItem item = iter.next();
                if (pkgName.equals(item.packageName)) {
                    iter.remove();
                }
            }
            VendorPackageManagerCallback.callScanPackageLI(this.mVendorCallbacks, 500, pkg, this.mPackages, false);
            if (currentTime != 0) {
                if (pkgSetting.firstInstallTime == 0) {
                    pkgSetting.lastUpdateTime = currentTime;
                    pkgSetting.firstInstallTime = currentTime;
                } else if ((scanFlags & SCAN_UPDATE_TIME) != 0) {
                    pkgSetting.lastUpdateTime = currentTime;
                }
            } else if (pkgSetting.firstInstallTime == 0) {
                pkgSetting.lastUpdateTime = scanFileTime;
                pkgSetting.firstInstallTime = scanFileTime;
            } else if ((parseFlags & SCAN_UPDATE_TIME) != 0 && scanFileTime != pkgSetting.timeStamp) {
                pkgSetting.lastUpdateTime = scanFileTime;
            }
            KeySetManagerService ksms = this.mSettings.mKeySetManagerService;
            try {
                try {
                    ksms.removeAppKeySetDataLPw(pkg.packageName);
                    ksms.addSigningKeySetToPackageLPw(pkg.packageName, pkg.mSigningKeys);
                    if (pkg.mKeySetMapping != null) {
                        for (Map.Entry<String, ArraySet<PublicKey>> entry : pkg.mKeySetMapping.entrySet()) {
                            if (entry.getValue() != null) {
                                ksms.addDefinedKeySetToPackageLPw(pkg.packageName, entry.getValue(), entry.getKey());
                            }
                        }
                        if (pkg.mUpgradeKeySets != null) {
                            Iterator i$2 = pkg.mUpgradeKeySets.iterator();
                            while (i$2.hasNext()) {
                                String upgradeAlias = (String) i$2.next();
                                ksms.addUpgradeKeySetToPackageLPw(pkg.packageName, upgradeAlias);
                            }
                        }
                    }
                } catch (IllegalArgumentException e3) {
                    Slog.e(TAG, "Could not add KeySet to malformed package" + pkg.packageName, e3);
                }
            } catch (NullPointerException e4) {
                Slog.e(TAG, "Could not add KeySet to " + pkg.packageName, e4);
            }
            int N2 = pkg.providers.size();
            StringBuilder r = null;
            for (int i7 = DEX_OPT_SKIPPED; i7 < N2; i7++) {
                PackageParser.Provider p3 = (PackageParser.Provider) pkg.providers.get(i7);
                p3.info.processName = fixProcessName(pkg.applicationInfo.processName, p3.info.processName, pkg.applicationInfo.uid);
                this.mProviders.addProvider(p3);
                p3.syncable = p3.info.isSyncable;
                if (p3.info.authority != null) {
                    String[] names2 = p3.info.authority.split(";");
                    p3.info.authority = null;
                    int j3 = DEX_OPT_SKIPPED;
                    PackageParser.Provider p4 = p3;
                    while (j3 < names2.length) {
                        if (j3 == 1 && p4.syncable) {
                            p = new PackageParser.Provider(p4);
                            p.syncable = false;
                        } else {
                            p = p4;
                        }
                        if (!this.mProvidersByAuthority.containsKey(names2[j3])) {
                            this.mProvidersByAuthority.put(names2[j3], p);
                            if (p.info.authority == null) {
                                p.info.authority = names2[j3];
                            } else {
                                p.info.authority += ";" + names2[j3];
                            }
                        } else {
                            PackageParser.Provider other2 = this.mProvidersByAuthority.get(names2[j3]);
                            Slog.w(TAG, "Skipping provider name " + names2[j3] + " (in package " + pkg.applicationInfo.packageName + "): name already used by " + ((other2 == null || other2.getComponentName() == null) ? "?" : other2.getComponentName().getPackageName()));
                        }
                        j3++;
                        p4 = p;
                    }
                    p3 = p4;
                }
                if ((parseFlags & 2) != 0) {
                    if (r == null) {
                        r = new StringBuilder(SCAN_BOOTING);
                    } else {
                        r.append(' ');
                    }
                    r.append(p3.info.name);
                }
            }
            if (r != null) {
            }
            int N3 = pkg.services.size();
            StringBuilder r2 = null;
            for (int i8 = DEX_OPT_SKIPPED; i8 < N3; i8++) {
                PackageParser.Service s = (PackageParser.Service) pkg.services.get(i8);
                s.info.processName = fixProcessName(pkg.applicationInfo.processName, s.info.processName, pkg.applicationInfo.uid);
                this.mServices.addService(s);
                if ((parseFlags & 2) != 0) {
                    if (r2 == null) {
                        r2 = new StringBuilder(SCAN_BOOTING);
                    } else {
                        r2.append(' ');
                    }
                    r2.append(s.info.name);
                }
            }
            if (r2 != null) {
            }
            int N4 = pkg.receivers.size();
            StringBuilder r3 = null;
            for (int i9 = DEX_OPT_SKIPPED; i9 < N4; i9++) {
                PackageParser.Activity a = (PackageParser.Activity) pkg.receivers.get(i9);
                a.info.processName = fixProcessName(pkg.applicationInfo.processName, a.info.processName, pkg.applicationInfo.uid);
                this.mReceivers.addActivity(a, "receiver");
                if ((parseFlags & 2) != 0) {
                    if (r3 == null) {
                        r3 = new StringBuilder(SCAN_BOOTING);
                    } else {
                        r3.append(' ');
                    }
                    r3.append(a.info.name);
                }
            }
            if (r3 != null) {
            }
            int N5 = pkg.activities.size();
            StringBuilder r4 = null;
            for (int i10 = DEX_OPT_SKIPPED; i10 < N5; i10++) {
                PackageParser.Activity a2 = (PackageParser.Activity) pkg.activities.get(i10);
                a2.info.processName = fixProcessName(pkg.applicationInfo.processName, a2.info.processName, pkg.applicationInfo.uid);
                this.mActivities.addActivity(a2, "activity");
                if ((parseFlags & 2) != 0) {
                    if (r4 == null) {
                        r4 = new StringBuilder(SCAN_BOOTING);
                    } else {
                        r4.append(' ');
                    }
                    r4.append(a2.info.name);
                }
            }
            if (r4 != null) {
            }
            int N6 = pkg.permissionGroups.size();
            StringBuilder r5 = null;
            for (int i11 = DEX_OPT_SKIPPED; i11 < N6; i11++) {
                PackageParser.PermissionGroup pg = (PackageParser.PermissionGroup) pkg.permissionGroups.get(i11);
                PackageParser.PermissionGroup cur = this.mPermissionGroups.get(pg.info.name);
                if (cur == null) {
                    this.mPermissionGroups.put(pg.info.name, pg);
                    if ((parseFlags & 2) != 0) {
                        if (r5 == null) {
                            r5 = new StringBuilder(SCAN_BOOTING);
                        } else {
                            r5.append(' ');
                        }
                        r5.append(pg.info.name);
                    }
                } else {
                    Slog.w(TAG, "Permission group " + pg.info.name + " from package " + pg.info.packageName + " ignored: original from " + cur.info.packageName);
                    if ((parseFlags & 2) != 0) {
                        if (r5 == null) {
                            r5 = new StringBuilder(SCAN_BOOTING);
                        } else {
                            r5.append(' ');
                        }
                        r5.append("DUP:");
                        r5.append(pg.info.name);
                    }
                }
            }
            if (r5 != null) {
            }
            int N7 = pkg.permissions.size();
            StringBuilder r6 = null;
            for (int i12 = DEX_OPT_SKIPPED; i12 < N7; i12++) {
                PackageParser.Permission p5 = (PackageParser.Permission) pkg.permissions.get(i12);
                ArrayMap<String, BasePermission> permissionMap = p5.tree ? this.mSettings.mPermissionTrees : this.mSettings.mPermissions;
                p5.group = this.mPermissionGroups.get(p5.info.group);
                if (p5.info.group == null || p5.group != null) {
                    BasePermission bp = permissionMap.get(p5.info.name);
                    if (bp != null && !Objects.equals(bp.sourcePackage, p5.info.packageName)) {
                        boolean currentOwnerIsSystem = bp.perm != null && isSystemApp(bp.perm.owner);
                        if (isSystemApp(p5.owner)) {
                            if (bp.type == 1 && bp.perm == null) {
                                bp.packageSetting = pkgSetting;
                                bp.perm = p5;
                                bp.uid = pkg.applicationInfo.uid;
                                bp.sourcePackage = p5.info.packageName;
                            } else if (!currentOwnerIsSystem) {
                                reportSettingsProblem(INIT_COPY, "New decl " + p5.owner + " of permission  " + p5.info.name + " is system; overriding " + bp.sourcePackage);
                                bp = null;
                            }
                        }
                    }
                    if (bp == null) {
                        bp = new BasePermission(p5.info.name, p5.info.packageName, DEX_OPT_SKIPPED);
                        permissionMap.put(p5.info.name, bp);
                    }
                    if (bp.perm == null) {
                        if (bp.sourcePackage == null || bp.sourcePackage.equals(p5.info.packageName)) {
                            BasePermission tree = findPermissionTreeLP(p5.info.name);
                            if (tree == null || tree.sourcePackage.equals(p5.info.packageName)) {
                                bp.packageSetting = pkgSetting;
                                bp.perm = p5;
                                bp.uid = pkg.applicationInfo.uid;
                                bp.sourcePackage = p5.info.packageName;
                                if ((parseFlags & 2) != 0) {
                                    if (r6 == null) {
                                        r6 = new StringBuilder(SCAN_BOOTING);
                                    } else {
                                        r6.append(' ');
                                    }
                                    r6.append(p5.info.name);
                                }
                            } else {
                                Slog.w(TAG, "Permission " + p5.info.name + " from package " + p5.info.packageName + " ignored: base tree " + tree.name + " is from package " + tree.sourcePackage);
                            }
                        } else {
                            Slog.w(TAG, "Permission " + p5.info.name + " from package " + p5.info.packageName + " ignored: original from " + bp.sourcePackage);
                        }
                    } else if ((parseFlags & 2) != 0) {
                        if (r6 == null) {
                            r6 = new StringBuilder(SCAN_BOOTING);
                        } else {
                            r6.append(' ');
                        }
                        r6.append("DUP:");
                        r6.append(p5.info.name);
                    }
                    if (bp.perm == p5) {
                        bp.protectionLevel = p5.info.protectionLevel;
                    }
                } else {
                    Slog.w(TAG, "Permission " + p5.info.name + " from package " + p5.info.packageName + " ignored: no group " + p5.group);
                }
            }
            if (r6 != null) {
            }
            int N8 = pkg.instrumentation.size();
            StringBuilder r7 = null;
            for (int i13 = DEX_OPT_SKIPPED; i13 < N8; i13++) {
                PackageParser.Instrumentation a3 = (PackageParser.Instrumentation) pkg.instrumentation.get(i13);
                a3.info.packageName = pkg.applicationInfo.packageName;
                a3.info.sourceDir = pkg.applicationInfo.sourceDir;
                a3.info.publicSourceDir = pkg.applicationInfo.publicSourceDir;
                a3.info.splitSourceDirs = pkg.applicationInfo.splitSourceDirs;
                a3.info.splitPublicSourceDirs = pkg.applicationInfo.splitPublicSourceDirs;
                a3.info.dataDir = pkg.applicationInfo.dataDir;
                a3.info.nativeLibraryDir = pkg.applicationInfo.nativeLibraryDir;
                this.mInstrumentation.put(a3.getComponentName(), a3);
                if ((parseFlags & 2) != 0) {
                    if (r7 == null) {
                        r7 = new StringBuilder(SCAN_BOOTING);
                    } else {
                        r7.append(' ');
                    }
                    r7.append(a3.info.name);
                }
            }
            if (r7 != null) {
            }
            if (pkg.protectedBroadcasts != null) {
                int N9 = pkg.protectedBroadcasts.size();
                for (int i14 = DEX_OPT_SKIPPED; i14 < N9; i14++) {
                    this.mProtectedBroadcasts.add(pkg.protectedBroadcasts.get(i14));
                }
            }
            pkgSetting.setTimeStamp(scanFileTime);
            if (pkg.mOverlayTarget != null) {
                if (pkg.mOverlayTarget != null && !pkg.mOverlayTarget.equals("android")) {
                    if (!this.mOverlays.containsKey(pkg.mOverlayTarget)) {
                        this.mOverlays.put(pkg.mOverlayTarget, new ArrayMap<>());
                    }
                    ArrayMap<String, PackageParser.Package> map = this.mOverlays.get(pkg.mOverlayTarget);
                    map.put(pkg.packageName, pkg);
                    PackageParser.Package orig2 = this.mPackages.get(pkg.mOverlayTarget);
                    if (orig2 != null && !createIdmapForPackagePairLI(orig2, pkg)) {
                        throw new PackageManagerException(-7, "scanPackageLI failed to createIdmap");
                    }
                }
            } else if (this.mOverlays.containsKey(pkg.packageName) && !pkg.packageName.equals("android")) {
                createIdmapsForPackageLI(pkg);
            }
            VendorPackageManagerCallback.callScanPackageLI(this.mVendorCallbacks, 1000, pkg, this.mPackages, (scanFlags & SCAN_BOOTING) == 0);
        }
        return pkg;
    }

    private void adjustCpuAbisForSharedUserLPw(Set<PackageSetting> packagesForUser, PackageParser.Package scannedPackage, boolean forceDexOpt, boolean deferDexOpt) {
        String adjustedAbi;
        String requiredInstructionSet = null;
        if (scannedPackage != null && scannedPackage.applicationInfo.primaryCpuAbi != null) {
            requiredInstructionSet = VMRuntime.getInstructionSet(scannedPackage.applicationInfo.primaryCpuAbi);
        }
        String str = null;
        Iterator i$ = packagesForUser.iterator();
        while (i$.hasNext()) {
            String str2 = (PackageSetting) i$.next();
            if (scannedPackage == null || !scannedPackage.packageName.equals(((PackageSetting) str2).name)) {
                if (((PackageSetting) str2).primaryCpuAbiString != null) {
                    String instructionSet = VMRuntime.getInstructionSet(((PackageSetting) str2).primaryCpuAbiString);
                    if (requiredInstructionSet != null && !instructionSet.equals(requiredInstructionSet)) {
                        String errorMessage = "Instruction set mismatch, " + ((Object) (str == null ? "[caller]" : str)) + " requires " + requiredInstructionSet + " whereas " + ((Object) str2) + " requires " + instructionSet;
                        Slog.w(TAG, errorMessage);
                    }
                    if (requiredInstructionSet == null) {
                        requiredInstructionSet = instructionSet;
                        str = str2;
                    }
                }
            }
        }
        if (requiredInstructionSet != null) {
            if (str != null) {
                adjustedAbi = ((PackageSetting) str).primaryCpuAbiString;
                if (scannedPackage != null) {
                    scannedPackage.applicationInfo.primaryCpuAbi = adjustedAbi;
                }
            } else {
                adjustedAbi = scannedPackage.applicationInfo.primaryCpuAbi;
            }
            for (PackageSetting ps : packagesForUser) {
                if (scannedPackage == null || !scannedPackage.packageName.equals(ps.name)) {
                    if (ps.primaryCpuAbiString == null) {
                        ps.primaryCpuAbiString = adjustedAbi;
                        if (ps.pkg != null && ps.pkg.applicationInfo != null) {
                            ps.pkg.applicationInfo.primaryCpuAbi = adjustedAbi;
                            Slog.i(TAG, "Adjusting ABI for : " + ps.name + " to " + adjustedAbi);
                            if (performDexOptLI(ps.pkg, (String[]) null, forceDexOpt, deferDexOpt, true) == DEX_OPT_FAILED) {
                                ps.primaryCpuAbiString = null;
                                ps.pkg.applicationInfo.primaryCpuAbi = null;
                                return;
                            }
                            this.mInstaller.rmdex(ps.codePathString, getDexCodeInstructionSet(getPreferredInstructionSet()));
                        }
                    } else {
                        continue;
                    }
                }
            }
        }
    }

    private void setUpCustomResolverActivity(PackageParser.Package pkg) {
        synchronized (this.mPackages) {
            this.mResolverReplaced = true;
            this.mResolveActivity.applicationInfo = pkg.applicationInfo;
            this.mResolveActivity.name = this.mCustomResolverComponentName.getClassName();
            this.mResolveActivity.packageName = pkg.applicationInfo.packageName;
            this.mResolveActivity.processName = pkg.applicationInfo.packageName;
            this.mResolveActivity.launchMode = DEX_OPT_SKIPPED;
            this.mResolveActivity.flags = 288;
            this.mResolveActivity.theme = DEX_OPT_SKIPPED;
            this.mResolveActivity.exported = true;
            this.mResolveActivity.enabled = true;
            this.mResolveInfo.activityInfo = this.mResolveActivity;
            this.mResolveInfo.priority = DEX_OPT_SKIPPED;
            this.mResolveInfo.preferredOrder = DEX_OPT_SKIPPED;
            this.mResolveInfo.match = DEX_OPT_SKIPPED;
            this.mResolveComponentName = this.mCustomResolverComponentName;
            Slog.i(TAG, "Replacing default ResolverActivity with custom activity: " + this.mResolveComponentName);
        }
    }

    private static String calculateBundledApkRoot(String codePathString) {
        File codeRoot;
        File codePath = new File(codePathString);
        if (FileUtils.contains(Environment.getRootDirectory(), codePath)) {
            codeRoot = Environment.getRootDirectory();
        } else if (FileUtils.contains(Environment.getOemDirectory(), codePath)) {
            codeRoot = Environment.getOemDirectory();
        } else if (FileUtils.contains(Environment.getVendorDirectory(), codePath)) {
            codeRoot = Environment.getVendorDirectory();
        } else {
            try {
                File f = codePath.getCanonicalFile();
                File parent = f.getParentFile();
                while (true) {
                    File tmp = parent.getParentFile();
                    if (tmp == null) {
                        break;
                    }
                    f = parent;
                    parent = tmp;
                }
                codeRoot = f;
                Slog.w(TAG, "Unrecognized code path " + codePath + " - using " + codeRoot);
            } catch (IOException e) {
                Slog.w(TAG, "Can't canonicalize code path " + codePath);
                return Environment.getRootDirectory().getPath();
            }
        }
        return codeRoot.getPath();
    }

    private void setNativeLibraryPaths(PackageParser.Package pkg) {
        ApplicationInfo info = pkg.applicationInfo;
        String codePath = pkg.codePath;
        File codeFile = new File(codePath);
        boolean bundledApp = isSystemApp(info) && !isUpdatedSystemApp(info);
        boolean asecApp = isForwardLocked(info) || isExternal(info);
        info.nativeLibraryRootDir = null;
        info.nativeLibraryRootRequiresIsa = false;
        info.nativeLibraryDir = null;
        info.secondaryNativeLibraryDir = null;
        if (PackageParser.isApkFile(codeFile)) {
            if (bundledApp) {
                String apkRoot = calculateBundledApkRoot(info.sourceDir);
                boolean is64Bit = VMRuntime.is64BitInstructionSet(getPrimaryInstructionSet(info));
                String apkName = deriveCodePathName(codePath);
                String libDir = is64Bit ? "lib64" : "lib";
                info.nativeLibraryRootDir = Environment.buildPath(new File(apkRoot), new String[]{libDir, apkName}).getAbsolutePath();
                if (info.secondaryCpuAbi != null) {
                    String secondaryLibDir = is64Bit ? "lib" : "lib64";
                    info.secondaryNativeLibraryDir = Environment.buildPath(new File(apkRoot), new String[]{secondaryLibDir, apkName}).getAbsolutePath();
                }
            } else if (asecApp) {
                info.nativeLibraryRootDir = new File(codeFile.getParentFile(), "lib").getAbsolutePath();
            } else {
                info.nativeLibraryRootDir = new File(this.mAppLib32InstallDir, deriveCodePathName(codePath)).getAbsolutePath();
            }
            info.nativeLibraryRootRequiresIsa = false;
            info.nativeLibraryDir = info.nativeLibraryRootDir;
            return;
        }
        info.nativeLibraryRootDir = new File(codeFile, "lib").getAbsolutePath();
        info.nativeLibraryRootRequiresIsa = true;
        info.nativeLibraryDir = new File(info.nativeLibraryRootDir, getPrimaryInstructionSet(info)).getAbsolutePath();
        if (info.secondaryCpuAbi != null) {
            info.secondaryNativeLibraryDir = new File(info.nativeLibraryRootDir, VMRuntime.getInstructionSet(info.secondaryCpuAbi)).getAbsolutePath();
        }
    }

    private void setBundledAppAbisAndRoots(PackageParser.Package pkg, PackageSetting pkgSetting) {
        String apkName = deriveCodePathName(pkg.applicationInfo.getCodePath());
        String apkRoot = calculateBundledApkRoot(pkg.applicationInfo.sourceDir);
        setBundledAppAbi(pkg, apkRoot, apkName);
        if (pkgSetting != null) {
            pkgSetting.primaryCpuAbiString = pkg.applicationInfo.primaryCpuAbi;
            pkgSetting.secondaryCpuAbiString = pkg.applicationInfo.secondaryCpuAbi;
        }
    }

    private static boolean amazonShouldForceAbi(PackageParser.Package pkg) {
        return false;
    }

    private static void setBundledAppAbi(PackageParser.Package pkg, String apkRoot, String apkName) {
        boolean has64BitLibs;
        boolean has32BitLibs;
        File codeFile = new File(pkg.codePath);
        if (amazonShouldForceAbi(pkg)) {
            Log.i(TAG, "Forcing package=" + pkg + " to 32bit ABI " + Build.SUPPORTED_32_BIT_ABIS[DEX_OPT_SKIPPED]);
            has32BitLibs = true;
            has64BitLibs = false;
        } else if (PackageParser.isApkFile(codeFile)) {
            has64BitLibs = new File(apkRoot, new File("lib64", apkName).getPath()).exists();
            has32BitLibs = new File(apkRoot, new File("lib", apkName).getPath()).exists();
        } else {
            File rootDir = new File(codeFile, "lib");
            if (!ArrayUtils.isEmpty(Build.SUPPORTED_64_BIT_ABIS) && !TextUtils.isEmpty(Build.SUPPORTED_64_BIT_ABIS[DEX_OPT_SKIPPED])) {
                String isa = VMRuntime.getInstructionSet(Build.SUPPORTED_64_BIT_ABIS[DEX_OPT_SKIPPED]);
                has64BitLibs = new File(rootDir, isa).exists();
            } else {
                has64BitLibs = false;
            }
            if (!ArrayUtils.isEmpty(Build.SUPPORTED_32_BIT_ABIS) && !TextUtils.isEmpty(Build.SUPPORTED_32_BIT_ABIS[DEX_OPT_SKIPPED])) {
                String isa2 = VMRuntime.getInstructionSet(Build.SUPPORTED_32_BIT_ABIS[DEX_OPT_SKIPPED]);
                has32BitLibs = new File(rootDir, isa2).exists();
            } else {
                has32BitLibs = false;
            }
        }
        if (has64BitLibs && !has32BitLibs) {
            pkg.applicationInfo.primaryCpuAbi = Build.SUPPORTED_64_BIT_ABIS[DEX_OPT_SKIPPED];
            pkg.applicationInfo.secondaryCpuAbi = null;
            return;
        }
        if (has32BitLibs && !has64BitLibs) {
            pkg.applicationInfo.primaryCpuAbi = Build.SUPPORTED_32_BIT_ABIS[DEX_OPT_SKIPPED];
            pkg.applicationInfo.secondaryCpuAbi = null;
            return;
        }
        if (has32BitLibs && has64BitLibs) {
            if ((pkg.applicationInfo.flags & Integer.MIN_VALUE) == 0) {
                Slog.e(TAG, "Package: " + pkg + " has multiple bundled libs, but is not multiarch.");
            }
            if (VMRuntime.is64BitInstructionSet(getPreferredInstructionSet())) {
                pkg.applicationInfo.primaryCpuAbi = Build.SUPPORTED_64_BIT_ABIS[DEX_OPT_SKIPPED];
                pkg.applicationInfo.secondaryCpuAbi = Build.SUPPORTED_32_BIT_ABIS[DEX_OPT_SKIPPED];
                return;
            }
            pkg.applicationInfo.primaryCpuAbi = Build.SUPPORTED_32_BIT_ABIS[DEX_OPT_SKIPPED];
            pkg.applicationInfo.secondaryCpuAbi = Build.SUPPORTED_64_BIT_ABIS[DEX_OPT_SKIPPED];
            return;
        }
        pkg.applicationInfo.primaryCpuAbi = null;
        pkg.applicationInfo.secondaryCpuAbi = null;
    }

    private void killApplication(String pkgName, int appId, String reason) {
        IActivityManager am = ActivityManagerNative.getDefault();
        if (am != null) {
            try {
                am.killApplicationWithAppId(pkgName, appId, reason);
            } catch (RemoteException e) {
            }
        }
    }

    void removePackageLI(PackageSetting ps, boolean chatty) {
        synchronized (this.mPackages) {
            this.mPackages.remove(ps.name);
            PackageParser.Package pkg = ps.pkg;
            if (pkg != null) {
                VendorPackageManagerCallback.callRemovePackageLI(this.mVendorCallbacks, pkg, chatty, this.mPackages);
                cleanPackageDataStructuresLILPw(pkg, chatty);
            }
        }
    }

    void removeInstalledPackageLI(PackageParser.Package pkg, boolean chatty) {
        synchronized (this.mPackages) {
            this.mPackages.remove(pkg.applicationInfo.packageName);
            VendorPackageManagerCallback.callRemoveInstalledPackageLI(this.mVendorCallbacks, pkg, chatty, this.mPackages);
            cleanPackageDataStructuresLILPw(pkg, chatty);
        }
    }

    void cleanPackageDataStructuresLILPw(PackageParser.Package pkg, boolean chatty) {
        ArraySet<String> appOpPerms;
        ArraySet<String> appOpPerms2;
        int N = pkg.providers.size();
        for (int i = DEX_OPT_SKIPPED; i < N; i++) {
            PackageParser.Provider p = (PackageParser.Provider) pkg.providers.get(i);
            this.mProviders.removeProvider(p);
            if (p.info.authority != null) {
                String[] names = p.info.authority.split(";");
                for (int j = DEX_OPT_SKIPPED; j < names.length; j++) {
                    if (this.mProvidersByAuthority.get(names[j]) == p) {
                        this.mProvidersByAuthority.remove(names[j]);
                    }
                }
            }
        }
        if (DEX_OPT_SKIPPED != 0) {
        }
        int N2 = pkg.services.size();
        StringBuilder r = null;
        for (int i2 = DEX_OPT_SKIPPED; i2 < N2; i2++) {
            PackageParser.Service s = (PackageParser.Service) pkg.services.get(i2);
            this.mServices.removeService(s);
            if (chatty) {
                if (r == null) {
                    r = new StringBuilder(SCAN_BOOTING);
                } else {
                    r.append(' ');
                }
                r.append(s.info.name);
            }
        }
        if (r != null) {
        }
        int N3 = pkg.receivers.size();
        for (int i3 = DEX_OPT_SKIPPED; i3 < N3; i3++) {
            PackageParser.Activity a = (PackageParser.Activity) pkg.receivers.get(i3);
            this.mReceivers.removeActivity(a, "receiver");
        }
        if (DEX_OPT_SKIPPED != 0) {
        }
        int N4 = pkg.activities.size();
        for (int i4 = DEX_OPT_SKIPPED; i4 < N4; i4++) {
            PackageParser.Activity a2 = (PackageParser.Activity) pkg.activities.get(i4);
            this.mActivities.removeActivity(a2, "activity");
        }
        if (DEX_OPT_SKIPPED != 0) {
        }
        int N5 = pkg.permissions.size();
        for (int i5 = DEX_OPT_SKIPPED; i5 < N5; i5++) {
            PackageParser.Permission p2 = (PackageParser.Permission) pkg.permissions.get(i5);
            BasePermission bp = (BasePermission) this.mSettings.mPermissions.get(p2.info.name);
            if (bp == null) {
                bp = (BasePermission) this.mSettings.mPermissionTrees.get(p2.info.name);
            }
            if (bp != null && bp.perm == p2) {
                bp.perm = null;
            }
            if ((p2.info.protectionLevel & SCAN_UPDATE_TIME) != 0 && (appOpPerms2 = this.mAppOpPermissionPackages.get(p2.info.name)) != null) {
                appOpPerms2.remove(pkg.packageName);
            }
        }
        if (DEX_OPT_SKIPPED != 0) {
        }
        int N6 = pkg.requestedPermissions.size();
        for (int i6 = DEX_OPT_SKIPPED; i6 < N6; i6++) {
            String perm = (String) pkg.requestedPermissions.get(i6);
            BasePermission bp2 = (BasePermission) this.mSettings.mPermissions.get(perm);
            if (bp2 != null && (bp2.protectionLevel & SCAN_UPDATE_TIME) != 0 && (appOpPerms = this.mAppOpPermissionPackages.get(perm)) != null) {
                appOpPerms.remove(pkg.packageName);
                if (appOpPerms.isEmpty()) {
                    this.mAppOpPermissionPackages.remove(perm);
                }
            }
        }
        if (DEX_OPT_SKIPPED != 0) {
        }
        int N7 = pkg.instrumentation.size();
        for (int i7 = DEX_OPT_SKIPPED; i7 < N7; i7++) {
            PackageParser.Instrumentation a3 = (PackageParser.Instrumentation) pkg.instrumentation.get(i7);
            this.mInstrumentation.remove(a3.getComponentName());
        }
        if (DEX_OPT_SKIPPED != 0) {
        }
        if ((pkg.applicationInfo.flags & 1) != 0 && pkg.libraryNames != null) {
            for (int i8 = DEX_OPT_SKIPPED; i8 < pkg.libraryNames.size(); i8++) {
                String name = (String) pkg.libraryNames.get(i8);
                SharedLibraryEntry cur = this.mSharedLibraries.get(name);
                if (cur != null && cur.apk != null && cur.apk.equals(pkg.packageName)) {
                    this.mSharedLibraries.remove(name);
                }
            }
        }
        if (DEX_OPT_SKIPPED != 0) {
        }
    }

    private static boolean hasPermission(PackageParser.Package pkgInfo, String perm) {
        for (int i = pkgInfo.permissions.size() + DEX_OPT_FAILED; i >= 0; i += DEX_OPT_FAILED) {
            if (((PackageParser.Permission) pkgInfo.permissions.get(i)).info.name.equals(perm)) {
                return true;
            }
        }
        return false;
    }

    private void updatePermissionsLPw(String changingPkg, PackageParser.Package pkgInfo, int flags) {
        BasePermission tree;
        Iterator<BasePermission> it = this.mSettings.mPermissionTrees.values().iterator();
        while (it.hasNext()) {
            BasePermission bp = it.next();
            if (bp.packageSetting == null) {
                bp.packageSetting = (PackageSettingBase) this.mSettings.mPackages.get(bp.sourcePackage);
            }
            if (bp.packageSetting == null) {
                Slog.w(TAG, "Removing dangling permission tree: " + bp.name + " from package " + bp.sourcePackage);
                it.remove();
            } else if (changingPkg != null && changingPkg.equals(bp.sourcePackage) && (pkgInfo == null || !hasPermission(pkgInfo, bp.name))) {
                Slog.i(TAG, "Removing old permission tree: " + bp.name + " from package " + bp.sourcePackage);
                flags |= 1;
                it.remove();
            }
        }
        Iterator<BasePermission> it2 = this.mSettings.mPermissions.values().iterator();
        while (it2.hasNext()) {
            BasePermission bp2 = it2.next();
            if (bp2.type == 2 && bp2.packageSetting == null && bp2.pendingInfo != null && (tree = findPermissionTreeLP(bp2.name)) != null && tree.perm != null) {
                bp2.packageSetting = tree.packageSetting;
                bp2.perm = new PackageParser.Permission(tree.perm.owner, new PermissionInfo(bp2.pendingInfo));
                bp2.perm.info.packageName = tree.perm.info.packageName;
                bp2.perm.info.name = bp2.name;
                bp2.uid = tree.uid;
            }
            if (bp2.packageSetting == null) {
                bp2.packageSetting = (PackageSettingBase) this.mSettings.mPackages.get(bp2.sourcePackage);
            }
            if (bp2.packageSetting == null) {
                Slog.w(TAG, "Removing dangling permission: " + bp2.name + " from package " + bp2.sourcePackage);
                it2.remove();
            } else if (changingPkg != null && changingPkg.equals(bp2.sourcePackage) && (pkgInfo == null || !hasPermission(pkgInfo, bp2.name))) {
                Slog.i(TAG, "Removing old permission: " + bp2.name + " from package " + bp2.sourcePackage);
                flags |= 1;
                it2.remove();
            }
        }
        if ((flags & 1) != 0) {
            for (PackageParser.Package pkg : this.mPackages.values()) {
                if (pkg != pkgInfo) {
                    grantPermissionsLPw(pkg, (flags & 4) != 0 ? true : DEX_OPT_SKIPPED, changingPkg);
                }
            }
        }
        if (pkgInfo != null) {
            grantPermissionsLPw(pkgInfo, (flags & 2) == 0 ? DEX_OPT_SKIPPED : true, changingPkg);
        }
    }

    private void grantPermissionsLPw(PackageParser.Package pkg, boolean replace, String packageOfInterest) {
        boolean allowed;
        SharedUserSetting sharedUserSetting = (PackageSetting) pkg.mExtras;
        if (sharedUserSetting != null) {
            SharedUserSetting sharedUserSetting2 = ((PackageSetting) sharedUserSetting).sharedUser != null ? ((PackageSetting) sharedUserSetting).sharedUser : sharedUserSetting;
            ArraySet<String> origPermissions = ((GrantedPermissions) sharedUserSetting2).grantedPermissions;
            boolean changedPermission = false;
            if (replace) {
                ((PackageSetting) sharedUserSetting).permissionsFixed = false;
                if (sharedUserSetting2 == sharedUserSetting) {
                    origPermissions = new ArraySet<>((ArraySet<String>) ((GrantedPermissions) sharedUserSetting2).grantedPermissions);
                    ((GrantedPermissions) sharedUserSetting2).grantedPermissions.clear();
                    ((GrantedPermissions) sharedUserSetting2).gids = this.mGlobalGids;
                }
            }
            if (((GrantedPermissions) sharedUserSetting2).gids == null) {
                ((GrantedPermissions) sharedUserSetting2).gids = this.mGlobalGids;
            }
            int N = pkg.requestedPermissions.size();
            for (int i = DEX_OPT_SKIPPED; i < N; i++) {
                String name = (String) pkg.requestedPermissions.get(i);
                boolean required = ((Boolean) pkg.requestedPermissionsRequired.get(i)).booleanValue();
                BasePermission bp = (BasePermission) this.mSettings.mPermissions.get(name);
                if (bp == null || bp.packageSetting == null) {
                    if (packageOfInterest == null || packageOfInterest.equals(pkg.packageName)) {
                        Slog.w(TAG, "Unknown permission " + name + " in package " + pkg.packageName);
                    }
                } else {
                    String perm = bp.name;
                    boolean allowedSig = false;
                    if ((bp.protectionLevel & SCAN_UPDATE_TIME) != 0) {
                        ArraySet<String> pkgs = this.mAppOpPermissionPackages.get(bp.name);
                        if (pkgs == null) {
                            pkgs = new ArraySet<>();
                            this.mAppOpPermissionPackages.put(bp.name, pkgs);
                        }
                        pkgs.add(pkg.packageName);
                    }
                    int level = bp.protectionLevel & PACKAGE_VERIFIED;
                    if (level == 0 || level == 1) {
                        allowed = (required || origPermissions.contains(perm) || (isSystemApp((PackageSetting) sharedUserSetting) && !isUpdatedSystemApp((PackageSetting) sharedUserSetting))) && !VendorPackageManagerCallback.callIsDangerousPermissionRestricted(this.mVendorCallbacks, perm, sharedUserSetting, this.mContext);
                    } else if (bp.packageSetting == null) {
                        allowed = false;
                    } else if (level == 2) {
                        allowed = grantSignaturePermission(perm, pkg, bp, origPermissions);
                        if (allowed) {
                            allowedSig = true;
                        }
                    } else {
                        allowed = false;
                    }
                    if (allowed) {
                        if (!isSystemApp((PackageSetting) sharedUserSetting) && ((PackageSetting) sharedUserSetting).permissionsFixed && !allowedSig && !((GrantedPermissions) sharedUserSetting2).grantedPermissions.contains(perm)) {
                            allowed = isNewPlatformPermissionForPackage(perm, pkg);
                        }
                        if (allowed) {
                            if (!((GrantedPermissions) sharedUserSetting2).grantedPermissions.contains(perm)) {
                                changedPermission = true;
                                ((GrantedPermissions) sharedUserSetting2).grantedPermissions.add(perm);
                                ((GrantedPermissions) sharedUserSetting2).gids = appendInts(((GrantedPermissions) sharedUserSetting2).gids, bp.gids);
                            } else if (!((PackageSetting) sharedUserSetting).haveGids) {
                                ((GrantedPermissions) sharedUserSetting2).gids = appendInts(((GrantedPermissions) sharedUserSetting2).gids, bp.gids);
                            }
                        } else if (packageOfInterest == null || packageOfInterest.equals(pkg.packageName)) {
                            Slog.w(TAG, "Not granting permission " + perm + " to package " + pkg.packageName + " because it was previously installed without");
                        }
                    } else if (((GrantedPermissions) sharedUserSetting2).grantedPermissions.remove(perm)) {
                        changedPermission = true;
                        ((GrantedPermissions) sharedUserSetting2).gids = removeInts(((GrantedPermissions) sharedUserSetting2).gids, bp.gids);
                        Slog.i(TAG, "Un-granting permission " + perm + " from package " + pkg.packageName + " (protectionLevel=" + bp.protectionLevel + " flags=0x" + Integer.toHexString(pkg.applicationInfo.flags) + ")");
                    } else if ((bp.protectionLevel & SCAN_UPDATE_TIME) == 0 && (packageOfInterest == null || packageOfInterest.equals(pkg.packageName))) {
                        Slog.w(TAG, "Not granting permission " + perm + " to package " + pkg.packageName + " (protectionLevel=" + bp.protectionLevel + " flags=0x" + Integer.toHexString(pkg.applicationInfo.flags) + ")");
                    }
                }
            }
            if (((changedPermission || replace) && !((PackageSetting) sharedUserSetting).permissionsFixed && !isSystemApp((PackageSetting) sharedUserSetting)) || isUpdatedSystemApp((PackageSetting) sharedUserSetting)) {
                ((PackageSetting) sharedUserSetting).permissionsFixed = true;
            }
            ((PackageSetting) sharedUserSetting).haveGids = true;
        }
    }

    private boolean isNewPlatformPermissionForPackage(String perm, PackageParser.Package pkg) {
        int NP = PackageParser.NEW_PERMISSIONS.length;
        for (int ip = DEX_OPT_SKIPPED; ip < NP; ip++) {
            PackageParser.NewPermissionInfo npi = PackageParser.NEW_PERMISSIONS[ip];
            if (npi.name.equals(perm) && pkg.applicationInfo.targetSdkVersion < npi.sdkVersion) {
                Log.i(TAG, "Auto-granting " + perm + " to old pkg " + pkg.packageName);
                return true;
            }
        }
        return false;
    }

    private boolean grantSignaturePermission(String perm, PackageParser.Package pkg, BasePermission bp, ArraySet<String> origPermissions) {
        Signature trustLevel1;
        Signature[] amazonSignatures = {this.mSettings.getAmzSignature()};
        boolean allowed = (compareSignatures(bp.packageSetting.signatures.mSignatures, pkg.mSignatures) == 0 || compareSignatures(this.mPlatformPackage.mSignatures, pkg.mSignatures) == 0 || allowedOnTrust(perm, pkg)) ? true : DEX_OPT_SKIPPED;
        if (!allowed && (bp.protectionLevel & 16) != 0 && isSystemApp(pkg)) {
            if (isUpdatedSystemApp(pkg)) {
                SharedUserSetting disabledSystemPkgLPr = this.mSettings.getDisabledSystemPkgLPr(pkg.packageName);
                if (((GrantedPermissions) (((PackageSetting) disabledSystemPkgLPr).sharedUser != null ? ((PackageSetting) disabledSystemPkgLPr).sharedUser : disabledSystemPkgLPr)).grantedPermissions.contains(perm)) {
                    if (disabledSystemPkgLPr.isPrivileged()) {
                        allowed = true;
                    }
                } else if (((PackageSetting) disabledSystemPkgLPr).pkg != null && disabledSystemPkgLPr.isPrivileged()) {
                    int j = DEX_OPT_SKIPPED;
                    while (true) {
                        if (j >= ((PackageSetting) disabledSystemPkgLPr).pkg.requestedPermissions.size()) {
                            break;
                        }
                        if (!perm.equals(((PackageSetting) disabledSystemPkgLPr).pkg.requestedPermissions.get(j))) {
                            j++;
                        } else {
                            allowed = true;
                            break;
                        }
                    }
                }
            } else {
                allowed = isPrivilegedApp(pkg);
            }
        }
        if (!allowed && (bp.protectionLevel & SCAN_DEFER_DEX) != 0 && compareSignatures(amazonSignatures, pkg.mSignatures) == 0) {
            allowed = true;
        }
        if (!allowed && (bp.protectionLevel & 2) != 0 && (trustLevel1 = this.mSettings.getTrustLevel1Signature()) != null && compareSignatures(new Signature[]{trustLevel1}, pkg.mSignatures) == 0) {
            allowed = true;
        }
        if (!allowed && (bp.protectionLevel & SCAN_NO_PATHS) != 0) {
            allowed = origPermissions.contains(perm);
        }
        if (!allowed && VendorPackageManagerCallback.callGrantSignaturePermission(this.mVendorCallbacks, perm, pkg, bp)) {
            return true;
        }
        return allowed;
    }

    static final void sendPackageBroadcast(String action, String pkg, Bundle extras, String targetPkg, IIntentReceiver finishedReceiver, int[] userIds) {
        IActivityManager am = ActivityManagerNative.getDefault();
        if (am != null) {
            if (userIds == null) {
                try {
                    userIds = am.getRunningUserIds();
                } catch (RemoteException e) {
                    return;
                }
            }
            int[] arr$ = userIds;
            int len$ = arr$.length;
            for (int i$ = DEX_OPT_SKIPPED; i$ < len$; i$++) {
                int id = arr$[i$];
                Intent intent = new Intent(action, pkg != null ? Uri.fromParts("package", pkg, null) : null);
                if (extras != null) {
                    intent.putExtras(extras);
                }
                if (targetPkg != null) {
                    intent.setPackage(targetPkg);
                }
                int uid = intent.getIntExtra("android.intent.extra.UID", DEX_OPT_FAILED);
                if (uid > 0 && UserHandle.getUserId(uid) != id) {
                    intent.putExtra("android.intent.extra.UID", UserHandle.getUid(id, UserHandle.getAppId(uid)));
                }
                intent.putExtra("android.intent.extra.user_handle", id);
                intent.addFlags(0x04000000);
                am.broadcastIntent((IApplicationThread) null, intent, (String) null, finishedReceiver, DEX_OPT_SKIPPED, (String) null, (Bundle) null, (String) null, DEX_OPT_FAILED, finishedReceiver != null, false, id);
            }
        }
    }

    private boolean isExternalMediaAvailable() {
        return this.mMediaMounted || Environment.isExternalStorageEmulated();
    }

    public PackageCleanItem nextPackageToClean(PackageCleanItem lastPackage) {
        PackageCleanItem packageCleanItem = null;
        synchronized (this.mPackages) {
            if (isExternalMediaAvailable()) {
                ArrayList<PackageCleanItem> pkgs = this.mSettings.mPackagesToBeCleaned;
                if (lastPackage != null) {
                    pkgs.remove(lastPackage);
                }
                if (pkgs.size() > 0) {
                    packageCleanItem = pkgs.get(DEX_OPT_SKIPPED);
                }
            }
        }
        return packageCleanItem;
    }

    void schedulePackageCleaning(String packageName, int userId, boolean andCode) {
        Message msg = this.mHandler.obtainMessage(START_CLEANING_PACKAGE, userId, andCode ? 1 : DEX_OPT_SKIPPED, packageName);
        if (this.mSystemReady) {
            msg.sendToTarget();
            return;
        }
        if (this.mPostSystemReadyMessages == null) {
            this.mPostSystemReadyMessages = new ArrayList<>();
        }
        this.mPostSystemReadyMessages.add(msg);
    }

    void startCleaningPackages() {
        synchronized (this.mPackages) {
            if (isExternalMediaAvailable()) {
                if (!this.mSettings.mPackagesToBeCleaned.isEmpty()) {
                    Intent intent = new Intent("android.content.pm.CLEAN_EXTERNAL_STORAGE");
                    intent.setComponent(DEFAULT_CONTAINER_COMPONENT);
                    IActivityManager am = ActivityManagerNative.getDefault();
                    if (am != null) {
                        try {
                            am.startService((IApplicationThread) null, intent, (String) null, DEX_OPT_SKIPPED);
                        } catch (RemoteException e) {
                        }
                    }
                }
            }
        }
    }

    public void installPackage(String originPath, IPackageInstallObserver2 observer, int installFlags, String installerPackageName, VerificationParams verificationParams, String packageAbiOverride) {
        installPackageAsUser(originPath, observer, installFlags, installerPackageName, verificationParams, packageAbiOverride, UserHandle.getCallingUserId());
    }

    public void installPackageAsUser(String originPath, IPackageInstallObserver2 observer, int installFlags, String installerPackageName, VerificationParams verificationParams, String packageAbiOverride, int userId) {
        int installFlags2;
        UserHandle user;
        this.mContext.enforceCallingOrSelfPermission("android.permission.INSTALL_PACKAGES", null);
        int callingUid = Binder.getCallingUid();
        enforceCrossUserPermission(callingUid, userId, true, true, "installPackageAsUser");
        if (isUserRestricted(userId, "no_install_apps")) {
            if (observer != null) {
                try {
                    observer.onPackageInstalled("", -111, (String) null, (Bundle) null);
                    return;
                } catch (RemoteException e) {
                    return;
                }
            }
            return;
        }
        if (callingUid == SHELL_UID || callingUid == 0) {
            installFlags2 = installFlags | SCAN_NO_PATHS;
        } else {
            installFlags2 = installFlags & (-33) & (-65);
        }
        String tempInstallerPackageName = VendorPackageManagerCallback.callGetInstallerPackageName(this.mVendorCallbacks, callingUid);
        if (tempInstallerPackageName != null) {
            installerPackageName = tempInstallerPackageName;
        }
        if ((installFlags2 & SCAN_UPDATE_TIME) != 0) {
            user = UserHandle.ALL;
        } else {
            user = new UserHandle(userId);
        }
        verificationParams.setInstallerUid(callingUid);
        File originFile = new File(originPath);
        OriginInfo origin = OriginInfo.fromUntrustedFile(originFile);
        Message msg = this.mHandler.obtainMessage(INIT_COPY);
        msg.obj = new InstallParams(this, origin, observer, installFlags2, installerPackageName, verificationParams, user, packageAbiOverride);
        this.mHandler.sendMessage(msg);
    }

    void installStage(String packageName, File stagedDir, String stagedCid, IPackageInstallObserver2 observer, PackageInstaller.SessionParams params, String installerPackageName, int installerUid, UserHandle user) {
        OriginInfo origin;
        VerificationParams verifParams = new VerificationParams((Uri) null, params.originatingUri, params.referrerUri, installerUid, (ManifestDigest) null);
        if (stagedDir != null) {
            origin = OriginInfo.fromStagedFile(stagedDir);
        } else {
            origin = OriginInfo.fromStagedContainer(stagedCid);
        }
        Message msg = this.mHandler.obtainMessage(INIT_COPY);
        msg.obj = new InstallParams(this, origin, observer, params.installFlags, installerPackageName, verifParams, user, params.abiOverride);
        this.mHandler.sendMessage(msg);
    }

    private void sendPackageAddedForUser(String packageName, PackageSetting pkgSetting, int userId) {
        Bundle extras = new Bundle(1);
        extras.putInt("android.intent.extra.UID", UserHandle.getUid(userId, pkgSetting.appId));
        sendPackageBroadcast("android.intent.action.PACKAGE_ADDED", packageName, extras, null, null, new int[]{userId});
        try {
            IActivityManager am = ActivityManagerNative.getDefault();
            boolean isSystem = isSystemApp(pkgSetting) || isUpdatedSystemApp(pkgSetting);
            if (isSystem && am.isUserRunning(userId, false)) {
                Intent bcIntent = new Intent("android.intent.action.BOOT_COMPLETED").addFlags(SCAN_NO_PATHS).setPackage(packageName);
                am.broadcastIntent((IApplicationThread) null, bcIntent, (String) null, (IIntentReceiver) null, DEX_OPT_SKIPPED, (String) null, (Bundle) null, (String) null, DEX_OPT_FAILED, false, false, userId);
            }
        } catch (RemoteException e) {
            Slog.w(TAG, "Unable to bootstrap installed package", e);
        }
    }

    public boolean setApplicationHiddenSettingAsUser(String packageName, boolean hidden, int userId) {
        ApplicationInfo appInfo;
        this.mContext.enforceCallingOrSelfPermission("android.permission.MANAGE_USERS", null);
        int uid = Binder.getCallingUid();
        enforceCrossUserPermission(uid, userId, true, true, "setApplicationHiddenSetting for user " + userId);
        if (hidden && isPackageDeviceAdmin(packageName, userId)) {
            Slog.w(TAG, "Not hiding package " + packageName + ": has active device admin");
            return false;
        }
        if (uid == SHELL_UID && (appInfo = getApplicationInfo(packageName, DEX_OPT_SKIPPED, userId)) != null && (appInfo.flags & 1) != 0) {
            Slog.w(TAG, "Unable to hide systemapp " + packageName);
            return false;
        }
        long callingId = Binder.clearCallingIdentity();
        boolean sendAdded = false;
        boolean sendRemoved = false;
        try {
            synchronized (this.mPackages) {
                PackageSetting pkgSetting = (PackageSetting) this.mSettings.mPackages.get(packageName);
                if (pkgSetting == null) {
                    return false;
                }
                if (pkgSetting.getHidden(userId) != hidden) {
                    pkgSetting.setHidden(hidden, userId);
                    this.mSettings.writePackageRestrictionsLPr(userId);
                    if (hidden) {
                        sendRemoved = true;
                    } else {
                        sendAdded = true;
                    }
                }
                if (sendAdded) {
                    sendPackageAddedForUser(packageName, pkgSetting, userId);
                    return true;
                }
                if (sendRemoved) {
                    killApplication(packageName, UserHandle.getUid(userId, pkgSetting.appId), "hiding pkg");
                    sendApplicationHiddenForUser(packageName, pkgSetting, userId);
                }
                Binder.restoreCallingIdentity(callingId);
                return false;
            }
        } finally {
            Binder.restoreCallingIdentity(callingId);
        }
    }

    private void sendApplicationHiddenForUser(String packageName, PackageSetting pkgSetting, int userId) {
        PackageRemovedInfo info = new PackageRemovedInfo();
        info.removedPackage = packageName;
        info.removedUsers = new int[]{userId};
        info.uid = UserHandle.getUid(userId, pkgSetting.appId);
        info.sendBroadcast(false, false, false);
    }

    public boolean getApplicationHiddenSettingAsUser(String packageName, int userId) {
        boolean z = true;
        this.mContext.enforceCallingOrSelfPermission("android.permission.MANAGE_USERS", null);
        enforceCrossUserPermission(Binder.getCallingUid(), userId, true, false, "getApplicationHidden for user " + userId);
        long callingId = Binder.clearCallingIdentity();
        try {
            synchronized (this.mPackages) {
                PackageSetting pkgSetting = (PackageSetting) this.mSettings.mPackages.get(packageName);
                if (pkgSetting != null) {
                    z = pkgSetting.getHidden(userId);
                }
            }
            return z;
        } finally {
            Binder.restoreCallingIdentity(callingId);
        }
    }

    public int installExistingPackageAsUser(String packageName, int userId) {
        this.mContext.enforceCallingOrSelfPermission("android.permission.INSTALL_PACKAGES", null);
        int uid = Binder.getCallingUid();
        enforceCrossUserPermission(uid, userId, true, true, "installExistingPackage for user " + userId);
        if (isUserRestricted(userId, "no_install_apps")) {
            return -111;
        }
        long callingId = Binder.clearCallingIdentity();
        boolean sendAdded = false;
        try {
            new Bundle(1);
            synchronized (this.mPackages) {
                PackageSetting pkgSetting = (PackageSetting) this.mSettings.mPackages.get(packageName);
                if (pkgSetting == null) {
                    return -3;
                }
                if (!pkgSetting.getInstalled(userId)) {
                    pkgSetting.setInstalled(true, userId);
                    pkgSetting.setHidden(false, userId);
                    this.mSettings.writePackageRestrictionsLPr(userId);
                    sendAdded = true;
                }
                if (sendAdded) {
                    sendPackageAddedForUser(packageName, pkgSetting, userId);
                }
                return 1;
            }
        } finally {
            Binder.restoreCallingIdentity(callingId);
        }
    }

    boolean isUserRestricted(int userId, String restrictionKey) {
        Bundle restrictions = sUserManager.getUserRestrictions(userId);
        if (!restrictions.getBoolean(restrictionKey, false)) {
            return false;
        }
        Log.w(TAG, "User is restricted: " + restrictionKey);
        return true;
    }

    public void verifyPendingInstall(int id, int verificationCode) throws RemoteException {
        this.mContext.enforceCallingOrSelfPermission("android.permission.PACKAGE_VERIFICATION_AGENT", "Only package verification agents can verify applications");
        Message msg = this.mHandler.obtainMessage(PACKAGE_VERIFIED);
        PackageVerificationResponse response = new PackageVerificationResponse(verificationCode, Binder.getCallingUid());
        msg.arg1 = id;
        msg.obj = response;
        this.mHandler.sendMessage(msg);
    }

    /* JADX WARN: Code restructure failed: missing block: B:14:0x0039, code lost:
    
        if (r2.timeoutExtended() != false) goto L19;
     */
    /* JADX WARN: Code restructure failed: missing block: B:15:0x003b, code lost:
    
        r2.extendTimeout();
        r0 = r7.mHandler.obtainMessage(com.android.server.pm.PackageManagerService.PACKAGE_VERIFIED);
        r0.arg1 = r8;
        r0.obj = r1;
        r7.mHandler.sendMessageDelayed(r0, r10);
     */
    /* JADX WARN: Code restructure failed: missing block: B:16:0x004f, code lost:
    
        return;
     */
    /* JADX WARN: Code restructure failed: missing block: B:18:?, code lost:
    
        return;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
    */
    public void extendVerificationTimeout(int id, int verificationCodeAtTimeout, long millisecondsToDelay) {
        this.mContext.enforceCallingOrSelfPermission("android.permission.PACKAGE_VERIFICATION_AGENT", "Only package verification agents can extend verification timeouts");
        PackageVerificationState state = this.mPendingVerification.get(id);
        PackageVerificationResponse response = new PackageVerificationResponse(verificationCodeAtTimeout, Binder.getCallingUid());
        if (millisecondsToDelay > 3600000) {
            millisecondsToDelay = 3600000;
        }
        if (millisecondsToDelay < 0) {
            millisecondsToDelay = 0;
        }
        if (verificationCodeAtTimeout == 1 || verificationCodeAtTimeout != DEX_OPT_FAILED) {
        }
    }

    public void broadcastPackageVerified(int verificationId, Uri packageUri, int verificationCode, UserHandle user) {
        Intent intent = new Intent("android.intent.action.PACKAGE_VERIFIED");
        intent.setDataAndType(packageUri, PACKAGE_MIME_TYPE);
        intent.addFlags(1);
        intent.putExtra("android.content.pm.extra.VERIFICATION_ID", verificationId);
        intent.putExtra("android.content.pm.extra.VERIFICATION_RESULT", verificationCode);
        this.mContext.sendBroadcastAsUser(intent, user, "android.permission.PACKAGE_VERIFICATION_AGENT");
    }

    public ComponentName matchComponentForVerifier(String packageName, List<ResolveInfo> receivers) {
        ActivityInfo targetReceiver = null;
        int NR = receivers.size();
        int i = DEX_OPT_SKIPPED;
        while (true) {
            if (i >= NR) {
                break;
            }
            ResolveInfo info = receivers.get(i);
            if (info.activityInfo == null || !packageName.equals(info.activityInfo.packageName)) {
                i++;
            } else {
                targetReceiver = info.activityInfo;
                break;
            }
        }
        if (targetReceiver == null) {
            return null;
        }
        return new ComponentName(targetReceiver.packageName, targetReceiver.name);
    }

    public List<ComponentName> matchVerifiers(PackageInfoLite pkgInfo, List<ResolveInfo> receivers, PackageVerificationState verificationState) {
        int verifierUid;
        if (pkgInfo.verifiers.length == 0) {
            return null;
        }
        int N = pkgInfo.verifiers.length;
        List<ComponentName> sufficientVerifiers = new ArrayList<>(N + 1);
        for (int i = DEX_OPT_SKIPPED; i < N; i++) {
            VerifierInfo verifierInfo = pkgInfo.verifiers[i];
            ComponentName comp = matchComponentForVerifier(verifierInfo.packageName, receivers);
            if (comp != null && (verifierUid = getUidForVerifier(verifierInfo)) != DEX_OPT_FAILED) {
                sufficientVerifiers.add(comp);
                verificationState.addSufficientVerifier(verifierUid);
            }
        }
        return sufficientVerifiers;
    }

    private int getUidForVerifier(VerifierInfo verifierInfo) {
        int i = DEX_OPT_FAILED;
        synchronized (this.mPackages) {
            PackageParser.Package pkg = this.mPackages.get(verifierInfo.packageName);
            if (pkg != null) {
                if (pkg.mSignatures.length != 1) {
                    Slog.i(TAG, "Verifier package " + verifierInfo.packageName + " has more than one signature; ignoring");
                } else {
                    try {
                        Signature verifierSig = pkg.mSignatures[DEX_OPT_SKIPPED];
                        PublicKey publicKey = verifierSig.getPublicKey();
                        byte[] expectedPublicKey = publicKey.getEncoded();
                        byte[] actualPublicKey = verifierInfo.publicKey.getEncoded();
                        if (!Arrays.equals(actualPublicKey, expectedPublicKey)) {
                            Slog.i(TAG, "Verifier package " + verifierInfo.packageName + " does not have the expected public key; ignoring");
                        } else {
                            i = pkg.applicationInfo.uid;
                        }
                    } catch (CertificateException e) {
                    }
                }
            }
        }
        return i;
    }

    public void finishPackageInstall(int token) {
        enforceSystemOrRoot("Only the system is allowed to finish installs");
        Message msg = this.mHandler.obtainMessage(POST_INSTALL, token, DEX_OPT_SKIPPED);
        this.mHandler.sendMessage(msg);
    }

    public long getVerificationTimeout() {
        return Settings.Global.getLong(this.mContext.getContentResolver(), "verifier_timeout", DEFAULT_VERIFICATION_TIMEOUT);
    }

    public int getDefaultVerificationResponse() {
        return Settings.Global.getInt(this.mContext.getContentResolver(), "verifier_default_response", 1);
    }

    public boolean isVerificationEnabled(int userId, int installFlags) {
        boolean ensureVerifyAppsEnabled = isUserRestricted(userId, "ensure_verify_apps");
        if ((installFlags & SCAN_NO_PATHS) != 0) {
            if (ActivityManager.isRunningInTestHarness()) {
                return false;
            }
            if (ensureVerifyAppsEnabled) {
                return true;
            }
            if (Settings.Global.getInt(this.mContext.getContentResolver(), "verifier_verify_adb_installs", 1) == 0) {
                return false;
            }
        }
        return ensureVerifyAppsEnabled || Settings.Global.getInt(this.mContext.getContentResolver(), "package_verifier_enable", 1) == 1;
    }

    public int getUnknownSourcesSettings() {
        return Settings.Global.getInt(this.mContext.getContentResolver(), "install_non_market_apps", DEX_OPT_FAILED);
    }

    public void setInstallerPackageName(String targetPackage, String installerPackageName) {
        PackageSetting installerPackageSetting;
        Signature[] callerSignature;
        PackageSetting setting;
        int uid = Binder.getCallingUid();
        synchronized (this.mPackages) {
            PackageSetting targetPackageSetting = (PackageSetting) this.mSettings.mPackages.get(targetPackage);
            if (targetPackageSetting == null) {
                throw new IllegalArgumentException("Unknown target package: " + targetPackage);
            }
            if (installerPackageName != null) {
                installerPackageSetting = (PackageSetting) this.mSettings.mPackages.get(installerPackageName);
                if (installerPackageSetting == null) {
                    throw new IllegalArgumentException("Unknown installer package: " + installerPackageName);
                }
            } else {
                installerPackageSetting = null;
            }
            Object obj = this.mSettings.getUserIdLPw(uid);
            if (obj != null) {
                if (obj instanceof SharedUserSetting) {
                    callerSignature = ((SharedUserSetting) obj).signatures.mSignatures;
                } else if (obj instanceof PackageSetting) {
                    callerSignature = ((PackageSetting) obj).signatures.mSignatures;
                } else {
                    throw new SecurityException("Bad object " + obj + " for uid " + uid);
                }
                if (installerPackageSetting != null && compareSignatures(callerSignature, installerPackageSetting.signatures.mSignatures) != 0) {
                    throw new SecurityException("Caller does not have same cert as new installer package " + installerPackageName);
                }
                if (targetPackageSetting.installerPackageName != null && (setting = (PackageSetting) this.mSettings.mPackages.get(targetPackageSetting.installerPackageName)) != null && compareSignatures(callerSignature, setting.signatures.mSignatures) != 0) {
                    throw new SecurityException("Caller does not have same cert as old installer package " + targetPackageSetting.installerPackageName);
                }
                targetPackageSetting.installerPackageName = installerPackageName;
                scheduleWriteSettingsLocked();
            } else {
                throw new SecurityException("Unknown calling uid " + uid);
            }
        }
    }

    public void processPendingInstall(InstallArgs args, int currentStatus) {
        this.mHandler.post(new PackageManagerService$6(this, currentStatus, args));
    }

    public static long calculateDirectorySize(IMediaContainerService mcs, File[] paths) throws RemoteException {
        long result = 0;
        int len$ = paths.length;
        for (int i$ = DEX_OPT_SKIPPED; i$ < len$; i$++) {
            File path = paths[i$];
            result += mcs.calculateDirectorySize(path.getAbsolutePath());
        }
        return result;
    }

    private static void clearDirectory(IMediaContainerService mcs, File[] paths) {
        int len$ = paths.length;
        for (int i$ = DEX_OPT_SKIPPED; i$ < len$; i$++) {
            File path = paths[i$];
            try {
                mcs.clearDirectory(path.getAbsolutePath());
            } catch (RemoteException e) {
            }
        }
    }

    private static boolean installOnSd(int installFlags) {
        return (installFlags & 16) == 0 && (installFlags & 8) != 0;
    }

    private static boolean installForwardLocked(int installFlags) {
        return (installFlags & 1) != 0;
    }

    public InstallArgs createInstallArgs(InstallParams params) {
        return (installOnSd(params.installFlags) || params.isForwardLocked()) ? new AsecInstallArgs(this, params) : new FileInstallArgs(this, params);
    }

    private InstallArgs createInstallArgsForExisting(int installFlags, String codePath, String resourcePath, String nativeLibraryRoot, String[] instructionSets) {
        boolean isInAsec;
        if (installOnSd(installFlags)) {
            isInAsec = true;
        } else if (installForwardLocked(installFlags) && !codePath.startsWith(this.mDrmAppPrivateInstallDir.getAbsolutePath())) {
            isInAsec = true;
        } else {
            isInAsec = false;
        }
        if (isInAsec) {
            return new AsecInstallArgs(this, codePath, instructionSets, installOnSd(installFlags), installForwardLocked(installFlags));
        }
        return new FileInstallArgs(this, codePath, resourcePath, nativeLibraryRoot, instructionSets);
    }

    public boolean isAsecExternal(String cid) {
        String asecPath = PackageHelper.getSdFilesystem(cid);
        return (asecPath == null || asecPath.startsWith(this.mAsecInternalPath)) ? false : true;
    }

    private static void maybeThrowExceptionForMultiArchCopy(String message, int copyRet) throws PackageManagerException {
        if (copyRet < 0 && copyRet != -114 && copyRet != -113) {
            throw new PackageManagerException(copyRet, message);
        }
    }

    static String cidFromCodePath(String fullCodePath) {
        int eidx = fullCodePath.lastIndexOf("/");
        String subStr1 = fullCodePath.substring(DEX_OPT_SKIPPED, eidx);
        int sidx = subStr1.lastIndexOf("/");
        return subStr1.substring(sidx + 1, eidx);
    }

    static String getAsecPackageName(String packageCid) {
        int idx = packageCid.lastIndexOf(INSTALL_PACKAGE_SUFFIX);
        return idx == DEX_OPT_FAILED ? packageCid : packageCid.substring(DEX_OPT_SKIPPED, idx);
    }

    public static String getNextCodePath(String oldCodePath, String prefix, String suffix) {
        String subStr;
        int idx = 1;
        if (oldCodePath != null) {
            String subStr2 = oldCodePath;
            if (suffix != null && subStr2.endsWith(suffix)) {
                subStr2 = subStr2.substring(DEX_OPT_SKIPPED, subStr2.length() - suffix.length());
            }
            int sidx = subStr2.lastIndexOf(prefix);
            if (sidx != DEX_OPT_FAILED && (subStr = subStr2.substring(prefix.length() + sidx)) != null) {
                if (subStr.startsWith(INSTALL_PACKAGE_SUFFIX)) {
                    subStr = subStr.substring(INSTALL_PACKAGE_SUFFIX.length());
                }
                try {
                    int idx2 = Integer.parseInt(subStr);
                    idx = idx2 <= 1 ? idx2 + 1 : idx2 + DEX_OPT_FAILED;
                } catch (NumberFormatException e) {
                }
            }
        }
        String idxStr = INSTALL_PACKAGE_SUFFIX + Integer.toString(idx);
        return prefix + idxStr;
    }

    public File getNextCodePath(String packageName) {
        File result;
        int suffix = 1;
        do {
            result = new File(this.mAppInstallDir, packageName + INSTALL_PACKAGE_SUFFIX + suffix);
            suffix++;
        } while (result.exists());
        return result;
    }

    private static boolean ignoreCodePath(String fullPathStr) {
        String apkName = deriveCodePathName(fullPathStr);
        int idx = apkName.lastIndexOf(INSTALL_PACKAGE_SUFFIX);
        if (idx != DEX_OPT_FAILED && idx + 1 < apkName.length()) {
            String version = apkName.substring(idx + 1);
            try {
                Integer.parseInt(version);
                return true;
            } catch (NumberFormatException e) {
            }
        }
        return false;
    }

    static String deriveCodePathName(String codePath) {
        if (codePath == null) {
            return null;
        }
        File codeFile = new File(codePath);
        String name = codeFile.getName();
        if (!codeFile.isDirectory()) {
            if (name.endsWith(".apk") || name.endsWith(".tmp")) {
                int lastDot = name.lastIndexOf(46);
                return name.substring(DEX_OPT_SKIPPED, lastDot);
            }
            Slog.w(TAG, "Odd, " + codePath + " doesn't look like an APK");
            return null;
        }
        return name;
    }

    private void installNewPackageLI(PackageParser.Package pkg, int parseFlags, int scanFlags, UserHandle user, String installerPackageName, PackageInstalledInfo res) {
        String pkgName = pkg.packageName;
        if (!VendorPackageManagerCallback.callShouldLogNewPackageInstallation(this.mVendorCallbacks, pkgName, parseFlags, scanFlags, installerPackageName)) {
            Slog.d(TAG, "Sideloading logging is not enabled on the device");
        }
        boolean dataDirExists = getDataPathForPackage(pkg.packageName, DEX_OPT_SKIPPED).exists();
        synchronized (this.mPackages) {
            if (this.mSettings.mRenamedPackages.containsKey(pkgName)) {
                res.setError(DEX_OPT_FAILED, "Attempt to re-install " + pkgName + " without first uninstalling package running as " + ((String) this.mSettings.mRenamedPackages.get(pkgName)));
                return;
            }
            if (this.mPackages.containsKey(pkgName)) {
                res.setError(DEX_OPT_FAILED, "Attempt to re-install " + pkgName + " without first uninstalling.");
                return;
            }
            try {
                PackageParser.Package newPackage = scanPackageLI(pkg, parseFlags, scanFlags, System.currentTimeMillis(), user);
                if (newPackage == null) {
                    throw new PackageManagerException(-2, "ScanPackageLI returned a null package");
                }
                updateSettingsLI(newPackage, installerPackageName, null, null, res);
                if (res.returnCode != 1) {
                    deletePackageLI(pkgName, UserHandle.ALL, false, null, null, dataDirExists ? 1 : DEX_OPT_SKIPPED, res.removedInfo, true);
                }
            } catch (PackageManagerException e) {
                res.setError("Package couldn't be installed in " + pkg.codePath, e);
            }
        }
    }

    private boolean checkUpgradeKeySetLP(PackageSetting oldPS, PackageParser.Package newPkg) {
        long[] upgradeKeySets = oldPS.keySetData.getUpgradeKeySets();
        KeySetManagerService ksms = this.mSettings.mKeySetManagerService;
        for (int i = DEX_OPT_SKIPPED; i < upgradeKeySets.length; i++) {
            Set<PublicKey> upgradeSet = ksms.getPublicKeysFromKeySetLPr(upgradeKeySets[i]);
            if (newPkg.mSigningKeys.containsAll(upgradeSet)) {
                return true;
            }
        }
        return false;
    }

    private void replacePackageLI(PackageParser.Package pkg, int parseFlags, int scanFlags, UserHandle user, String installerPackageName, PackageInstalledInfo res) {
        boolean weFroze;
        String pkgName = pkg.packageName;
        synchronized (this.mPackages) {
            PackageParser.Package oldPackage = this.mPackages.get(pkgName);
            PackageSetting ps = (PackageSetting) this.mSettings.mPackages.get(pkgName);
            if (ps == null || !ps.keySetData.isUsingUpgradeKeySets() || ps.sharedUser != null) {
                if (compareSignatures(oldPackage.mSignatures, pkg.mSignatures) != 0 && !PackageHelper.checkMatchingSignature(PackageHelper.readCertificateAsSignature("/system/vendor/data/amz.rsa"), pkg.mSignatures)) {
                    res.setError(-7, "New package has a different signature: " + pkgName);
                    return;
                }
            } else if (!checkUpgradeKeySetLP(ps, pkg)) {
                res.setError(-7, "New package not signed by keys specified by upgrade-keysets: " + pkgName);
                return;
            }
            if (!Objects.equals(oldPackage.mSharedUserId, pkg.mSharedUserId)) {
                res.setError(-8, "Forbidding shared user change from " + oldPackage.mSharedUserId + " to " + pkg.mSharedUserId);
                return;
            }
            int[] allUsers = sUserManager.getUserIds();
            boolean[] perUserInstalled = new boolean[allUsers.length];
            for (int i = DEX_OPT_SKIPPED; i < allUsers.length; i++) {
                perUserInstalled[i] = ps != null ? ps.getInstalled(allUsers[i]) : false;
            }
            if (!ps.frozen) {
                ps.frozen = true;
                weFroze = true;
            } else {
                weFroze = false;
            }
            try {
                killApplication(pkgName, oldPackage.applicationInfo.uid, "replace pkg");
                boolean sysPkg = isSystemApp(oldPackage);
                if (sysPkg) {
                    replaceSystemPackageLI(oldPackage, pkg, parseFlags, scanFlags, user, allUsers, perUserInstalled, installerPackageName, res);
                } else {
                    replaceNonSystemPackageLI(oldPackage, pkg, parseFlags, scanFlags, user, allUsers, perUserInstalled, installerPackageName, res);
                }
            } finally {
                if (weFroze) {
                    unfreezePackage(pkgName);
                }
            }
        }
    }

    private void replaceNonSystemPackageLI(PackageParser.Package deletedPackage, PackageParser.Package pkg, int parseFlags, int scanFlags, UserHandle user, int[] allUsers, boolean[] perUserInstalled, String installerPackageName, PackageInstalledInfo res) {
        long origUpdateTime;
        String pkgName = deletedPackage.packageName;
        boolean deletedPkg = true;
        boolean updatedSettings = false;
        if (pkg.mExtras != null) {
            origUpdateTime = ((PackageSetting) pkg.mExtras).lastUpdateTime;
        } else {
            origUpdateTime = 0;
        }
        if (!deletePackageLI(pkgName, null, true, null, null, 1, res.removedInfo, true)) {
            res.setError(-10, "replaceNonSystemPackageLI");
            deletedPkg = false;
        } else {
            if (isForwardLocked(deletedPackage) || isExternal(deletedPackage)) {
                int[] uidArray = {deletedPackage.applicationInfo.uid};
                ArrayList<String> pkgList = new ArrayList<>(1);
                pkgList.add(deletedPackage.applicationInfo.packageName);
                sendResourcesChangedBroadcast(false, true, pkgList, uidArray, null);
            }
            deleteCodeCacheDirsLI(pkgName);
            try {
                PackageParser.Package newPackage = scanPackageLI(pkg, parseFlags, scanFlags | SCAN_UPDATE_TIME, System.currentTimeMillis(), user);
                updateSettingsLI(newPackage, installerPackageName, allUsers, perUserInstalled, res);
                updatedSettings = true;
            } catch (PackageManagerException e) {
                res.setError("Package couldn't be installed in " + pkg.codePath, e);
            }
        }
        if (res.returnCode != 1) {
            if (updatedSettings) {
                deletePackageLI(pkgName, null, true, allUsers, perUserInstalled, 1, res.removedInfo, true);
            }
            if (deletedPkg) {
                File restoreFile = new File(deletedPackage.codePath);
                boolean oldOnSd = isExternal(deletedPackage);
                int oldParseFlags = this.mDefParseFlags | 2 | (isForwardLocked(deletedPackage) ? 16 : DEX_OPT_SKIPPED) | (oldOnSd ? SCAN_NO_PATHS : DEX_OPT_SKIPPED);
                try {
                    scanPackageLI(restoreFile, oldParseFlags, 72, origUpdateTime, (UserHandle) null);
                    synchronized (this.mPackages) {
                        updatePermissionsLPw(deletedPackage.packageName, deletedPackage, 1);
                        this.mSettings.writeLPr();
                    }
                    Slog.i(TAG, "Successfully restored package : " + pkgName + " after failed upgrade");
                } catch (PackageManagerException e2) {
                    Slog.e(TAG, "Failed to restore package : " + pkgName + " after failed upgrade: " + e2.getMessage());
                }
            }
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:41:0x0133  */
    /* JADX WARN: Removed duplicated region for block: B:69:0x01c2 A[LOOP:0: B:67:0x01be->B:69:0x01c2, LOOP_END] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
    */
    private void replaceSystemPackageLI(PackageParser.Package deletedPackage, PackageParser.Package pkg, int parseFlags, int scanFlags, UserHandle user, int[] allUsers, boolean[] perUserInstalled, String installerPackageName, PackageInstalledInfo res) {
        boolean disabledSystem;
        PackageParser.Package newPackage;
        int len$;
        int i$;
        boolean updatedSettings = false;
        int parseFlags2 = parseFlags | 1;
        if ((deletedPackage.applicationInfo.flags & 0x40000000) != 0) {
            parseFlags2 |= SCAN_DEFER_DEX;
        }
        String packageName = deletedPackage.packageName;
        if (packageName == null) {
            res.setError(-10, "Attempt to delete null packageName.");
            return;
        }
        synchronized (this.mPackages) {
            PackageParser.Package oldPkg = this.mPackages.get(packageName);
            PackageSetting oldPkgSetting = (PackageSetting) this.mSettings.mPackages.get(packageName);
            if (oldPkg == null || oldPkg.applicationInfo == null || oldPkgSetting == null) {
                res.setError(-10, "Couldn't find package:" + packageName + " information");
            } else {
                res.removedInfo.uid = oldPkg.applicationInfo.uid;
                res.removedInfo.removedPackage = packageName;
                removePackageLI(oldPkgSetting, true);
                synchronized (this.mPackages) {
                    disabledSystem = this.mSettings.disableSystemPackageLPw(packageName);
                    if (!disabledSystem && deletedPackage != null) {
                        res.removedInfo.args = createInstallArgsForExisting(DEX_OPT_SKIPPED, deletedPackage.applicationInfo.getCodePath(), deletedPackage.applicationInfo.getResourcePath(), deletedPackage.applicationInfo.nativeLibraryRootDir, getAppDexInstructionSets(deletedPackage.applicationInfo));
                    } else {
                        res.removedInfo.args = null;
                        updatedSettings = true;
                    }
                }
                deleteCodeCacheDirsLI(packageName);
                res.returnCode = 1;
                pkg.applicationInfo.flags |= SCAN_DEFER_DEX;
                try {
                    newPackage = scanPackageLI(pkg, parseFlags2, scanFlags, 0L, user);
                } catch (PackageManagerException e) {
                    e = e;
                    newPackage = null;
                }
                try {
                    if (newPackage.mExtras != null) {
                        PackageSetting newPkgSetting = (PackageSetting) newPackage.mExtras;
                        newPkgSetting.firstInstallTime = oldPkgSetting.firstInstallTime;
                        newPkgSetting.lastUpdateTime = System.currentTimeMillis();
                    }
                    if (res.returnCode == 1) {
                        updateSettingsLI(newPackage, installerPackageName, allUsers, perUserInstalled, res);
                        updatedSettings = true;
                    }
                } catch (PackageManagerException e2) {
                    e = e2;
                    res.setError("Package couldn't be installed in " + pkg.codePath, e);
                    if (res.returnCode != 1) {
                    }
                    if (res.returnCode == 1) {
                        newPackage.applicationInfo.flags |= 8;
                        Slog.i(TAG, "Updated system package " + packageName + " is persistent, killing it.");
                        int appId = UserHandle.getAppId(newPackage.applicationInfo.uid);
                        int[] users = sUserManager.getUserIds();
                        len$ = users.length;
                        while (i$ < len$) {
                        }
                    }
                }
                if (res.returnCode != 1) {
                    if (newPackage != null) {
                        removeInstalledPackageLI(newPackage, true);
                    }
                    try {
                        scanPackageLI(oldPkg, parseFlags2, 8, 0L, user);
                    } catch (PackageManagerException e3) {
                        Slog.e(TAG, "Failed to restore original package: " + e3.getMessage());
                    }
                    synchronized (this.mPackages) {
                        if (disabledSystem) {
                            this.mSettings.enableSystemPackageLPw(packageName);
                        }
                        if (updatedSettings) {
                            this.mSettings.setInstallerPackageName(packageName, oldPkgSetting.installerPackageName);
                        }
                        this.mSettings.writeLPr();
                    }
                }
                if (res.returnCode == 1 && (oldPkg.applicationInfo.flags & 8) != 0) {
                    newPackage.applicationInfo.flags |= 8;
                    Slog.i(TAG, "Updated system package " + packageName + " is persistent, killing it.");
                    int appId2 = UserHandle.getAppId(newPackage.applicationInfo.uid);
                    int[] users2 = sUserManager.getUserIds();
                    len$ = users2.length;
                    for (i$ = DEX_OPT_SKIPPED; i$ < len$; i$++) {
                        int u = users2[i$];
                        killProcess(packageName, UserHandle.getUid(u, appId2));
                    }
                }
            }
        }
    }

    private void updateSettingsLI(PackageParser.Package newPackage, String installerPackageName, int[] allUsers, boolean[] perUserInstalled, PackageInstalledInfo res) {
        PackageSetting ps;
        String pkgName = newPackage.packageName;
        synchronized (this.mPackages) {
            this.mSettings.setInstallStatus(pkgName, DEX_OPT_SKIPPED);
            this.mSettings.writeLPr();
        }
        synchronized (this.mPackages) {
            updatePermissionsLPw(newPackage.packageName, newPackage, (newPackage.permissions.size() > 0 ? 1 : DEX_OPT_SKIPPED) | 2);
            if (isSystemApp(newPackage) && (ps = (PackageSetting) this.mSettings.mPackages.get(pkgName)) != null) {
                if (res.origUsers != null) {
                    int[] arr$ = res.origUsers;
                    int len$ = arr$.length;
                    for (int i$ = DEX_OPT_SKIPPED; i$ < len$; i$++) {
                        int userHandle = arr$[i$];
                        ps.setEnabled(DEX_OPT_SKIPPED, userHandle, installerPackageName);
                    }
                }
                if (allUsers != null && perUserInstalled != null) {
                    for (int i = DEX_OPT_SKIPPED; i < allUsers.length; i++) {
                        ps.setInstalled(perUserInstalled[i], allUsers[i]);
                    }
                }
            }
            res.name = pkgName;
            res.uid = newPackage.applicationInfo.uid;
            res.pkg = newPackage;
            this.mSettings.setInstallStatus(pkgName, 1);
            this.mSettings.setInstallerPackageName(pkgName, installerPackageName);
            res.returnCode = 1;
            this.mSettings.writeLPr();
        }
    }

    public void installPackageLI(InstallArgs args, PackageInstalledInfo res) {
        boolean sigsOk;
        int installFlags = args.installFlags;
        String installerPackageName = args.installerPackageName;
        File tmpPackageFile = new File(args.getCodePath());
        boolean forwardLocked = (installFlags & 1) != 0;
        boolean onSd = (installFlags & 8) != 0;
        boolean replace = false;
        res.returnCode = 1;
        int parseFlags = (onSd ? SCAN_NO_PATHS : DEX_OPT_SKIPPED) | this.mDefParseFlags | 2 | (forwardLocked ? 16 : DEX_OPT_SKIPPED) | SCAN_DELETE_DATA_ON_FAILURES;
        PackageParser pp = new PackageParser();
        pp.setSeparateProcesses(this.mSeparateProcesses);
        pp.setDisplayMetrics(this.mMetrics);
        try {
            PackageParser.Package pkg = pp.parsePackage(tmpPackageFile, parseFlags);
            if (VendorPackageManagerCallback.callShouldBounceInstall(this.mVendorCallbacks, installerPackageName)) {
                res.setError(-111, "Installation blocked");
                return;
            }
            if (VendorPackageManagerCallback.callShouldBlockInstallation(this.mVendorCallbacks, pkg.packageName)) {
                res.setError(-111, "Installation blocked");
                return;
            }
            if (args.abiOverride != null) {
                pkg.cpuAbiOverride = args.abiOverride;
            }
            String pkgName = pkg.packageName;
            res.name = pkgName;
            if ((pkg.applicationInfo.flags & SCAN_BOOTING) != 0 && (installFlags & 4) == 0) {
                res.setError(-15, "installPackageLI");
                return;
            }
            try {
                pp.collectCertificates(pkg, parseFlags);
                pp.collectManifestDigest(pkg);
                if (args.manifestDigest != null && !args.manifestDigest.equals(pkg.manifestDigest)) {
                    res.setError(-23, "Manifest digest changed");
                    return;
                }
                String oldCodePath = null;
                boolean systemApp = false;
                synchronized (this.mPackages) {
                    if ((installFlags & 2) != 0) {
                        String oldName = (String) this.mSettings.mRenamedPackages.get(pkgName);
                        if (pkg.mOriginalPackages != null && pkg.mOriginalPackages.contains(oldName) && this.mPackages.containsKey(oldName)) {
                            pkg.setPackageName(oldName);
                            pkgName = pkg.packageName;
                            replace = true;
                        } else if (this.mPackages.containsKey(pkgName)) {
                            replace = true;
                        }
                    }
                    PackageSetting ps = (PackageSetting) this.mSettings.mPackages.get(pkgName);
                    if (ps != null) {
                        if (!ps.keySetData.isUsingUpgradeKeySets() || ps.sharedUser != null) {
                            try {
                                verifySignaturesLP(ps, pkg);
                            } catch (PackageManagerException e) {
                                res.setError(e.error, e.getMessage());
                                return;
                            }
                        } else if (!checkUpgradeKeySetLP(ps, pkg)) {
                            res.setError(-7, "Package " + pkg.packageName + " upgrade keys do not match the previously installed version");
                            return;
                        }
                        oldCodePath = ((PackageSetting) this.mSettings.mPackages.get(pkgName)).codePathString;
                        if (ps.pkg != null && ps.pkg.applicationInfo != null) {
                            systemApp = (ps.pkg.applicationInfo.flags & 1) != 0;
                        }
                        res.origUsers = ps.queryInstalledUsers(sUserManager.getUserIds(), true);
                    }
                    int N = pkg.permissions.size();
                    for (int i = N + DEX_OPT_FAILED; i >= 0; i += DEX_OPT_FAILED) {
                        PackageParser.Permission perm = (PackageParser.Permission) pkg.permissions.get(i);
                        BasePermission bp = (BasePermission) this.mSettings.mPermissions.get(perm.info.name);
                        if (compareSignatures(new Signature[]{this.mSettings.getAmzSignature()}, pkg.mSignatures) == 0 && (bp == null || !bp.sourcePackage.equals("android.amazon.perm"))) {
                            Slog.w(TAG, "Centralized permission: Package " + pkg.packageName + "is declaring a permission " + perm.info.name + " which is notdeclared in the centralized apk");
                        }
                        if (bp != null) {
                            if (!bp.sourcePackage.equals(pkg.packageName) || !(bp.packageSetting instanceof PackageSetting) || !bp.packageSetting.keySetData.isUsingUpgradeKeySets() || bp.packageSetting.sharedUser != null) {
                                sigsOk = compareSignatures(bp.packageSetting.signatures.mSignatures, pkg.mSignatures) == 0;
                            } else {
                                sigsOk = checkUpgradeKeySetLP((PackageSetting) bp.packageSetting, pkg);
                            }
                            if (!sigsOk && !VendorPackageManagerCallback.callOnParsePermission(this.mVendorCallbacks, pkg, perm)) {
                                if (!bp.sourcePackage.equals("android") && !bp.sourcePackage.equals("android.amazon.perm")) {
                                    res.setError(-112, "Package " + pkg.packageName + " attempting to redeclare permission " + perm.info.name + " already owned by " + bp.sourcePackage);
                                    res.origPermission = perm.info.name;
                                    res.origPackage = bp.sourcePackage;
                                    return;
                                }
                                Slog.w(TAG, "Package " + pkg.packageName + " attempting to redeclare system permission " + perm.info.name + "; ignoring new declaration");
                                pkg.permissions.remove(i);
                            }
                        }
                    }
                    if (systemApp && onSd) {
                        res.setError(-19, "Cannot install updates to system apps on sdcard");
                        return;
                    }
                    if (!args.doRename(res.returnCode, pkg, oldCodePath)) {
                        res.setError(-4, "Failed rename");
                        return;
                    }
                    updateTrustLevelBySignatures(pkg);
                    if (replace) {
                        replacePackageLI(pkg, parseFlags, 2076, args.user, installerPackageName, res);
                    } else {
                        installNewPackageLI(pkg, parseFlags, 1052, args.user, installerPackageName, res);
                    }
                    synchronized (this.mPackages) {
                        PackageSetting ps2 = (PackageSetting) this.mSettings.mPackages.get(pkgName);
                        if (ps2 != null) {
                            res.newUsers = ps2.queryInstalledUsers(sUserManager.getUserIds(), true);
                        }
                    }
                }
            } catch (PackageParser.PackageParserException e2) {
                res.setError("Failed collect during installPackageLI", e2);
            }
        } catch (PackageParser.PackageParserException e3) {
            res.setError("Failed parse during installPackageLI", e3);
        }
    }

    public static boolean isForwardLocked(PackageParser.Package pkg) {
        return (pkg.applicationInfo.flags & 0x20000000) != 0;
    }

    private static boolean isForwardLocked(ApplicationInfo info) {
        return (info.flags & 0x20000000) != 0;
    }

    private boolean isForwardLocked(PackageSetting ps) {
        return (ps.pkgFlags & 0x20000000) != 0;
    }

    private static boolean isMultiArch(PackageSetting ps) {
        return (ps.pkgFlags & Integer.MIN_VALUE) != 0;
    }

    private static boolean isMultiArch(ApplicationInfo info) {
        return (info.flags & Integer.MIN_VALUE) != 0;
    }

    public static boolean isExternal(PackageParser.Package pkg) {
        return (pkg.applicationInfo.flags & 262144) != 0;
    }

    private static boolean isExternal(PackageSetting ps) {
        return (ps.pkgFlags & 262144) != 0;
    }

    private static boolean isExternal(ApplicationInfo info) {
        return (info.flags & 262144) != 0;
    }

    private static boolean isSystemApp(PackageParser.Package pkg) {
        return (pkg.applicationInfo.flags & 1) != 0;
    }

    private static boolean isPrivilegedApp(PackageParser.Package pkg) {
        return (pkg.applicationInfo.flags & 0x40000000) != 0;
    }

    public static boolean isSystemApp(ApplicationInfo info) {
        return (info.flags & 1) != 0;
    }

    private static boolean isSystemApp(PackageSetting ps) {
        return (ps.pkgFlags & 1) != 0;
    }

    private static boolean isUpdatedSystemApp(PackageSetting ps) {
        return (ps.pkgFlags & SCAN_DEFER_DEX) != 0;
    }

    private static boolean isUpdatedSystemApp(PackageParser.Package pkg) {
        return (pkg.applicationInfo.flags & SCAN_DEFER_DEX) != 0;
    }

    private static boolean isUpdatedSystemApp(ApplicationInfo info) {
        return (info.flags & SCAN_DEFER_DEX) != 0;
    }

    private int packageFlagsToInstallFlags(PackageSetting ps) {
        int installFlags = DEX_OPT_SKIPPED;
        if (isExternal(ps)) {
            installFlags = DEX_OPT_SKIPPED | 8;
        }
        if (isForwardLocked(ps)) {
            return installFlags | 1;
        }
        return installFlags;
    }

    private void deleteTempPackageFiles() {
        FilenameFilter filter = new PackageManagerService$7(this);
        File[] arr$ = this.mDrmAppPrivateInstallDir.listFiles(filter);
        int len$ = arr$.length;
        for (int i$ = DEX_OPT_SKIPPED; i$ < len$; i$++) {
            File file = arr$[i$];
            file.delete();
        }
    }

    public void deletePackageAsUser(String packageName, IPackageDeleteObserver observer, int userId, int flags) {
        deletePackage(packageName, new PackageManager.LegacyPackageDeleteObserver(observer).getBinder(), userId, flags);
    }

    public void deletePackage(String packageName, IPackageDeleteObserver2 observer, int userId, int flags) {
        this.mContext.enforceCallingOrSelfPermission("android.permission.DELETE_PACKAGES", null);
        int uid = Binder.getCallingUid();
        if (UserHandle.getUserId(uid) != userId) {
            this.mContext.enforceCallingPermission("android.permission.INTERACT_ACROSS_USERS_FULL", "deletePackage for user " + userId);
        }
        if (isUserRestricted(userId, "no_uninstall_apps")) {
            try {
                observer.onPackageDeleted(packageName, -3, (String) null);
                return;
            } catch (RemoteException e) {
                return;
            }
        }
        boolean uninstallBlocked = false;
        if ((flags & 2) != 0) {
            int[] users = sUserManager.getUserIds();
            int i = DEX_OPT_SKIPPED;
            while (true) {
                if (i >= users.length) {
                    break;
                }
                if (!getBlockUninstallForUser(packageName, users[i])) {
                    i++;
                } else {
                    uninstallBlocked = true;
                    break;
                }
            }
        } else {
            uninstallBlocked = getBlockUninstallForUser(packageName, userId);
        }
        if (uninstallBlocked) {
            try {
                observer.onPackageDeleted(packageName, -4, (String) null);
            } catch (RemoteException e2) {
            }
        } else {
            this.mHandler.post(new PackageManagerService$8(this, packageName, userId, flags, observer));
        }
    }

    private boolean isPackageDeviceAdmin(String packageName, int userId) {
        int[] users;
        IDevicePolicyManager dpm = IDevicePolicyManager.Stub.asInterface(ServiceManager.getService("device_policy"));
        if (dpm != null) {
            try {
                if (dpm.isDeviceOwner(packageName)) {
                    return true;
                }
                if (userId == DEX_OPT_FAILED) {
                    users = sUserManager.getUserIds();
                } else {
                    users = new int[]{userId};
                }
                for (int i = DEX_OPT_SKIPPED; i < users.length; i++) {
                    if (dpm.packageHasActiveAdmins(packageName, users[i])) {
                        return true;
                    }
                }
            } catch (RemoteException e) {
            }
        }
        return false;
    }

    public int deletePackageX(String packageName, int userId, int flags) {
        int[] allUsers;
        boolean[] perUserInstalled;
        boolean res;
        boolean systemUpdate;
        PackageRemovedInfo info = new PackageRemovedInfo();
        UserHandle removeForUser = (flags & 2) != 0 ? UserHandle.ALL : new UserHandle(userId);
        if (isPackageDeviceAdmin(packageName, removeForUser.getIdentifier())) {
            Slog.w(TAG, "Not removing package " + packageName + ": has active device admin");
            return -2;
        }
        boolean removedForAllUsers = false;
        synchronized (this.mPackages) {
            PackageSetting ps = (PackageSetting) this.mSettings.mPackages.get(packageName);
            allUsers = sUserManager.getUserIds();
            perUserInstalled = new boolean[allUsers.length];
            for (int i = DEX_OPT_SKIPPED; i < allUsers.length; i++) {
                perUserInstalled[i] = ps != null ? ps.getInstalled(allUsers[i]) : false;
            }
        }
        synchronized (this.mInstallLock) {
            res = deletePackageLI(packageName, removeForUser, true, allUsers, perUserInstalled, flags | REMOVE_CHATTY, info, true);
            systemUpdate = info.isRemovedPackageSystemUpdate;
            if (res && !systemUpdate && this.mPackages.get(packageName) == null) {
                removedForAllUsers = true;
            }
        }
        if (res) {
            info.sendBroadcast(true, systemUpdate, removedForAllUsers);
            if (systemUpdate) {
                Bundle extras = new Bundle(1);
                extras.putInt("android.intent.extra.UID", info.removedAppId >= 0 ? info.removedAppId : info.uid);
                extras.putBoolean("android.intent.extra.REPLACING", true);
                sendPackageBroadcast("android.intent.action.PACKAGE_ADDED", packageName, extras, null, null, null);
                sendPackageBroadcast("android.intent.action.PACKAGE_REPLACED", packageName, extras, null, null, null);
                sendPackageBroadcast("android.intent.action.MY_PACKAGE_REPLACED", null, null, packageName, null, null);
            }
        }
        Runtime.getRuntime().gc();
        if (info.args != null) {
            synchronized (this.mInstallLock) {
                info.args.doPostDeleteLI(true);
            }
        }
        if (res) {
            return 1;
        }
        return DEX_OPT_FAILED;
    }

    private void removePackageDataLI(PackageSetting ps, int[] allUserHandles, boolean[] perUserInstalled, PackageRemovedInfo outInfo, int flags, boolean writeSettings) {
        PackageSetting deletedPs;
        String packageName = ps.name;
        removePackageLI(ps, (REMOVE_CHATTY & flags) != 0);
        synchronized (this.mPackages) {
            deletedPs = (PackageSetting) this.mSettings.mPackages.get(packageName);
            if (outInfo != null) {
                outInfo.removedPackage = packageName;
                outInfo.removedUsers = deletedPs != null ? deletedPs.queryInstalledUsers(sUserManager.getUserIds(), true) : null;
            }
        }
        if ((flags & 1) == 0) {
            removeDataDirsLI(packageName);
            schedulePackageCleaning(packageName, DEX_OPT_FAILED, true);
        }
        synchronized (this.mPackages) {
            if (deletedPs != null) {
                if ((flags & 1) == 0) {
                    if (outInfo != null) {
                        this.mSettings.mKeySetManagerService.removeAppKeySetDataLPw(packageName);
                        outInfo.removedAppId = this.mSettings.removePackageLPw(packageName);
                    }
                    if (deletedPs != null) {
                        updatePermissionsLPw(deletedPs.name, null, DEX_OPT_SKIPPED);
                        if (deletedPs.sharedUser != null) {
                            this.mSettings.updateSharedUserPermsLPw(deletedPs, this.mGlobalGids);
                        }
                    }
                    clearPackagePreferredActivitiesLPw(deletedPs.name, DEX_OPT_FAILED);
                }
                if (allUserHandles != null && perUserInstalled != null) {
                    for (int i = DEX_OPT_SKIPPED; i < allUserHandles.length; i++) {
                        ps.setInstalled(perUserInstalled[i], allUserHandles[i]);
                    }
                }
            }
            if (writeSettings) {
                this.mSettings.writeLPr();
            }
        }
        if (outInfo != null) {
            removeKeystoreDataIfNeeded(DEX_OPT_FAILED, outInfo.removedAppId);
        }
    }

    static boolean locationIsPrivileged(File path) {
        try {
            String privilegedAppDir = new File(Environment.getRootDirectory(), "priv-app").getCanonicalPath();
            return path.getCanonicalPath().startsWith(privilegedAppDir);
        } catch (IOException e) {
            Slog.e(TAG, "Unable to access code path " + path);
            return false;
        }
    }

    private boolean deleteSystemPackageLI(PackageSetting newPs, int[] allUserHandles, boolean[] perUserInstalled, int flags, PackageRemovedInfo outInfo, boolean writeSettings) {
        PackageSetting disabledPs;
        int flags2;
        boolean applyUserRestrictions = (allUserHandles == null || perUserInstalled == null) ? false : true;
        synchronized (this.mPackages) {
            disabledPs = this.mSettings.getDisabledSystemPkgLPr(newPs.name);
        }
        if (disabledPs == null) {
            Slog.w(TAG, "Attempt to delete unknown system package " + newPs.name);
            return false;
        }
        if (outInfo != null) {
            outInfo.isRemovedPackageSystemUpdate = true;
        }
        if (disabledPs.versionCode < newPs.versionCode) {
            flags2 = flags & (-2);
        } else {
            flags2 = flags | 1;
        }
        boolean ret = deleteInstalledPackageLI(newPs, true, flags2, allUserHandles, perUserInstalled, outInfo, writeSettings);
        if (!ret) {
            return false;
        }
        synchronized (this.mPackages) {
            this.mSettings.enableSystemPackageLPw(newPs.name);
            NativeLibraryHelper.removeNativeBinariesLI(newPs.legacyNativeLibraryPathString);
        }
        int parseFlags = INIT_COPY;
        if (locationIsPrivileged(disabledPs.codePath)) {
            parseFlags = INIT_COPY | SCAN_DEFER_DEX;
        }
        try {
            PackageParser.Package newPkg = scanPackageLI(disabledPs.codePath, parseFlags, SCAN_NO_PATHS, 0L, (UserHandle) null);
            synchronized (this.mPackages) {
                PackageSetting ps = (PackageSetting) this.mSettings.mPackages.get(newPkg.packageName);
                updatePermissionsLPw(newPkg.packageName, newPkg, MCS_BOUND);
                if (applyUserRestrictions) {
                    for (int i = DEX_OPT_SKIPPED; i < allUserHandles.length; i++) {
                        ps.setInstalled(perUserInstalled[i], allUserHandles[i]);
                    }
                    this.mSettings.writeAllUsersPackageRestrictionsLPr();
                }
                if (writeSettings) {
                    this.mSettings.writeLPr();
                }
            }
            return true;
        } catch (PackageManagerException e) {
            Slog.w(TAG, "Failed to restore system package:" + newPs.name + ": " + e.getMessage());
            return false;
        }
    }

    private boolean deleteInstalledPackageLI(PackageSetting ps, boolean deleteCodeAndResources, int flags, int[] allUserHandles, boolean[] perUserInstalled, PackageRemovedInfo outInfo, boolean writeSettings) {
        if (outInfo != null) {
            outInfo.uid = ps.appId;
        }
        removePackageDataLI(ps, allUserHandles, perUserInstalled, outInfo, flags, writeSettings);
        if (deleteCodeAndResources && outInfo != null) {
            outInfo.args = createInstallArgsForExisting(packageFlagsToInstallFlags(ps), ps.codePathString, ps.resourcePathString, ps.legacyNativeLibraryPathString, getAppDexInstructionSets(ps));
            return true;
        }
        return true;
    }

    public boolean setBlockUninstallForUser(String packageName, boolean blockUninstall, int userId) {
        this.mContext.enforceCallingOrSelfPermission("android.permission.DELETE_PACKAGES", null);
        synchronized (this.mPackages) {
            PackageSetting ps = (PackageSetting) this.mSettings.mPackages.get(packageName);
            if (ps == null) {
                Log.i(TAG, "Package doesn't exist in set block uninstall " + packageName);
                return false;
            }
            if (!ps.getInstalled(userId)) {
                Log.i(TAG, "Package not installed in set block uninstall " + packageName);
                return false;
            }
            ps.setBlockUninstall(blockUninstall, userId);
            this.mSettings.writePackageRestrictionsLPr(userId);
            return true;
        }
    }

    public boolean getBlockUninstallForUser(String packageName, int userId) {
        boolean blockUninstall;
        synchronized (this.mPackages) {
            PackageSetting ps = (PackageSetting) this.mSettings.mPackages.get(packageName);
            if (ps == null) {
                Log.i(TAG, "Package doesn't exist in get block uninstall " + packageName);
                blockUninstall = false;
            } else {
                blockUninstall = ps.getBlockUninstall(userId);
            }
        }
        return blockUninstall;
    }

    private boolean deletePackageLI(String packageName, UserHandle user, boolean deleteCodeAndResources, int[] allUserHandles, boolean[] perUserInstalled, int flags, PackageRemovedInfo outInfo, boolean writeSettings) {
        if (packageName == null) {
            Slog.w(TAG, "Attempt to delete null packageName.");
            return false;
        }
        int removeUser = DEX_OPT_FAILED;
        int appId = DEX_OPT_FAILED;
        synchronized (this.mPackages) {
            PackageSetting ps = (PackageSetting) this.mSettings.mPackages.get(packageName);
            if (ps == null) {
                Slog.w(TAG, "Package named '" + packageName + "' doesn't exist.");
                return false;
            }
            if ((!isSystemApp(ps) || (flags & 4) != 0) && user != null && user.getIdentifier() != DEX_OPT_FAILED) {
                ps.setUserState(user.getIdentifier(), DEX_OPT_SKIPPED, false, true, true, false, (String) null, (ArraySet) null, (ArraySet) null, false);
                if (!isSystemApp(ps)) {
                    if (ps.isAnyInstalled(sUserManager.getUserIds())) {
                        removeUser = user.getIdentifier();
                        appId = ps.appId;
                        this.mSettings.writePackageRestrictionsLPr(removeUser);
                    } else {
                        ps.setInstalled(true, user.getIdentifier());
                    }
                } else {
                    removeUser = user.getIdentifier();
                    appId = ps.appId;
                    this.mSettings.writePackageRestrictionsLPr(removeUser);
                }
            }
            if (removeUser >= 0) {
                if (outInfo != null) {
                    outInfo.removedPackage = packageName;
                    outInfo.removedAppId = appId;
                    outInfo.removedUsers = new int[]{removeUser};
                }
                this.mInstaller.clearUserData(packageName, removeUser);
                removeKeystoreDataIfNeeded(removeUser, appId);
                schedulePackageCleaning(packageName, removeUser, false);
                return true;
            }
            if (DEX_OPT_SKIPPED != 0) {
                removePackageDataLI(ps, null, null, outInfo, flags, writeSettings);
                return true;
            }
            if (isSystemApp(ps)) {
                boolean ret = deleteSystemPackageLI(ps, allUserHandles, perUserInstalled, flags, outInfo, writeSettings);
                return ret;
            }
            killApplication(packageName, ps.appId, "uninstall pkg");
            boolean ret2 = deleteInstalledPackageLI(ps, deleteCodeAndResources, flags, allUserHandles, perUserInstalled, outInfo, writeSettings);
            return ret2;
        }
    }

    public void clearExternalStorageDataSync(String packageName, int userId, boolean allData) {
        boolean mounted;
        int[] users;
        if (Environment.isExternalStorageEmulated()) {
            mounted = true;
        } else {
            String status = Environment.getExternalStorageState();
            mounted = status.equals("mounted") || status.equals("mounted_ro");
        }
        if (mounted) {
            Intent containerIntent = new Intent().setComponent(DEFAULT_CONTAINER_COMPONENT);
            if (userId == DEX_OPT_FAILED) {
                users = sUserManager.getUserIds();
            } else {
                users = new int[]{userId};
            }
            ServiceConnection clearStorageConnection = new ClearStorageConnection(this, (PackageManagerService$1) null);
            if (this.mContext.bindServiceAsUser(containerIntent, clearStorageConnection, 1, UserHandle.OWNER)) {
                int[] arr$ = users;
                try {
                    int len$ = arr$.length;
                    for (int i$ = DEX_OPT_SKIPPED; i$ < len$; i$++) {
                        int curUser = arr$[i$];
                        long timeout = SystemClock.uptimeMillis() + 5000;
                        synchronized (clearStorageConnection) {
                            long now = SystemClock.uptimeMillis();
                            while (((ClearStorageConnection) clearStorageConnection).mContainerService == null && now < timeout) {
                                try {
                                    clearStorageConnection.wait(timeout - now);
                                } catch (InterruptedException e) {
                                }
                            }
                        }
                        if (((ClearStorageConnection) clearStorageConnection).mContainerService != null) {
                            Environment.UserEnvironment userEnv = new Environment.UserEnvironment(curUser);
                            clearDirectory(((ClearStorageConnection) clearStorageConnection).mContainerService, userEnv.buildExternalStorageAppCacheDirs(packageName));
                            if (allData) {
                                clearDirectory(((ClearStorageConnection) clearStorageConnection).mContainerService, userEnv.buildExternalStorageAppDataDirs(packageName));
                                clearDirectory(((ClearStorageConnection) clearStorageConnection).mContainerService, userEnv.buildExternalStorageAppMediaDirs(packageName));
                            }
                        } else {
                            return;
                        }
                    }
                } finally {
                    this.mContext.unbindService(clearStorageConnection);
                }
            }
        }
    }

    public void clearApplicationUserData(String packageName, IPackageDataObserver observer, int userId) {
        this.mContext.enforceCallingOrSelfPermission("android.permission.CLEAR_APP_USER_DATA", null);
        enforceCrossUserPermission(Binder.getCallingUid(), userId, true, false, "clear application data");
        this.mHandler.post(new PackageManagerService$9(this, packageName, userId, observer));
    }

    public boolean clearApplicationUserDataLI(String packageName, int userId) {
        PackageParser.Package pkg;
        PackageSetting ps;
        if (packageName == null) {
            Slog.w(TAG, "Attempt to delete null packageName.");
            return false;
        }
        synchronized (this.mPackages) {
            pkg = this.mPackages.get(packageName);
            if (pkg == null && (ps = (PackageSetting) this.mSettings.mPackages.get(packageName)) != null) {
                pkg = ps.pkg;
            }
        }
        if (pkg == null) {
            Slog.w(TAG, "Package named '" + packageName + "' doesn't exist.");
        }
        int retCode = this.mInstaller.clearUserData(packageName, userId);
        if (retCode < 0) {
            Slog.w(TAG, "Couldn't remove cache files for package: " + packageName);
            return false;
        }
        if (pkg == null) {
            return false;
        }
        if (pkg != null && pkg.applicationInfo != null) {
            int appId = pkg.applicationInfo.uid;
            removeKeystoreDataIfNeeded(userId, appId);
        }
        if (pkg != null && pkg.applicationInfo.primaryCpuAbi != null && !VMRuntime.is64BitAbi(pkg.applicationInfo.primaryCpuAbi)) {
            String nativeLibPath = pkg.applicationInfo.nativeLibraryDir;
            if (this.mInstaller.linkNativeLibraryDirectory(pkg.packageName, nativeLibPath, userId) < 0) {
                Slog.w(TAG, "Failed linking native library dir");
                return false;
            }
        }
        return true;
    }

    private static void removeKeystoreDataIfNeeded(int userId, int appId) {
        if (appId >= 0) {
            KeyStore keyStore = KeyStore.getInstance();
            if (keyStore != null) {
                if (userId == DEX_OPT_FAILED) {
                    int[] arr$ = sUserManager.getUserIds();
                    int len$ = arr$.length;
                    for (int i$ = DEX_OPT_SKIPPED; i$ < len$; i$++) {
                        int individual = arr$[i$];
                        keyStore.clearUid(UserHandle.getUid(individual, appId));
                    }
                    return;
                }
                keyStore.clearUid(UserHandle.getUid(userId, appId));
                return;
            }
            Slog.w(TAG, "Could not contact keystore to clear entries for app id " + appId);
        }
    }

    public void deleteApplicationCacheFiles(String packageName, IPackageDataObserver observer) {
        this.mContext.enforceCallingOrSelfPermission("android.permission.DELETE_CACHE_FILES", null);
        int userId = UserHandle.getCallingUserId();
        this.mHandler.post(new PackageManagerService$10(this, packageName, userId, observer));
    }

    public boolean deleteApplicationCacheFilesLI(String packageName, int userId) {
        PackageParser.Package p;
        if (packageName == null) {
            Slog.w(TAG, "Attempt to delete null packageName.");
            return false;
        }
        synchronized (this.mPackages) {
            p = this.mPackages.get(packageName);
        }
        if (p == null) {
            Slog.w(TAG, "Package named '" + packageName + "' doesn't exist.");
            return false;
        }
        ApplicationInfo applicationInfo = p.applicationInfo;
        if (applicationInfo == null) {
            Slog.w(TAG, "Package " + packageName + " has no applicationInfo.");
            return false;
        }
        int retCode = this.mInstaller.deleteCacheFiles(packageName, userId);
        if (retCode < 0) {
            Slog.w(TAG, "Couldn't remove cache files for package: " + packageName + " u" + userId);
            return false;
        }
        return true;
    }

    public void getPackageSizeInfo(String packageName, int userHandle, IPackageStatsObserver observer) {
        this.mContext.enforceCallingOrSelfPermission("android.permission.GET_PACKAGE_SIZE", null);
        if (packageName == null) {
            throw new IllegalArgumentException("Attempt to get size of null packageName");
        }
        PackageStats stats = (PackageStats) FireOSInit.getInstance(PackageStats.class, new Class[]{String.class, Integer.TYPE}, new Object[]{packageName, Integer.valueOf(userHandle)});
        if (stats == null) {
            stats = new PackageStats(packageName, userHandle);
        }
        Message msg = this.mHandler.obtainMessage(INIT_COPY);
        msg.obj = new MeasureParams(this, stats, observer);
        this.mHandler.sendMessage(msg);
    }

    public boolean getPackageSizeInfoLI(String packageName, int userHandle, PackageStats pStats) {
        String secureContainerId;
        if (packageName == null) {
            Slog.w(TAG, "Attempt to get size of null packageName.");
            return false;
        }
        boolean dataOnly = false;
        String libDirRoot = null;
        String asecPath = null;
        synchronized (this.mPackages) {
            PackageParser.Package p = this.mPackages.get(packageName);
            PackageSetting ps = (PackageSetting) this.mSettings.mPackages.get(packageName);
            if (p == null) {
                dataOnly = true;
                if (ps == null || ps.pkg == null) {
                    Slog.w(TAG, "Package named '" + packageName + "' doesn't exist.");
                    return false;
                }
                p = ps.pkg;
            }
            if (ps != null) {
                libDirRoot = ps.legacyNativeLibraryPathString;
            }
            if (p != null && ((isExternal(p) || isForwardLocked(p)) && (secureContainerId = cidFromCodePath(p.applicationInfo.getBaseCodePath())) != null)) {
                asecPath = PackageHelper.getSdFilesystem(secureContainerId);
            }
            String publicSrcDir = null;
            if (!dataOnly) {
                ApplicationInfo applicationInfo = p.applicationInfo;
                if (applicationInfo == null) {
                    Slog.w(TAG, "Package " + packageName + " has no applicationInfo.");
                    return false;
                }
                if (isForwardLocked(p)) {
                    publicSrcDir = applicationInfo.getBaseResourcePath();
                }
            }
            String[] dexCodeInstructionSets = getDexCodeInstructionSets(getAppDexInstructionSets(ps));
            int res = this.mInstaller.getSizeInfo(packageName, userHandle, p.baseCodePath, libDirRoot, publicSrcDir, asecPath, dexCodeInstructionSets, pStats);
            if (res < 0) {
                return false;
            }
            if (!isExternal(p)) {
                pStats.codeSize += pStats.externalCodeSize;
                pStats.externalCodeSize = 0L;
            }
            return true;
        }
    }

    public void addPackageToPreferred(String packageName) {
        Slog.w(TAG, "addPackageToPreferred: this is now a no-op");
    }

    public void removePackageFromPreferred(String packageName) {
        Slog.w(TAG, "removePackageFromPreferred: this is now a no-op");
    }

    public List<PackageInfo> getPreferredPackages(int flags) {
        return new ArrayList();
    }

    private int getUidTargetSdkVersionLockedLPr(int uid) {
        int v;
        Object obj = this.mSettings.getUserIdLPw(uid);
        if (obj instanceof SharedUserSetting) {
            SharedUserSetting sus = (SharedUserSetting) obj;
            int vers = 10000;
            Iterator<PackageSetting> it = sus.packages.iterator();
            while (it.hasNext()) {
                PackageSetting ps = it.next();
                if (ps.pkg != null && (v = ps.pkg.applicationInfo.targetSdkVersion) < vers) {
                    vers = v;
                }
            }
            return vers;
        }
        if (obj instanceof PackageSetting) {
            PackageSetting ps2 = (PackageSetting) obj;
            if (ps2.pkg != null) {
                return ps2.pkg.applicationInfo.targetSdkVersion;
            }
        }
        return 10000;
    }

    public void addPreferredActivity(IntentFilter filter, int match, ComponentName[] set, ComponentName activity, int userId) {
        addPreferredActivityInternal(filter, match, set, activity, true, userId, "Adding preferred");
    }

    private void addPreferredActivityInternal(IntentFilter filter, int match, ComponentName[] set, ComponentName activity, boolean always, int userId, String opname) {
        int callingUid = Binder.getCallingUid();
        enforceCrossUserPermission(callingUid, userId, true, false, "add preferred activity");
        if (filter.countActions() == 0) {
            Slog.w(TAG, "Cannot set a preferred activity with no filter actions");
            return;
        }
        synchronized (this.mPackages) {
            if (this.mContext.checkCallingOrSelfPermission("android.permission.SET_PREFERRED_APPLICATIONS") != 0) {
                if (getUidTargetSdkVersionLockedLPr(callingUid) < 8) {
                    Slog.w(TAG, "Ignoring addPreferredActivity() from uid " + callingUid);
                    return;
                }
                this.mContext.enforceCallingOrSelfPermission("android.permission.SET_PREFERRED_APPLICATIONS", null);
            }
            PreferredIntentResolver pir = this.mSettings.editPreferredActivitiesLPw(userId);
            Slog.i(TAG, opname + " activity " + activity.flattenToShortString() + " for user " + userId + ":");
            filter.dump(new LogPrinter(4, TAG), "  ");
            pir.addFilter(new PreferredActivity(filter, match, set, activity, always));
            scheduleWritePackageRestrictionsLocked(userId);
        }
    }

    public void replacePreferredActivity(IntentFilter filter, int match, ComponentName[] set, ComponentName activity, int userId) {
        if (filter.countActions() != 1) {
            throw new IllegalArgumentException("replacePreferredActivity expects filter to have only 1 action.");
        }
        if (filter.countDataAuthorities() != 0 || filter.countDataPaths() != 0 || filter.countDataSchemes() > 1 || filter.countDataTypes() != 0) {
            throw new IllegalArgumentException("replacePreferredActivity expects filter to have no data authorities, paths, or types; and at most one scheme.");
        }
        int callingUid = Binder.getCallingUid();
        enforceCrossUserPermission(callingUid, userId, true, false, "replace preferred activity");
        synchronized (this.mPackages) {
            if (this.mContext.checkCallingOrSelfPermission("android.permission.SET_PREFERRED_APPLICATIONS") != 0) {
                if (getUidTargetSdkVersionLockedLPr(callingUid) < 8) {
                    Slog.w(TAG, "Ignoring replacePreferredActivity() from uid " + Binder.getCallingUid());
                    return;
                }
                this.mContext.enforceCallingOrSelfPermission("android.permission.SET_PREFERRED_APPLICATIONS", null);
            }
            PreferredIntentResolver pir = (PreferredIntentResolver) this.mSettings.mPreferredActivities.get(userId);
            if (pir != null) {
                ArrayList<PreferredActivity> existing = pir.findFilters(filter);
                if (existing != null && existing.size() == 1) {
                    PreferredActivity cur = existing.get(DEX_OPT_SKIPPED);
                    if (cur.mPref.mAlways && cur.mPref.mComponent.equals(activity) && cur.mPref.mMatch == (0x0fff0000 & match) && cur.mPref.sameSet(set)) {
                        return;
                    }
                }
                if (existing != null) {
                    for (int i = DEX_OPT_SKIPPED; i < existing.size(); i++) {
                        PreferredActivity pa = existing.get(i);
                        pir.removeFilter(pa);
                    }
                }
            }
            addPreferredActivityInternal(filter, match, set, activity, true, userId, "Replacing preferred");
        }
    }

    public void clearPackagePreferredActivities(String packageName) {
        int uid = Binder.getCallingUid();
        synchronized (this.mPackages) {
            PackageParser.Package pkg = this.mPackages.get(packageName);
            if ((pkg == null || pkg.applicationInfo.uid != uid) && this.mContext.checkCallingOrSelfPermission("android.permission.SET_PREFERRED_APPLICATIONS") != 0) {
                if (getUidTargetSdkVersionLockedLPr(Binder.getCallingUid()) < 8) {
                    Slog.w(TAG, "Ignoring clearPackagePreferredActivities() from uid " + Binder.getCallingUid());
                    return;
                }
                this.mContext.enforceCallingOrSelfPermission("android.permission.SET_PREFERRED_APPLICATIONS", null);
            }
            int user = UserHandle.getCallingUserId();
            if (clearPackagePreferredActivitiesLPw(packageName, user)) {
                scheduleWritePackageRestrictionsLocked(user);
            }
        }
    }

    boolean clearPackagePreferredActivitiesLPw(String packageName, int userId) {
        ArrayList<PreferredActivity> removed = null;
        boolean changed = false;
        for (int i = DEX_OPT_SKIPPED; i < this.mSettings.mPreferredActivities.size(); i++) {
            int thisUserId = this.mSettings.mPreferredActivities.keyAt(i);
            PreferredIntentResolver pir = (PreferredIntentResolver) this.mSettings.mPreferredActivities.valueAt(i);
            if (userId == DEX_OPT_FAILED || userId == thisUserId) {
                Iterator<PreferredActivity> it = pir.filterIterator();
                while (it.hasNext()) {
                    PreferredActivity pa = it.next();
                    if (packageName == null || (pa.mPref.mComponent.getPackageName().equals(packageName) && pa.mPref.mAlways)) {
                        if (removed == null) {
                            removed = new ArrayList<>();
                        }
                        removed.add(pa);
                    }
                }
                if (removed != null) {
                    for (int j = DEX_OPT_SKIPPED; j < removed.size(); j++) {
                        pir.removeFilter(removed.get(j));
                    }
                    changed = true;
                }
            }
        }
        return changed;
    }

    public void resetPreferredActivities(int userId) {
        this.mContext.enforceCallingOrSelfPermission("android.permission.SET_PREFERRED_APPLICATIONS", null);
        synchronized (this.mPackages) {
            int user = UserHandle.getCallingUserId();
            clearPackagePreferredActivitiesLPw(null, user);
            this.mSettings.readDefaultPreferredAppsLPw(this, user);
            scheduleWritePackageRestrictionsLocked(user);
        }
    }

    public int getPreferredActivities(List<IntentFilter> outFilters, List<ComponentName> outActivities, String packageName) {
        int userId = UserHandle.getCallingUserId();
        synchronized (this.mPackages) {
            PreferredIntentResolver pir = (PreferredIntentResolver) this.mSettings.mPreferredActivities.get(userId);
            if (pir != null) {
                Iterator<PreferredActivity> it = pir.filterIterator();
                while (it.hasNext()) {
                    PreferredActivity pa = it.next();
                    if (packageName == null || (pa.mPref.mComponent.getPackageName().equals(packageName) && pa.mPref.mAlways)) {
                        if (outFilters != null) {
                            outFilters.add(new IntentFilter((IntentFilter) pa));
                        }
                        if (outActivities != null) {
                            outActivities.add(pa.mPref.mComponent);
                        }
                    }
                }
            }
        }
        return DEX_OPT_SKIPPED;
    }

    public void addPersistentPreferredActivity(IntentFilter filter, ComponentName activity, int userId) {
        int callingUid = Binder.getCallingUid();
        if (callingUid != 1000) {
            throw new SecurityException("addPersistentPreferredActivity can only be run by the system");
        }
        if (filter.countActions() == 0) {
            Slog.w(TAG, "Cannot set a preferred activity with no filter actions");
            return;
        }
        synchronized (this.mPackages) {
            Slog.i(TAG, "Adding persistent preferred activity " + activity + " for user " + userId + " :");
            filter.dump(new LogPrinter(4, TAG), "  ");
            this.mSettings.editPersistentPreferredActivitiesLPw(userId).addFilter(new PersistentPreferredActivity(filter, activity));
            scheduleWritePackageRestrictionsLocked(userId);
        }
    }

    public void clearPackagePersistentPreferredActivities(String packageName, int userId) {
        ArrayList<PersistentPreferredActivity> removed;
        int callingUid = Binder.getCallingUid();
        if (callingUid != 1000) {
            throw new SecurityException("clearPackagePersistentPreferredActivities can only be run by the system");
        }
        ArrayList<PersistentPreferredActivity> removed2 = null;
        boolean changed = false;
        synchronized (this.mPackages) {
            for (int i = DEX_OPT_SKIPPED; i < this.mSettings.mPersistentPreferredActivities.size(); i++) {
                try {
                    int thisUserId = this.mSettings.mPersistentPreferredActivities.keyAt(i);
                    PersistentPreferredIntentResolver ppir = (PersistentPreferredIntentResolver) this.mSettings.mPersistentPreferredActivities.valueAt(i);
                    if (userId == thisUserId) {
                        Iterator<PersistentPreferredActivity> it = ppir.filterIterator();
                        while (true) {
                            try {
                                removed = removed2;
                                if (!it.hasNext()) {
                                    break;
                                }
                                PersistentPreferredActivity ppa = it.next();
                                if (ppa.mComponent.getPackageName().equals(packageName)) {
                                    removed2 = removed == null ? new ArrayList<>() : removed;
                                    removed2.add(ppa);
                                } else {
                                    removed2 = removed;
                                }
                            } catch (Throwable th) {
                                th = th;
                                throw th;
                            }
                        }
                        if (removed != null) {
                            for (int j = DEX_OPT_SKIPPED; j < removed.size(); j++) {
                                ppir.removeFilter(removed.get(j));
                            }
                            changed = true;
                            removed2 = removed;
                        } else {
                            removed2 = removed;
                        }
                    }
                } catch (Throwable th2) {
                    th = th2;
                }
            }
            if (changed) {
                scheduleWritePackageRestrictionsLocked(userId);
            }
        }
    }

    public void addCrossProfileIntentFilter(IntentFilter intentFilter, String ownerPackage, int ownerUserId, int sourceUserId, int targetUserId, int flags) {
        this.mContext.enforceCallingOrSelfPermission("android.permission.INTERACT_ACROSS_USERS_FULL", null);
        int callingUid = Binder.getCallingUid();
        enforceOwnerRights(ownerPackage, ownerUserId, callingUid);
        enforceShellRestriction("no_debugging_features", callingUid, sourceUserId);
        if (intentFilter.countActions() == 0) {
            Slog.w(TAG, "Cannot set a crossProfile intent filter with no filter actions");
            return;
        }
        synchronized (this.mPackages) {
            CrossProfileIntentFilter newFilter = new CrossProfileIntentFilter(intentFilter, ownerPackage, UserHandle.getUserId(callingUid), targetUserId, flags);
            CrossProfileIntentResolver resolver = this.mSettings.editCrossProfileIntentResolverLPw(sourceUserId);
            ArrayList<CrossProfileIntentFilter> existing = resolver.findFilters(intentFilter);
            if (existing != null) {
                int size = existing.size();
                for (int i = DEX_OPT_SKIPPED; i < size; i++) {
                    if (newFilter.equalsIgnoreFilter(existing.get(i))) {
                        break;
                    }
                }
            }
            resolver.addFilter(newFilter);
            scheduleWritePackageRestrictionsLocked(sourceUserId);
        }
    }

    public void clearCrossProfileIntentFilters(int sourceUserId, String ownerPackage, int ownerUserId) {
        this.mContext.enforceCallingOrSelfPermission("android.permission.INTERACT_ACROSS_USERS_FULL", null);
        int callingUid = Binder.getCallingUid();
        enforceOwnerRights(ownerPackage, ownerUserId, callingUid);
        enforceShellRestriction("no_debugging_features", callingUid, sourceUserId);
        int callingUserId = UserHandle.getUserId(callingUid);
        synchronized (this.mPackages) {
            CrossProfileIntentResolver resolver = this.mSettings.editCrossProfileIntentResolverLPw(sourceUserId);
            ArraySet<CrossProfileIntentFilter> set = new ArraySet<>(resolver.filterSet());
            Iterator i$ = set.iterator();
            while (i$.hasNext()) {
                CrossProfileIntentFilter filter = i$.next();
                if (filter.getOwnerPackage().equals(ownerPackage) && filter.getOwnerUserId() == callingUserId) {
                    resolver.removeFilter(filter);
                }
            }
            scheduleWritePackageRestrictionsLocked(sourceUserId);
        }
    }

    private void enforceOwnerRights(String pkg, int userId, int callingUid) {
        if (UserHandle.getAppId(callingUid) != 1000) {
            int callingUserId = UserHandle.getUserId(callingUid);
            if (callingUserId != userId) {
                throw new SecurityException("calling uid " + callingUid + " pretends to own " + pkg + " on user " + userId + " but belongs to user " + callingUserId);
            }
            PackageInfo pi = getPackageInfo(pkg, DEX_OPT_SKIPPED, callingUserId);
            if (pi == null) {
                throw new IllegalArgumentException("Unknown package " + pkg + " on user " + callingUserId);
            }
            if (!UserHandle.isSameApp(pi.applicationInfo.uid, callingUid)) {
                throw new SecurityException("Calling uid " + callingUid + " does not own package " + pkg);
            }
        }
    }

    public ComponentName getHomeActivities(List<ResolveInfo> allHomeCandidates) {
        Intent intent = new Intent("android.intent.action.MAIN");
        intent.addCategory("android.intent.category.HOME");
        int callingUserId = UserHandle.getCallingUserId();
        List<ResolveInfo> list = queryIntentActivities(intent, null, SCAN_DEFER_DEX, callingUserId);
        ResolveInfo preferred = findPreferredActivity(intent, null, DEX_OPT_SKIPPED, list, DEX_OPT_SKIPPED, true, false, false, callingUserId);
        allHomeCandidates.clear();
        if (list != null) {
            for (ResolveInfo ri : list) {
                allHomeCandidates.add(ri);
            }
        }
        if (preferred == null || preferred.activityInfo == null) {
            return null;
        }
        return new ComponentName(preferred.activityInfo.packageName, preferred.activityInfo.name);
    }

    public void setApplicationEnabledSetting(String appPackageName, int newState, int flags, int userId, String callingPackage) {
        if (sUserManager.exists(userId)) {
            if (callingPackage == null) {
                callingPackage = Integer.toString(Binder.getCallingUid());
            }
            setEnabledSetting(appPackageName, null, newState, flags, userId, callingPackage);
        }
    }

    public void setComponentEnabledSetting(ComponentName componentName, int newState, int flags, int userId) {
        if (sUserManager.exists(userId)) {
            setEnabledSetting(componentName.getPackageName(), componentName.getClassName(), newState, flags, userId, null);
        }
    }

    private void setEnabledSetting(String packageName, String className, int newState, int flags, int userId, String callingPackage) {
        if (newState != 0 && newState != 1 && newState != 2 && newState != MCS_BOUND && newState != 4) {
            throw new IllegalArgumentException("Invalid new component state: " + newState);
        }
        int uid = Binder.getCallingUid();
        int permission = this.mContext.checkCallingOrSelfPermission("android.permission.CHANGE_COMPONENT_ENABLED_STATE");
        enforceCrossUserPermission(uid, userId, false, true, "set enabled");
        boolean allowedByPermission = permission == 0;
        boolean sendNow = false;
        boolean isApp = className == null;
        String componentName = isApp ? packageName : className;
        synchronized (this.mPackages) {
            PackageSetting pkgSetting = (PackageSetting) this.mSettings.mPackages.get(packageName);
            if (pkgSetting == null) {
                if (className == null) {
                    throw new IllegalArgumentException("Unknown package: " + packageName);
                }
                throw new IllegalArgumentException("Unknown component: " + packageName + "/" + className);
            }
            if (!allowedByPermission && !UserHandle.isSameApp(uid, pkgSetting.appId)) {
                throw new SecurityException("Permission Denial: attempt to change component state from pid=" + Binder.getCallingPid() + ", uid=" + uid + ", package uid=" + pkgSetting.appId);
            }
            if (className == null) {
                if (pkgSetting.getEnabled(userId) != newState) {
                    if (newState == 0 || newState == 1) {
                        callingPackage = null;
                    }
                    pkgSetting.setEnabled(newState, userId, callingPackage);
                } else {
                    return;
                }
            } else {
                PackageParser.Package pkg = pkgSetting.pkg;
                if (pkg == null || !pkg.hasComponentClassName(className)) {
                    if (pkg.applicationInfo.targetSdkVersion >= 16) {
                        throw new IllegalArgumentException("Component class " + className + " does not exist in " + packageName);
                    }
                    Slog.w(TAG, "Failed setComponentEnabledSetting: component class " + className + " does not exist in " + packageName);
                }
                switch (newState) {
                    case DEX_OPT_SKIPPED:
                        if (!pkgSetting.restoreComponentLPw(className, userId)) {
                            return;
                        }
                        break;
                    case 1:
                        if (!pkgSetting.enableComponentLPw(className, userId)) {
                            return;
                        }
                        break;
                    case 2:
                        if (!pkgSetting.disableComponentLPw(className, userId)) {
                            return;
                        }
                        break;
                    default:
                        Slog.e(TAG, "Invalid new component state: " + newState);
                        return;
                }
            }
            this.mSettings.writePackageRestrictionsLPr(userId);
            ArrayList<String> components = this.mPendingBroadcasts.get(userId, packageName);
            boolean newPackage = components == null;
            if (newPackage) {
                components = new ArrayList<>();
            }
            if (!components.contains(componentName)) {
                components.add(componentName);
            }
            if ((flags & 1) == 0) {
                sendNow = true;
                this.mPendingBroadcasts.remove(userId, packageName);
            } else {
                if (newPackage) {
                    this.mPendingBroadcasts.put(userId, packageName, components);
                }
                if (!this.mHandler.hasMessages(1)) {
                    this.mHandler.sendEmptyMessageDelayed(1, DEFAULT_VERIFICATION_TIMEOUT);
                }
            }
            long callingId = Binder.clearCallingIdentity();
            if (sendNow) {
                try {
                    int packageUid = UserHandle.getUid(userId, pkgSetting.appId);
                    sendPackageChangedBroadcast(packageName, (flags & 1) != 0, components, packageUid);
                } finally {
                    Binder.restoreCallingIdentity(callingId);
                }
            }
        }
    }

    public void sendPackageChangedBroadcast(String packageName, boolean killFlag, ArrayList<String> componentNames, int packageUid) {
        Bundle extras = new Bundle(4);
        extras.putString("android.intent.extra.changed_component_name", componentNames.get(DEX_OPT_SKIPPED));
        String[] nameList = new String[componentNames.size()];
        componentNames.toArray(nameList);
        extras.putStringArray("android.intent.extra.changed_component_name_list", nameList);
        extras.putBoolean("android.intent.extra.DONT_KILL_APP", killFlag);
        extras.putInt("android.intent.extra.UID", packageUid);
        sendPackageBroadcast("android.intent.action.PACKAGE_CHANGED", packageName, extras, null, null, new int[]{UserHandle.getUserId(packageUid)});
    }

    public void setPackageStoppedState(String packageName, boolean stopped, int userId) {
        if (sUserManager.exists(userId)) {
            int uid = Binder.getCallingUid();
            int permission = this.mContext.checkCallingOrSelfPermission("android.permission.CHANGE_COMPONENT_ENABLED_STATE");
            boolean allowedByPermission = permission == 0;
            enforceCrossUserPermission(uid, userId, true, true, "stop package");
            synchronized (this.mPackages) {
                if (this.mSettings.setPackageStoppedStateLPw(packageName, stopped, allowedByPermission, uid, userId)) {
                    scheduleWritePackageRestrictionsLocked(userId);
                }
            }
        }
    }

    public String getInstallerPackageName(String packageName) {
        String installerPackageNameLPr;
        synchronized (this.mPackages) {
            installerPackageNameLPr = this.mSettings.getInstallerPackageNameLPr(packageName);
        }
        return installerPackageNameLPr;
    }

    public int getApplicationEnabledSetting(String packageName, int userId) {
        int applicationEnabledSettingLPr;
        if (!sUserManager.exists(userId)) {
            return 2;
        }
        int uid = Binder.getCallingUid();
        enforceCrossUserPermission(uid, userId, false, false, "get enabled");
        synchronized (this.mPackages) {
            applicationEnabledSettingLPr = this.mSettings.getApplicationEnabledSettingLPr(packageName, userId);
        }
        return applicationEnabledSettingLPr;
    }

    public int getComponentEnabledSetting(ComponentName componentName, int userId) {
        int componentEnabledSettingLPr;
        if (!sUserManager.exists(userId)) {
            return 2;
        }
        int uid = Binder.getCallingUid();
        enforceCrossUserPermission(uid, userId, false, false, "get component enabled");
        synchronized (this.mPackages) {
            componentEnabledSettingLPr = this.mSettings.getComponentEnabledSettingLPr(componentName, userId);
        }
        return componentEnabledSettingLPr;
    }

    public void enterSafeMode() {
        enforceSystemOrRoot("Only the system can request entering safe mode");
        if (!this.mSystemReady) {
            this.mSafeMode = true;
        }
    }

    public void systemReady() {
        this.mSystemReady = true;
        boolean compatibilityModeEnabled = Settings.Global.getInt(this.mContext.getContentResolver(), "compatibility_mode", 1) == 1;
        PackageParser.setCompatibilityModeEnabled(compatibilityModeEnabled);
        synchronized (this.mPackages) {
            ArrayList<PreferredActivity> removed = new ArrayList<>();
            for (int i = DEX_OPT_SKIPPED; i < this.mSettings.mPreferredActivities.size(); i++) {
                PreferredIntentResolver pir = (PreferredIntentResolver) this.mSettings.mPreferredActivities.valueAt(i);
                removed.clear();
                for (PreferredActivity pa : pir.filterSet()) {
                    if (ActivityIntentResolver.access$1700(this.mActivities).get(pa.mPref.mComponent) == null) {
                        removed.add(pa);
                    }
                }
                if (removed.size() > 0) {
                    for (int r = DEX_OPT_SKIPPED; r < removed.size(); r++) {
                        PreferredActivity pa2 = removed.get(r);
                        Slog.w(TAG, "Removing dangling preferred activity: " + pa2.mPref.mComponent);
                        pir.removeFilter(pa2);
                    }
                    this.mSettings.writePackageRestrictionsLPr(this.mSettings.mPreferredActivities.keyAt(i));
                }
            }
        }
        sUserManager.systemReady();
        VendorPackageManagerCallback.callOnSystemReady(this.mVendorCallbacks);
        if (this.mPostSystemReadyMessages != null) {
            Iterator i$ = this.mPostSystemReadyMessages.iterator();
            while (i$.hasNext()) {
                Message msg = i$.next();
                msg.sendToTarget();
            }
            this.mPostSystemReadyMessages = null;
        }
    }

    public boolean isSafeMode() {
        return this.mSafeMode;
    }

    public boolean hasSystemUidErrors() {
        return this.mHasSystemUidErrors;
    }

    static String arrayToString(int[] array) {
        StringBuffer buf = new StringBuffer(SCAN_DEFER_DEX);
        buf.append('[');
        if (array != null) {
            for (int i = DEX_OPT_SKIPPED; i < array.length; i++) {
                if (i > 0) {
                    buf.append(", ");
                }
                buf.append(array[i]);
            }
        }
        buf.append(']');
        return buf.toString();
    }

    /* JADX WARN: Removed duplicated region for block: B:402:0x0929 A[Catch: IOException -> 0x0942, all -> 0x095d, TryCatch #9 {IOException -> 0x0942, all -> 0x095d, blocks: (B:400:0x0923, B:402:0x0929, B:405:0x0933), top: B:399:0x0923 }] */
    /* JADX WARN: Removed duplicated region for block: B:409:0x0954 A[EDGE_INSN: B:409:0x0954->B:410:0x0954 BREAK  A[LOOP:9: B:399:0x0923->B:407:0x0923], SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
    */
    protected void dump(FileDescriptor fd, PrintWriter pw, String[] args) {
        BufferedReader in;
        String line;
        String opt;
        if (this.mContext.checkCallingOrSelfPermission("android.permission.DUMP") != 0) {
            pw.println("Permission Denial: can't dump ActivityManager from from pid=" + Binder.getCallingPid() + ", uid=" + Binder.getCallingUid() + " without permission android.permission.DUMP");
            return;
        }
        DumpState dumpState = new DumpState();
        boolean fullPreferred = false;
        boolean checkin = false;
        String packageName = null;
        int opti = DEX_OPT_SKIPPED;
        while (opti < args.length && (opt = args[opti]) != null && opt.length() > 0 && opt.charAt(DEX_OPT_SKIPPED) == '-') {
            opti++;
            if (!"-a".equals(opt)) {
                if ("-h".equals(opt)) {
                    pw.println("Package manager dump options:");
                    pw.println("  [-h] [-f] [--checkin] [cmd] ...");
                    pw.println("    --checkin: dump for a checkin");
                    pw.println("    -f: print details of intent filters");
                    pw.println("    -h: print this help");
                    pw.println("  cmd may be one of:");
                    pw.println("    l[ibraries]: list known shared libraries");
                    pw.println("    f[ibraries]: list device features");
                    pw.println("    k[eysets]: print known keysets");
                    pw.println("    r[esolvers]: dump intent resolvers");
                    pw.println("    perm[issions]: dump permissions");
                    pw.println("    pref[erred]: print preferred package settings");
                    pw.println("    preferred-xml [--full]: print preferred package settings as xml");
                    pw.println("    prov[iders]: dump content providers");
                    pw.println("    p[ackages]: dump installed packages");
                    pw.println("    s[hared-users]: dump shared user IDs");
                    pw.println("    m[essages]: print collected runtime messages");
                    pw.println("    v[erifiers]: print package verifier info");
                    pw.println("    version: print database version info");
                    pw.println("    write: write current settings now");
                    pw.println("    <package.name>: info about given package");
                    pw.println("    installs: details about install sessions");
                    return;
                }
                if ("--checkin".equals(opt)) {
                    checkin = true;
                } else if ("-f".equals(opt)) {
                    dumpState.setOptionEnabled(1);
                } else {
                    pw.println("Unknown argument: " + opt + "; use -h for help");
                }
            }
        }
        if (opti < args.length) {
            String cmd = args[opti];
            int opti2 = opti + 1;
            if ("android".equals(cmd) || cmd.contains(".")) {
                packageName = cmd;
                dumpState.setOptionEnabled(1);
            } else if ("l".equals(cmd) || "libraries".equals(cmd)) {
                dumpState.setDump(1);
            } else if ("f".equals(cmd) || "features".equals(cmd)) {
                dumpState.setDump(2);
            } else if ("r".equals(cmd) || "resolvers".equals(cmd)) {
                dumpState.setDump(4);
            } else if ("perm".equals(cmd) || "permissions".equals(cmd)) {
                dumpState.setDump(8);
            } else if ("pref".equals(cmd) || "preferred".equals(cmd)) {
                dumpState.setDump(SCAN_TRUSTED_OVERLAY);
            } else if ("preferred-xml".equals(cmd)) {
                dumpState.setDump(SCAN_DELETE_DATA_ON_FAILURES);
                if (opti2 < args.length && "--full".equals(args[opti2])) {
                    fullPreferred = true;
                    int i = opti2 + 1;
                }
            } else if ("p".equals(cmd) || "packages".equals(cmd)) {
                dumpState.setDump(16);
            } else if ("s".equals(cmd) || "shared-users".equals(cmd)) {
                dumpState.setDump(SCAN_NO_PATHS);
            } else if ("prov".equals(cmd) || "providers".equals(cmd)) {
                dumpState.setDump(SCAN_DEFER_DEX);
            } else if ("m".equals(cmd) || "messages".equals(cmd)) {
                dumpState.setDump(SCAN_UPDATE_TIME);
            } else if ("v".equals(cmd) || "verifiers".equals(cmd)) {
                dumpState.setDump(SCAN_BOOTING);
            } else if ("version".equals(cmd)) {
                dumpState.setDump(SCAN_REQUIRE_KNOWN);
            } else if ("k".equals(cmd) || "keysets".equals(cmd)) {
                dumpState.setDump(SCAN_REPLACING);
            } else if ("installs".equals(cmd)) {
                dumpState.setDump(8192);
            } else if ("write".equals(cmd)) {
                synchronized (this.mPackages) {
                    this.mSettings.writeLPr();
                    pw.println("Settings written.");
                }
                return;
            }
        }
        if (checkin) {
            pw.println("vers,1");
        }
        synchronized (this.mPackages) {
            if (dumpState.isDumping(SCAN_REQUIRE_KNOWN) && packageName == null && !checkin) {
                if (dumpState.onTitlePrinted()) {
                    pw.println();
                }
                pw.println("Database versions:");
                pw.print("  SDK Version:");
                pw.print(" internal=");
                pw.print(this.mSettings.mInternalSdkPlatform);
                pw.print(" external=");
                pw.println(this.mSettings.mExternalSdkPlatform);
                pw.print("  DB Version:");
                pw.print(" internal=");
                pw.print(this.mSettings.mInternalDatabaseVersion);
                pw.print(" external=");
                pw.println(this.mSettings.mExternalDatabaseVersion);
            }
            if (dumpState.isDumping(SCAN_BOOTING) && packageName == null) {
                if (!checkin) {
                    if (dumpState.onTitlePrinted()) {
                        pw.println();
                    }
                    pw.println("Verifiers:");
                    pw.print("  Required: ");
                    pw.print(this.mRequiredVerifierPackage);
                    pw.print(" (uid=");
                    pw.print(getPackageUid(this.mRequiredVerifierPackage, DEX_OPT_SKIPPED));
                    pw.println(")");
                } else if (this.mRequiredVerifierPackage != null) {
                    pw.print("vrfy,");
                    pw.print(this.mRequiredVerifierPackage);
                    pw.print(",");
                    pw.println(getPackageUid(this.mRequiredVerifierPackage, DEX_OPT_SKIPPED));
                }
            }
            if (dumpState.isDumping(1) && packageName == null) {
                boolean printedHeader = false;
                for (String name : this.mSharedLibraries.keySet()) {
                    SharedLibraryEntry ent = this.mSharedLibraries.get(name);
                    if (!checkin) {
                        if (!printedHeader) {
                            if (dumpState.onTitlePrinted()) {
                                pw.println();
                            }
                            pw.println("Libraries:");
                            printedHeader = true;
                        }
                        pw.print("  ");
                    } else {
                        pw.print("lib,");
                    }
                    pw.print(name);
                    if (!checkin) {
                        pw.print(" -> ");
                    }
                    if (ent.path != null) {
                        if (!checkin) {
                            pw.print("(jar) ");
                            pw.print(ent.path);
                        } else {
                            pw.print(",jar,");
                            pw.print(ent.path);
                        }
                    } else if (!checkin) {
                        pw.print("(apk) ");
                        pw.print(ent.apk);
                    } else {
                        pw.print(",apk,");
                        pw.print(ent.apk);
                    }
                    pw.println();
                }
            }
            if (dumpState.isDumping(2) && packageName == null) {
                if (dumpState.onTitlePrinted()) {
                    pw.println();
                }
                if (!checkin) {
                    pw.println("Features:");
                }
                for (FeatureInfo feat : this.mAvailableFeatures.values()) {
                    if (checkin) {
                        pw.print("feat,");
                        pw.print(feat.name);
                        pw.print(",");
                        pw.println(feat.version);
                    } else {
                        pw.print("  ");
                        pw.print(feat.name);
                        if (feat.version > 0) {
                            pw.print(" version=");
                            pw.print(feat.version);
                        }
                        pw.println();
                    }
                }
            }
            if (!checkin && dumpState.isDumping(4)) {
                if (this.mActivities.dump(pw, dumpState.getTitlePrinted() ? "\nActivity Resolver Table:" : "Activity Resolver Table:", "  ", packageName, dumpState.isOptionEnabled(1), true)) {
                    dumpState.setTitlePrinted(true);
                }
                if (this.mReceivers.dump(pw, dumpState.getTitlePrinted() ? "\nReceiver Resolver Table:" : "Receiver Resolver Table:", "  ", packageName, dumpState.isOptionEnabled(1), true)) {
                    dumpState.setTitlePrinted(true);
                }
                if (this.mServices.dump(pw, dumpState.getTitlePrinted() ? "\nService Resolver Table:" : "Service Resolver Table:", "  ", packageName, dumpState.isOptionEnabled(1), true)) {
                    dumpState.setTitlePrinted(true);
                }
                if (this.mProviders.dump(pw, dumpState.getTitlePrinted() ? "\nProvider Resolver Table:" : "Provider Resolver Table:", "  ", packageName, dumpState.isOptionEnabled(1), true)) {
                    dumpState.setTitlePrinted(true);
                }
            }
            if (!checkin && dumpState.isDumping(SCAN_TRUSTED_OVERLAY)) {
                for (int i2 = DEX_OPT_SKIPPED; i2 < this.mSettings.mPreferredActivities.size(); i2++) {
                    PreferredIntentResolver pir = (PreferredIntentResolver) this.mSettings.mPreferredActivities.valueAt(i2);
                    int user = this.mSettings.mPreferredActivities.keyAt(i2);
                    if (pir.dump(pw, dumpState.getTitlePrinted() ? "\nPreferred Activities User " + user + ":" : "Preferred Activities User " + user + ":", "  ", packageName, true, false)) {
                        dumpState.setTitlePrinted(true);
                    }
                }
            }
            if (!checkin && dumpState.isDumping(SCAN_DELETE_DATA_ON_FAILURES)) {
                pw.flush();
                FileOutputStream fout = new FileOutputStream(fd);
                BufferedOutputStream str = new BufferedOutputStream(fout);
                FastXmlSerializer fastXmlSerializer = new FastXmlSerializer();
                try {
                    try {
                        fastXmlSerializer.setOutput(str, "utf-8");
                        fastXmlSerializer.startDocument(null, true);
                        fastXmlSerializer.setFeature("http://xmlpull.org/v1/doc/features.html#indent-output", true);
                        this.mSettings.writePreferredActivitiesLPr(fastXmlSerializer, DEX_OPT_SKIPPED, fullPreferred);
                        fastXmlSerializer.endDocument();
                        fastXmlSerializer.flush();
                    } catch (IllegalArgumentException e) {
                        pw.println("Failed writing: " + e);
                    }
                } catch (IOException e2) {
                    pw.println("Failed writing: " + e2);
                } catch (IllegalStateException e3) {
                    pw.println("Failed writing: " + e3);
                }
            }
            if (!checkin && dumpState.isDumping(8)) {
                this.mSettings.dumpPermissionsLPr(pw, packageName, dumpState);
                if (packageName == null) {
                    for (int iperm = DEX_OPT_SKIPPED; iperm < this.mAppOpPermissionPackages.size(); iperm++) {
                        if (iperm == 0) {
                            if (dumpState.onTitlePrinted()) {
                                pw.println();
                            }
                            pw.println("AppOp Permissions:");
                        }
                        pw.print("  AppOp Permission ");
                        pw.print(this.mAppOpPermissionPackages.keyAt(iperm));
                        pw.println(":");
                        ArraySet<String> pkgs = this.mAppOpPermissionPackages.valueAt(iperm);
                        for (int ipkg = DEX_OPT_SKIPPED; ipkg < pkgs.size(); ipkg++) {
                            pw.print("    ");
                            pw.println(pkgs.valueAt(ipkg));
                        }
                    }
                }
            }
            if (!checkin && dumpState.isDumping(SCAN_DEFER_DEX)) {
                boolean printedSomething = false;
                for (PackageParser.Provider p : ProviderIntentResolver.access$1900(this.mProviders).values()) {
                    if (packageName == null || packageName.equals(p.info.packageName)) {
                        if (!printedSomething) {
                            if (dumpState.onTitlePrinted()) {
                                pw.println();
                            }
                            pw.println("Registered ContentProviders:");
                            printedSomething = true;
                        }
                        pw.print("  ");
                        p.printComponentShortName(pw);
                        pw.println(":");
                        pw.print("    ");
                        pw.println(p.toString());
                    }
                }
                boolean printedSomething2 = false;
                for (Map.Entry<String, PackageParser.Provider> entry : this.mProvidersByAuthority.entrySet()) {
                    PackageParser.Provider p2 = entry.getValue();
                    if (packageName == null || packageName.equals(p2.info.packageName)) {
                        if (!printedSomething2) {
                            if (dumpState.onTitlePrinted()) {
                                pw.println();
                            }
                            pw.println("ContentProvider Authorities:");
                            printedSomething2 = true;
                        }
                        pw.print("  [");
                        pw.print(entry.getKey());
                        pw.println("]:");
                        pw.print("    ");
                        pw.println(p2.toString());
                        if (p2.info != null && p2.info.applicationInfo != null) {
                            String appInfo = p2.info.applicationInfo.toString();
                            pw.print("      applicationInfo=");
                            pw.println(appInfo);
                        }
                    }
                }
            }
            if (!checkin && dumpState.isDumping(SCAN_REPLACING)) {
                this.mSettings.mKeySetManagerService.dumpLPr(pw, packageName, dumpState);
            }
            if (dumpState.isDumping(16)) {
                this.mSettings.dumpPackagesLPr(pw, packageName, dumpState, checkin);
            }
            if (dumpState.isDumping(SCAN_NO_PATHS)) {
                this.mSettings.dumpSharedUsersLPr(pw, packageName, dumpState, checkin);
            }
            if (!checkin && dumpState.isDumping(8192) && packageName == null) {
                if (dumpState.onTitlePrinted()) {
                    pw.println();
                }
                this.mInstallerService.dump(new IndentingPrintWriter(pw, "  ", 120));
            }
            if (!checkin && dumpState.isDumping(SCAN_UPDATE_TIME) && packageName == null) {
                if (dumpState.onTitlePrinted()) {
                    pw.println();
                }
                this.mSettings.dumpReadMessagesLPr(pw, dumpState);
                pw.println();
                pw.println("Package warning messages:");
                BufferedReader in2 = null;
                try {
                    BufferedReader in3 = new BufferedReader(new FileReader(getSettingsProblemFile()));
                    while (true) {
                        try {
                            String line2 = in3.readLine();
                            if (line2 == null) {
                                break;
                            } else if (!line2.contains("ignored: updated version")) {
                                pw.println(line2);
                            }
                        } catch (IOException e4) {
                            in2 = in3;
                            IoUtils.closeQuietly(in2);
                            if (checkin) {
                                BufferedReader in4 = null;
                                try {
                                    in = new BufferedReader(new FileReader(getSettingsProblemFile()));
                                    while (true) {
                                        try {
                                            line = in.readLine();
                                            if (line != null) {
                                            }
                                        } catch (IOException e5) {
                                            in4 = in;
                                            IoUtils.closeQuietly(in4);
                                        } catch (Throwable th) {
                                            th = th;
                                            in4 = in;
                                            IoUtils.closeQuietly(in4);
                                            throw th;
                                        }
                                    }
                                    IoUtils.closeQuietly(in);
                                } catch (IOException e6) {
                                } catch (Throwable th2) {
                                    th = th2;
                                }
                            }
                        } catch (Throwable th3) {
                            th = th3;
                            in2 = in3;
                            IoUtils.closeQuietly(in2);
                            throw th;
                        }
                    }
                    IoUtils.closeQuietly(in3);
                } catch (IOException e7) {
                } catch (Throwable th4) {
                    th = th4;
                }
            }
            if (checkin && dumpState.isDumping(SCAN_UPDATE_TIME)) {
                BufferedReader in42 = null;
                in = new BufferedReader(new FileReader(getSettingsProblemFile()));
                while (true) {
                    line = in.readLine();
                    if (line != null) {
                        break;
                    } else if (!line.contains("ignored: updated version")) {
                        pw.print("msg,");
                        pw.println(line);
                    }
                }
                IoUtils.closeQuietly(in);
            }
        }
    }

    static String getEncryptKey() {
        try {
            String sdEncKey = SystemKeyStore.getInstance().retrieveKeyHexString(SD_ENCRYPTION_KEYSTORE_NAME);
            if (sdEncKey == null) {
                String sdEncKey2 = SystemKeyStore.getInstance().generateNewKeyHexString(SCAN_DEFER_DEX, SD_ENCRYPTION_ALGORITHM, SD_ENCRYPTION_KEYSTORE_NAME);
                if (sdEncKey2 == null) {
                    Slog.e(TAG, "Failed to create encryption keys");
                    return null;
                }
                return sdEncKey2;
            }
            return sdEncKey;
        } catch (IOException ioe) {
            Slog.e(TAG, "Failed to retrieve encryption keys with exception: " + ioe);
            return null;
        } catch (NoSuchAlgorithmException nsae) {
            Slog.e(TAG, "Failed to create encryption keys with exception: " + nsae);
            return null;
        }
    }

    public void updateExternalMediaStatus(boolean mediaStatus, boolean reportStatus) {
        int callingUid = Binder.getCallingUid();
        if (callingUid != 0 && callingUid != 1000) {
            throw new SecurityException("Media status can only be updated by the system");
        }
        synchronized (this.mPackages) {
            Log.i(TAG, "Updating external media status from " + (this.mMediaMounted ? "mounted" : "unmounted") + " to " + (mediaStatus ? "mounted" : "unmounted"));
            if (mediaStatus == this.mMediaMounted) {
                Message msg = this.mHandler.obtainMessage(UPDATED_MEDIA_STATUS, reportStatus ? 1 : DEX_OPT_SKIPPED, DEX_OPT_FAILED);
                this.mHandler.sendMessage(msg);
            } else {
                this.mMediaMounted = mediaStatus;
                this.mHandler.post(new PackageManagerService$11(this, mediaStatus, reportStatus));
            }
        }
    }

    public void scanAvailableAsecs() {
        updateExternalMediaStatusInner(true, false, false);
        if (this.mShouldRestoreconData) {
            SELinuxMMAC.setRestoreconDone();
            this.mShouldRestoreconData = false;
        }
    }

    public void updateExternalMediaStatusInner(boolean isMounted, boolean reportStatus, boolean externalStorage) {
        ArrayMap<AsecInstallArgs, String> processCids = new ArrayMap<>();
        int[] uidArr = EmptyArray.INT;
        String[] list = PackageHelper.getSecureContainerList();
        if (ArrayUtils.isEmpty(list)) {
            Log.i(TAG, "No secure containers found");
        } else {
            synchronized (this.mPackages) {
                int len$ = list.length;
                for (int i$ = DEX_OPT_SKIPPED; i$ < len$; i$++) {
                    String cid = list[i$];
                    if (!PackageInstallerService.isStageName(cid)) {
                        String pkgName = getAsecPackageName(cid);
                        if (pkgName == null) {
                            Slog.i(TAG, "Found stale container " + cid + " with no package name");
                        } else {
                            PackageSetting ps = (PackageSetting) this.mSettings.mPackages.get(pkgName);
                            if (ps == null) {
                                Slog.i(TAG, "Found stale container " + cid + " with no matching settings");
                            } else if (!externalStorage || isMounted || isExternal(ps)) {
                                String mountPath = PackageHelper.getSdDir(cid);
                                if (mountPath == null) {
                                    Slog.i(TAG, "Found NULL mount path for container " + cid);
                                } else {
                                    AsecInstallArgs args = new AsecInstallArgs(this, cid, getAppDexInstructionSets(ps), isForwardLocked(ps));
                                    if (ps.codePathString != null && ps.codePathString.startsWith(args.getCodePath())) {
                                        processCids.put(args, ps.codePathString);
                                        int uid = ps.appId;
                                        if (uid != DEX_OPT_FAILED) {
                                            uidArr = ArrayUtils.appendInt(uidArr, uid);
                                        }
                                    } else {
                                        Slog.i(TAG, "Found stale container " + cid + ": expected codePath=" + ps.codePathString);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            Arrays.sort(uidArr);
        }
        if (isMounted) {
            loadMediaPackages(processCids, uidArr);
            startCleaningPackages();
            this.mInstallerService.onSecureContainersAvailable();
            sendPackageBroadcast("amazon.intent.action.ACTION_EXTERNAL_MEDIA_PKG_LOAD_COMPLETE", null, null, null, null, null);
            return;
        }
        unloadMediaPackages(processCids, uidArr, reportStatus);
    }

    public void sendResourcesChangedBroadcast(boolean mediaStatus, boolean replacing, ArrayList<String> pkgList, int[] uidArr, IIntentReceiver finishedReceiver) {
        int size = pkgList.size();
        if (size > 0) {
            Bundle extras = new Bundle();
            extras.putStringArray("android.intent.extra.changed_package_list", (String[]) pkgList.toArray(new String[size]));
            if (uidArr != null) {
                extras.putIntArray("android.intent.extra.changed_uid_list", uidArr);
            }
            if (replacing) {
                extras.putBoolean("android.intent.extra.REPLACING", replacing);
            }
            String action = mediaStatus ? "android.intent.action.EXTERNAL_APPLICATIONS_AVAILABLE" : "android.intent.action.EXTERNAL_APPLICATIONS_UNAVAILABLE";
            sendPackageBroadcast(action, null, extras, null, finishedReceiver, null);
        }
    }

    private void loadMediaPackages(ArrayMap<AsecInstallArgs, String> processCids, int[] uidArr) {
        ArrayList<String> pkgList = new ArrayList<>();
        Set<AsecInstallArgs> keys = processCids.keySet();
        for (AsecInstallArgs args : keys) {
            String codePath = processCids.get(args);
            int retCode = -18;
            try {
                if (args.doPreInstall(1) != 1) {
                    Slog.e(TAG, "Failed to mount cid : " + args.cid + " when installing from sdcard");
                    if (-18 != 1) {
                        Log.w(TAG, "Container " + args.cid + " is stale, retCode=-18");
                    }
                } else if (codePath == null || !codePath.startsWith(args.getCodePath())) {
                    Slog.e(TAG, "Container " + args.cid + " cachepath " + args.getCodePath() + " does not match one in settings " + codePath);
                    if (-18 != 1) {
                        Log.w(TAG, "Container " + args.cid + " is stale, retCode=-18");
                    }
                } else {
                    int parseFlags = this.mDefParseFlags;
                    if (args.isExternal()) {
                        parseFlags |= SCAN_NO_PATHS;
                    }
                    if (args.isFwdLocked()) {
                        parseFlags |= 16;
                    }
                    synchronized (this.mInstallLock) {
                        PackageParser.Package pkg = null;
                        try {
                            pkg = scanPackageLI(new File(codePath), parseFlags, DEX_OPT_SKIPPED, 0L, (UserHandle) null);
                        } catch (PackageManagerException e) {
                            Slog.w(TAG, "Failed to scan " + codePath + ": " + e.getMessage());
                        }
                        if (pkg != null) {
                            synchronized (this.mPackages) {
                                retCode = 1;
                                pkgList.add(pkg.packageName);
                                args.doPostInstall(1, pkg.applicationInfo.uid);
                            }
                        } else {
                            Slog.i(TAG, "Failed to install pkg from  " + codePath + " from sdcard");
                        }
                    }
                    if (retCode != 1) {
                        Log.w(TAG, "Container " + args.cid + " is stale, retCode=" + retCode);
                    }
                }
            } catch (Throwable th) {
                if (retCode != 1) {
                    Log.w(TAG, "Container " + args.cid + " is stale, retCode=" + retCode);
                }
                throw th;
            }
        }
        synchronized (this.mPackages) {
            boolean regrantPermissions = this.mSettings.mExternalSdkPlatform != this.mSdkVersion;
            if (regrantPermissions) {
                Slog.i(TAG, "Platform changed from " + this.mSettings.mExternalSdkPlatform + " to " + this.mSdkVersion + "; regranting permissions for external storage");
            }
            this.mSettings.mExternalSdkPlatform = this.mSdkVersion;
            updatePermissionsLPw(null, null, (regrantPermissions ? MCS_UNBIND : DEX_OPT_SKIPPED) | 1);
            this.mSettings.updateExternalDatabaseVersion();
            this.mSettings.writeLPr();
        }
        if (pkgList.size() > 0) {
            sendResourcesChangedBroadcast(true, false, pkgList, uidArr, null);
        }
    }

    public void unloadAllContainers(Set<AsecInstallArgs> cidArgs) {
        for (AsecInstallArgs arg : cidArgs) {
            synchronized (this.mInstallLock) {
                arg.doPostDeleteLI(false);
            }
        }
    }

    private void unloadMediaPackages(ArrayMap<AsecInstallArgs, String> processCids, int[] uidArr, boolean reportStatus) {
        ArrayList<String> pkgList = new ArrayList<>();
        ArrayList<AsecInstallArgs> failedList = new ArrayList<>();
        Set<AsecInstallArgs> keys = processCids.keySet();
        for (AsecInstallArgs args : keys) {
            String pkgName = args.getPackageName();
            PackageRemovedInfo outInfo = new PackageRemovedInfo();
            synchronized (this.mInstallLock) {
                boolean res = deletePackageLI(pkgName, null, false, null, null, 1, outInfo, false);
                if (res) {
                    pkgList.add(pkgName);
                } else {
                    Slog.e(TAG, "Failed to delete pkg from sdcard : " + pkgName);
                    failedList.add(args);
                }
            }
        }
        synchronized (this.mPackages) {
            this.mSettings.writeLPr();
        }
        if (pkgList.size() > 0) {
            sendResourcesChangedBroadcast(false, false, pkgList, uidArr, new PackageManagerService$12(this, reportStatus, keys));
        } else {
            Message msg = this.mHandler.obtainMessage(UPDATED_MEDIA_STATUS, reportStatus ? 1 : DEX_OPT_SKIPPED, DEX_OPT_FAILED, keys);
            this.mHandler.sendMessage(msg);
        }
    }

    public void movePackage(String packageName, IPackageMoveObserver observer, int flags) {
        this.mContext.enforceCallingOrSelfPermission("android.permission.MOVE_PACKAGE", null);
        UserHandle user = new UserHandle(UserHandle.getCallingUserId());
        int returnCode = 1;
        int newInstallFlags = DEX_OPT_SKIPPED;
        File codeFile = null;
        String installerPackageName = null;
        String packageAbiOverride = null;
        int appId = DEX_OPT_FAILED;
        synchronized (this.mPackages) {
            try {
                PackageParser.Package pkg = this.mPackages.get(packageName);
                PackageSetting ps = (PackageSetting) this.mSettings.mPackages.get(packageName);
                if (pkg == null || ps == null) {
                    returnCode = -2;
                } else {
                    if (pkg.applicationInfo != null && isSystemApp(pkg)) {
                        Slog.w(TAG, "Cannot move system application");
                        returnCode = -3;
                    } else if (ps.frozen) {
                        Slog.w(TAG, "Failed to move already frozen package");
                        returnCode = -7;
                    } else {
                        if ((flags & 2) != 0 && (flags & 1) != 0) {
                            Slog.w(TAG, "Ambigous flags specified for move location.");
                            returnCode = -5;
                        } else {
                            newInstallFlags = (flags & 2) != 0 ? 8 : 16;
                            int currInstallFlags = isExternal(pkg) ? 8 : 16;
                            if (newInstallFlags == currInstallFlags) {
                                Slog.w(TAG, "No move required. Trying to move to same location");
                                returnCode = -5;
                            } else if (isForwardLocked(pkg)) {
                                int i = currInstallFlags | 1;
                                newInstallFlags |= 1;
                            }
                        }
                        if (returnCode == 1) {
                            ps.frozen = true;
                        }
                    }
                    File codeFile2 = new File(pkg.codePath);
                    try {
                        installerPackageName = ps.installerPackageName;
                        packageAbiOverride = ps.cpuAbiOverrideString;
                        appId = UserHandle.getAppId(pkg.applicationInfo.uid);
                        codeFile = codeFile2;
                    } catch (Throwable th) {
                        th = th;
                        throw th;
                    }
                }
                if (returnCode != 1) {
                    try {
                        observer.packageMoved(packageName, returnCode);
                        return;
                    } catch (RemoteException e) {
                        return;
                    }
                }
                if (appId != DEX_OPT_FAILED) {
                    long token = Binder.clearCallingIdentity();
                    try {
                        killApplication(packageName, appId, "move pkg");
                    } finally {
                        Binder.restoreCallingIdentity(token);
                    }
                }
                UserHandle user2 = VendorPackageManagerCallback.callGetUserForMovingPackage(this.mVendorCallbacks, packageName, sUserManager, user);
                Message msg = this.mHandler.obtainMessage(INIT_COPY);
                OriginInfo origin = OriginInfo.fromExistingFile(codeFile);
                msg.obj = new InstallParams(this, origin, new PackageManagerService$13(this, packageName, observer), newInstallFlags | 2, installerPackageName, (VerificationParams) null, user2, packageAbiOverride);
                this.mHandler.sendMessage(msg);
            } catch (Throwable th2) {
                th = th2;
            }
        }
    }

    public boolean setInstallLocation(int loc) {
        this.mContext.enforceCallingOrSelfPermission("android.permission.WRITE_SECURE_SETTINGS", null);
        if (getInstallLocation() == loc) {
            return true;
        }
        if (loc == 0 || loc == 1 || loc == 2) {
            Settings.Global.putInt(this.mContext.getContentResolver(), "default_install_location", loc);
            return true;
        }
        return false;
    }

    public int getInstallLocation() {
        return Settings.Global.getInt(this.mContext.getContentResolver(), "default_install_location", DEX_OPT_SKIPPED);
    }

    public boolean setPermissions(String name, int bits) {
        this.mContext.checkCallingOrSelfPermission("android.permission.FILE_PERMISSION_UPDATE");
        if (this.mInstaller != null) {
            synchronized (this.mInstallLock) {
                r0 = this.mInstaller.setPermissions(name, bits) == 0;
            }
        }
        return r0;
    }

    public boolean linkFiles(String srcFile, String dstFile, int bits) {
        if (this.mInstaller != null) {
            synchronized (this.mInstallLock) {
                r0 = this.mInstaller.linkFiles(srcFile, dstFile, bits) == 0;
            }
        }
        return r0;
    }

    public boolean giveFile(String name, int uid) {
        if (this.mInstaller != null) {
            synchronized (this.mInstallLock) {
                r0 = this.mInstaller.giveFile(name, uid) == 0;
            }
        }
        return r0;
    }

    void cleanUpUserLILPw(UserManagerService userManager, int userHandle) {
        this.mDirtyUsers.remove(Integer.valueOf(userHandle));
        this.mSettings.removeUserLPw(userHandle);
        this.mPendingBroadcasts.remove(userHandle);
        if (this.mInstaller != null) {
            this.mInstaller.removeUserDataDirs(userHandle);
        }
        this.mUserNeedsBadging.delete(userHandle);
        removeUnusedPackagesLILPw(userManager, userHandle);
    }

    private void removeUnusedPackagesLILPw(UserManagerService userManager, int userHandle) {
        int[] users = userManager.getUserIdsLPr();
        for (PackageSetting ps : this.mSettings.mPackages.values()) {
            if (ps.pkg != null) {
                String packageName = ps.pkg.packageName;
                if ((ps.pkgFlags & 1) == 0) {
                    boolean keep = false;
                    int i = DEX_OPT_SKIPPED;
                    while (true) {
                        if (i >= users.length) {
                            break;
                        }
                        if (users[i] == userHandle || !ps.getInstalled(users[i])) {
                            i++;
                        } else {
                            keep = true;
                            break;
                        }
                    }
                    if (!keep) {
                        this.mHandler.post(new PackageManagerService$14(this, packageName, userHandle));
                    }
                }
            }
        }
    }

    void createNewUserLILPw(int userHandle, File path) {
        if (this.mInstaller != null) {
            this.mInstaller.createUserConfig(userHandle);
            this.mSettings.createNewUserLILPw(this, this.mInstaller, userHandle, path);
        }
    }

    public VerifierDeviceIdentity getVerifierDeviceIdentity() throws RemoteException {
        VerifierDeviceIdentity verifierDeviceIdentityLPw;
        this.mContext.enforceCallingOrSelfPermission("android.permission.PACKAGE_VERIFICATION_AGENT", "Only package verification agents can read the verifier device identity");
        synchronized (this.mPackages) {
            verifierDeviceIdentityLPw = this.mSettings.getVerifierDeviceIdentityLPw();
        }
        return verifierDeviceIdentityLPw;
    }

    public void unfreezePackage(String packageName) {
        synchronized (this.mPackages) {
            PackageSetting ps = (PackageSetting) this.mSettings.mPackages.get(packageName);
            if (ps != null) {
                ps.frozen = false;
            }
        }
    }

    public void setPermissionEnforced(String permission, boolean enforced) {
        this.mContext.enforceCallingOrSelfPermission("android.permission.GRANT_REVOKE_PERMISSIONS", null);
        if ("android.permission.READ_EXTERNAL_STORAGE".equals(permission)) {
            synchronized (this.mPackages) {
                if (this.mSettings.mReadExternalStorageEnforced == null || this.mSettings.mReadExternalStorageEnforced.booleanValue() != enforced) {
                    this.mSettings.mReadExternalStorageEnforced = Boolean.valueOf(enforced);
                    this.mSettings.writeLPr();
                }
            }
            IActivityManager am = ActivityManagerNative.getDefault();
            if (am != null) {
                long token = Binder.clearCallingIdentity();
                try {
                    am.killProcessesBelowForeground("setPermissionEnforcement");
                    return;
                } catch (RemoteException e) {
                    return;
                } finally {
                    Binder.restoreCallingIdentity(token);
                }
            }
            return;
        }
        throw new IllegalArgumentException("No selective enforcement for " + permission);
    }

    @Deprecated
    public boolean isPermissionEnforced(String permission) {
        return true;
    }

    public boolean isStorageLow() {
        long token = Binder.clearCallingIdentity();
        try {
            DeviceStorageMonitorInternal dsm = (DeviceStorageMonitorInternal) LocalServices.getService(DeviceStorageMonitorInternal.class);
            if (dsm != null) {
                return dsm.isMemoryLow();
            }
            return false;
        } finally {
            Binder.restoreCallingIdentity(token);
        }
    }

    public IPackageInstaller getPackageInstaller() {
        return this.mInstallerService;
    }

    public boolean userNeedsBadging(int userId) {
        boolean b;
        int index = this.mUserNeedsBadging.indexOfKey(userId);
        if (index < 0) {
            long token = Binder.clearCallingIdentity();
            try {
                UserInfo userInfo = sUserManager.getUserInfo(userId);
                if (userInfo != null && userInfo.isManagedProfile()) {
                    b = true;
                } else {
                    b = false;
                }
                this.mUserNeedsBadging.put(userId, b);
                return b;
            } finally {
                Binder.restoreCallingIdentity(token);
            }
        }
        boolean b2 = this.mUserNeedsBadging.valueAt(index);
        return b2;
    }

    public KeySet getKeySetByAlias(String packageName, String alias) {
        KeySet keySet;
        if (packageName == null || alias == null) {
            return null;
        }
        synchronized (this.mPackages) {
            PackageParser.Package pkg = this.mPackages.get(packageName);
            if (pkg == null) {
                Slog.w(TAG, "KeySet requested for unknown package:" + packageName);
                throw new IllegalArgumentException("Unknown package: " + packageName);
            }
            KeySetManagerService ksms = this.mSettings.mKeySetManagerService;
            keySet = new KeySet(ksms.getKeySetByAliasAndPackageNameLPr(packageName, alias));
        }
        return keySet;
    }

    public KeySet getSigningKeySet(String packageName) {
        KeySet keySet;
        if (packageName == null) {
            return null;
        }
        synchronized (this.mPackages) {
            PackageParser.Package pkg = this.mPackages.get(packageName);
            if (pkg == null) {
                Slog.w(TAG, "KeySet requested for unknown package:" + packageName);
                throw new IllegalArgumentException("Unknown package: " + packageName);
            }
            if (pkg.applicationInfo.uid != Binder.getCallingUid() && 1000 != Binder.getCallingUid()) {
                throw new SecurityException("May not access signing KeySet of other apps.");
            }
            KeySetManagerService ksms = this.mSettings.mKeySetManagerService;
            keySet = new KeySet(ksms.getSigningKeySetByPackageNameLPr(packageName));
        }
        return keySet;
    }

    public boolean isPackageSignedByKeySet(String packageName, KeySet ks) {
        boolean z = false;
        if (packageName != null && ks != null) {
            synchronized (this.mPackages) {
                PackageParser.Package pkg = this.mPackages.get(packageName);
                if (pkg == null) {
                    Slog.w(TAG, "KeySet requested for unknown package:" + packageName);
                    throw new IllegalArgumentException("Unknown package: " + packageName);
                }
                KeySetHandle token = ks.getToken();
                if (token instanceof KeySetHandle) {
                    KeySetManagerService ksms = this.mSettings.mKeySetManagerService;
                    z = ksms.packageIsSignedByLPr(packageName, token);
                }
            }
        }
        return z;
    }

    public boolean isPackageSignedByKeySetExactly(String packageName, KeySet ks) {
        boolean z = false;
        if (packageName != null && ks != null) {
            synchronized (this.mPackages) {
                PackageParser.Package pkg = this.mPackages.get(packageName);
                if (pkg == null) {
                    Slog.w(TAG, "KeySet requested for unknown package:" + packageName);
                    throw new IllegalArgumentException("Unknown package: " + packageName);
                }
                KeySetHandle token = ks.getToken();
                if (token instanceof KeySetHandle) {
                    KeySetManagerService ksms = this.mSettings.mKeySetManagerService;
                    z = ksms.packageIsSignedByExactlyLPr(packageName, token);
                }
            }
        }
        return z;
    }

    public void getUsageStatsIfNoPackageUsageInfo() {
        if (!this.mPackageUsage.isHistoricalPackageUsageAvailable()) {
            UsageStatsManager usm = (UsageStatsManager) this.mContext.getSystemService("usagestats");
            if (usm == null) {
                throw new IllegalStateException("UsageStatsManager must be initialized");
            }
            long now = System.currentTimeMillis();
            Map<String, UsageStats> stats = usm.queryAndAggregateUsageStats(now - this.mDexOptLRUThresholdInMills, now);
            for (Map.Entry<String, UsageStats> entry : stats.entrySet()) {
                String packageName = entry.getKey();
                PackageParser.Package pkg = this.mPackages.get(packageName);
                if (pkg != null) {
                    UsageStats usage = entry.getValue();
                    pkg.mLastPackageUsageTimeInMills = usage.getLastTimeUsed();
                    PackageUsage.access$4702(this.mPackageUsage, true);
                }
            }
        }
    }

    public static void checkDowngrade(PackageParser.Package before, PackageInfoLite after) throws PackageManagerException {
        if (after.versionCode < before.mVersionCode) {
            throw new PackageManagerException(-25, "Update version code " + after.versionCode + " is older than current " + before.mVersionCode);
        }
        if (after.versionCode == before.mVersionCode) {
            if (after.baseRevisionCode < before.baseRevisionCode) {
                throw new PackageManagerException(-25, "Update base revision code " + after.baseRevisionCode + " is older than current " + before.baseRevisionCode);
            }
            if (!ArrayUtils.isEmpty(after.splitNames)) {
                for (int i = DEX_OPT_SKIPPED; i < after.splitNames.length; i++) {
                    String splitName = after.splitNames[i];
                    int j = ArrayUtils.indexOf(before.splitNames, splitName);
                    if (j != DEX_OPT_FAILED && after.splitRevisionCodes[i] < before.splitRevisionCodes[j]) {
                        throw new PackageManagerException(-25, "Update split " + splitName + " revision code " + after.splitRevisionCodes[i] + " is older than current " + before.splitRevisionCodes[j]);
                    }
                }
            }
        }
    }

    private static void killProcess(String packageName, int appUid) {
        ActivityManagerService activityManagerService = ActivityManagerNative.getDefault();
        if (activityManagerService != null && (activityManagerService instanceof ActivityManagerService)) {
            ActivityManagerService ams = activityManagerService;
            int pid = ams.getProcessPid(packageName, appUid);
            if (pid > 0) {
                Process.killProcess(pid);
            }
        }
    }

    public boolean registerProxyReceiver(Intent intentToFilter, PendingIntent intentToRelay) {
        return ProxyReceiver.getInstance().registerProxyReceiver(intentToFilter, intentToRelay, this.mContext);
    }

    public boolean deregisterProxyReceiver(Intent intent) {
        return ProxyReceiver.getInstance().deregisterProxyReceiver(intent, this.mContext);
    }

    public void symlinkNativeLibraries(int userId) {
        synchronized (this.mPackages) {
            for (PackageParser.Package pkg : this.mPackages.values()) {
                synchronized (this.mInstallLock) {
                    if (this.mInstaller.linkNativeLibraryDirectory(pkg.packageName, pkg.applicationInfo.nativeLibraryDir, userId) < 0) {
                        Slog.w(TAG, "Failed linking native library dir (user=" + userId + ")");
                    }
                }
            }
        }
    }
}
