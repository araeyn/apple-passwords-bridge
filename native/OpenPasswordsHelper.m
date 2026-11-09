#import <AppKit/AppKit.h>
#import <Security/Security.h>
#import <libproc.h>
#import <poll.h>
#import <spawn.h>
#import <dispatch/dispatch.h>
#import <sys/socket.h>
#import <sys/stat.h>
#import <sys/un.h>
#import <sys/wait.h>
#import <errno.h>
#import <fcntl.h>
#import <signal.h>
#import "PasskeyHost.h"

extern char **environ;

static NSString *const kBundleID = @"com.openpasswords.helper";
static NSString *const kHostName = @"com.openpasswords.icloud";
static NSString *const kPasskeyHostName = @"com.openpasswords.passkeys";
static NSString *const kExtensionOrigin = @"chrome-extension://abpahgnajbkclfhpodhjhlmgfjhpibaa/";
static NSString *const kPreviousExtensionOrigin = @"chrome-extension://pejdijmoenmkgeppbflobdenhhabjlaj/";
static NSString *const kHandoffVariable = @"OPENPASSWORDS_HELPER_HANDOFF";
static NSString *const kBrowserEntitlement = @"com.apple.developer.web-browser.public-key-credential";
static NSString *const kSelectedBrowserPreference = @"SelectedBrowserAppPath";
static NSString *const kBrowserCandidatesPreference = @"BrowserCandidatesCache";
static NSString *const kBrowserProbeResultsPreference = @"BrowserProbeResults";
static NSString *const kAppVisibilityPreference = @"AppVisibilityMode";
static NSString *const kAppleHostManifest = @"/Library/Google/Chrome/NativeMessagingHosts/com.apple.passwordmanager.json";
static const uint32_t kMaxHandoffBytes = 1 << 20;
static const NSTimeInterval kStartupTimeout = 20.0;
static const NSTimeInterval kProbeTimeout = 25.0;
static NSString *gLaunchDirectory;

static NSArray<NSString *> *extensionOrigins(void) {
    return @[ kExtensionOrigin, kPreviousExtensionOrigin ];
}

static BOOL isAllowedExtensionOrigin(NSString *origin) {
    return origin.length > 0 && [extensionOrigins() containsObject:origin];
}

typedef NS_ENUM(NSInteger, OPAppVisibilityMode) {
    OPAppVisibilityDockOnly = 0,
    OPAppVisibilityMenuBarOnly = 1,
    OPAppVisibilityDockAndMenuBar = 2,
};

static OPAppVisibilityMode appVisibilityMode(void) {
    NSInteger mode = [NSUserDefaults.standardUserDefaults integerForKey:kAppVisibilityPreference];
    if (mode < OPAppVisibilityDockOnly || mode > OPAppVisibilityDockAndMenuBar) return OPAppVisibilityDockOnly;
    return (OPAppVisibilityMode)mode;
}

static BOOL appShowsMenuBarIcon(void) {
    OPAppVisibilityMode mode = appVisibilityMode();
    return mode == OPAppVisibilityMenuBarOnly || mode == OPAppVisibilityDockAndMenuBar;
}

static void logError(NSString *message) {
    NSData *line = [[message stringByAppendingString:@"\n"] dataUsingEncoding:NSUTF8StringEncoding];
    if (line) write(STDERR_FILENO, line.bytes, line.length);
}

static NSString *homePath(NSString *relative) {
    return [NSHomeDirectory() stringByAppendingPathComponent:relative];
}

static NSURL *installedAppURL(void) {
    return [NSURL fileURLWithPath:homePath(@"Applications/Open Passwords Helper.app")];
}

static NSURL *hostManifestURL(void) {
    return [NSURL fileURLWithPath:homePath(@"Library/Application Support/Google/Chrome/NativeMessagingHosts/com.openpasswords.icloud.json")];
}

static NSURL *passkeyHostManifestURL(void) {
    return [NSURL fileURLWithPath:homePath(@"Library/Application Support/Google/Chrome/NativeMessagingHosts/com.openpasswords.passkeys.json")];
}

static NSArray<NSURL *> *hostManifestURLs(void) {
    return @[
        hostManifestURL(),
        [NSURL fileURLWithPath:homePath(@"Library/Application Support/Arc/User Data/NativeMessagingHosts/com.openpasswords.icloud.json")],
    ];
}

static NSArray<NSURL *> *passkeyHostManifestURLs(void) {
    return @[
        passkeyHostManifestURL(),
        [NSURL fileURLWithPath:homePath(@"Library/Application Support/Arc/User Data/NativeMessagingHosts/com.openpasswords.passkeys.json")],
    ];
}

static NSString *executablePathForApp(NSURL *appURL) {
    NSDictionary *info = [NSDictionary dictionaryWithContentsOfURL:[appURL URLByAppendingPathComponent:@"Contents/Info.plist"]];
    NSString *executable = info[@"CFBundleExecutable"];
    if (![executable isKindOfClass:NSString.class] || !executable.length) return nil;
    return [[appURL URLByAppendingPathComponent:[@"Contents/MacOS" stringByAppendingPathComponent:executable]] path];
}

static NSString *passkeyHostPathForApp(NSURL *appURL) {
    return [[appURL URLByAppendingPathComponent:@"Contents/Resources/OpenPasswordsPasskeyHost"] path];
}

static NSString *currentExecutablePath(void) {
    return NSBundle.mainBundle.executablePath.stringByStandardizingPath;
}

static NSDictionary *selectedBrowserCandidate(void);

static BOOL isAppOwnedHostManifest(NSDictionary *manifest) {
    if (![manifest isKindOfClass:NSDictionary.class] || ![manifest[@"name"] isEqual:kHostName]) return NO;
    NSString *path = manifest[@"path"];
    if (![path isKindOfClass:NSString.class]) return NO;
    NSString *installedExecutable = executablePathForApp(installedAppURL());
    return installedExecutable && [path.stringByStandardizingPath isEqual:installedExecutable.stringByStandardizingPath];
}

static BOOL isAppOwnedPasskeyHostManifest(NSDictionary *manifest) {
    if (![manifest isKindOfClass:NSDictionary.class] || ![manifest[@"name"] isEqual:kPasskeyHostName]) return NO;
    NSString *path = manifest[@"path"];
    if (![path isKindOfClass:NSString.class]) return NO;
    NSString *installedHost = passkeyHostPathForApp(installedAppURL());
    return installedHost && [path.stringByStandardizingPath isEqual:installedHost.stringByStandardizingPath];
}

static BOOL isAnyAppOwnedHostManifest(void) {
    for (NSURL *url in hostManifestURLs()) {
        NSDictionary *manifest = [NSJSONSerialization JSONObjectWithData:[NSData dataWithContentsOfURL:url] ?: NSData.data options:0 error:nil];
        if (isAppOwnedHostManifest(manifest)) return YES;
    }
    for (NSURL *url in passkeyHostManifestURLs()) {
        NSDictionary *manifest = [NSJSONSerialization JSONObjectWithData:[NSData dataWithContentsOfURL:url] ?: NSData.data options:0 error:nil];
        if (isAppOwnedPasskeyHostManifest(manifest)) return YES;
    }
    return NO;
}

static BOOL installHostManifestAtURL(NSURL *url, NSString *executable, NSError **errorOut) {
    NSFileManager *fm = NSFileManager.defaultManager;
    NSString *parent = url.URLByDeletingLastPathComponent.path;
    if (![fm createDirectoryAtPath:parent withIntermediateDirectories:YES attributes:@{ NSFilePosixPermissions : @0700 } error:errorOut]) return NO;

    if ([fm fileExistsAtPath:url.path]) {
        NSData *existingData = [NSData dataWithContentsOfURL:url];
        NSDictionary *existing = existingData ? [NSJSONSerialization JSONObjectWithData:existingData options:0 error:nil] : nil;
        if (!isAppOwnedHostManifest(existing)) {
            if (errorOut) *errorOut = [NSError errorWithDomain:kBundleID code:1 userInfo:@{ NSLocalizedDescriptionKey : @"A different app already registered this native host name." }];
            return NO;
        }
    }

    NSDictionary *manifest = @{
        @"name" : kHostName,
        @"description" : @"Open Passwords local bridge",
        @"path" : executable,
        @"type" : @"stdio",
        @"allowed_origins" : extensionOrigins(),
    };
    NSData *json = [NSJSONSerialization dataWithJSONObject:manifest options:NSJSONWritingPrettyPrinted error:errorOut];
    return json && [json writeToURL:url options:NSDataWritingAtomic error:errorOut];
}

static BOOL installPasskeyHostManifestAtURL(NSURL *url, NSString *executable, NSError **errorOut) {
    NSFileManager *fm = NSFileManager.defaultManager;
    NSString *parent = url.URLByDeletingLastPathComponent.path;
    if (![fm createDirectoryAtPath:parent withIntermediateDirectories:YES attributes:@{ NSFilePosixPermissions : @0700 } error:errorOut]) return NO;

    if ([fm fileExistsAtPath:url.path]) {
        NSData *existingData = [NSData dataWithContentsOfURL:url];
        NSDictionary *existing = existingData ? [NSJSONSerialization JSONObjectWithData:existingData options:0 error:nil] : nil;
        if (!isAppOwnedPasskeyHostManifest(existing)) {
            if (errorOut) *errorOut = [NSError errorWithDomain:kBundleID code:6 userInfo:@{ NSLocalizedDescriptionKey : @"A different app already registered the passkey native host name." }];
            return NO;
        }
    }

    NSDictionary *manifest = @{
        @"name" : kPasskeyHostName,
        @"description" : @"Open Passwords on-demand passkey broker",
        @"path" : executable,
        @"type" : @"stdio",
        @"allowed_origins" : extensionOrigins(),
    };
    NSData *json = [NSJSONSerialization dataWithJSONObject:manifest options:NSJSONWritingPrettyPrinted error:errorOut];
    return json && [json writeToURL:url options:NSDataWritingAtomic error:errorOut];
}

static BOOL copyAppToApplications(NSURL *source, NSURL **installedOut, NSError **errorOut) {
    NSFileManager *fm = NSFileManager.defaultManager;
    NSURL *target = installedAppURL();
    NSString *sourcePath = source.URLByResolvingSymlinksInPath.path.stringByStandardizingPath;
    NSString *targetPath = target.URLByResolvingSymlinksInPath.path.stringByStandardizingPath;
    if ([sourcePath isEqual:targetPath]) {
        NSString *executable = executablePathForApp(target);
        if (!executable || ![fm isExecutableFileAtPath:executable]) {
            if (errorOut) *errorOut = [NSError errorWithDomain:kBundleID code:9 userInfo:@{
                NSLocalizedDescriptionKey : @"This helper app bundle was removed while it was still open. Reopen the project’s native/install-password-helper.sh to reinstall it."
            }];
            return NO;
        }
        if (installedOut) *installedOut = target;
        return YES;
    }

    if (![fm createDirectoryAtURL:target.URLByDeletingLastPathComponent withIntermediateDirectories:YES attributes:nil error:errorOut]) return NO;

    BOOL targetExists = [fm fileExistsAtPath:target.path];
    if (targetExists) {
        NSDictionary *existingInfo = [NSDictionary dictionaryWithContentsOfURL:[target URLByAppendingPathComponent:@"Contents/Info.plist"]];
        if (![existingInfo[@"CFBundleIdentifier"] isEqual:kBundleID]) {
            if (errorOut) *errorOut = [NSError errorWithDomain:kBundleID code:2 userInfo:@{ NSLocalizedDescriptionKey : @"~/Applications already contains a different Open Passwords Helper app." }];
            return NO;
        }
    }

    NSString *stageName = [NSString stringWithFormat:@".Open Passwords Helper.%@.new.app", NSUUID.UUID.UUIDString];
    NSURL *stage = [target.URLByDeletingLastPathComponent URLByAppendingPathComponent:stageName];
    if (![fm copyItemAtURL:source toURL:stage error:errorOut]) return NO;

    if (targetExists) {
        NSURL *backup = [target.URLByDeletingLastPathComponent URLByAppendingPathComponent:[NSString stringWithFormat:@".Open Passwords Helper.%@.old.app", NSUUID.UUID.UUIDString]];
        if (![fm moveItemAtURL:target toURL:backup error:errorOut]) {
            [fm removeItemAtURL:stage error:nil];
            return NO;
        }
        NSError *moveError = nil;
        if (![fm moveItemAtURL:stage toURL:target error:&moveError]) {
            [fm moveItemAtURL:backup toURL:target error:nil];
            [fm removeItemAtURL:stage error:nil];
            if (errorOut) *errorOut = moveError;
            return NO;
        }
        [fm removeItemAtURL:backup error:nil];
    } else if (![fm moveItemAtURL:stage toURL:target error:errorOut]) {
        [fm removeItemAtURL:stage error:nil];
        return NO;
    }

    if (installedOut) *installedOut = target;
    return YES;
}

static BOOL installHelper(NSError **errorOut) {
    if (!selectedBrowserCandidate()) {
        if (errorOut) *errorOut = [NSError errorWithDomain:kBundleID code:5 userInfo:@{ NSLocalizedDescriptionKey : @"No installed Chromium browser with Apple's public-key credential entitlement was found." }];
        return NO;
    }
    NSURL *installed = nil;
    if (!copyAppToApplications(NSBundle.mainBundle.bundleURL, &installed, errorOut)) return NO;
    NSString *executable = executablePathForApp(installed);
    if (!executable || ![[NSFileManager defaultManager] isExecutableFileAtPath:executable]) {
        if (errorOut) *errorOut = [NSError errorWithDomain:kBundleID code:3 userInfo:@{ NSLocalizedDescriptionKey : @"The helper app executable is missing." }];
        return NO;
    }
    NSString *passkeyHost = passkeyHostPathForApp(installed);
    if (![NSFileManager.defaultManager isExecutableFileAtPath:passkeyHost]) {
        if (errorOut) *errorOut = [NSError errorWithDomain:kBundleID code:7 userInfo:@{ NSLocalizedDescriptionKey : @"The on-demand passkey host is missing or not executable." }];
        return NO;
    }
    for (NSURL *url in hostManifestURLs()) {
        if (!installHostManifestAtURL(url, executable, errorOut)) return NO;
    }
    for (NSURL *url in passkeyHostManifestURLs()) {
        if (!installPasskeyHostManifestAtURL(url, passkeyHost, errorOut)) return NO;
    }
    return YES;
}

static BOOL removeHostManifest(NSError **errorOut) {
    NSFileManager *fm = NSFileManager.defaultManager;
    NSMutableArray<NSURL *> *ownedURLs = [NSMutableArray array];
    for (NSURL *url in hostManifestURLs()) {
        if (![fm fileExistsAtPath:url.path]) continue;
        NSDictionary *manifest = [NSJSONSerialization JSONObjectWithData:[NSData dataWithContentsOfURL:url] ?: NSData.data options:0 error:nil];
        if (!isAppOwnedHostManifest(manifest)) {
            if (errorOut) *errorOut = [NSError errorWithDomain:kBundleID code:4 userInfo:@{ NSLocalizedDescriptionKey : @"A Passwords host manifest belongs to another app; it was left in place." }];
            return NO;
        }
        [ownedURLs addObject:url];
    }
    for (NSURL *url in passkeyHostManifestURLs()) {
        if (![fm fileExistsAtPath:url.path]) continue;
        NSDictionary *manifest = [NSJSONSerialization JSONObjectWithData:[NSData dataWithContentsOfURL:url] ?: NSData.data options:0 error:nil];
        if (!isAppOwnedPasskeyHostManifest(manifest)) {
            if (errorOut) *errorOut = [NSError errorWithDomain:kBundleID code:8 userInfo:@{ NSLocalizedDescriptionKey : @"A passkey host manifest belongs to another app; it was left in place." }];
            return NO;
        }
        [ownedURLs addObject:url];
    }
    for (NSURL *url in ownedURLs) {
        if (![fm removeItemAtURL:url error:errorOut]) return NO;
    }
    return YES;
}

static BOOL removeHelper(NSError **errorOut) {
    if (!removeHostManifest(errorOut)) return NO;

    NSURL *installed = installedAppURL();
    if (![NSFileManager.defaultManager fileExistsAtPath:installed.path]) return YES;
    NSDictionary *info = [NSDictionary dictionaryWithContentsOfURL:[installed URLByAppendingPathComponent:@"Contents/Info.plist"]];
    if (![info[@"CFBundleIdentifier"] isEqual:kBundleID]) return YES;
    return [NSFileManager.defaultManager removeItemAtURL:installed error:errorOut];
}

static NSDictionary *appleHostManifest(void) {
    NSData *data = [NSData dataWithContentsOfFile:kAppleHostManifest];
    id value = data ? [NSJSONSerialization JSONObjectWithData:data options:0 error:nil] : nil;
    if (![value isKindOfClass:NSDictionary.class]) return nil;
    return value;
}

static NSString *appleHelperPath(void) {
    NSString *path = appleHostManifest()[@"path"];
    if (![path isKindOfClass:NSString.class] || !path.isAbsolutePath) return nil;
    NSString *resolved = path.stringByResolvingSymlinksInPath;
    if (![resolved hasPrefix:@"/System/"] || ![NSFileManager.defaultManager isExecutableFileAtPath:resolved]) return nil;
    return resolved;
}

static NSDictionary *codeSigningInfo(NSString *path, OSStatus *statusOut) {
    SecStaticCodeRef code = NULL;
    CFURLRef url = (__bridge CFURLRef)[NSURL fileURLWithPath:path];
    OSStatus created = SecStaticCodeCreateWithPath(url, kSecCSDefaultFlags, &code);
    if (created != errSecSuccess || !code) {
        if (statusOut) *statusOut = created;
        return nil;
    }
    OSStatus valid = SecStaticCodeCheckValidity(code, kSecCSStrictValidate, NULL);
    CFDictionaryRef info = NULL;
    OSStatus copied = valid == errSecSuccess ? SecCodeCopySigningInformation(code, kSecCSDefaultFlags, &info) : errSecCSSignatureFailed;
    CFRelease(code);
    if (statusOut) *statusOut = valid == errSecSuccess ? copied : valid;
    if (copied != errSecSuccess || !info) return nil;
    NSDictionary *result = CFBridgingRelease(info);
    return [result isKindOfClass:NSDictionary.class] ? result : nil;
}

static BOOL hasChromiumHelper(NSURL *appURL, NSString *bundleIdentifier) {
    NSString *frameworksPath = [[appURL URLByAppendingPathComponent:@"Contents/Frameworks"] path];
    NSArray<NSString *> *frameworkNames = [NSFileManager.defaultManager contentsOfDirectoryAtPath:frameworksPath error:nil];
    for (NSString *frameworkName in frameworkNames) {
        if (![frameworkName hasSuffix:@".framework"]) continue;
        NSURL *versionsURL = [[NSURL fileURLWithPath:frameworksPath] URLByAppendingPathComponent:[frameworkName stringByAppendingPathComponent:@"Versions"]];
        NSMutableArray<NSURL *> *helperDirectories = [NSMutableArray array];
        NSURL *currentHelpers = [[versionsURL URLByAppendingPathComponent:@"Current"] URLByAppendingPathComponent:@"Helpers"];
        if ([NSFileManager.defaultManager fileExistsAtPath:currentHelpers.path]) [helperDirectories addObject:currentHelpers];
        else {
            NSArray<NSString *> *versionNames = [NSFileManager.defaultManager contentsOfDirectoryAtPath:versionsURL.path error:nil];
            for (NSString *versionName in versionNames) {
                if ([versionName isEqual:@"Current"]) continue;
                NSURL *helpers = [[versionsURL URLByAppendingPathComponent:versionName] URLByAppendingPathComponent:@"Helpers"];
                if ([NSFileManager.defaultManager fileExistsAtPath:helpers.path]) [helperDirectories addObject:helpers];
            }
        }

        for (NSURL *helpers in helperDirectories) {
            NSArray<NSString *> *helperNames = [NSFileManager.defaultManager contentsOfDirectoryAtPath:helpers.path error:nil];
            for (NSString *helperName in helperNames) {
                if (![helperName hasSuffix:@".app"] || [helperName rangeOfString:@"helper" options:NSCaseInsensitiveSearch].location == NSNotFound) continue;
                NSURL *helperURL = [helpers URLByAppendingPathComponent:helperName];
                NSDictionary *helperInfo = [NSDictionary dictionaryWithContentsOfURL:[helperURL URLByAppendingPathComponent:@"Contents/Info.plist"]];
                NSString *helperIdentifier = helperInfo[@"CFBundleIdentifier"];
                NSString *helperExecutable = helperInfo[@"CFBundleExecutable"];
                NSString *executablePath = helperExecutable.length ? [[helperURL URLByAppendingPathComponent:[@"Contents/MacOS" stringByAppendingPathComponent:helperExecutable]] path] : nil;
                NSString *helperPrefix = [[bundleIdentifier stringByAppendingString:@"."] lowercaseString];
                if ([helperIdentifier.lowercaseString hasPrefix:helperPrefix]
                    && executablePath.length
                    && [NSFileManager.defaultManager isExecutableFileAtPath:executablePath]) return YES;
            }
        }
    }
    return NO;
}

static NSDictionary *browserCandidateAtURL(NSURL *appURL) {
    NSDictionary *info = [NSDictionary dictionaryWithContentsOfURL:[appURL URLByAppendingPathComponent:@"Contents/Info.plist"]];
    NSString *bundleIdentifier = info[@"CFBundleIdentifier"];
    NSString *executableName = info[@"CFBundleExecutable"];
    if (![info[@"CFBundlePackageType"] isEqual:@"APPL"] || !bundleIdentifier.length || !executableName.length) return nil;
    if (!hasChromiumHelper(appURL, bundleIdentifier)) return nil;

    NSString *appPath = appURL.URLByResolvingSymlinksInPath.path.stringByStandardizingPath;
    NSDictionary *signature = codeSigningInfo(appPath, NULL);
    NSString *signedIdentifier = signature[(__bridge NSString *)kSecCodeInfoIdentifier];
    NSDictionary *entitlements = signature[(__bridge NSString *)kSecCodeInfoEntitlementsDict];
    id passkeyEntitlement = entitlements[kBrowserEntitlement];
    if (!signature || ![signedIdentifier isEqual:bundleIdentifier]
        || ![passkeyEntitlement respondsToSelector:@selector(boolValue)] || ![passkeyEntitlement boolValue]) return nil;

    NSString *executablePath = [[appURL URLByAppendingPathComponent:[@"Contents/MacOS" stringByAppendingPathComponent:executableName]] path];
    if (![NSFileManager.defaultManager isExecutableFileAtPath:executablePath]) return nil;
    NSString *name = info[@"CFBundleDisplayName"] ?: info[@"CFBundleName"] ?: appURL.lastPathComponent.stringByDeletingPathExtension;
    return @{
        @"name" : name,
        @"bundlePath" : appPath,
        @"bundleIdentifier" : bundleIdentifier,
        @"executablePath" : executablePath.stringByStandardizingPath,
    };
}

static NSArray<NSDictionary *> *installedBrowserCandidates(void) {
    NSFileManager *fm = NSFileManager.defaultManager;
    NSArray<NSURL *> *roots = @[
        [NSURL fileURLWithPath:@"/Applications"],
        [NSURL fileURLWithPath:homePath(@"Applications")],
        [NSURL fileURLWithPath:@"/System/Applications"],
    ];
    NSMutableDictionary<NSString *, NSDictionary *> *byPath = [NSMutableDictionary dictionary];
    NSMutableSet<NSString *> *visitedPaths = [NSMutableSet set];
    for (NSURL *root in roots) {
        NSArray<NSURL *> *contents = [fm contentsOfDirectoryAtURL:root includingPropertiesForKeys:nil options:NSDirectoryEnumerationSkipsHiddenFiles error:nil];
        for (NSURL *url in contents) {
            if (![url.pathExtension.lowercaseString isEqual:@"app"]) continue;
            NSString *resolvedPath = url.URLByResolvingSymlinksInPath.path.stringByStandardizingPath;
            if (!resolvedPath.length || [visitedPaths containsObject:resolvedPath]) continue;
            [visitedPaths addObject:resolvedPath];
            NSDictionary *candidate = browserCandidateAtURL(url);
            if (candidate) byPath[candidate[@"bundlePath"]] = candidate;
        }
    }
    NSArray<NSDictionary *> *all = byPath.allValues;
    return [all sortedArrayUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) {
        BOOL aChrome = [a[@"bundleIdentifier"] isEqual:@"com.google.Chrome"];
        BOOL bChrome = [b[@"bundleIdentifier"] isEqual:@"com.google.Chrome"];
        if (aChrome != bChrome) return aChrome ? NSOrderedAscending : NSOrderedDescending;
        return [a[@"name"] localizedCaseInsensitiveCompare:b[@"name"]];
    }];
}

static NSDictionary *preferredBrowserFromCandidates(NSArray<NSDictionary *> *candidates) {
    NSString *savedPath = [[NSUserDefaults standardUserDefaults] stringForKey:kSelectedBrowserPreference].stringByStandardizingPath;
    for (NSDictionary *candidate in candidates) {
        if (savedPath.length && [candidate[@"bundlePath"] isEqual:savedPath]) return candidate;
    }
    for (NSDictionary *candidate in candidates) {
        if ([candidate[@"bundleIdentifier"] isEqual:@"com.google.Chrome"]) return candidate;
    }
    return candidates.firstObject;
}

static NSDictionary *selectedBrowserCandidate(void) {
    NSString *savedPath = [[NSUserDefaults standardUserDefaults] stringForKey:kSelectedBrowserPreference].stringByStandardizingPath;
    if (savedPath.length) {
        NSDictionary *saved = browserCandidateAtURL([NSURL fileURLWithPath:savedPath]);
        if (saved && [saved[@"bundlePath"] isEqual:savedPath]) return saved;
    }
    NSArray<NSDictionary *> *candidates = installedBrowserCandidates();
    NSDictionary *candidate = preferredBrowserFromCandidates(candidates);
    if (candidate) [[NSUserDefaults standardUserDefaults] setObject:candidate[@"bundlePath"] forKey:kSelectedBrowserPreference];
    return candidate;
}

static pid_t parentPID(pid_t pid) {
    struct proc_bsdinfo info;
    int bytes = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, sizeof info);
    return bytes == sizeof info ? (pid_t)info.pbi_ppid : 0;
}

static NSString *processPath(pid_t pid) {
    char path[PROC_PIDPATHINFO_MAXSIZE] = { 0 };
    if (proc_pidpath(pid, path, sizeof path) <= 0) return nil;
    return [NSString stringWithUTF8String:path];
}

static int listenAt(NSString *path) {
    struct sockaddr_un address = { 0 };
    if (strlcpy(address.sun_path, path.fileSystemRepresentation, sizeof address.sun_path) >= sizeof address.sun_path) return -1;
    address.sun_len = sizeof address;
    address.sun_family = AF_UNIX;
    unlink(address.sun_path);
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    if (bind(fd, (struct sockaddr *)&address, sizeof address) != 0 || chmod(path.fileSystemRepresentation, 0600) != 0 || listen(fd, 4) != 0) {
        close(fd);
        unlink(address.sun_path);
        return -1;
    }
    return fd;
}

static int acceptBrowserSubprocess(int listener, pid_t browser, NSString *selfPath) {
    NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:kStartupTimeout];
    NSString *resolvedSelf = selfPath.stringByResolvingSymlinksInPath;
    while (deadline.timeIntervalSinceNow > 0) {
        struct pollfd ready = { .fd = listener, .events = POLLIN };
        int status = poll(&ready, 1, 100);
        if (status < 0 && errno != EINTR) return -1;
        if (status <= 0) {
            if (waitpid(browser, NULL, WNOHANG) == browser) return -1;
            continue;
        }
        int client = accept(listener, NULL, NULL);
        if (client < 0) continue;
        pid_t peer = 0;
        socklen_t peerLength = sizeof peer;
        BOOL trusted = getsockopt(client, SOL_LOCAL, LOCAL_PEERPID, &peer, &peerLength) == 0
            && parentPID(peer) == browser
            && [processPath(peer).stringByResolvingSymlinksInPath isEqual:resolvedSelf];
        if (trusted) return client;
        close(client);
    }
    return -1;
}

static BOOL sendHandoff(int client, NSArray<NSString *> *arguments, NSArray<NSString *> *environment) {
    NSDictionary *handoff = @{ @"arguments" : arguments, @"environment" : environment };
    NSData *payload = [NSJSONSerialization dataWithJSONObject:handoff options:0 error:nil];
    if (!payload || payload.length > kMaxHandoffBytes) return NO;
    uint32_t length = (uint32_t)payload.length;
    int fds[3] = { STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO };
    char control[CMSG_SPACE(sizeof fds)] = { 0 };
    struct iovec iov = { .iov_base = &length, .iov_len = sizeof length };
    struct msghdr message = { .msg_iov = &iov, .msg_iovlen = 1, .msg_control = control, .msg_controllen = sizeof control };
    struct cmsghdr *header = CMSG_FIRSTHDR(&message);
    if (!header) return NO;
    header->cmsg_len = CMSG_LEN(sizeof fds);
    header->cmsg_level = SOL_SOCKET;
    header->cmsg_type = SCM_RIGHTS;
    memcpy(CMSG_DATA(header), fds, sizeof fds);
    if (sendmsg(client, &message, 0) != sizeof length) return NO;
    for (NSUInteger sent = 0; sent < payload.length;) {
        ssize_t n = write(client, (const char *)payload.bytes + sent, payload.length - sent);
        if (n <= 0) return NO;
        sent += (NSUInteger)n;
    }
    return YES;
}

static BOOL becameAppleHelper(int client, pid_t peer, NSString *helper) {
    fcntl(client, F_SETFD, FD_CLOEXEC);
    struct timeval timeout = { .tv_sec = 5 };
    setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout);
    char byte;
    while (read(client, &byte, 1) > 0) {}
    NSString *resolvedHelper = helper.stringByResolvingSymlinksInPath;
    for (int i = 0; i < 50; i++, usleep(10000)) {
        if ([processPath(peer).stringByResolvingSymlinksInPath isEqual:resolvedHelper]) return YES;
    }
    return NO;
}

static NSString *makeLaunchDirectory(void) {
    char template[] = "/tmp/open-passwords.XXXXXX";
    char *path = mkdtemp(template);
    if (!path) return nil;
    chmod(path, 0700);
    return [NSString stringWithUTF8String:path];
}

static NSMutableArray<NSString *> *currentEnvironment(void) {
    NSMutableArray *values = [NSMutableArray array];
    for (char **entry = environ; entry && *entry; entry++) {
        NSString *value = [NSString stringWithUTF8String:*entry];
        if (value) [values addObject:value];
    }
    return values;
}

static int spawnBrowser(NSDictionary *browser, NSString *socket, NSString *directory, NSString *helperExecutable, pid_t *pidOut) {
    NSString *browserExecutable = browser[@"executablePath"];
    if (!browserExecutable.length) return EINVAL;
    NSString *userData = [@"--user-data-dir=" stringByAppendingString:[directory stringByAppendingPathComponent:@"profile"]];
    NSString *subprocess = [@"--browser-subprocess-path=" stringByAppendingString:helperExecutable];
    NSArray<NSString *> *args = @[ browserExecutable, userData, subprocess, @"--headless=new", @"--no-first-run", @"--no-default-browser-check", @"--use-mock-keychain", @"--mute-audio" ];
    NSMutableArray<NSString *> *environment = currentEnvironment();
    for (NSInteger i = (NSInteger)environment.count - 1; i >= 0; i--) {
        NSString *value = environment[(NSUInteger)i];
        if ([value hasPrefix:[kHandoffVariable stringByAppendingString:@"="]] || [value hasPrefix:@"CFFIXED_USER_HOME="])
            [environment removeObjectAtIndex:(NSUInteger)i];
    }
    [environment addObject:[NSString stringWithFormat:@"%@=%@", kHandoffVariable, socket]];
    [environment addObject:[NSString stringWithFormat:@"CFFIXED_USER_HOME=%@", directory]];
    NSMutableData *argvData = [NSMutableData dataWithLength:(args.count + 1) * sizeof(char *)];
    char **argv = argvData.mutableBytes;
    for (NSUInteger i = 0; i < args.count; i++) argv[i] = (char *)args[i].fileSystemRepresentation;
    argv[args.count] = NULL;
    NSMutableData *envData = [NSMutableData dataWithLength:(environment.count + 1) * sizeof(char *)];
    char **envp = envData.mutableBytes;
    for (NSUInteger i = 0; i < environment.count; i++) envp[i] = (char *)environment[i].UTF8String;
    envp[environment.count] = NULL;

    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_addopen(&actions, STDIN_FILENO, "/dev/null", O_RDONLY, 0);
    posix_spawn_file_actions_addopen(&actions, STDOUT_FILENO, "/dev/null", O_WRONLY, 0);
    posix_spawn_file_actions_addopen(&actions, STDERR_FILENO, "/dev/null", O_WRONLY, 0);
    posix_spawnattr_t attributes;
    posix_spawnattr_init(&attributes);
    posix_spawnattr_setflags(&attributes, POSIX_SPAWN_CLOEXEC_DEFAULT | POSIX_SPAWN_SETPGROUP);
    posix_spawnattr_setpgroup(&attributes, 0);
    pid_t pid = 0;
    int result = posix_spawn(&pid, browserExecutable.fileSystemRepresentation, &actions, &attributes, argv, envp);
    posix_spawn_file_actions_destroy(&actions);
    posix_spawnattr_destroy(&attributes);
    if (result == 0) *pidOut = pid;
    return result;
}

static pid_t startAppleHelper(NSDictionary *browser, NSArray<NSString *> *arguments, NSString *helper, NSString *helperExecutable) {
    NSString *directory = makeLaunchDirectory();
    if (!directory) return 0;
    gLaunchDirectory = directory;
    NSString *socket = [directory stringByAppendingPathComponent:@"handoff.sock"];
    int listener = listenAt(socket);
    if (listener < 0) {
        [[NSFileManager defaultManager] removeItemAtPath:directory error:nil];
        return 0;
    }
    pid_t browserPID = 0;
    int spawned = spawnBrowser(browser, socket, directory, helperExecutable, &browserPID);
    int client = spawned == 0 ? acceptBrowserSubprocess(listener, browserPID, helperExecutable) : -1;
    close(listener);
    unlink(socket.fileSystemRepresentation);
    pid_t helperPID = 0;
    if (client >= 0) {
        BOOL handed = sendHandoff(client, arguments, currentEnvironment());
        pid_t peer = 0;
        socklen_t peerLength = sizeof peer;
        if (handed && getsockopt(client, SOL_LOCAL, LOCAL_PEERPID, &peer, &peerLength) == 0 && becameAppleHelper(client, peer, helper)) helperPID = peer;
        close(client);
    }
    if (browserPID > 0) {
        // Chrome also starts a crash reporter as a child. Reap the whole isolated
        // process group so a short broker launch does not leave that child behind.
        kill(-browserPID, SIGTERM);
        usleep(100000);
        kill(-browserPID, SIGKILL);
        while (waitpid(browserPID, NULL, 0) < 0 && errno == EINTR) {}
    }
    if (!helperPID) [[NSFileManager defaultManager] removeItemAtPath:directory error:nil];
    return helperPID;
}

static int runNativeHost(int argc, const char *argv[]) {
    NSString *origin = argc >= 2 ? [NSString stringWithUTF8String:argv[1]] : nil;
    if (!isAllowedExtensionOrigin(origin)) {
        logError(@"Open Passwords Helper: rejected an unexpected extension origin.");
        return 1;
    }
    NSDictionary *browser = selectedBrowserCandidate();
    if (!browser) {
        logError(@"Open Passwords Helper: no signed Chromium browser with Apple's public-key credential entitlement was found.");
        return 1;
    }
    NSString *appleHelper = appleHelperPath();
    if (!appleHelper) {
        logError(@"Open Passwords Helper: Apple's system Passwords helper was not found.");
        return 1;
    }
    NSString *helperExecutable = currentExecutablePath();
    if (!helperExecutable.length) {
        logError(@"Open Passwords Helper: could not resolve its executable path.");
        return 1;
    }
    NSMutableArray<NSString *> *arguments = [NSMutableArray array];
    for (int i = 1; i < argc; i++) {
        NSString *value = [NSString stringWithUTF8String:argv[i]];
        if (value) [arguments addObject:value];
    }
    pid_t helperPID = startAppleHelper(browser, arguments, appleHelper, helperExecutable);
    if (!helperPID) {
        logError([NSString stringWithFormat:@"Open Passwords Helper: %@ did not start Apple's Passwords helper.", browser[@"name"] ?: @"The selected browser"]);
        return 1;
    }

    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    while (kill(helperPID, 0) == 0) usleep(100000);
    if (gLaunchDirectory) [[NSFileManager defaultManager] removeItemAtPath:gLaunchDirectory error:nil];
    return 0;
}

static BOOL readExact(int fd, void *buffer, size_t size) {
    size_t received = 0;
    while (received < size) {
        ssize_t n = read(fd, (char *)buffer + received, size - received);
        if (n <= 0) return NO;
        received += (size_t)n;
    }
    return YES;
}

static BOOL writeExact(int fd, const void *buffer, size_t size) {
    size_t written = 0;
    while (written < size) {
        ssize_t n = write(fd, (const char *)buffer + written, size - written);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return NO;
        written += (size_t)n;
    }
    return YES;
}

static BOOL writeNativeMessage(int fd, NSDictionary *message) {
    NSData *payload = [NSJSONSerialization dataWithJSONObject:message options:0 error:nil];
    if (!payload || payload.length > kMaxHandoffBytes) return NO;
    uint32_t length = CFSwapInt32HostToLittle((uint32_t)payload.length);
    struct sigaction ignore = { 0 };
    struct sigaction previous = { 0 };
    ignore.sa_handler = SIG_IGN;
    sigemptyset(&ignore.sa_mask);
    sigaction(SIGPIPE, &ignore, &previous);
    BOOL succeeded = writeExact(fd, &length, sizeof length) && writeExact(fd, payload.bytes, payload.length);
    sigaction(SIGPIPE, &previous, NULL);
    return succeeded;
}

static BOOL readExactWithTimeout(int fd, void *buffer, size_t size, NSTimeInterval timeout) {
    size_t received = 0;
    NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:timeout];
    while (received < size) {
        NSTimeInterval remaining = deadline.timeIntervalSinceNow;
        if (remaining <= 0) return NO;
        struct pollfd ready = { .fd = fd, .events = POLLIN | POLLHUP };
        int result = poll(&ready, 1, MAX(1, (int)(remaining * 1000.0)));
        if (result < 0 && errno == EINTR) continue;
        if (result <= 0) return NO;
        ssize_t n = read(fd, (char *)buffer + received, size - received);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return NO;
        received += (size_t)n;
    }
    return YES;
}

static NSDictionary *readNativeMessageWithTimeout(int fd, NSString **errorOut) {
    uint32_t encodedLength = 0;
    if (!readExactWithTimeout(fd, &encodedLength, sizeof encodedLength, kProbeTimeout)) {
        if (errorOut) *errorOut = @"Apple Passwords did not answer before the probe timed out.";
        return nil;
    }
    uint32_t length = CFSwapInt32LittleToHost(encodedLength);
    if (length == 0 || length > kMaxHandoffBytes) {
        if (errorOut) *errorOut = @"Apple Passwords returned an invalid native-messaging frame.";
        return nil;
    }
    NSMutableData *payload = [NSMutableData dataWithLength:length];
    if (!readExactWithTimeout(fd, payload.mutableBytes, length, kProbeTimeout)) {
        if (errorOut) *errorOut = @"Apple Passwords returned an incomplete capabilities response.";
        return nil;
    }
    id value = [NSJSONSerialization JSONObjectWithData:payload options:0 error:nil];
    if (![value isKindOfClass:NSDictionary.class]) {
        if (errorOut) *errorOut = @"Apple Passwords returned an unreadable capabilities response.";
        return nil;
    }
    return value;
}

static NSDictionary *readNativeMessageBlocking(int fd) {
    uint32_t encodedLength = 0;
    if (!readExact(fd, &encodedLength, sizeof encodedLength)) return nil;
    uint32_t length = CFSwapInt32LittleToHost(encodedLength);
    if (length == 0 || length > kMaxHandoffBytes) return nil;
    NSMutableData *payload = [NSMutableData dataWithLength:length];
    if (!readExact(fd, payload.mutableBytes, length)) return nil;
    id value = [NSJSONSerialization JSONObjectWithData:payload options:0 error:nil];
    return [value isKindOfClass:NSDictionary.class] ? value : nil;
}

static int runPasskeyNativeHost(int argc, const char *argv[]) {
    NSString *origin = argc >= 3 ? [NSString stringWithUTF8String:argv[2]] : nil;
    if (argc < 3 || strcmp(argv[1], "--passkey-host") != 0 || !isAllowedExtensionOrigin(origin)) {
        logError(@"Open Passwords Helper: rejected an unexpected passkey-host origin.");
        return 1;
    }

    NSDictionary *request = readNativeMessageBlocking(STDIN_FILENO);
    NSString *requestID = [request[@"requestId"] isKindOfClass:NSString.class] ? request[@"requestId"] : @"";
    NSString *kind = [request[@"kind"] isKindOfClass:NSString.class] ? request[@"kind"] : @"";
    NSString *pageOrigin = [request[@"origin"] isKindOfClass:NSString.class] ? request[@"origin"] : @"";
    NSDictionary *options = [request[@"options"] isKindOfClass:NSDictionary.class] ? request[@"options"] : nil;
    if (![request[@"type"] isEqual:@"request"] || !requestID.length || requestID.length > 128 || !options) {
        writeNativeMessage(STDOUT_FILENO, @{
            @"requestId" : requestID,
            @"error" : @{ @"name" : @"TypeError", @"message" : @"The passkey request was malformed." },
        });
        return 1;
    }

    volatile int *cancelled = calloc(1, sizeof(*cancelled));
    if (!cancelled) {
        writeNativeMessage(STDOUT_FILENO, @{
            @"requestId" : requestID,
            @"error" : @{ @"name" : @"UnknownError", @"message" : @"Could not allocate passkey cancellation state." },
        });
        return 1;
    }
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        NSDictionary *cancel = readNativeMessageBlocking(STDIN_FILENO);
        if (!cancel || ([cancel[@"type"] isEqual:@"cancel"] && [cancel[@"requestId"] isEqual:requestID])) {
            __atomic_store_n(cancelled, 1, __ATOMIC_RELEASE);
        } else {
            // Only one request and one matching cancellation are valid on this host.
            __atomic_store_n(cancelled, 1, __ATOMIC_RELEASE);
        }
    });

    NSDictionary *browser = selectedBrowserCandidate();
    NSDictionary *result = nil;
    if (!browser) {
        result = @{ @"error" : @{ @"name" : @"NotSupportedError", @"message" : @"No signed Chromium browser with Apple's public-key credential entitlement is available." } };
    } else {
        result = OPRunPasskeyRequest(browser, pageOrigin, kind, options, cancelled);
    }
    NSMutableDictionary *reply = [result isKindOfClass:NSDictionary.class] ? [result mutableCopy] : [@{ @"error" : @{ @"name" : @"UnknownError", @"message" : @"The passkey helper returned no result." } } mutableCopy];
    reply[@"requestId"] = requestID;
    BOOL sent = writeNativeMessage(STDOUT_FILENO, reply);
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    return sent ? 0 : 1;
}

static void stopProbeProcess(pid_t pid, NSTimeInterval grace) {
    if (pid <= 0) return;
    NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:grace];
    int status = 0;
    while (deadline.timeIntervalSinceNow > 0) {
        pid_t waited = waitpid(pid, &status, WNOHANG);
        if (waited == pid || (waited < 0 && errno == ECHILD)) return;
        usleep(50000);
    }
    kill(-pid, SIGTERM);
    usleep(200000);
    kill(-pid, SIGKILL);
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
}

static NSDictionary *probeSelectedBrowser(NSString **errorOut) {
    int inputPipe[2] = { -1, -1 };
    int outputPipe[2] = { -1, -1 };
    if (pipe(inputPipe) != 0 || pipe(outputPipe) != 0) {
        if (inputPipe[0] >= 0) close(inputPipe[0]);
        if (inputPipe[1] >= 0) close(inputPipe[1]);
        if (outputPipe[0] >= 0) close(outputPipe[0]);
        if (outputPipe[1] >= 0) close(outputPipe[1]);
        if (errorOut) *errorOut = @"Could not create the temporary native-messaging pipes.";
        return nil;
    }

    NSString *executable = currentExecutablePath();
    if (!executable.length) {
        close(inputPipe[0]); close(inputPipe[1]); close(outputPipe[0]); close(outputPipe[1]);
        if (errorOut) *errorOut = @"Could not locate the helper executable for the probe.";
        return nil;
    }

    posix_spawn_file_actions_t actions;
    posix_spawnattr_t attributes;
    posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_adddup2(&actions, inputPipe[0], STDIN_FILENO);
    posix_spawn_file_actions_adddup2(&actions, outputPipe[1], STDOUT_FILENO);
    posix_spawn_file_actions_addopen(&actions, STDERR_FILENO, "/dev/null", O_WRONLY, 0);
    if (inputPipe[0] != STDIN_FILENO) posix_spawn_file_actions_addclose(&actions, inputPipe[0]);
    if (inputPipe[1] != STDIN_FILENO && inputPipe[1] != STDOUT_FILENO) posix_spawn_file_actions_addclose(&actions, inputPipe[1]);
    if (outputPipe[0] != STDIN_FILENO && outputPipe[0] != STDOUT_FILENO) posix_spawn_file_actions_addclose(&actions, outputPipe[0]);
    if (outputPipe[1] != STDOUT_FILENO) posix_spawn_file_actions_addclose(&actions, outputPipe[1]);
    posix_spawnattr_init(&attributes);
    posix_spawnattr_setflags(&attributes, POSIX_SPAWN_CLOEXEC_DEFAULT | POSIX_SPAWN_SETPGROUP);
    posix_spawnattr_setpgroup(&attributes, 0);

    char *arguments[] = { (char *)executable.fileSystemRepresentation, (char *)kExtensionOrigin.UTF8String, NULL };
    pid_t child = 0;
    int spawned = posix_spawn(&child, executable.fileSystemRepresentation, &actions, &attributes, arguments, environ);
    posix_spawn_file_actions_destroy(&actions);
    posix_spawnattr_destroy(&attributes);
    close(inputPipe[0]);
    close(outputPipe[1]);
    if (spawned != 0) {
        close(inputPipe[1]); close(outputPipe[0]);
        if (errorOut) *errorOut = [NSString stringWithFormat:@"Could not start the probe process (error %d).", spawned];
        return nil;
    }

    NSDictionary *response = nil;
    NSString *probeError = nil;
    BOOL requestSent = writeNativeMessage(inputPipe[1], @{ @"cmd" : @14 });
    if (!requestSent) probeError = @"Could not send the capabilities request.";
    else response = readNativeMessageWithTimeout(outputPipe[0], &probeError);

    BOOL compatible = NO;
    NSDictionary *capabilities = nil;
    if ([response[@"cmd"] respondsToSelector:@selector(integerValue)] && [response[@"cmd"] integerValue] == 14) {
        id rawCapabilities = response[@"capabilities"];
        capabilities = [rawCapabilities isKindOfClass:NSDictionary.class] ? rawCapabilities : @{};
        id version = capabilities[@"secretSessionVersion"];
        compatible = ![version respondsToSelector:@selector(integerValue)] || [version integerValue] == 1;
        if (!compatible) probeError = @"Apple Passwords returned an unsupported session version.";
    } else if (response) {
        probeError = @"Apple Passwords did not return the expected capabilities command.";
    }

    if (compatible) writeNativeMessage(inputPipe[1], @{ @"cmd" : @0 });
    close(inputPipe[1]);
    stopProbeProcess(child, compatible ? 3.0 : 1.0);
    close(outputPipe[0]);

    if (!compatible) {
        if (errorOut) *errorOut = probeError ?: @"The selected browser did not connect to Apple Passwords.";
        return nil;
    }
    return capabilities;
}

static NSDictionary *browserProbeResultForPath(NSString *path) {
    NSDictionary *results = [[NSUserDefaults standardUserDefaults] dictionaryForKey:kBrowserProbeResultsPreference];
    NSDictionary *result = results[path];
    if (![result isKindOfClass:NSDictionary.class]) return nil;
    NSTimeInterval checkedAt = [result[@"checkedAt"] doubleValue];
    if (checkedAt <= 0 || [NSDate.date timeIntervalSince1970] - checkedAt > 24 * 60 * 60) return nil;
    return result;
}

static void saveBrowserProbeResult(NSString *path, BOOL connected, NSString *detail) {
    NSUserDefaults *defaults = NSUserDefaults.standardUserDefaults;
    NSMutableDictionary *results = [[defaults dictionaryForKey:kBrowserProbeResultsPreference] mutableCopy] ?: [NSMutableDictionary dictionary];
    results[path] = @{
        @"connected" : @(connected),
        @"checkedAt" : @([NSDate.date timeIntervalSince1970]),
        @"detail" : detail ?: @"",
    };
    [defaults setObject:results forKey:kBrowserProbeResultsPreference];
    [defaults synchronize];
}

static int connectHandoffSocket(NSString *path) {
    struct sockaddr_un address = { 0 };
    if (strlcpy(address.sun_path, path.fileSystemRepresentation, sizeof address.sun_path) >= sizeof address.sun_path) return -1;
    address.sun_len = sizeof address;
    address.sun_family = AF_UNIX;
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    if (connect(fd, (struct sockaddr *)&address, sizeof address) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static char **cStringArray(NSArray<NSString *> *values) {
    char **result = calloc(values.count + 1, sizeof(char *));
    if (!result) return NULL;
    for (NSUInteger i = 0; i < values.count; i++) result[i] = strdup(values[i].UTF8String);
    return result;
}

static void freeCStringArray(char **values) {
    if (!values) return;
    for (NSUInteger i = 0; values[i]; i++) free(values[i]);
    free(values);
}

static int runHandoff(int argc, const char *argv[]) {
    const char *socketValue = getenv(kHandoffVariable.UTF8String);
    if (!socketValue || argc < 2 || strncmp(argv[1], "--type=", 7) != 0) return 1;
    // Preserve the system Passwords helper when the temporary browser broker's
    // process group is reaped after handoff.
    if (setpgid(0, 0) != 0) return 1;
    int socket = connectHandoffSocket(@(socketValue));
    if (socket < 0) return 1;

    uint32_t length = 0;
    int fds[3] = { -1, -1, -1 };
    char control[CMSG_SPACE(sizeof fds)] = { 0 };
    struct iovec iov = { .iov_base = &length, .iov_len = sizeof length };
    struct msghdr message = { .msg_iov = &iov, .msg_iovlen = 1, .msg_control = control, .msg_controllen = sizeof control };
    ssize_t count = recvmsg(socket, &message, 0);
    struct cmsghdr *header = CMSG_FIRSTHDR(&message);
    if (count <= 0 || !header || header->cmsg_level != SOL_SOCKET || header->cmsg_type != SCM_RIGHTS || header->cmsg_len < CMSG_LEN(sizeof fds)) {
        close(socket);
        return 1;
    }
    if ((size_t)count < sizeof length && !readExact(socket, (char *)&length + count, sizeof length - (size_t)count)) {
        close(socket);
        return 1;
    }
    memcpy(fds, CMSG_DATA(header), sizeof fds);
    if (length > kMaxHandoffBytes) {
        close(socket);
        for (int i = 0; i < 3; i++) if (fds[i] >= 0) close(fds[i]);
        return 1;
    }
    NSMutableData *payload = [NSMutableData dataWithLength:length];
    if (!readExact(socket, payload.mutableBytes, length)) {
        close(socket);
        for (int i = 0; i < 3; i++) if (fds[i] >= 0) close(fds[i]);
        return 1;
    }
    close(socket);

    NSDictionary *handoff = [NSJSONSerialization JSONObjectWithData:payload options:0 error:nil];
    NSArray *arguments = [handoff[@"arguments"] isKindOfClass:NSArray.class] ? handoff[@"arguments"] : nil;
    NSArray *environment = [handoff[@"environment"] isKindOfClass:NSArray.class] ? handoff[@"environment"] : nil;
    NSString *handoffOrigin = [arguments.firstObject isKindOfClass:NSString.class] ? arguments.firstObject : nil;
    if (!isAllowedExtensionOrigin(handoffOrigin) || !environment || fds[0] < 0 || fds[1] < 0 || fds[2] < 0) {
        for (int i = 0; i < 3; i++) if (fds[i] >= 0) close(fds[i]);
        return 1;
    }
    for (int i = 0; i < 3; i++) {
        if (dup2(fds[i], i) < 0) {
            for (int j = 0; j < 3; j++) if (fds[j] >= 0) close(fds[j]);
            return 1;
        }
        close(fds[i]);
    }

    NSString *helper = appleHelperPath();
    if (!helper) return 1;
    NSMutableArray<NSString *> *execArguments = [NSMutableArray arrayWithObject:helper];
    [execArguments addObjectsFromArray:arguments];
    char **execArgv = cStringArray(execArguments);
    char **execEnv = cStringArray(environment);
    if (!execArgv || !execEnv) return 1;
    execve(helper.fileSystemRepresentation, execArgv, execEnv);
    freeCStringArray(execArgv);
    freeCStringArray(execEnv);
    return 1;
}

static void setStatusLabel(NSTextField *label, NSString *text, BOOL error) {
    label.stringValue = text;
    label.textColor = error ? NSColor.systemRedColor : NSColor.secondaryLabelColor;
}

@interface OpenPasswordsAppDelegate : NSObject <NSApplicationDelegate, NSWindowDelegate>
@property(nonatomic, strong) NSWindow *window;
@property(nonatomic, strong) NSTextField *status;
@property(nonatomic, strong) NSPopUpButton *browserPicker;
@property(nonatomic, strong) NSButton *toggleInstallButton;
@property(nonatomic, strong) NSButton *checkBrowserButton;
@property(nonatomic, strong) NSPopUpButton *visibilityPicker;
@property(nonatomic, strong) NSStatusItem *statusItem;
@property(nonatomic, copy) NSArray<NSDictionary *> *browserCandidates;
@property(nonatomic) BOOL checkingBrowser;
@property(nonatomic) BOOL loadingBrowserCandidates;
- (void)applyAppVisibility;
- (void)updateStatusItem:(BOOL)enabled;
- (void)installMainMenu;
- (void)closeWindow:(id)sender;
- (void)showWindow:(id)sender;
@end

@implementation OpenPasswordsAppDelegate
- (BOOL)applicationShouldTerminateAfterLastWindowClosed:(NSApplication *)sender {
    return NO;
}

- (BOOL)applicationShouldHandleReopen:(NSApplication *)sender hasVisibleWindows:(BOOL)flag {
    if (!flag) [self showWindow:nil];
    return YES;
}

- (void)installMainMenu {
    NSMenu *mainMenu = [[NSMenu alloc] initWithTitle:@""];

    NSMenuItem *appMenuItem = [[NSMenuItem alloc] initWithTitle:@"Open Passwords Helper" action:nil keyEquivalent:@""];
    NSMenu *appMenu = [[NSMenu alloc] initWithTitle:@"Open Passwords Helper"];
    NSMenuItem *quitItem = [[NSMenuItem alloc] initWithTitle:@"Quit Open Passwords Helper" action:@selector(terminate:) keyEquivalent:@"q"];
    quitItem.target = NSApp;
    quitItem.keyEquivalentModifierMask = NSEventModifierFlagCommand;
    [appMenu addItem:quitItem];
    appMenuItem.submenu = appMenu;
    [mainMenu addItem:appMenuItem];

    NSMenuItem *windowMenuItem = [[NSMenuItem alloc] initWithTitle:@"Window" action:nil keyEquivalent:@""];
    NSMenu *windowMenu = [[NSMenu alloc] initWithTitle:@"Window"];
    NSMenuItem *closeItem = [[NSMenuItem alloc] initWithTitle:@"Close Window" action:@selector(closeWindow:) keyEquivalent:@"w"];
    closeItem.target = self;
    closeItem.keyEquivalentModifierMask = NSEventModifierFlagCommand;
    [windowMenu addItem:closeItem];
    windowMenuItem.submenu = windowMenu;
    [mainMenu addItem:windowMenuItem];

    [NSApp setMainMenu:mainMenu];
    [NSApp setWindowsMenu:windowMenu];
}

- (void)closeWindow:(id)sender {
    [self.window performClose:sender];
}

- (BOOL)windowShouldClose:(NSWindow *)sender {
    if (appVisibilityMode() == OPAppVisibilityMenuBarOnly) {
        [sender orderOut:nil];
        return NO;
    }
    return YES;
}

- (void)updateStatusItem:(BOOL)enabled {
    if (!enabled) {
        if (self.statusItem) {
            [NSStatusBar.systemStatusBar removeStatusItem:self.statusItem];
            self.statusItem = nil;
        }
        return;
    }
    if (self.statusItem) return;

    self.statusItem = [NSStatusBar.systemStatusBar statusItemWithLength:NSVariableStatusItemLength];
    NSStatusBarButton *button = self.statusItem.button;
    NSImage *symbol = [NSImage imageWithSystemSymbolName:@"key.horizontal.fill" accessibilityDescription:@"Open Passwords"];
    if (symbol) {
        symbol.template = YES;
        button.image = symbol;
    }
    button.toolTip = @"Open Passwords Helper";
    button.accessibilityLabel = @"Open Passwords Helper";

    NSMenu *menu = [[NSMenu alloc] initWithTitle:@"Open Passwords"];
    NSMenuItem *openItem = [[NSMenuItem alloc] initWithTitle:@"Open Passwords Helper…" action:@selector(showWindow:) keyEquivalent:@""];
    openItem.target = self;
    [menu addItem:openItem];
    [menu addItem:NSMenuItem.separatorItem];
    NSMenuItem *quitItem = [[NSMenuItem alloc] initWithTitle:@"Quit Open Passwords Helper" action:@selector(terminate:) keyEquivalent:@""];
    quitItem.target = NSApp;
    [menu addItem:quitItem];
    self.statusItem.menu = menu;
}

- (void)applyAppVisibility {
    OPAppVisibilityMode mode = appVisibilityMode();
    BOOL showDockIcon = mode != OPAppVisibilityMenuBarOnly;
    NSApplicationActivationPolicy policy = showDockIcon ? NSApplicationActivationPolicyRegular : NSApplicationActivationPolicyAccessory;
    if (NSApp.activationPolicy != policy) [NSApp setActivationPolicy:policy];
    [self updateStatusItem:appShowsMenuBarIcon()];
}

- (void)showWindow:(id)sender {
    [NSApp activateIgnoringOtherApps:YES];
    [self.window makeKeyAndOrderFront:sender];
}

- (void)applicationDidFinishLaunching:(NSNotification *)notification {
    [self installMainMenu];
    [self applyAppVisibility];

    NSRect frame = NSMakeRect(0, 0, 500, 350);
    self.window = [[NSWindow alloc] initWithContentRect:frame styleMask:(NSWindowStyleMaskTitled | NSWindowStyleMaskClosable) backing:NSBackingStoreBuffered defer:NO];
    self.window.releasedWhenClosed = NO;
    self.window.delegate = self;
    self.window.title = @"Open Passwords Helper";
    [self.window center];

    NSView *content = self.window.contentView;
    NSTextField *title = [NSTextField labelWithString:@"Connect this extension to Apple Passwords"];
    title.font = [NSFont boldSystemFontOfSize:17];
    title.frame = NSMakeRect(24, 296, 452, 24);
    [content addSubview:title];

    NSTextField *detail = [NSTextField wrappingLabelWithString:@"Choose a signed Chromium broker for Passwords and optional on-demand passkey requests. The extension opens this browser only when a site explicitly asks for a passkey. Check reads Passwords capabilities only; it never requests a PIN or credential."];
    detail.frame = NSMakeRect(24, 246, 452, 42);
    [content addSubview:detail];

    NSTextField *browserLabel = [NSTextField labelWithString:@"Browser"];
    browserLabel.frame = NSMakeRect(24, 207, 82, 24);
    [content addSubview:browserLabel];

    self.browserPicker = [[NSPopUpButton alloc] initWithFrame:NSMakeRect(108, 203, 368, 30) pullsDown:NO];
    self.browserPicker.target = self;
    self.browserPicker.action = @selector(browserChanged:);
    [content addSubview:self.browserPicker];

    NSTextField *visibilityLabel = [NSTextField labelWithString:@"Show in"];
    visibilityLabel.frame = NSMakeRect(24, 163, 82, 24);
    [content addSubview:visibilityLabel];

    self.visibilityPicker = [[NSPopUpButton alloc] initWithFrame:NSMakeRect(108, 159, 368, 30) pullsDown:NO];
    [self.visibilityPicker addItemsWithTitles:@[@"Dock only", @"Menu bar only", @"Dock and menu bar"]];
    self.visibilityPicker.target = self;
    self.visibilityPicker.action = @selector(visibilityChanged:);
    [self.visibilityPicker selectItemAtIndex:appVisibilityMode()];
    [content addSubview:self.visibilityPicker];

    self.status = [NSTextField wrappingLabelWithString:@""];
    self.status.frame = NSMakeRect(24, 88, 452, 50);
    [content addSubview:self.status];

    self.toggleInstallButton = [NSButton buttonWithTitle:@"Install helper" target:self action:@selector(toggleInstallation:)];
    self.toggleInstallButton.bezelStyle = NSBezelStyleRounded;
    self.toggleInstallButton.frame = NSMakeRect(24, 25, 190, 34);
    [content addSubview:self.toggleInstallButton];

    self.checkBrowserButton = [NSButton buttonWithTitle:@"Check selected browser" target:self action:@selector(checkSelectedBrowser:)];
    self.checkBrowserButton.bezelStyle = NSBezelStyleRounded;
    self.checkBrowserButton.frame = NSMakeRect(230, 25, 246, 34);
    [content addSubview:self.checkBrowserButton];

    NSArray *cachedCandidates = [NSUserDefaults.standardUserDefaults arrayForKey:kBrowserCandidatesPreference];
    self.browserCandidates = [cachedCandidates isKindOfClass:NSArray.class] ? cachedCandidates : @[];
    self.loadingBrowserCandidates = YES;
    [self refreshBrowserPicker];
    [self refreshStatus];
    [self.window makeKeyAndOrderFront:nil];
    [NSApp activateIgnoringOtherApps:YES];

    // Browser bundle signature checks can take several seconds. Show the helper
    // window immediately and refresh the cached list off the main thread.
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSArray<NSDictionary *> *candidates = installedBrowserCandidates();
        dispatch_async(dispatch_get_main_queue(), ^{
            self.browserCandidates = candidates;
            self.loadingBrowserCandidates = NO;
            [NSUserDefaults.standardUserDefaults setObject:candidates forKey:kBrowserCandidatesPreference];
            [self refreshBrowserPicker];
            [self refreshStatus];
        });
    });
}

- (void)visibilityChanged:(id)sender {
    NSInteger selected = self.visibilityPicker.indexOfSelectedItem;
    if (selected < OPAppVisibilityDockOnly || selected > OPAppVisibilityDockAndMenuBar) return;
    [NSUserDefaults.standardUserDefaults setInteger:selected forKey:kAppVisibilityPreference];
    [NSUserDefaults.standardUserDefaults synchronize];
    [self applyAppVisibility];
}

- (void)refreshStatus {
    if (self.loadingBrowserCandidates) {
        BOOL installed = isAnyAppOwnedHostManifest();
        self.toggleInstallButton.title = installed ? @"Remove helper" : @"Install helper";
        self.browserPicker.enabled = NO;
        self.toggleInstallButton.enabled = NO;
        self.checkBrowserButton.enabled = NO;
        NSString *message = self.browserCandidates.count ? @"Refreshing compatible browsers…" : @"Finding compatible browsers…";
        setStatusLabel(self.status, message, NO);
        return;
    }
    BOOL installed = isAnyAppOwnedHostManifest();
    self.toggleInstallButton.title = installed ? @"Remove helper" : @"Install helper";
    NSDictionary *browser = preferredBrowserFromCandidates(self.browserCandidates ?: @[]);
    self.toggleInstallButton.enabled = !self.checkingBrowser && (installed || self.browserCandidates.count > 0);
    self.checkBrowserButton.enabled = !self.checkingBrowser && self.browserCandidates.count > 0;
    if (!browser) {
        self.browserPicker.enabled = NO;
        setStatusLabel(self.status, @"No signed Chromium browser with Apple's public-key credential entitlement was found.", YES);
        return;
    }
    self.browserPicker.enabled = !self.checkingBrowser;
    NSString *prefix = installed ? @"Installed." : @"Not installed.";
    NSDictionary *probe = browserProbeResultForPath(browser[@"bundlePath"]);
    NSString *message = nil;
    if (self.checkingBrowser) {
        message = [NSString stringWithFormat:@"Checking %@ with a capabilities-only request…", browser[@"name"]];
    } else if ([probe[@"connected"] boolValue]) {
        message = [NSString stringWithFormat:@"%@ Connected through %@. Apple Passwords answered; no PIN or password was requested.", prefix, browser[@"name"]];
    } else if (probe) {
        message = [NSString stringWithFormat:@"%@ %@ did not connect to Apple Passwords. This browser is detected but not verified.", prefix, browser[@"name"]];
    } else {
        message = [NSString stringWithFormat:@"%@ %@ detected. Compatibility is unverified; choose Check selected browser. Reload the extension after installation.", prefix, browser[@"name"]];
    }
    setStatusLabel(self.status, message, NO);
}

- (void)refreshBrowserPicker {
    [self.browserPicker removeAllItems];
    if (self.browserCandidates.count == 0) {
        [self.browserPicker addItemWithTitle:self.loadingBrowserCandidates ? @"Finding browsers…" : @"No compatible browsers found"];
        self.browserPicker.enabled = NO;
        return;
    }
    for (NSDictionary *candidate in self.browserCandidates ?: @[]) {
        [self.browserPicker addItemWithTitle:candidate[@"name"]];
        self.browserPicker.lastItem.representedObject = candidate[@"bundlePath"];
    }

    NSDictionary *selected = preferredBrowserFromCandidates(self.browserCandidates ?: @[]);
    if (selected) {
        NSInteger index = NSNotFound;
        for (NSUInteger i = 0; i < self.browserCandidates.count; i++) {
            if ([self.browserCandidates[i][@"bundlePath"] isEqual:selected[@"bundlePath"]]) {
                index = (NSInteger)i;
                break;
            }
        }
        if (index != NSNotFound) [self.browserPicker selectItemAtIndex:index];
        [[NSUserDefaults standardUserDefaults] setObject:selected[@"bundlePath"] forKey:kSelectedBrowserPreference];
    }
    self.browserPicker.enabled = self.browserCandidates.count > 0;
}

- (void)browserChanged:(id)sender {
    NSString *path = self.browserPicker.selectedItem.representedObject;
    if (path.length) {
        NSUserDefaults *defaults = NSUserDefaults.standardUserDefaults;
        [defaults setObject:path forKey:kSelectedBrowserPreference];
        [defaults synchronize];
    }
    [self refreshStatus];
}

- (void)checkSelectedBrowser:(id)sender {
    NSString *path = self.browserPicker.selectedItem.representedObject;
    if (!path.length || self.checkingBrowser) return;
    NSUserDefaults *defaults = NSUserDefaults.standardUserDefaults;
    [defaults setObject:path forKey:kSelectedBrowserPreference];
    [defaults synchronize];

    self.checkingBrowser = YES;
    [self refreshStatus];
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        NSString *error = nil;
        NSDictionary *capabilities = probeSelectedBrowser(&error);
        BOOL connected = capabilities != nil;
        NSString *detail = connected ? @"Capabilities received." : (error ?: @"No response from Apple Passwords.");
        dispatch_async(dispatch_get_main_queue(), ^{
            saveBrowserProbeResult(path, connected, detail);
            self.checkingBrowser = NO;
            [self refreshStatus];
        });
    });
}

- (void)toggleInstallation:(id)sender {
    BOOL installed = isAnyAppOwnedHostManifest();
    NSString *runningBundlePath = NSBundle.mainBundle.bundleURL.URLByResolvingSymlinksInPath.path.stringByStandardizingPath;
    NSString *installedBundlePath = installedAppURL().URLByResolvingSymlinksInPath.path.stringByStandardizingPath;
    BOOL removingRunningBundle = installed && [runningBundlePath isEqual:installedBundlePath];
    NSError *error = nil;
    BOOL succeeded = installed ? removeHelper(&error) : installHelper(&error);
    [self refreshStatus];
    if (!succeeded) setStatusLabel(self.status, error.localizedDescription ?: (installed ? @"Could not remove the helper." : @"Installation failed."), YES);
    else if (installed) {
        setStatusLabel(self.status, @"Helper and browser registration removed.", NO);
        if (removingRunningBundle) dispatch_async(dispatch_get_main_queue(), ^{ [NSApp terminate:nil]; });
    }
}
@end

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        const char *handoff = getenv(kHandoffVariable.UTF8String);
        if (handoff && argc > 1 && strncmp(argv[1], "--type=", 7) == 0) return runHandoff(argc, argv);
        if (argc > 1 && strcmp(argv[1], "--passkey-host") == 0) return runPasskeyNativeHost(argc, argv);
        if (argc > 1 && [[NSString stringWithUTF8String:argv[1]] hasPrefix:@"chrome-extension://"]) return runNativeHost(argc, argv);
        if (argc > 1 && strcmp(argv[1], "--install") == 0) {
            NSError *error = nil;
            if (!installHelper(&error)) { logError(error.localizedDescription ?: @"Installation failed."); return 1; }
            return 0;
        }
        if (argc > 1 && strcmp(argv[1], "--remove-host") == 0) {
            NSError *error = nil;
            if (!removeHostManifest(&error)) { logError(error.localizedDescription ?: @"Removal failed."); return 1; }
            return 0;
        }
        NSApplication *app = NSApplication.sharedApplication;
        OpenPasswordsAppDelegate *delegate = [OpenPasswordsAppDelegate new];
        app.delegate = delegate;
        [app run];
    }
    return 0;
}
