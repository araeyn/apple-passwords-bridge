#import "PasskeyHost.h"

#import <AppKit/AppKit.h>
#import <arpa/inet.h>
#import <errno.h>
#import <fcntl.h>
#import <limits.h>
#import <math.h>
#import <poll.h>
#import <signal.h>
#import <spawn.h>
#import <stdlib.h>
#import <string.h>
#import <sys/stat.h>
#import <sys/types.h>
#import <sys/wait.h>
#import <unistd.h>

extern char **environ;

// Direct CDP use is not a stable supported Chrome API. Keep the connection on
// the private fd 3/4 pipe, use a fresh profile, and fail closed when a browser
// doesn't implement the Chromium commands this runner needs.
static const NSUInteger kMaximumRequestBytes = 64 * 1024;
// BufferSource markers expand to base64url strings before the 64KB parsed-option cap.
static const NSUInteger kMaximumIncomingRequestBytes = 128 * 1024;
static const NSUInteger kMaximumCDPMessageBytes = 2 * 1024 * 1024;
static const NSTimeInterval kMaximumOperationSeconds = 120.0;
static const NSTimeInterval kBrowserStartupSeconds = 20.0;
static const NSTimeInterval kOriginLoadSeconds = 20.0;
static const NSTimeInterval kDefaultWebAuthnTimeoutMS = 60000.0;
static const NSTimeInterval kMaximumWebAuthnTimeoutMS = 120000.0;
static const char kTemporaryDirectoryTemplate[] = "/tmp/open-passwords-passkey.XXXXXX";

@interface OPPipeConnection : NSObject
@property(nonatomic) int inputFD;
@property(nonatomic) int outputFD;
@property(nonatomic) pid_t processID;
@property(nonatomic) uint32_t nextCommandID;
@property(nonatomic, strong) NSMutableData *inputBuffer;
@property(nonatomic, strong) NSMutableArray<NSDictionary *> *pendingMessages;
@property(nonatomic, copy) NSString *sessionID;
@property(nonatomic, copy) NSString *targetID;
@property(nonatomic) NSTimeInterval deadline;
@property(nonatomic) volatile int *cancelled;
@end

@implementation OPPipeConnection
- (instancetype)init {
    self = [super init];
    if (self) {
        _inputFD = -1;
        _outputFD = -1;
        _processID = 0;
        _nextCommandID = 1;
        _inputBuffer = [NSMutableData data];
        _pendingMessages = [NSMutableArray array];
        _sessionID = @"";
        _targetID = @"";
        _deadline = 0;
        _cancelled = NULL;
    }
    return self;
}
@end

static NSDictionary *OPError(NSString *name, NSString *message) {
    if (![name isKindOfClass:NSString.class] || !name.length) name = @"Error";
    if (![message isKindOfClass:NSString.class] || !message.length) message = @"Passkey request failed.";
    NSString *safeName = name.length <= 80 ? name : @"Error";
    NSString *safeMessage = message.length <= 1024 ? message : [message substringToIndex:1024];
    return @{ @"error" : @{ @"name" : safeName ?: @"Error", @"message" : safeMessage ?: @"Passkey request failed." } };
}

static NSDictionary *OPErrorFromNSError(NSError *error, NSString *fallbackName) {
    NSString *name = error.userInfo[@"OPErrorName"];
    if (![name isKindOfClass:NSString.class] || !name.length) name = fallbackName ?: @"Error";
    NSString *message = error.localizedDescription ?: @"Passkey request failed.";
    return OPError(name, message);
}

static NSError *OPMakeNSError(NSString *name, NSString *message) {
    return [NSError errorWithDomain:@"com.openpasswords.passkey-host" code:1 userInfo:@{
        NSLocalizedDescriptionKey : message ?: @"Passkey request failed.",
        @"OPErrorName" : name ?: @"Error",
    }];
}

static BOOL OPCancelled(OPPipeConnection *connection) {
    volatile int *flag = connection.cancelled;
    return flag && __atomic_load_n(flag, __ATOMIC_ACQUIRE) != 0;
}

static NSTimeInterval OPMonotonicTime(void) {
    return NSProcessInfo.processInfo.systemUptime;
}

static int OPRemainingMilliseconds(OPPipeConnection *connection, NSTimeInterval requestedSeconds) {
    if (OPCancelled(connection)) return 0;
    NSTimeInterval remaining = connection.deadline - OPMonotonicTime();
    if (requestedSeconds > 0) remaining = MIN(remaining, requestedSeconds);
    if (remaining <= 0) return 0;
    return (int)MIN(remaining * 1000.0, (NSTimeInterval)INT_MAX);
}

static BOOL OPWriteAll(int fd, const void *bytes, size_t length) {
    const uint8_t *cursor = bytes;
    size_t written = 0;
    while (written < length) {
        ssize_t count = write(fd, cursor + written, length - written);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return NO;
        written += (size_t)count;
    }
    return YES;
}

static BOOL OPCreatePipe(int pipeFDs[2]) {
    int lowFDs[2] = { -1, -1 };
    if (pipe(lowFDs) != 0) return NO;
    int highRead = fcntl(lowFDs[0], F_DUPFD_CLOEXEC, 20);
    int readError = errno;
    int highWrite = fcntl(lowFDs[1], F_DUPFD_CLOEXEC, 20);
    int writeError = errno;
    close(lowFDs[0]);
    close(lowFDs[1]);
    if (highRead < 0 || highWrite < 0) {
        if (highRead >= 0) close(highRead);
        if (highWrite >= 0) close(highWrite);
        errno = highRead < 0 ? readError : writeError;
        return NO;
    }
    pipeFDs[0] = highRead;
    pipeFDs[1] = highWrite;
    return YES;
}

static BOOL OPSpawnBrowser(OPPipeConnection *connection, NSDictionary *browser, NSString *profilePath, NSError **errorOut) {
    NSString *executable = browser[@"executablePath"];
    if (![executable isKindOfClass:NSString.class] || !executable.isAbsolutePath || ![NSFileManager.defaultManager isExecutableFileAtPath:executable]) {
        if (errorOut) *errorOut = OPMakeNSError(@"NotSupportedError", @"The selected browser executable is unavailable.");
        return NO;
    }

    int toBrowser[2] = { -1, -1 };   // parent writes to child fd 3
    int fromBrowser[2] = { -1, -1 }; // parent reads from child fd 4
    if (!OPCreatePipe(toBrowser) || !OPCreatePipe(fromBrowser)) {
        int savedErrno = errno;
        if (toBrowser[0] >= 0) close(toBrowser[0]);
        if (toBrowser[1] >= 0) close(toBrowser[1]);
        if (fromBrowser[0] >= 0) close(fromBrowser[0]);
        if (fromBrowser[1] >= 0) close(fromBrowser[1]);
        if (errorOut) *errorOut = OPMakeNSError(@"NotSupportedError", [NSString stringWithFormat:@"Could not create the private browser control pipe (%d).", savedErrno]);
        return NO;
    }

    NSString *userData = [@"--user-data-dir=" stringByAppendingString:profilePath];
    NSArray<NSString *> *arguments = @[
        executable,
        userData,
        @"--remote-debugging-pipe",
        @"--no-first-run",
        @"--no-default-browser-check",
        @"--disable-sync",
        @"--disable-extensions",
        @"--disable-background-networking",
        @"--window-size=480,320",
        @"--app=about:blank",
    ];
    char **argv = calloc(arguments.count + 1, sizeof(char *));
    if (!argv) {
        close(toBrowser[0]); close(toBrowser[1]); close(fromBrowser[0]); close(fromBrowser[1]);
        if (errorOut) *errorOut = OPMakeNSError(@"NotSupportedError", @"Could not prepare the browser launch.");
        return NO;
    }
    for (NSUInteger i = 0; i < arguments.count; i++) argv[i] = strdup(arguments[i].UTF8String);

    posix_spawn_file_actions_t actions;
    posix_spawnattr_t attributes;
    int setupError = posix_spawn_file_actions_init(&actions);
    BOOL actionsReady = setupError == 0;
    BOOL attributesReady = NO;
    if (setupError == 0) {
        setupError = posix_spawnattr_init(&attributes);
        attributesReady = setupError == 0;
    }
    if (setupError == 0) setupError = posix_spawn_file_actions_addopen(&actions, STDIN_FILENO, "/dev/null", O_RDONLY, 0);
    if (setupError == 0) setupError = posix_spawn_file_actions_addopen(&actions, STDOUT_FILENO, "/dev/null", O_WRONLY, 0);
    if (setupError == 0) setupError = posix_spawn_file_actions_addopen(&actions, STDERR_FILENO, "/dev/null", O_WRONLY, 0);
    if (setupError == 0) setupError = posix_spawn_file_actions_adddup2(&actions, toBrowser[0], 3);
    if (setupError == 0) setupError = posix_spawn_file_actions_adddup2(&actions, fromBrowser[1], 4);
    if (setupError == 0) setupError = posix_spawn_file_actions_addclose(&actions, toBrowser[0]);
    if (setupError == 0) setupError = posix_spawn_file_actions_addclose(&actions, toBrowser[1]);
    if (setupError == 0) setupError = posix_spawn_file_actions_addclose(&actions, fromBrowser[0]);
    if (setupError == 0) setupError = posix_spawn_file_actions_addclose(&actions, fromBrowser[1]);
    short flags = POSIX_SPAWN_SETPGROUP | POSIX_SPAWN_CLOEXEC_DEFAULT;
    if (setupError == 0) setupError = posix_spawnattr_setflags(&attributes, flags);
    if (setupError == 0) setupError = posix_spawnattr_setpgroup(&attributes, 0);

    if (setupError != 0) {
        if (attributesReady) posix_spawnattr_destroy(&attributes);
        if (actionsReady) posix_spawn_file_actions_destroy(&actions);
        for (NSUInteger i = 0; i < arguments.count; i++) free(argv[i]);
        free(argv);
        close(toBrowser[0]); close(toBrowser[1]); close(fromBrowser[0]); close(fromBrowser[1]);
        if (errorOut) *errorOut = OPMakeNSError(@"NotSupportedError", [NSString stringWithFormat:@"Could not prepare the isolated browser process group (%d).", setupError]);
        return NO;
    }

    pid_t child = 0;
    int result = posix_spawn(&child, executable.fileSystemRepresentation, &actions, &attributes, argv, environ);
    posix_spawn_file_actions_destroy(&actions);
    posix_spawnattr_destroy(&attributes);
    for (NSUInteger i = 0; i < arguments.count; i++) free(argv[i]);
    free(argv);
    close(toBrowser[0]);
    close(fromBrowser[1]);

    if (result != 0) {
        close(toBrowser[1]);
        close(fromBrowser[0]);
        if (errorOut) *errorOut = OPMakeNSError(@"NotSupportedError", [NSString stringWithFormat:@"Could not start %@ (%d).", browser[@"name"] ?: @"the selected browser", result]);
        return NO;
    }

    connection.processID = child;
    connection.outputFD = toBrowser[1];
    connection.inputFD = fromBrowser[0];
    return YES;
}

static NSDictionary *OPReadCDPMessage(OPPipeConnection *connection, NSTimeInterval timeoutSeconds, NSError **errorOut) {
    while (YES) {
        if (OPCancelled(connection)) {
            if (errorOut) *errorOut = OPMakeNSError(@"AbortError", @"The passkey request was canceled.");
            return nil;
        }

        const uint8_t *bytes = connection.inputBuffer.bytes;
        const uint8_t *terminator = memchr(bytes, 0, connection.inputBuffer.length);
        if (terminator) {
            NSUInteger length = (NSUInteger)(terminator - bytes);
            if (length > kMaximumCDPMessageBytes) {
                if (errorOut) *errorOut = OPMakeNSError(@"DataError", @"The browser sent an oversized control message.");
                return nil;
            }
            NSData *messageData = [connection.inputBuffer subdataWithRange:NSMakeRange(0, length)];
            NSUInteger consumed = length + 1;
            [connection.inputBuffer replaceBytesInRange:NSMakeRange(0, consumed) withBytes:NULL length:0];
            id message = [NSJSONSerialization JSONObjectWithData:messageData options:0 error:nil];
            if ([message isKindOfClass:NSDictionary.class]) return message;
            if (errorOut) *errorOut = OPMakeNSError(@"DataError", @"The browser returned an invalid control message.");
            return nil;
        }
        if (connection.inputBuffer.length > kMaximumCDPMessageBytes) {
            if (errorOut) *errorOut = OPMakeNSError(@"DataError", @"The browser sent an oversized control message.");
            return nil;
        }

        int timeoutMS = OPRemainingMilliseconds(connection, timeoutSeconds);
        if (timeoutMS <= 0) {
            NSString *name = OPCancelled(connection) ? @"AbortError" : @"TimeoutError";
            NSString *message = OPCancelled(connection) ? @"The passkey request was canceled." : @"The browser operation timed out.";
            if (errorOut) *errorOut = OPMakeNSError(name, message);
            return nil;
        }
        struct pollfd ready = { .fd = connection.inputFD, .events = POLLIN };
        int polled;
        do { polled = poll(&ready, 1, MIN(timeoutMS, 200)); } while (polled < 0 && errno == EINTR);
        if (polled < 0) {
            if (errorOut) *errorOut = OPMakeNSError(@"UnknownError", @"The browser control pipe failed.");
            return nil;
        }
        if (polled == 0) {
            if (timeoutMS <= 200) {
                if (errorOut) *errorOut = OPMakeNSError(@"TimeoutError", @"The browser operation timed out.");
                return nil;
            }
            continue;
        }
        if (ready.revents & (POLLERR | POLLNVAL)) {
            if (errorOut) *errorOut = OPMakeNSError(@"AbortError", @"The browser closed the control pipe.");
            return nil;
        }
        uint8_t buffer[16384];
        ssize_t count = read(connection.inputFD, buffer, sizeof buffer);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) {
            if (errorOut) *errorOut = OPMakeNSError(@"AbortError", @"The browser closed before completing the passkey request.");
            return nil;
        }
        [connection.inputBuffer appendBytes:buffer length:(NSUInteger)count];
    }
}

static NSDictionary *OPSendCommand(OPPipeConnection *connection, NSString *method, NSDictionary *params, NSString *sessionID, NSTimeInterval timeoutSeconds, NSError **errorOut) {
    uint32_t commandID = connection.nextCommandID++;
    NSMutableDictionary *command = [@{ @"id" : @(commandID), @"method" : method, @"params" : params ?: @{} } mutableCopy];
    if (sessionID.length) command[@"sessionId"] = sessionID;
    NSData *data = [NSJSONSerialization dataWithJSONObject:command options:0 error:errorOut];
    if (!data || data.length > kMaximumCDPMessageBytes) {
        if (errorOut && !*errorOut) *errorOut = OPMakeNSError(@"DataError", @"The browser command is too large.");
        return nil;
    }
    NSMutableData *frame = [data mutableCopy];
    uint8_t terminator = 0;
    [frame appendBytes:&terminator length:1];
    if (!OPWriteAll(connection.outputFD, frame.bytes, frame.length)) {
        if (errorOut) *errorOut = OPMakeNSError(@"AbortError", @"Could not send a command to the browser.");
        return nil;
    }

    while (YES) {
        NSDictionary *reply = nil;
        for (NSUInteger i = 0; i < connection.pendingMessages.count; i++) {
            NSDictionary *pending = connection.pendingMessages[i];
            if (([pending[@"method"] isEqual:@"Target.targetDestroyed"] && [pending[@"params"][@"targetId"] isEqual:connection.targetID])
                || ([pending[@"method"] isEqual:@"Inspector.detached"] && [pending[@"sessionId"] isEqual:connection.sessionID])) {
                [connection.pendingMessages removeObjectAtIndex:i];
                if (errorOut) *errorOut = OPMakeNSError(@"AbortError", @"The passkey browser window was closed.");
                return nil;
            }
            if ([pending[@"id"] unsignedIntValue] == commandID) {
                reply = pending;
                [connection.pendingMessages removeObjectAtIndex:i];
                break;
            }
        }
        if (!reply) {
            reply = OPReadCDPMessage(connection, timeoutSeconds, errorOut);
        }
        if (!reply) return nil;
        if ([reply[@"id"] unsignedIntValue] == commandID) {
            NSDictionary *protocolError = reply[@"error"];
            if ([protocolError isKindOfClass:NSDictionary.class]) {
                if (errorOut) *errorOut = OPMakeNSError(@"NotSupportedError", protocolError[@"message"] ?: @"The browser rejected a required command.");
                return nil;
            }
            return reply;
        }
        if ([reply[@"method"] isEqual:@"Target.targetDestroyed"] && [reply[@"params"][@"targetId"] isEqual:connection.targetID]) {
            if (errorOut) *errorOut = OPMakeNSError(@"AbortError", @"The passkey browser window was closed.");
            return nil;
        }
        if ([reply[@"method"] isEqual:@"Inspector.detached"] && [reply[@"sessionId"] isEqual:connection.sessionID]) {
            if (errorOut) *errorOut = OPMakeNSError(@"AbortError", @"The passkey browser window was closed.");
            return nil;
        }
        [connection.pendingMessages addObject:reply];
        if (connection.pendingMessages.count > 256) {
            if (errorOut) *errorOut = OPMakeNSError(@"DataError", @"The browser emitted too many unrelated control events.");
            return nil;
        }
    }
}

static NSDictionary *OPRuntimeValue(OPPipeConnection *connection, NSString *expression, BOOL userGesture, NSTimeInterval timeoutSeconds, NSError **errorOut) {
    NSDictionary *reply = OPSendCommand(connection, @"Runtime.evaluate", @{
        @"expression" : expression,
        @"awaitPromise" : @YES,
        @"returnByValue" : @YES,
        @"userGesture" : @(userGesture),
        @"includeCommandLineAPI" : @NO,
    }, connection.sessionID, timeoutSeconds, errorOut);
    if (!reply) return nil;
    NSDictionary *remote = reply[@"result"][@"result"];
    NSDictionary *value = remote[@"value"];
    if ([value isKindOfClass:NSDictionary.class]) return value;
    NSDictionary *exception = reply[@"result"][@"exceptionDetails"];
    if (exception) {
        NSString *message = exception[@"text"] ?: exception[@"exception"][@"description"] ?: @"The browser could not evaluate the passkey request.";
        if (errorOut) *errorOut = OPMakeNSError(@"NotAllowedError", message);
    } else if (errorOut) {
        *errorOut = OPMakeNSError(@"NotAllowedError", @"The browser returned no passkey result.");
    }
    return nil;
}

// Wait for the script-free robots document to finish loading before replacing
// its DOM. The final HTTPS origin is checked against the request's RP ID below.
static NSDictionary *OPWaitForOriginLoaded(OPPipeConnection *connection, NSError **errorOut) {
    NSTimeInterval deadline = MIN(connection.deadline, OPMonotonicTime() + kOriginLoadSeconds);
    NSString *expression = @"(()=>({origin:location.origin,readyState:document.readyState,secure:isSecureContext}))()";
    while (OPMonotonicTime() < deadline) {
        if (OPCancelled(connection)) {
            if (errorOut) *errorOut = OPMakeNSError(@"AbortError", @"The passkey request was canceled.");
            return nil;
        }
        NSError *evaluationError = nil;
        NSTimeInterval timeout = MIN(1.0, deadline - OPMonotonicTime());
        NSDictionary *state = OPRuntimeValue(connection, expression, NO, timeout, &evaluationError);
        NSString *loadedOrigin = state[@"origin"];
        if ([loadedOrigin isKindOfClass:NSString.class]
            && [loadedOrigin hasPrefix:@"https://"]
            && [state[@"readyState"] isEqual:@"complete"]
            && [state[@"secure"] boolValue]) return state;
        usleep(100000);
    }
    if (errorOut) *errorOut = OPMakeNSError(@"TimeoutError", @"The browser did not finish loading a secure relying-party page.");
    return nil;
}

static NSDictionary *OPWaitForNeutralPage(OPPipeConnection *connection, NSString *origin, NSError **errorOut) {
    NSTimeInterval deadline = MIN(connection.deadline, OPMonotonicTime() + kOriginLoadSeconds);
    NSString *expression = @"(()=>({origin:location.origin,readyState:document.readyState,secure:isSecureContext,neutral:!!document.getElementById('open-passwords-passkey-sentinel'),path:location.pathname}))()";
    while (OPMonotonicTime() < deadline) {
        if (OPCancelled(connection)) {
            if (errorOut) *errorOut = OPMakeNSError(@"AbortError", @"The passkey request was canceled.");
            return nil;
        }
        NSError *evaluationError = nil;
        NSTimeInterval timeout = MIN(1.0, deadline - OPMonotonicTime());
        NSDictionary *state = OPRuntimeValue(connection, expression, NO, timeout, &evaluationError);
        if ([state[@"origin"] isEqual:origin]
            && [state[@"readyState"] isEqual:@"complete"]
            && [state[@"secure"] boolValue]
            && [state[@"neutral"] boolValue]
            && [state[@"path"] isEqual:@"/"]) return state;
        usleep(100000);
    }
    if (errorOut) *errorOut = OPMakeNSError(@"SecurityError", @"The browser could not verify the neutral same-origin passkey page.");
    return nil;
}

static BOOL OPRuntimeBoolean(OPPipeConnection *connection, NSString *expression, NSTimeInterval timeoutSeconds, BOOL *valueOut, NSError **errorOut) {
    NSDictionary *reply = OPSendCommand(connection, @"Runtime.evaluate", @{
        @"expression" : expression,
        @"awaitPromise" : @YES,
        @"returnByValue" : @YES,
        @"userGesture" : @NO,
        @"includeCommandLineAPI" : @NO,
    }, connection.sessionID, timeoutSeconds, errorOut);
    if (!reply) return NO;
    id value = reply[@"result"][@"result"][@"value"];
    if (![value isKindOfClass:NSNumber.class]) {
        if (errorOut) *errorOut = OPMakeNSError(@"DataError", @"The browser returned an invalid focus state.");
        return NO;
    }
    if (valueOut) *valueOut = [value boolValue];
    return YES;
}

static BOOL OPActivateAndWaitForFocus(OPPipeConnection *connection, NSError **errorOut) {
    if (OPCancelled(connection)) {
        if (errorOut) *errorOut = OPMakeNSError(@"AbortError", @"The passkey request was canceled.");
        return NO;
    }
    NSRunningApplication *application = [NSRunningApplication runningApplicationWithProcessIdentifier:connection.processID];
    if (!application) {
        if (errorOut) *errorOut = OPMakeNSError(@"AbortError", @"The passkey browser is no longer running.");
        return NO;
    }
    [application activateWithOptions:(NSApplicationActivateAllWindows | NSApplicationActivateIgnoringOtherApps)];
    OPSendCommand(connection, @"Target.activateTarget", @{ @"targetId" : connection.targetID }, nil, 2.0, nil);

    NSTimeInterval deadline = MIN(connection.deadline, OPMonotonicTime() + 5.0);
    while (OPMonotonicTime() < deadline) {
        if (OPCancelled(connection)) {
            if (errorOut) *errorOut = OPMakeNSError(@"AbortError", @"The passkey request was canceled.");
            return NO;
        }
        BOOL focused = NO;
        if (OPRuntimeBoolean(connection, @"document.hasFocus()", 0.8, &focused, errorOut) && focused) return YES;
        usleep(100000);
    }
    if (errorOut) *errorOut = OPMakeNSError(@"NotAllowedError", @"Bring the passkey browser window to the front and try again.");
    return NO;
}

static BOOL OPValidateDomain(NSString *domain) {
    if (![domain isKindOfClass:NSString.class] || !domain.length || domain.length > 253) return NO;
    NSString *host = domain.lowercaseString;
    if ([host hasSuffix:@"."] || [host hasPrefix:@"."]) return NO;
    NSCharacterSet *allowed = [NSCharacterSet characterSetWithCharactersInString:@"abcdefghijklmnopqrstuvwxyz0123456789.-"];
    if ([host rangeOfCharacterFromSet:allowed.invertedSet].location != NSNotFound) return NO;
    struct in_addr address4;
    if (inet_pton(AF_INET, host.UTF8String, &address4) == 1) return NO;

    NSArray<NSString *> *labels = [host componentsSeparatedByString:@"."];
    if (labels.count < 2 && ![host isEqual:@"localhost"]) return NO;
    for (NSString *label in labels) {
        if (!label.length || label.length > 63 || [label hasPrefix:@"-"] || [label hasSuffix:@"-"]) return NO;
    }
    return YES;
}

static NSString *OPNormalizedOrigin(NSString *input, NSString **hostOut, NSError **errorOut) {
    NSURLComponents *components = [NSURLComponents componentsWithString:input ?: @""];
    NSString *scheme = components.scheme.lowercaseString;
    NSString *host = components.host.lowercaseString;
    NSString *path = components.path ?: @"";
    BOOL localSecureHost = [host isEqual:@"localhost"] || [host hasSuffix:@".localhost"];
    BOOL secureScheme = [scheme isEqual:@"https"] || ([scheme isEqual:@"http"] && localSecureHost);
    if (!secureScheme || !OPValidateDomain(host)
        || components.user.length || components.password.length || components.query.length || components.fragment.length
        || (path.length && ![path isEqual:@"/"]) || (components.port && (components.port.intValue <= 0 || components.port.intValue > 65535))) {
        if (errorOut) *errorOut = OPMakeNSError(@"SecurityError", @"Passkey requests require HTTPS or a localhost secure-context origin.");
        return nil;
    }
    if (hostOut) *hostOut = host;
    int defaultPort = [scheme isEqual:@"https"] ? 443 : 80;
    if (components.port && components.port.intValue != defaultPort) {
        return [NSString stringWithFormat:@"%@://%@:%@", scheme, host, components.port];
    }
    return [NSString stringWithFormat:@"%@://%@", scheme, host];
}

static BOOL OPRelyingPartyMatchesOrigin(NSString *rpID, NSString *originHost) {
    // Chromium applies its Public Suffix List check during WebAuthn processing;
    // this boundary check also prevents unrelated and cross-site RP IDs here.
    NSString *rp = rpID.lowercaseString;
    if (!OPValidateDomain(rp)) return NO;
    if ([rp isEqual:originHost]) return YES;
    NSString *suffix = [@"." stringByAppendingString:rp];
    return [originHost hasSuffix:suffix];
}

static id OPNormalizeBufferSources(id value, NSError **errorOut) {
    if ([value isKindOfClass:NSDictionary.class]) {
        NSDictionary *dictionary = value;
        id marker = dictionary[@"__openPasswordsBufferSource"];
        if ([marker respondsToSelector:@selector(boolValue)] && [marker boolValue]) {
            id data = dictionary[@"data"];
            if (![data isKindOfClass:NSString.class] || ![data length] || [data length] > kMaximumIncomingRequestBytes) {
                if (errorOut) *errorOut = OPMakeNSError(@"DataError", @"A binary WebAuthn option is missing or too large.");
                return nil;
            }
            return data;
        }
        NSMutableDictionary *normalized = [NSMutableDictionary dictionaryWithCapacity:dictionary.count];
        for (id key in dictionary) {
            if (![key isKindOfClass:NSString.class]) {
                if (errorOut) *errorOut = OPMakeNSError(@"DataError", @"The WebAuthn request contains a non-string object key.");
                return nil;
            }
            id child = OPNormalizeBufferSources(dictionary[key], errorOut);
            if (!child) return nil;
            normalized[key] = child;
        }
        return normalized;
    }
    if ([value isKindOfClass:NSArray.class]) {
        NSMutableArray *normalized = [NSMutableArray arrayWithCapacity:[value count]];
        for (id childValue in value) {
            id child = OPNormalizeBufferSources(childValue, errorOut);
            if (!child) return nil;
            [normalized addObject:child];
        }
        return normalized;
    }
    return value;
}

static NSDictionary *OPNormalizedOptions(NSString *kind, NSDictionary *input, NSString *originHost, NSError **errorOut) {
    NSData *incomingData = [NSJSONSerialization dataWithJSONObject:input options:0 error:nil];
    if (!incomingData || incomingData.length > kMaximumIncomingRequestBytes) {
        if (errorOut) *errorOut = OPMakeNSError(@"DataError", @"The incoming WebAuthn request is too large or is not JSON-safe.");
        return nil;
    }
    id normalizedInput = OPNormalizeBufferSources(input, errorOut);
    if (![normalizedInput isKindOfClass:NSDictionary.class]) {
        if (errorOut && !*errorOut) *errorOut = OPMakeNSError(@"DataError", @"The normalized WebAuthn request is invalid.");
        return nil;
    }
    NSMutableDictionary *options = [normalizedInput mutableCopy];
    NSDictionary *publicKey = [options[@"publicKey"] isKindOfClass:NSDictionary.class] ? options[@"publicKey"] : options;
    if (publicKey != options) options = [publicKey mutableCopy];

    NSString *challenge = options[@"challenge"];
    if (![challenge isKindOfClass:NSString.class] || !challenge.length || challenge.length > 8192) {
        if (errorOut) *errorOut = OPMakeNSError(@"TypeError", @"The WebAuthn challenge is missing or too large.");
        return nil;
    }
    NSString *rpID = nil;
    if ([kind isEqual:@"create"]) {
        NSDictionary *rp = options[@"rp"];
        NSDictionary *user = options[@"user"];
        NSArray *parameters = options[@"pubKeyCredParams"];
        if (![rp isKindOfClass:NSDictionary.class] || ![user isKindOfClass:NSDictionary.class]
            || ![user[@"id"] isKindOfClass:NSString.class] || ![user[@"name"] isKindOfClass:NSString.class]
            || ![user[@"displayName"] isKindOfClass:NSString.class]
            || ![parameters isKindOfClass:NSArray.class] || parameters.count == 0 || parameters.count > 64) {
            if (errorOut) *errorOut = OPMakeNSError(@"TypeError", @"The passkey creation options are incomplete or malformed.");
            return nil;
        }
        if (rp[@"id"] && ![rp[@"id"] isKindOfClass:NSString.class]) {
            if (errorOut) *errorOut = OPMakeNSError(@"TypeError", @"The WebAuthn relying party ID must be a string.");
            return nil;
        }
        rpID = [rp[@"id"] isKindOfClass:NSString.class] ? rp[@"id"] : originHost;
        NSArray *excludeCredentials = options[@"excludeCredentials"];
        if (excludeCredentials && (![excludeCredentials isKindOfClass:NSArray.class] || excludeCredentials.count > 128)) {
            if (errorOut) *errorOut = OPMakeNSError(@"DataError", @"The passkey exclusion list is invalid or too large.");
            return nil;
        }
    } else {
        if (options[@"rpId"] && ![options[@"rpId"] isKindOfClass:NSString.class]) {
            if (errorOut) *errorOut = OPMakeNSError(@"TypeError", @"The WebAuthn relying party ID must be a string.");
            return nil;
        }
        rpID = [options[@"rpId"] isKindOfClass:NSString.class] ? options[@"rpId"] : originHost;
        NSArray *allowCredentials = options[@"allowCredentials"];
        if (allowCredentials && (![allowCredentials isKindOfClass:NSArray.class] || allowCredentials.count > 128)) {
            if (errorOut) *errorOut = OPMakeNSError(@"DataError", @"The passkey allow-list is invalid or too large.");
            return nil;
        }
    }
    if (![rpID isKindOfClass:NSString.class] || !OPRelyingPartyMatchesOrigin(rpID, originHost)) {
        if (errorOut) *errorOut = OPMakeNSError(@"SecurityError", @"The relying party ID does not match the HTTPS page origin.");
        return nil;
    }

    id timeoutValue = options[@"timeout"];
    double timeoutMS = kDefaultWebAuthnTimeoutMS;
    if (timeoutValue) {
        if (![timeoutValue respondsToSelector:@selector(doubleValue)] || !isfinite([timeoutValue doubleValue]) || [timeoutValue doubleValue] <= 0) {
            if (errorOut) *errorOut = OPMakeNSError(@"TypeError", @"The WebAuthn timeout is invalid.");
            return nil;
        }
        timeoutMS = MIN([timeoutValue doubleValue], kMaximumWebAuthnTimeoutMS);
    }
    options[@"timeout"] = @(timeoutMS);

    NSError *serializationError = nil;
    NSData *data = [NSJSONSerialization dataWithJSONObject:options options:0 error:&serializationError];
    if (!data || data.length > kMaximumRequestBytes) {
        if (errorOut) *errorOut = OPMakeNSError(@"DataError", @"The WebAuthn request is too large or is not JSON-safe.");
        return nil;
    }
    return options;
}

static NSString *OPCreateTemporaryProfile(void) {
    char path[sizeof(kTemporaryDirectoryTemplate) + 8] = { 0 };
    strlcpy(path, kTemporaryDirectoryTemplate, sizeof path);
    char *created = mkdtemp(path);
    if (!created) return nil;
    if (chmod(created, 0700) != 0) {
        rmdir(created);
        return nil;
    }
    return [NSString stringWithUTF8String:created];
}

static void OPStopBrowser(OPPipeConnection *connection, NSString *profilePath) {
    if (connection.outputFD >= 0) { close(connection.outputFD); connection.outputFD = -1; }
    if (connection.inputFD >= 0) { close(connection.inputFD); connection.inputFD = -1; }
    pid_t pid = connection.processID;
    if (pid > 0) {
        kill(-pid, SIGTERM);
        for (int i = 0; i < 40; i++) {
            int status = 0;
            waitpid(pid, &status, WNOHANG);
            if (kill(-pid, 0) != 0 && errno == ESRCH) break;
            usleep(50000);
        }
        kill(-pid, SIGKILL);
        for (int i = 0; i < 40; i++) {
            if (kill(-pid, 0) != 0 && errno == ESRCH) break;
            usleep(50000);
        }
        int status = 0;
        while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
        connection.processID = 0;
    }
    if (profilePath.length) {
        NSError *ignored = nil;
        [NSFileManager.defaultManager removeItemAtPath:profilePath error:&ignored];
        if (ignored) {
            usleep(100000);
            [NSFileManager.defaultManager removeItemAtPath:profilePath error:nil];
        }
    }
}

static NSDictionary *OPRunCDP(OPPipeConnection *connection, NSDictionary *browser, NSString *origin, NSString *originHost, NSString *kind, NSDictionary *options, NSError **errorOut) {
    NSTimeInterval startupTimeout = MIN(kBrowserStartupSeconds, connection.deadline - OPMonotonicTime());
    NSDictionary *version = OPSendCommand(connection, @"Browser.getVersion", @{}, nil, startupTimeout, errorOut);
    if (!version) return nil;
    if (!OPSendCommand(connection, @"Target.setDiscoverTargets", @{ @"discover" : @YES }, nil, 5.0, errorOut)) return nil;

    NSDictionary *targetsReply = OPSendCommand(connection, @"Target.getTargets", @{}, nil, kBrowserStartupSeconds, errorOut);
    if (!targetsReply) return nil;
    NSArray<NSDictionary *> *targets = targetsReply[@"result"][@"targetInfos"];
    NSDictionary *target = nil;
    for (NSDictionary *candidate in targets) {
        if ([candidate[@"type"] isEqual:@"page"]) { target = candidate; break; }
    }
    if (!target) {
        NSDictionary *created = OPSendCommand(connection, @"Target.createTarget", @{
            @"url" : @"about:blank",
            @"newWindow" : @YES,
            @"width" : @480,
            @"height" : @320,
        }, nil, kBrowserStartupSeconds, errorOut);
        target = created[@"result"];
    }
    NSString *targetID = target[@"targetId"];
    if (![targetID isKindOfClass:NSString.class] || !targetID.length) {
        if (errorOut) *errorOut = OPMakeNSError(@"NotSupportedError", [NSString stringWithFormat:@"%@ did not expose a browser page for the passkey request.", browser[@"name"] ?: @"The selected browser"]);
        return nil;
    }
    connection.targetID = targetID;

    NSDictionary *attached = OPSendCommand(connection, @"Target.attachToTarget", @{ @"targetId" : targetID, @"flatten" : @YES }, nil, kBrowserStartupSeconds, errorOut);
    NSString *sessionID = attached[@"result"][@"sessionId"];
    if (![sessionID isKindOfClass:NSString.class] || !sessionID.length) {
        if (errorOut) *errorOut = OPMakeNSError(@"NotSupportedError", @"The selected browser could not attach to its passkey page.");
        return nil;
    }
    connection.sessionID = sessionID;
    OPSendCommand(connection, @"Target.activateTarget", @{ @"targetId" : targetID }, nil, 5.0, nil);
    NSDictionary *window = OPSendCommand(connection, @"Browser.getWindowForTarget", @{ @"targetId" : targetID }, nil, 5.0, nil)[@"result"];
    NSNumber *windowID = window[@"windowId"];
    if (windowID) OPSendCommand(connection, @"Browser.setWindowBounds", @{ @"windowId" : windowID, @"bounds" : @{ @"width" : @480, @"height" : @320, @"windowState" : @"normal" } }, nil, 5.0, nil);
    if (!OPSendCommand(connection, @"Page.enable", @{}, sessionID, 5.0, errorOut)) return nil;
    if (!OPSendCommand(connection, @"Runtime.enable", @{}, sessionID, 5.0, errorOut)) return nil;

    // A robots document gives the helper a committed page without running
    // relying-party scripts. Validate its final origin against the request's RP ID.
    NSString *robotsURL = [origin stringByAppendingString:@"/robots.txt"];
    NSString *rpID = [options[@"rpId"] isKindOfClass:NSString.class] ? options[@"rpId"] : originHost;
    NSDictionary *navigation = OPSendCommand(connection, @"Page.navigate", @{ @"url" : robotsURL }, sessionID, kOriginLoadSeconds, errorOut);
    if (!navigation) return nil;
    NSString *navigateError = navigation[@"result"][@"errorText"];
    if (navigateError.length) {
        if (errorOut) *errorOut = OPMakeNSError(@"NetworkError", @"The browser could not open the HTTPS relying-party origin.");
        return nil;
    }
    NSDictionary *loadedPage = OPWaitForOriginLoaded(connection, errorOut);
    if (!loadedPage) return nil;
    NSString *pageOrigin = loadedPage[@"origin"];
    NSString *pageHost = nil;
    NSError *originError = nil;
    NSString *normalizedPageOrigin = OPNormalizedOrigin(pageOrigin, &pageHost, &originError);
    if (!normalizedPageOrigin || !OPRelyingPartyMatchesOrigin(rpID, pageHost)) {
        if (errorOut) *errorOut = OPMakeNSError(@"SecurityError", @"Apple redirected the passkey page outside the relying-party scope.");
        return nil;
    }

    NSString *hostHTML = [pageHost stringByReplacingOccurrencesOfString:@"&" withString:@"&amp;"];
    hostHTML = [hostHTML stringByReplacingOccurrencesOfString:@"<" withString:@"&lt;"];
    hostHTML = [hostHTML stringByReplacingOccurrencesOfString:@">" withString:@"&gt;"];

    NSString *neutralHTML = [NSString stringWithFormat:@"<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><meta name='color-scheme' content='light dark'><title>Passkey</title><style>html,body{height:100%%;margin:0}body{display:grid;place-items:center;text-align:center;font:13px -apple-system,sans-serif;background:Canvas;color:CanvasText}main{padding:24px}h1{font-size:15px}p{opacity:.65}</style></head><body><main id='open-passwords-passkey-sentinel'><h1>Use your passkey for %@</h1><p>Complete the system passkey prompt to continue. Close this window to cancel.</p></main></body></html>", hostHTML];
    NSData *htmlJSONData = [NSJSONSerialization dataWithJSONObject:@[ neutralHTML ] options:0 error:errorOut];
    NSString *htmlJSON = htmlJSONData ? [[NSString alloc] initWithData:htmlJSONData encoding:NSUTF8StringEncoding] : nil;
    if (!htmlJSON) {
        if (errorOut && !*errorOut) *errorOut = OPMakeNSError(@"DataError", @"The helper could not prepare its passkey page.");
        return nil;
    }
    NSString *replacePageExpression = [NSString stringWithFormat:@"(()=>{document.open();document.write(%@[0]);document.close();history.replaceState(null,'','/');return {written:true};})()", htmlJSON];
    if (!OPRuntimeValue(connection, replacePageExpression, NO, 5.0, errorOut)) return nil;
    if (!OPWaitForNeutralPage(connection, normalizedPageOrigin, errorOut)) return nil;
    if (!OPActivateAndWaitForFocus(connection, errorOut)) return nil;

    NSDictionary *json = @{ @"options" : options, @"origin" : normalizedPageOrigin, @"kind" : kind };
    NSData *jsonData = [NSJSONSerialization dataWithJSONObject:json options:0 error:nil];
    if (!jsonData || jsonData.length > kMaximumRequestBytes) {
        if (errorOut) *errorOut = OPMakeNSError(@"DataError", @"The passkey request is too large.");
        return nil;
    }
    NSString *encoded = [jsonData base64EncodedStringWithOptions:0];
    NSString *function = [kind isEqual:@"create"] ? @"create" : @"get";
    NSString *parser = [kind isEqual:@"create"] ? @"parseCreationOptionsFromJSON" : @"parseRequestOptionsFromJSON";
    NSString *expression = [NSString stringWithFormat:@"(async()=>{try{const raw=JSON.parse(new TextDecoder().decode(Uint8Array.from(atob('%@'),c=>c.charCodeAt(0))));if(location.origin!==raw.origin||!isSecureContext)throw new DOMException('The page origin changed.','SecurityError');const o=raw.options;if(!globalThis.PublicKeyCredential||typeof PublicKeyCredential.%@!=='function')throw new DOMException('This browser does not support WebAuthn JSON parsing.','NotSupportedError');const p=PublicKeyCredential.%@(o);const c=await navigator.credentials.%@({publicKey:p});if(!c)throw new DOMException('No passkey was returned.','NotAllowedError');if(typeof c.toJSON!=='function')throw new DOMException('This browser cannot serialize passkey results.','NotSupportedError');return {credential:c.toJSON()};}catch(e){return {error:{name:(e&&typeof e.name==='string'&&e.name)||'NotAllowedError',message:(e&&typeof e.message==='string'&&e.message)||'Passkey request failed.'}}}})()", encoded, parser, parser, function];
    NSDictionary *requestResult = OPRuntimeValue(connection, expression, YES, kMaximumOperationSeconds, errorOut);
    if (!requestResult) return nil;
    NSDictionary *requestError = requestResult[@"error"];
    if ([requestError isKindOfClass:NSDictionary.class]) {
        if (errorOut) *errorOut = OPMakeNSError(requestError[@"name"] ?: @"NotAllowedError", requestError[@"message"] ?: @"The passkey request failed.");
        return nil;
    }
    NSDictionary *credential = requestResult[@"credential"];
    if (![credential isKindOfClass:NSDictionary.class]) {
        if (errorOut) *errorOut = OPMakeNSError(@"DataError", @"The browser returned an invalid passkey result.");
        return nil;
    }
    return @{ @"credential" : credential };
}

NSDictionary *OPRunPasskeyRequest(NSDictionary *browser, NSString *originInput, NSString *kind, NSDictionary *inputOptions, volatile int *cancelled) {
    if (![kind isEqual:@"create"] && ![kind isEqual:@"get"]) return OPError(@"TypeError", @"Passkey request kind must be create or get.");
    if (![browser isKindOfClass:NSDictionary.class] || ![inputOptions isKindOfClass:NSDictionary.class]) return OPError(@"TypeError", @"The selected browser or WebAuthn request is invalid.");
    if (cancelled && __atomic_load_n(cancelled, __ATOMIC_ACQUIRE) != 0) return OPError(@"AbortError", @"The passkey request was canceled.");

    NSError *error = nil;
    NSString *originHost = nil;
    NSString *origin = OPNormalizedOrigin(originInput, &originHost, &error);
    if (!origin) return OPErrorFromNSError(error, @"SecurityError");
    NSDictionary *options = OPNormalizedOptions(kind, inputOptions, originHost, &error);
    if (!options) return OPErrorFromNSError(error, @"TypeError");

    NSString *profilePath = OPCreateTemporaryProfile();
    if (!profilePath) return OPError(@"UnknownError", @"Could not create an isolated passkey browser profile.");

    OPPipeConnection *connection = [OPPipeConnection new];
    connection.cancelled = cancelled;
    connection.deadline = OPMonotonicTime() + kMaximumOperationSeconds;
    NSDictionary *result = nil;
    @try {
        if (!OPSpawnBrowser(connection, browser, profilePath, &error)) {
            result = OPErrorFromNSError(error, @"NotSupportedError");
        } else {
            result = OPRunCDP(connection, browser, origin, originHost, kind, options, &error);
            if (!result) result = OPErrorFromNSError(error, @"NotAllowedError");
        }
    } @catch (NSException *exception) {
        result = OPError(@"UnknownError", exception.reason ?: @"The passkey browser failed unexpectedly.");
    } @finally {
        OPStopBrowser(connection, profilePath);
    }
    return result ?: OPError(@"UnknownError", @"The passkey request did not return a result.");
}
