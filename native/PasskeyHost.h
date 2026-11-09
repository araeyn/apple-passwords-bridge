#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

// Starts the selected Chromium broker in an isolated profile, performs one
// WebAuthn create/get request at the supplied HTTPS origin, and tears it down.
// The return value is always either { credential: ... } or
// { error: { name: ..., message: ... } }.
FOUNDATION_EXPORT NSDictionary *OPRunPasskeyRequest(
    NSDictionary *browser,
    NSString *origin,
    NSString *kind,
    NSDictionary *options,
    volatile int * _Nullable cancelled
);

NS_ASSUME_NONNULL_END
