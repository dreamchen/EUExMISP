//
//  AppProxyCap.h
//  MISP
//
//  Created by 孙默竹 on 13-8-26.
//
//

#import <Foundation/Foundation.h>

typedef enum {AppProxy_NONE, AppProxy_HTTP, AppProxy_SOCKS, AppProxy_PAC} AppProxyType;

@interface AppProxyCap : NSObject

//Initialize, invoke as early as possible in your app
+ (void) activate;

//Set HTTP or Socks proxy to use in app-wide call
+ (void) setProxy:(AppProxyType)type Host:(NSString *)host Port:(int)port;
+ (void) setPACURL:(NSString *)pacURL;
+ (void) setNoProxy;

@end