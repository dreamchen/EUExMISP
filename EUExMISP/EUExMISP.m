//
//  EUExMISP.m
//  EUExMISP
//
//  Created by chenerlei on 14/12/22.
//  Copyright (c) 2014年 wedge. All rights reserved.
//

#import "EUExMISP.h"

#import <MISP/Context.h>
#import <MISP/AuthentificationManager.h>
#import <MISP/UserAccount.h>
#import <MISP/SocketProxyManager.h>
#import <MISP/NSMutableData+Crypto.h>


@implementation EUExMISP


//初始化服务器、端口号和秘钥
//in ip/port/key
//out JSON
-(void)initMISP:(NSMutableArray *)array{
    NSLog(@"uexMISP:initMISP is begin!");
    if ([array isKindOfClass:[NSMutableArray class]] && [array count]>0) {
        NSString *ip = [array objectAtIndex:0];
        NSString *port = [array objectAtIndex:1];
        NSString *key = [array objectAtIndex:2];
        
        NSLog(@"uexMISP:initMISP ip:%@/port:%@/key:%@",ip,port,key);
        
        [Context setIp:ip prot:port];
        [Context setProductKey:key];
        Context *ctx = [Context getInstance];
        
        NSString *calStr = [[NSString alloc] initWithFormat:@"{\"ip\":\"%@\",\"port\":\"%@\",\"key\":\"%@\"}",ip,port,key];
        NSLog(@"uexMISP:initMISP calStr:%@",calStr);
        if (ctx!=nil) {
            [self jsSuccessWithName:@"uexMISP.cbInitMISP" opId:1 dataType:0 strData:calStr];
        }else{
            [self jsSuccessWithName:@"uexMISP.cbInitMISP" opId:0 dataType:0 strData:calStr];
        }
    }
}

//登陆认证
//in username/userpwd
-(void)login:(NSMutableArray *)array{
    NSLog(@"uexMISP:login is begin!");
    if ([array isKindOfClass:[NSMutableArray class]] && [array count]>0) {
        NSString *username = [array objectAtIndex:0];
        NSString *userpwd = [array objectAtIndex:1];
        
        NSLog(@"uexMISP:login username:%@/userpwd:%@",username,userpwd);
        
        AuthentificationManager *actManager = [AuthentificationManager getInstance];
        id<ICertify> certify = [actManager getUserNameCertifyPrivder];
        UserAccount *account = [[UserAccount alloc]initWithUserName:username password:userpwd];
        
        int iRet = [certify loginWithUserAccount:account];  //登录结果表示返回
        int nRet = [certify getLoginAccoutStutus];
        
        
        if(nRet == 10) {
            NSLog(@"uexMISP:login offline");
            //离线登陆
            NSString *userJson = [[NSString alloc] initWithFormat:@"{\"username\":\"%@\",\"userpwd\":\"%@\",\"online\":\"off\"}",username,userpwd];
            [self jsSuccessWithName:@"uexMISP.cbLogin" opId:1 dataType:0 strData:userJson];
        }
        else if( nRet == 20) {
            NSLog(@"uexMISP:login online");
            //在线登录成功
            NSString *userJson = [[NSString alloc] initWithFormat:@"{\"username\":\"%@\",\"userpwd\":\"%@\",\"online\":\"on\"}",username,userpwd];
            [self startProxy];
            [self jsSuccessWithName:@"uexMISP.cbLogin" opId:2 dataType:0 strData:userJson];
        } else {
            //登陆失败
            
            NSLog(@"uexMISP:login Login Error!");
            NSLog(@"uexMISP:login ErrorCode:%d,ErrorDesc:%@",iRet,[self loginErrInformation:iRet]);
            NSString *errorMsg = [[NSString alloc]initWithFormat:@"{\"errorCode\":%d,\"msg\":\"%@\"}",iRet,[self loginErrInformation:iRet]];
            
            [self jsSuccessWithName:@"uexMISP.cbLogin" opId:0 dataType:0 strData:errorMsg];
            
            //[self jsFailedWithOpId:0 errorCode:iRet errorDes:[self loginErrInformation:iRet]];
        }
    }
}

//注销认证
-(void)loginOut:(NSMutableArray *)array{
    NSLog(@"uexMISP:loginOut is begin");
    [self stopProxy];
    NSLog(@"uexMISP:loginOut is end");
    /*
     if ([array isKindOfClass:[NSMutableArray class]] && [array count]>0) {
     NSString *username = [array objectAtIndex:0];
     NSString *userpwd = [array objectAtIndex:1];
     
     AuthentificationManager *actManager = [AuthentificationManager getInstance];
     id<ICertify> certify = [actManager getUserNameCertifyPrivder];
     UserAccount *account = [[UserAccount alloc]initWithUserName:@"test2" password:@"123456789"];
     int num = [certify logoutWithUserAccount:account];//注销当前登录的用户
     if(num == 0){
     
     }else{
     
     }
     }
     */
}

//修改口令
-(void)changePWD:(NSMutableArray *)array{
    if ([array isKindOfClass:[NSMutableArray class]] && [array count]>0) {
        NSString *oldPwd = [array objectAtIndex:0];
        NSString *newPwd = [array objectAtIndex:1];
        
        AuthentificationManager *actManager = [AuthentificationManager getInstance];
        id<ICertify> certify = [actManager getUserNameCertifyPrivder];
        int changePWCount = [certify changePassword:oldPwd newPassword:newPwd];
        NSLog(@"changeLog:%d",changePWCount);
        if(changePWCount == 0){
            //密码修改成功
            [self jsSuccessWithName:@"uexMISP.cbChangePWD" opId:1 dataType:0 strData:@"{\"msg\":\"密码修改成功\"}"];
        }else{
            //密码修改失败
            [self jsSuccessWithName:@"uexMISP.cbChangePWD" opId:0 dataType:0 strData:@"{\"msg\":\"密码修改失败\"}"];
        }
    }
}

//文件加密
-(void)encryptFile:(NSMutableArray *)array{
    if ([array isKindOfClass:[NSMutableArray class]] && [array count]>0) {
        NSString *filePath = [array objectAtIndex:0];
        NSString *saveFilePath = [array objectAtIndex:1];
        NSString *keyLevel = [array objectAtIndex:2];
        
        NSMutableData *encryptData=[NSMutableData dataWithContentsOfFile:filePath];
        BOOL isencry =[encryptData encryptWriteToFile:saveFilePath level:keyLevel];
        if (isencry) {
            //加密成功
            
        }else{
            //加密失败
        }
    }
}

//文件解密
-(void)decryptFile:(NSMutableArray *)array{
    if ([array isKindOfClass:[NSMutableArray class]] && [array count]>0) {
        NSString *filePath = [array objectAtIndex:0];
        NSMutableData *data=[NSMutableData dataWithEncryptContentsOfFile: filePath];
        if(data==nil){
            
        }else{
            
        }
    }
}

//开启通道
-(void)startProxy{
    NSLog(@"uexMISP:startProxy begin");
    SocketProxyManager *socketProxy =[SocketProxyManager getInstance];
    [socketProxy start];
    NSLog(@"uexMISP:SafeTunnel start！ -- end");
}

//关闭通道
-(void)stopProxy{
    NSLog(@"uexMISP:stopProxy begin");
    SocketProxyManager *socketProxy = [SocketProxyManager getInstance];
    [socketProxy stop];
    NSLog(@"uexMISP:SafeTunnel stop!  -- end");
}


//登录错误信息
-(NSString *)loginErrInformation:(int)errorNumber{
    NSString *errorStr;
    switch (errorNumber) {
        case 2054:
            errorStr = @"网络连接失败";
            break;
        case 2800:
            errorStr = @"未知";
            break;
        case 2801:
            errorStr= @"包错误";
            break;
        case 2802:
            errorStr = @"签名错误";
            break;
        case 2803:
            errorStr = @"操作码错误";
            break;
        case 2804:
            errorStr = @"认证类型错误";
            break;
        case 2805:
            errorStr = @"guid错误" ;
            break;
        case 2806:
            errorStr = @"guid已绑定" ;
            break;
        case 2807:
            errorStr = @"设备已删除" ;
            break;
        case 2808:
            errorStr = @"设备已注销" ;
            break;
        case 2809:
            errorStr = @"设备已挂失" ;
            break;
        case 2810:
            errorStr = @"返回数据出错" ;
            break;
        case 2811:
            errorStr = @"账户已在认证" ;
            break;
        case 2812:
            errorStr = @"用户已删除" ;
            break;
        case 2813:
            errorStr = @"用户名错误,没有这个用户" ;
            break;
        case 2814:
            errorStr = @"密码错误";
            break;
        case 2815:
            errorStr = @"数据库操作失败";
            break;
        case 2816:
            errorStr = @"无对应SID,账户不存在" ;
            break;
        case 2817:
            errorStr = @"新建证书存储区错误" ;
            break;
        case 2818:
            errorStr = @"验证证书失败" ;
            break;
        case 2819:
            errorStr = @"认证模块, 解析GroupID失败" ;
            break;
        case 2820:
            errorStr = @"认证模块, 用户组树节点指针为空" ;
            break;
        case 2821:
            errorStr = @"认证模块, 修改用户状态失败" ;
            break;
        case 2900:
            errorStr = @"未知错误" ;
            break;
        case 2901:
            errorStr = @"数据库更新错误" ;
            break;
        case 2902 :
            errorStr = @"数据库查询错误" ;
            break;
        case 2903:
            errorStr = @"认证失败" ;
            break;
        case 2904:
            errorStr = @"认证成功后,创建用户数据库异常错误" ;
            break;
        case 2925 :
            errorStr = @"用户状态检查失败";
            break;
        case 2926:
            errorStr = @"设备状态检查失败";
            break;
        case 2927:
            errorStr = @"用户已禁用";
            break;
        case 2928:
            errorStr = @"用户已锁定";
            break;
        case 2929:
            errorStr = @"用户已在线";
            break;
        case 2940:
            errorStr = @"建树失败";
            break;
        case 2941:
            errorStr = @"没有可用的服务器";
            break;
        case 2942:
            errorStr = @"将服务器信息放到节点上失败";
            break;
        default:
            errorStr = @"错误";
            break;
    }//end switch
    return errorStr;
}

@end
