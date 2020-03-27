import java.util.Base64;

class jni_sign_api{

    /*
    *   签名验签均采用预处理的SM3摘要算法+SM2算法  曲线为p256椭圆曲线
    */

    /*
    * SM3withSM2 签名软算法
    *   @pucOriData       [String]    签名原文的base64编码
    *   @uiOriDataLen     [int]       签名原文Base64编码长度
    *   @pucPriKey        [String]    十六进制字符串私钥
    *   @uiPriKeyLen      [int]       十六进制字符串私钥长度 通常为64个字符
    * RETURN: [String]   der格式p1签名值base64编码
    */
    public native String SM2Sign(String pucOriData, int uiOriDataLen, String pucPriKey, int uiPriKeyLen);

    /*
    * SM3withSM2 验签软算法
    *   @pucOriData       [String]    签名原文的base64编码
    *   @uiOriDataLen     [int]       签名原文Base64编码长度
    *   @pucSign          [String]    der格式p1签名值base64编码
    *   @uiSignLen        [int]       der格式p1签名值base64编码长度 通常为140个字符
    *   @pucPubKey        [String]    十六进制字符串公钥
    *   @uiPubKeyLen      [int]       十六进制字符串公钥长度 通常为130个字符
    * RETURN: [int]      验签结果 0 表示成功 其他均表示失败
    */
    public native int SM2Verify(String pucOriData, int uiOriDataLen, String pucSign, int uiSignLen, String pucPubKey, int uiPubKeyLen);

    /*
    * SM3withSM2 P7 签名软算法
    *   @inData           [String]    签名原文的base64编码
    *   @dataLen          [int]       签名原文Base64编码长度
    *   @cert             [String]    pkcs7证书base64编码
    *   @certLen          [int]       pkcs7证书base64编码长度
    *   @pucPriKey        [String]    十六进制字符串私钥
    *   @uiPriKeyLen      [int]       十六进制字符串私钥长度 通常为64个字符
    * RETURN: [String]   签名P7包base64编码
    */
    public native String SM2SignP7(String inData, int dataLen,String cert, int certLen,String pucPriKey, int uiPriKeyLen);

    /*
    * SM3withSM2 P7 验签软算法
    *   @p7Data           [String]    签名P7包base64编码
    *   @p7DataLen        [int]       签名P7包base64编码长度
    * RETURN: [int]      验签结果 0 表示成功 其他均表示失败
    */
    public native int SM2VerifyP7(String p7Data, int p7DataLen);

    /*
    * 获取SM2证书内公钥
    *   @cert             [String]    pkcs7证书base64编码
    *   @certLen          [int]       pkcs7证书base64编码长度
    * RETURN: [String]   十六进制公钥字符串
    */
    public native String SM2CertGetPublicKey(String cert, int certLen);

    /*
    * SM3摘要
    *   @inData           [String]    要进行摘要的原文base64编码
    *   @inDataLen        [String]    要进行摘要的原文base64编码长度
    * RETURN: [String]   SM3摘要值的base64编码
    */
    public native String SM3Hash(String inData, int inDataLen);


    static {
        System.loadLibrary("jni_sign_api");
    }
    
    public static String signP1="MEQCIHRtdvgqFYnNudKLMoszKXKn/IcvMuGexaX8FCtvl1X2AiAZ9xg/aaFmdelzewnyffn70XA4\nZ/jLo2MXU8occJGBWQ==";
    public static String cert="MIICqTCCAk2gAwIBAgIEAZdgQzAMBggqgRzPVQGDdQUAMIGKMQswCQYDVQQGEwJDTjEOMAwGA1UECAwFSGVOYW4xEjAQBgNVBAcMCVpoZW5nWmhvdTE3MDUGA1UECgwuSGVOYW4gUHJvdmluY2UgSW5mb3JtYXRpb24gRGV2ZWxvcG1lbnQgQ28uIEx0ZDEPMA0GA1UECwwGSE5YQUNBMQ0wCwYDVQQDDARYQUNBMB4XDTIwMDMyNjA0MTk0NloXDTIxMDMyNjA0MTk0NlowdDELMAkGA1UEBhMCQ04xEjAQBgNVBAgMCeays+WNl+ecgTESMBAGA1UEBwwJ6YOR5bee5biCMRswGQYDVQQKDBLnpL7ljLrkuKrkurrnrb7lkI0xDzANBgNVBAsMBjQxMDE4NDEPMA0GA1UEAwwGNDEwMTg0MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAE7+2dUFKGvrZVusVAtR132ryOEeXiWBuCUx/FwGGV0Fog3M8U1KsAia0DypDU3QM0Dj6e76wVne6/RDPNC45bh6OBszCBsDAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwHwYDVR0jBBgwFoAUbPNNOEq/CbITtm+mvEtckjiBWlswNwYDVR0fBDAwLjAsoCqgKIYmaHR0cDovL2NybC5obnhhY2EuY29tL2NybC94YWNhX3NtMi5jcmwwCwYDVR0PBAQDAgbAMB0GA1UdDgQWBBSSQdMQyfxSGpbtPc28YTM14MjEzDAJBgNVHRMEAjAAMAwGCCqBHM9VAYN1BQADSAAwRQIhAOwEI6cNBxvDvOPFsmfMNNdhR8XiwP0uAwwu2u02A3T7AiAMizwMQ0ah/blJ6pLo+Nr9y9YDM/g2/XoyO1whKq+MkQ==\\\",\\\"encKey\\\":\\\"AQAAAAEEAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAoGqvemuerzUwNAVQ82xteFAXej8kPR2sAXJHK5+CP3AABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGB23qtTDAPkX+krDDCkH8lHp46hHWcro1v+l/D8gKIvAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD/x3nVyZ8QAfJ11fsL+Z42HVTGx6sRRYufPUQgKvp04gAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAa+NkZVCRkmMExtonCgFlRkWBg1OikCc7NkfU26Uqt1sAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB9Q8Hg/j3IK7rRlo/jS+rbG5iR1byyf6p9A+ezMdQAsNQohDoUQ6uRqx7njA9NoxCKQt5ivwxHtYOCioqDe1tUQAAAAWRL06WBMxtJ7BI/3yx762g==";
    public static String yw="投票测试";

    public static void main(String args[]){

        jni_sign_api api = new jni_sign_api();

        java.util.Base64.Encoder encoder = Base64.getEncoder();
        String b64PlainText = encoder.encodeToString(yw.getBytes());

        // String s = api.SM2Sign(b64PlainText,b64PlainText.length(),PriKey,PriKey.length());
        // System.out.println(s);

        String pk = api.SM2CertGetPublicKey(cert, cert.length());
        System.out.println(pk);

        // String HashData = api.SM3Hash(yw,yw.length());
        // System.out.println(HashData);

        int r = api.SM2Verify(b64PlainText,b64PlainText.length(),signP1,signP1.length(),pk,pk.length());
        System.out.println(r);

        // s = api.SM2SignP7(b64PlainText,b64PlainText.length(),cert,cert.length(),PriKey,PriKey.length());
        // System.out.println(s);

        // r = api.SM2VerifyP7(s,s.length());
        // System.out.println(r);
    }
}
