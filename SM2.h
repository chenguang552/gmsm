#ifndef _GM_SM2_H_ 
#define _GM_SM2_H_
#include "openssl/asn1t.h"
#include "openssl/x509.h"
#include "openssl/rand.h"
#include "openssl/bn.h"
#include "openssl/ec_lcl.h"
#include "openssl/ec.h"
#include "openssl/err.h"
#include "openssl/ecdsa.h"
#include "openssl/ecdh.h"
#include "openssl/asn1.h"

#include <string>

#define ULONG unsigned long
#define BYTE unsigned char*

#define	ASC_CHAR_TO_HEX(ch)		(ch>='0'&&ch<='9')?ch-'0':(ch>='a'&&ch<='f')?ch-'a'+10:(ch>='A'&&ch<='F')?ch-'A'+10:0xff

// SM4
#define ALGID_SM4_ECB				0x0000000B
#define ALGID_SM4_CBC				0x0000000C

// SM4加密算法的OID
#define SM4_ECB_OID					"1.2.156.10197.1.104"

#define OID_ECC_ALG					"1.2.840.10045.2.1"			// ECC椭圆曲线密码算法

#define OID_P7SM2_ALG				"1.2.156.10197.1.301.1"		// ECC椭圆曲线密码算法
#define OID_SM2_ALG					"1.2.156.10197.1.301"		// SM2椭圆曲线密码算法
#define OID_SM3_SM2_ALG				"1.2.156.10197.1.501"		// SM3WithSM2
#define OID_SM3_ALG					"1.2.156.10197.1.401"		// SM3摘要算法

#define	ALGID_HASH_SM3				0x00000006		//SM3算法

#define MAX_IV_LEN	32
// SM2签名默认用户ID，详见国密局SM2密码相关规范
#define SM2_DEFAULT_USER_ID		"1234567812345678"

#define ECC_MAX_MODULUS_BITS_LEN 512

#define ECC_MAX_XCOORDINATE_BITS_LEN 512
#define ECC_MAX_YCOORDINATE_BITS_LEN 512


typedef struct Struct_ECCPRIVATEKEYBLOB{
	ULONG	BitLen;
	BYTE	PrivateKey[ECC_MAX_MODULUS_BITS_LEN/8];
}ECCPRIVATEKEYBLOB, *PECCPRIVATEKEYBLOB;

typedef struct Struct_ECCPUBLICKEYBLOB{
	ULONG	BitLen;
	BYTE	XCoordinate[ECC_MAX_XCOORDINATE_BITS_LEN/8];
	BYTE	YCoordinate[ECC_MAX_YCOORDINATE_BITS_LEN/8];
}ECCPUBLICKEYBLOB, *PECCPUBLICKEYBLOB;

typedef struct Struct_ECCCIPHERBLOB{
	BYTE  XCoordinate[ECC_MAX_XCOORDINATE_BITS_LEN/8]; 
	BYTE  YCoordinate[ECC_MAX_XCOORDINATE_BITS_LEN/8]; 
	BYTE  HASH[32]; 
	ULONG CipherLen;
	BYTE  Cipher[1];
} ECCCIPHERBLOB, *PECCCIPHERBLOB;
// 
typedef struct SKF_ENVELOPEDKEYBLOB{
	ULONG Version;                
	ULONG ulSymmAlgID;           
	ULONG ulBits;					
	BYTE cbEncryptedPriKey[64];    
	ECCPUBLICKEYBLOB PubKey;     
	ECCCIPHERBLOB ECCCipherBlob;   
}ENVELOPEDKEYBLOB, *PENVELOPEDKEYBLOB;

typedef struct Struct_ECCSIGNATUREBLOB{
	BYTE r[ECC_MAX_XCOORDINATE_BITS_LEN/8];
	BYTE s[ECC_MAX_XCOORDINATE_BITS_LEN/8];
} ECCSIGNATUREBLOB, *PECCSIGNATUREBLOB;

typedef struct Struct_BLOCKCIPHERPARAM{
	BYTE	IV[MAX_IV_LEN];
	ULONG	IVLen;
	ULONG	PaddingType;
	ULONG	FeedBitLen;
} BLOCKCIPHERPARAM, *PBLOCKCIPHERPARAM;


// 定义SM2算法相关的ASN1结构 开始
typedef struct X509_algor_sm2_st
{
	ASN1_OBJECT *alg1;
	ASN1_OBJECT *alg2;
} X509_ALGOR_SM2;
DECLARE_ASN1_FUNCTIONS(X509_ALGOR_SM2);

typedef struct X509_pubkey_sm2_st
{
	X509_ALGOR_SM2 *algor;
	ASN1_BIT_STRING *public_key;
} X509_PUBKEY_SM2;
DECLARE_ASN1_FUNCTIONS(X509_PUBKEY_SM2);

// 请求内容
typedef struct X509_req_info_sm2_st
{
	ASN1_INTEGER *version;
	X509_name_st *subject;
	X509_PUBKEY_SM2 *pubkey;
} X509_REQ_INFO_SM2;
DECLARE_ASN1_FUNCTIONS(X509_REQ_INFO_SM2);

// SM2 证书请求文件
typedef struct X509_req_sm2_st
{
	X509_REQ_INFO_SM2 *req_info;
	X509_ALGOR *sig_alg;
	ASN1_BIT_STRING *signature;
} X509_REQ_SM2;
DECLARE_ASN1_FUNCTIONS(X509_REQ_SM2);
// 定义SM2算法相关的ASN1结构 结束

// 定义ASN1结构的加密数据
typedef struct ASN1_SM2_CIPHER
{
	BIGNUM *x;
	BIGNUM *y;
	ASN1_OCTET_STRING *hash;
	ASN1_OCTET_STRING *cipher;
} ASN1_SM2_CIPHER_st;
DECLARE_ASN1_FUNCTIONS(ASN1_SM2_CIPHER);

// 定义SM2私钥
typedef struct SM2_private_key_st
{
	ASN1_INTEGER *version;
	ASN1_INTEGER *prikey;
	STACK_OF(ASN1_TYPE) *alg;
	STACK_OF(ASN1_TYPE) *pubkey;
}SM2_PRIVATE_KEY;
DECLARE_ASN1_FUNCTIONS(SM2_PRIVATE_KEY);

// 定义SM2公钥
typedef struct SM2_public_key_st
{
	X509_ALGOR_SM2 *algor;
	ASN1_BIT_STRING *pubkey;
}SM2_PUBLIC_KEY;
DECLARE_ASN1_FUNCTIONS(SM2_PUBLIC_KEY);

// SM2软证书, 这里采用自定义p12格式
typedef struct SM2_pkcs12_st
{
	ASN1_INTEGER* version;
	ASN1_OCTET_STRING* prikey;
	X509* cert;
}SM2_PKCS12;
DECLARE_ASN1_FUNCTIONS(SM2_PKCS12);

class SM2
{
public:
	SM2(void);
	virtual ~SM2(void);

	static int SM2_GenKeyPair(unsigned char* pucPubKey, unsigned int* puiPubKeyLen, unsigned char* pucPriKey, unsigned int* puiPriKeyLen);

	static int SM2_Sign(unsigned char* pucOriData, unsigned int uiOriDataLen , unsigned char* pucPriKey, unsigned int uiPriKeyLen, unsigned char* pucSign, unsigned int* puiSignLen);

	static int SM2_Verify(unsigned char* pucOriData, unsigned int uiOriDataLen, unsigned char *pucSign, unsigned int uiSignLen, unsigned char* pucPubKey, unsigned int uiPubKeyLen);

	static int SM2EncryptByHexPubKey(char* OriData, int OriDataLen , char* pucPubKey, int puiPubKeyLen, char* cipherData, int* cipherDataLen);

	static int SM2DecryptByHexPrivKey(char* cipherData, int cipherDataLen , char* pucPriKey, int uiPriKeyLen, char* OriData, int* OriDataLen);

	static int SM2SignByHexPrivKey(char* pucOriData, int uiOriDataLen , char* pucPriKey, int uiPriKeyLen, char* pucSign, int* puiSignLen);

	static int SM2VerifyByHexPubKey(char* pucOriData, int uiOriDataLen, char *pucSign, int uiSignLen, char* pucPubKey, int uiPubKeyLen);

	static int SM2Sign_HexPriK_DerSigndata(char *pucOriData, int uiOriDataLen, char *pucPriKey, int uiPriKeyLen, char *pucSign, int *puiSignLen);
	
	static int SM2Verify_HexPubk_DerSigndata(char* pucOriData, int uiOriDataLen, char *pucSign, int uiSignLen, char* pucPubKey, int uiPubKeyLen);

	static int SM2SignByP7_HexPriK(char* inData, int dataLen,char* cert, int certLen, char *pucPriKey, int uiPriKeyLen,char* p7SignData, int* p7SignDataLen);

	static int SM2VerifyByP7(char* p7Data,int p7DataLen);

	static int SM2CertGetPublicKey(char* cert, int certLen, char* hexPublicKeyStr, int* hexPublicKeyStrLen);

private:
	static int GetSM2PublicECKeyFromXY(EC_KEY** eckey, char* pucPubKey, int uiPubKeyLen);

	static int GetSM2PrivateECKeyFromD(EC_KEY **eckey, char *pucPriKey, int uiPriKeylen);

	static int GetSM2Group(EC_GROUP** group);

	static int GetSM2PublicECKey(EC_KEY** eckey, unsigned char* pucPubKey, unsigned int uiPubKeyLen);

	static int GetSM2PrivateECKey(EC_KEY** eckey, unsigned char* pucPriKey, unsigned int uiPriKeylen);

	static int GetSM3HashForSign(unsigned char* pucOriData, unsigned int uiOriDataLen,
		unsigned char* pucUserId, unsigned int uiUserIdLen,
		EC_KEY* eckey, unsigned char* pucHashData);
	
	static int SM2Sign(const unsigned char* digest, int digestlen, EC_KEY* eckey, ECDSA_SIG** sig);

	static int SM2Verify(const unsigned char* digest, int digestlen, const ECDSA_SIG* sig, EC_KEY* eckey);

	static int SM2Encrypt(unsigned char* OriData, unsigned int OriDataLen ,EC_KEY* eckey, unsigned char* cipherData, unsigned int* cipherDataLen);

	static int SM2Decrypt(unsigned char* cipherData, unsigned int cipherDataLen ,EC_KEY* eckey, unsigned char* OriData, unsigned int* OriDataLen);

	static int Hex2Bin(unsigned char* pbDest, const char* szSrc);

	static int Bin2HexStr(unsigned char* binData, unsigned int binDataLen, unsigned char* hexStrData,unsigned int* hexStrDataLen);
	
	static int HexStrBin(unsigned char* hexStrData,unsigned int hexStrDataLen,unsigned char* binData,unsigned int* binDataLen);
	
	static int KDF(const char *cdata, int datalen, int keylen, char *retdata);

	static int i2dSignData(ECDSA_SIG* sig,unsigned char * signature, int *sLen);

	static int GetDerPubkey(const char* stDerCert,int stDerCertLen,char* pubkey,int *pubkeyLen);
	// 组P7 签名数据
	static int MakeP7SignData(unsigned char* pucInData, unsigned int uiInDataLen, 
		unsigned char* pucSignData, unsigned int uiSignDataLen, 
		unsigned char* pucCert, unsigned int uiCertLen,
		unsigned char* pucP7SignData, unsigned int* puiP7SignDataLen);
	
	// 解P7 签名数据
	static int OpenP7SignData(unsigned char* pucP7SignData, unsigned int uiP7SignDataLen, 
		unsigned char* pucInData, unsigned int* puiInDataLen, 
		unsigned char* pucSignData, unsigned int* puiSignDataLen, 
		unsigned char* pucCert, unsigned int* puiCertLen);

};

#endif//!_GM_SM2_H_