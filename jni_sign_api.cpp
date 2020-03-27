#include "jni_sign_api.h"
#include "SM2.h"
#include "SM3.h"
#include <iostream>
#include <string.h>
#include <memory>


static char base64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int Base64Encode(unsigned char *bin_data, int bin_size, char *base64_data, unsigned int *base64_size)
{
	long i, j, k;
	long blk_size, remain_size;
	unsigned char *p;
	unsigned char left[3];
	int i64;

	blk_size = bin_size / 3;
	remain_size = bin_size % 3;
	p = bin_data;
	j = 0;
	i64 = 0;

	for (i = 0; i < blk_size; i++)
	{
		k = (p[0] & 0xFC) >> 2;
		base64_data[j++] = base64_table[k];

		k = ((p[0] & 0x03) << 4) | (p[1] >> 4);
		base64_data[j++] = base64_table[k];

		k = ((p[1] & 0x0F) << 2) | (p[2] >> 6);
		base64_data[j++] = base64_table[k];

		k = p[2] & 0x3F;
		base64_data[j++] = base64_table[k];

		i64++;
		i64++;
		i64++;
		i64++;

		p += 3;
	}

	switch (remain_size)
	{
	case 0:
		break;

	case 1:
		left[0] = p[0];
		left[1] = 0;
		p = left;

		k = (p[0] & 0xFC) >> 2;
		base64_data[j++] = base64_table[k];
		k = ((p[0] & 0x03) << 4) | (p[1] >> 4);
		base64_data[j++] = base64_table[k];

		base64_data[j++] = '=';
		base64_data[j++] = '=';
		break;

	case 2:
		left[0] = p[0];
		left[1] = p[1];
		left[2] = 0;
		p = left;

		k = (p[0] & 0xFC) >> 2;
		base64_data[j++] = base64_table[k];
		k = ((p[0] & 0x03) << 4) | (p[1] >> 4);
		base64_data[j++] = base64_table[k];
		k = ((p[1] & 0x0F) << 2) | (p[2] >> 6);
		base64_data[j++] = base64_table[k];
		base64_data[j++] = '=';
		break;

	default:
		break;
	}

	base64_data[j] = 0;
	*base64_size = j;

	return 0;
}

static int Base64Decode(const char *base64_data, int base64_size, unsigned char *bin_data, unsigned int *bin_size)
{
	long i, j, k, m, n, l;
	unsigned char four_bin[4];
	char four_char[4];
	char c;

	j = base64_size;
	i = 0;
	l = 0;

	for (;;)
	{
		if ((i + 4) > j)
		{
			break;
		}

		k = 0;
		while (k < 4)
		{
			if (i == j)
			{
				break;
			}

			c = base64_data[i++];
			if ((c == '+') || (c == '/') || (c == '=') ||
				((c >= '0') && (c <= '9')) ||
				((c >= 'A') && (c <= 'Z')) ||
				((c >= 'a') && (c <= 'z')))
			{
				four_char[k++] = c;
			}
		}

		if (k != 4)
		{
			return -1;
		}

		n = 0;
		for (k = 0; k < 4; k++)
		{
			if (four_char[k] != '=')
			{
				for (m = 0; m < 64; m++)
				{
					if (base64_table[m] == four_char[k])
					{
						four_bin[k] = (unsigned char)m;
						break;
					}
				}
			}
			else
			{
				n++;
			}
		}

		switch (n)
		{
		case 0:
			bin_data[l++] = (four_bin[0] << 2) | (four_bin[1] >> 4);
			bin_data[l++] = (four_bin[1] << 4) | (four_bin[2] >> 2);
			bin_data[l++] = (four_bin[2] << 6) | four_bin[3];
			break;

		case 1:
			bin_data[l++] = (four_bin[0] << 2) | (four_bin[1] >> 4);
			bin_data[l++] = (four_bin[1] << 4) | (four_bin[2] >> 2);
			break;

		case 2:
			bin_data[l++] = (four_bin[0] << 2) | (four_bin[1] >> 4);
			break;

		default:
			break;
		}

		if (n != 0)
		{
			break;
		}
	}

	*bin_size = l;

	return 0;
}

const char* getString(JNIEnv *env, jobject, jstring jString)
{
    char *ptrcChar = NULL;
    jclass clsstring = env->FindClass("java/lang/String");
    jstring strencode = env->NewStringUTF("utf8");
    jmethodID mid = env->GetMethodID(clsstring, "getBytes", "(Ljava/lang/String;)[B");
    if(jString  == NULL)
        return NULL;
    jbyteArray barr = (jbyteArray)env->CallObjectMethod(jString, mid, strencode); 
    jsize alen = env->GetArrayLength(barr);
    jbyte *ba = env->GetByteArrayElements(barr, JNI_FALSE);
    if (alen > 0)
    {
        ptrcChar = (char *)malloc(alen + 1); //"\0"
        memcpy(ptrcChar, ba, alen);
        ptrcChar[alen] = 0;
    }
    env->ReleaseByteArrayElements(barr, ba, 0);
    return ptrcChar;
}

JNIEXPORT jstring JNICALL Java_jni_1sign_1api_SM2Sign
  (JNIEnv *env, jobject object, jstring pucOriData, jint uiOriDataLen, jstring pucPriKey, jint uiPriKeyLen)
  {
    const char *bcPlainText = getString(env, object, pucOriData);
    int buiPlainTextLen = uiOriDataLen;

    const char *cECCPrivateKey = getString(env, object, pucPriKey);
    int uiECCPrivateKeySize = uiPriKeyLen;

    char rtSignature[2048] = {0};
    int rtSignatureLen = 2048;

    
    std::shared_ptr<char> ucPlainText(new char[buiPlainTextLen+1]());
    unsigned int uiPlainTextLen = buiPlainTextLen;
    Base64Decode(bcPlainText,buiPlainTextLen,(unsigned char*)ucPlainText.get(),&uiPlainTextLen);
	// printf("%s",ucPlainText.get());
    int iRet = SM2::SM2Sign_HexPriK_DerSigndata((char*)ucPlainText.get(), uiPlainTextLen, (char*)cECCPrivateKey, uiECCPrivateKeySize, rtSignature, &rtSignatureLen);
    if(iRet){
        return env->NewStringUTF("");
    }

    char base64SignData[512] = {0};
    int base64SignDataLen = 512;
    Base64Encode((unsigned char*)rtSignature,rtSignatureLen,base64SignData,(unsigned int*)&base64SignDataLen);
    return env->NewStringUTF((const char *)base64SignData);
  }

JNIEXPORT jint JNICALL Java_jni_1sign_1api_SM2Verify
  (JNIEnv *env, jobject object, jstring pucOriData, jint uiOriDataLen, jstring pucSign, jint uiSignLen, jstring pucPubKey, jint uiPubKeyLen)
  {
    const char *bcPlainText = getString(env, object, pucOriData);
    int buiPlainTextLen = uiOriDataLen;
    const char *rtSignature = getString(env, object, pucSign);
    int rtSignatureLen = uiSignLen;
    const char *ECCPublicKey = getString(env, object, pucPubKey);
    int ECCPublicKeySize = uiPubKeyLen;

    std::shared_ptr<char> ucPlainText(new char[buiPlainTextLen+1]());
    unsigned int uiPlainTextLen = buiPlainTextLen;
    Base64Decode(bcPlainText,buiPlainTextLen,(unsigned char*)ucPlainText.get(),&uiPlainTextLen);

    std::shared_ptr<char> ucSignature(new char[rtSignatureLen+1]());
    unsigned int uiSignatureLen = rtSignatureLen;
    Base64Decode(rtSignature,rtSignatureLen,(unsigned char*)ucSignature.get(),&uiSignatureLen);
	// printf("%s",ucPlainText.get());
    int iRet = SM2::SM2Verify_HexPubk_DerSigndata((char*)ucPlainText.get(), uiPlainTextLen, (char*)ucSignature.get(), uiSignatureLen, (char*)ECCPublicKey, ECCPublicKeySize);
    if(iRet){
        return iRet;
    }
    return 0;
  }

JNIEXPORT jstring JNICALL Java_jni_1sign_1api_SM2SignP7
  (JNIEnv *env, jobject object, jstring inData, jint inDataLen, jstring cert, jint certLen, jstring privKey, jint privKeyLen)
  {
	const char *bcPlainText = getString(env, object, inData);
    int buiPlainTextLen = inDataLen;
    const char *b64Cert = getString(env, object, cert);
    int b64CertLen = certLen;
	const char *privKeyData = getString(env, object, privKey);
    int privKeyDataLen = privKeyLen;

    std::shared_ptr<char> ucPlainText(new char[buiPlainTextLen+1]());
    unsigned int uiPlainTextLen = buiPlainTextLen;
    Base64Decode(bcPlainText,buiPlainTextLen,(unsigned char*)ucPlainText.get(),&uiPlainTextLen);

    std::shared_ptr<char> ucCert(new char[b64CertLen+1]());
    unsigned int ucCertLen = b64CertLen;
    Base64Decode(b64Cert,b64CertLen,(unsigned char*)ucCert.get(),&ucCertLen);

	// std::shared_ptr<char> p7SignData(new char[4096*10]());
	char p7SignData[4096*10] = {0};
    int p7SignDataLen = 4096*10;

	int iRet = SM2::SM2SignByP7_HexPriK(ucPlainText.get(),uiPlainTextLen,ucCert.get(),ucCertLen,(char*)privKeyData,privKeyDataLen, p7SignData,&p7SignDataLen);
	if(iRet){
        return env->NewStringUTF("");
    }
	char base64P7SignData[4096*10] = {0};
    int base64P7SignDataLen = 4096*10;
    Base64Encode((unsigned char*)p7SignData,p7SignDataLen,base64P7SignData,(unsigned int*)&base64P7SignDataLen);
    return env->NewStringUTF((const char *)base64P7SignData);
  }

  JNIEXPORT jint JNICALL Java_jni_1sign_1api_SM2VerifyP7
  (JNIEnv *env, jobject object, jstring p7Data, jint p7DataLen)
  {
	const char *b64P7Data = getString(env, object, p7Data);
    int b64P7DataLen = p7DataLen;

	std::shared_ptr<char> derP7Data(new char[b64P7DataLen+1]());
    unsigned int derP7DataLen = b64P7DataLen;
    Base64Decode(b64P7Data,b64P7DataLen,(unsigned char*)derP7Data.get(),&derP7DataLen);

	int iRet = SM2::SM2VerifyByP7(derP7Data.get(),derP7DataLen);
    if(iRet){
        return iRet;
    }
    return 0;

  }

  JNIEXPORT jstring JNICALL Java_jni_1sign_1api_SM2CertGetPublicKey
  (JNIEnv *env, jobject object, jstring cert, jint certLen)
  {
	const char *b64Cert = getString(env, object, cert);
    int b64CertLen = certLen;

	std::shared_ptr<char> ucCert(new char[b64CertLen+1]());
    unsigned int ucCertLen = b64CertLen;
    Base64Decode(b64Cert,b64CertLen,(unsigned char*)ucCert.get(),&ucCertLen);

	char hexPublicKeyStr[512] = {0};
	int hexPublicKeyStrLen = 512;
	int iRet = SM2::SM2CertGetPublicKey(ucCert.get(),ucCertLen, hexPublicKeyStr, &hexPublicKeyStrLen);
	if(iRet){
        return env->NewStringUTF("");
    }
    return env->NewStringUTF((const char *)hexPublicKeyStr);
  }

  JNIEXPORT jstring JNICALL Java_jni_1sign_1api_SM3Hash
  (JNIEnv *env, jobject object, jstring inData, jint inDataLen)
  {
	const char *b64Data = getString(env, object, inData);
    int b64DataLen = inDataLen;

	std::shared_ptr<char> cIndata(new char[b64DataLen+1]());
    unsigned int cIndataLen = b64DataLen;
    Base64Decode(b64Data,b64DataLen,(unsigned char*)cIndata.get(),&cIndataLen);

	unsigned char sm3HashData[64+1] = {0};
	SM3::sm3_sum((unsigned char*)cIndata.get(),cIndataLen,sm3HashData);

	char base64Sm3HashData[128] = {0};
    int base64Sm3HashDataLen =128;
    Base64Encode((unsigned char*)sm3HashData,32,base64Sm3HashData,(unsigned int*)&base64Sm3HashDataLen);

	return env->NewStringUTF((const char*)base64Sm3HashData);
  }