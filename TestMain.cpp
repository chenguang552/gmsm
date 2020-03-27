#include <iostream>
#include <memory>
#include "SM2.h"
#include "SM3.h"
#include "SM4.h"


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

int iRet = 0;

char *cECCPrivateKey_ = "73C85DC3FA28079FEB638091E4B32851FAEAEEF043325C72E279613369FBB754";
unsigned int uiECCPrivateKeySize_ = strlen(cECCPrivateKey_);

char *ECCPublicKey_ = "04DC3405D5283B64721925126DCBF95E8B44582B421AA5D97792ADA40D51347BAACE8C93DF5964AC29BCDD8BCA9AE0CFA5FA3B527C7336A010489D42E99B81F004";
unsigned int ECCPublicKeySize_ = strlen(ECCPublicKey_);

char bcPlainText[2048] = {0};
int buiPlainTextLen = 2048;

char rtCipherText[2048] = {0};
int rtCipherTextLen = 2048;

char rtSignature[2048] = {0};
int rtSignatureLen = 2048;

int SM2Test();
int SM3Test();
int SM4Test();
int JNITest();

int main()
{
    memcpy(bcPlainText, "aaa123", 6);
	buiPlainTextLen = 6;
    // SM2Test();
    // SM3Test();
    // SM4Test();
    return 0;
}

int JNITest()
{
	int mRet = 0;
	char *yw="lWhL1Q==";
	unsigned int ywLen = strlen(yw);
	char *signP1="MEQCIHRtdvgqFYnNudKLMoszKXKn/IcvMuGexaX8FCtvl1X2AiAZ9xg/aaFmdelzewnyffn70XA4\nZ/jLo2MXU8occJGBWQ==";
	unsigned int signP1Len = strlen(signP1);
	char *cert = "MIICxzCCAmygAwIBAgIEAZbpEjAMBggqgRzPVQGDdQUAMIGKMQswCQYDVQQGEwJDTjEOMAwGA1UECAwFSGVOYW4xEjAQBgNVBAcMCVpoZW5nWmhvdTE3MDUGA1UECgwuSGVOYW4gUHJvdmluY2UgSW5mb3JtYXRpb24gRGV2ZWxvcG1lbnQgQ28uIEx0ZDEPMA0GA1UECwwGSE5YQUNBMQ0wCwYDVQQDDARYQUNBMB4XDTIwMDMyMzEzMzAxOVoXDTIxMDMyMzEzMzAxOVowgZIxCzAJBgNVBAYTAkNOMRIwEAYDVQQIDAnmsrPljZfnnIExEjAQBgNVBAcMCemDkeW3nuW4gjEhMB8GA1UECgwY5bel5ZWG57O757uf55S15a2Q5pS/5YqhMRswGQYDVQQLDBI0MTAxODQxOTg5MDQxMjAwNTIxGzAZBgNVBAMMEjQxMDE4NDE5ODkwNDEyMDA1MjBZMBMGByqGSM49AgEGCCqBHM9VAYItA0IABEvt1tq/GJD3AVOlLFneyT/eMBOdebEpb5LZKE5FB2iDoBa9Ykab2jYPhWS4dH9A4tmm/I3cO1OMjddiFNabUmSjgbMwgbAwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMBMB8GA1UdIwQYMBaAFGzzTThKvwmyE7ZvprxLXJI4gVpbMDcGA1UdHwQwMC4wLKAqoCiGJmh0dHA6Ly9jcmwuaG54YWNhLmNvbS9jcmwveGFjYV9zbTIuY3JsMAsGA1UdDwQEAwIGwDAdBgNVHQ4EFgQUwPyaBi9Q7dlivkxFIZBzWeIbhiEwCQYDVR0TBAIwADAMBggqgRzPVQGDdQUAA0cAMEQCIHIZwUq3R9UvLOy/UYMgkdpXd2Fy54VVI4aE4mYG1PikAiA2GZ6wUz6DLO6MNO3d33LSfYmi+3LR+TjBY74C6/MuCA==";
	unsigned int certLen = strlen(cert);

	std::shared_ptr<char> ucCert(new char[certLen+1]());
    unsigned int ucCertLen = certLen;
    Base64Decode(cert,certLen,(unsigned char*)ucCert.get(),&ucCertLen);

	std::shared_ptr<char> ucCert(new char[certLen+1]());
    unsigned int ucCertLen = certLen;
    Base64Decode(cert,certLen,(unsigned char*)ucCert.get(),&ucCertLen);

	// mRet = SM2::SM2Sign_HexPriK_DerSigndata(bcPlainText, buiPlainTextLen, cECCPrivateKey_, uiECCPrivateKeySize_, rtSignature, &rtSignatureLen);
    // char base64SignData[512] = {0};
    // unsigned int base64SignDataLen = 512;
    // Base64Encode((unsigned char*)rtSignature,rtSignatureLen,base64SignData,&base64SignDataLen);
	// printf("\nSM2Sign_HexPk_DerSigndata:[RET:%x, Len:%d]\n%s\n", iRet, rtSignatureLen, rtSignature);

	// std::shared_ptr<char> p7SignData(new char[4096*10]());
	// char p7SignData[4096*10] = {0};
    // int p7SignDataLen = 4096*10;

	// mRet = SM2::SM2SignByP7_HexPriK(bcPlainText,buiPlainTextLen,ucCert.get(),ucCertLen,(char*)cECCPrivateKey_,uiECCPrivateKeySize_, p7SignData,&p7SignDataLen);

	// mRet = SM2::SM2VerifyByP7(p7SignData,p7SignDataLen);
	// printf("\nSM2VerifyByP7:[RET:%x]\n", iRet);
}

int SM2Test()
{
	// iRet = SM2::SM2SignByHexPrivKey(bcPlainText, buiPlainTextLen, cECCPrivateKey_, uiECCPrivateKeySize_, rtSignature, &rtSignatureLen);
	// printf("\nKS_ExtECCSign:[RET:%x, Len:%d]\n%s\n", iRet, rtSignatureLen, rtSignature);

	// iRet = SM2::SM2VerifyByHexPubKey(bcPlainText, buiPlainTextLen, rtSignature, rtSignatureLen, ECCPublicKey_, ECCPublicKeySize_);
	// printf("\nKS_ExtECCVerify:[RET:%x]\n", iRet);

    // iRet = SM2::SM2EncryptByHexPubKey(bcPlainText, buiPlainTextLen, ECCPublicKey_, ECCPublicKeySize_,rtCipherText, &rtCipherTextLen);
    // printf("\nSM2DecryptByHexPrivKey:[RET:%x]\n密文[len:%d]:%s", iRet,rtCipherTextLen,rtCipherText);

    // memset(bcPlainText,0x0,2048); 
    // buiPlainTextLen = 0;
    // iRet = SM2::SM2DecryptByHexPrivKey(rtCipherText, rtCipherTextLen, cECCPrivateKey_, uiECCPrivateKeySize_, bcPlainText, &buiPlainTextLen);
    // printf("\nSM2DecryptByHexPrivKey:[RET:%x]\n原文[len:%d]:%s", iRet,buiPlainTextLen,bcPlainText);

}

int SM3Test()
{  
    unsigned char hash[32 + 1] = {0};
	SM3::sm3_sum((unsigned char *)bcPlainText, (unsigned int)buiPlainTextLen, hash);
    printf("\nSM3 Hash:\n");
    for(int i = 0; i < 32; i++)
    {
        printf("%02X",hash[i]);
        if((i+1)%4 == 0 && i != 0)
            printf(" ");
    }
    printf("\n");
    return 0;
}

int SM4Test()
{
    unsigned char key[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
    unsigned char input[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
    unsigned char output[16];
    sm4_context ctx;
    unsigned long i;

    //encrypt standard testing vector
    sm4_setkey_enc(&ctx, key);
    sm4_crypt_ecb(&ctx, 1, 16, input, output);
    printf("\necb加密:\n");
    for (i = 0; i < 16; i++)
        printf("%02x ", output[i]);
    printf("\n");

    //decrypt testing
    sm4_setkey_dec(&ctx, key);
    sm4_crypt_ecb(&ctx, 0, 16, output, output);
    printf("\necb解密:\n");
    for (i = 0; i < 16; i++)
        printf("%02x ", output[i]);
    printf("\n");

    //decrypt 1M times testing vector based on standards.
    i = 0;
    sm4_setkey_enc(&ctx, key);
    while (i < 1000000)
    {
        sm4_crypt_ecb(&ctx, 1, 16, input, input);
        i++;
    }
    printf("\necb加密1000000次:\n");
    for (i = 0; i < 16; i++)
        printf("%02x ", input[i]);
    printf("\n");

    return 0;
}