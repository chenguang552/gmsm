#include "SM2.h"
#include "SM3.h"

//===============================================================================================================================================

ASN1_SEQUENCE(X509_ALGOR_SM2) =
	{
		ASN1_SIMPLE(X509_ALGOR_SM2, alg1, ASN1_OBJECT),
		ASN1_SIMPLE(X509_ALGOR_SM2, alg2, ASN1_OBJECT)} ASN1_SEQUENCE_END(X509_ALGOR_SM2)
		IMPLEMENT_ASN1_FUNCTIONS(X509_ALGOR_SM2)

			ASN1_SEQUENCE(X509_PUBKEY_SM2) =
				{
					ASN1_SIMPLE(X509_PUBKEY_SM2, algor, X509_ALGOR_SM2),
					ASN1_SIMPLE(X509_PUBKEY_SM2, public_key, ASN1_BIT_STRING)} ASN1_SEQUENCE_END(X509_PUBKEY_SM2)
					IMPLEMENT_ASN1_FUNCTIONS(X509_PUBKEY_SM2)

						ASN1_SEQUENCE(X509_REQ_INFO_SM2) =
							{
								ASN1_SIMPLE(X509_REQ_INFO_SM2, version, ASN1_INTEGER),
								ASN1_SIMPLE(X509_REQ_INFO_SM2, subject, X509_NAME),
								ASN1_SIMPLE(X509_REQ_INFO_SM2, pubkey, X509_PUBKEY_SM2)} ASN1_SEQUENCE_END(X509_REQ_INFO_SM2)
								IMPLEMENT_ASN1_FUNCTIONS(X509_REQ_INFO_SM2)

									ASN1_SEQUENCE(X509_REQ_SM2) =
										{
											ASN1_SIMPLE(X509_REQ_SM2, req_info, X509_REQ_INFO_SM2),
											ASN1_SIMPLE(X509_REQ_SM2, sig_alg, X509_ALGOR),
											ASN1_SIMPLE(X509_REQ_SM2, signature, ASN1_BIT_STRING)} ASN1_SEQUENCE_END(X509_REQ_SM2)
											IMPLEMENT_ASN1_FUNCTIONS(X509_REQ_SM2)

												ASN1_SEQUENCE(ASN1_SM2_CIPHER) =
													{
														ASN1_SIMPLE(ASN1_SM2_CIPHER, x, BIGNUM),
														ASN1_SIMPLE(ASN1_SM2_CIPHER, y, BIGNUM),
														ASN1_SIMPLE(ASN1_SM2_CIPHER, hash, ASN1_OCTET_STRING),
														ASN1_SIMPLE(ASN1_SM2_CIPHER, cipher, ASN1_OCTET_STRING)} ASN1_SEQUENCE_END(ASN1_SM2_CIPHER)
														IMPLEMENT_ASN1_FUNCTIONS(ASN1_SM2_CIPHER)

															ASN1_SEQUENCE(SM2_PRIVATE_KEY) =
																{
																	ASN1_SIMPLE(SM2_PRIVATE_KEY, version, ASN1_INTEGER),
																	ASN1_SIMPLE(SM2_PRIVATE_KEY, prikey, ASN1_INTEGER),
																	ASN1_IMP_SET_OF(SM2_PRIVATE_KEY, alg, ASN1_ANY, 0),
																	ASN1_IMP_SET_OF(SM2_PRIVATE_KEY, pubkey, ASN1_ANY, 1)} ASN1_SEQUENCE_END(SM2_PRIVATE_KEY)
																	IMPLEMENT_ASN1_FUNCTIONS(SM2_PRIVATE_KEY)

																		ASN1_SEQUENCE(SM2_PUBLIC_KEY) =
																			{
																				ASN1_SIMPLE(SM2_PUBLIC_KEY, algor, X509_ALGOR_SM2),
																				ASN1_SIMPLE(SM2_PUBLIC_KEY, pubkey, ASN1_BIT_STRING)} ASN1_SEQUENCE_END(SM2_PUBLIC_KEY)
																				IMPLEMENT_ASN1_FUNCTIONS(SM2_PUBLIC_KEY)

																					ASN1_SEQUENCE(SM2_PKCS12) =
																						{
																							ASN1_SIMPLE(SM2_PKCS12, version, ASN1_INTEGER),
																							ASN1_SIMPLE(SM2_PKCS12, prikey, ASN1_OCTET_STRING),
																							ASN1_SIMPLE(SM2_PKCS12, cert, X509)} ASN1_SEQUENCE_END(SM2_PKCS12)
																							IMPLEMENT_ASN1_FUNCTIONS(SM2_PKCS12)

	//===============================================================================================================================================
	const char const_p[] = "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF";
const char const_a[] = "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC";
const char const_b[] = "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93";
const char const_xG[] = "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7";
const char const_yG[] = "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0";
const char const_n[] = "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123";

const char rnd_seed[] = "random seed.today is 2015/07/30/ 10:02. YX";

// SM2公钥头，算法标识等
const unsigned char SM2_ALG_HEADER_256[] = {0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x82, 0x2d, 0x03, 0x42, 0x00, 0x04};

SM2::SM2(void)
{
}

SM2::~SM2(void)
{
}

int SM2::SM2_GenKeyPair(unsigned char *pucPubKey, unsigned int *puiPubKeyLen, unsigned char *pucPriKey, unsigned int *puiPriKeyLen)
{
	EC_GROUP *group = NULL;
	EC_KEY *eckey = NULL;

	int iRet = GetSM2Group(&group);
	if (!group)
	{
		iRet = -1;
		goto END;
	}
	// 创建SM2密钥对
	if ((eckey = EC_KEY_new()) == NULL)
	{
		iRet = -1;
		goto END;
	}
	if (EC_KEY_set_group(eckey, group) == 0)
	{
		iRet = -1;
		goto END;
	}
	// 生成密钥
	if (1 != EC_KEY_generate_key(eckey))
	{
		iRet = -1;
		goto END;
	}
	// 检查密钥
	if (1 != EC_KEY_check_key(eckey))
	{
		iRet = -1;
		goto END;
	}

	// // 输出公钥和私钥
	// I_To_DSM2PrivateKey(*eckey, pucPriKey, puiPriKeyLen);
	// I_To_DSM2PublicKey(*eckey, pucPubKey, puiPubKeyLen);

	iRet = 0;
END:
	if (group)
	{
		EC_GROUP_free(group);
		group = NULL;
	}
	if (eckey)
	{
		EC_KEY_free(eckey);
		eckey = NULL;
	}

	return iRet;
}

int SM2::SM2_Sign(unsigned char *pucOriData, unsigned int uiOriDataLen, unsigned char *pucPriKey, unsigned int uiPriKeyLen, unsigned char *pucSign, unsigned int *puiSignLen)
{
	int iRet = 0;
	EC_KEY *eckey = NULL;
	ECDSA_SIG *s = NULL;
	unsigned char ucHash[32] = {0};

	// 将私钥转换为EC_KEY结构
	iRet = GetSM2PrivateECKey(&eckey, pucPriKey, uiPriKeyLen);
	if (iRet != 0)
	{
		goto END;
	}

	// SM3摘要
	iRet = GetSM3HashForSign(pucOriData, uiOriDataLen, (unsigned char *)SM2_DEFAULT_USER_ID, strlen(SM2_DEFAULT_USER_ID), eckey, ucHash);
	if (iRet != 0)
	{
		goto END;
	}

	RAND_seed(ucHash, 32);
	iRet = SM2Sign(ucHash, 32, eckey, &s);
	if (iRet != 0)
	{
		iRet = -1;
		goto END;
	}
	*puiSignLen = i2d_ECDSA_SIG(s, &pucSign);
	iRet = 0;
END:

	if (eckey != NULL)
	{
		EC_KEY_free(eckey);
		eckey = NULL;
	}
	if (s != NULL)
	{
		ECDSA_SIG_free(s);
		s = NULL;
	}

	return iRet;
}

int SM2::SM2_Verify(unsigned char *pucOriData, unsigned int uiOriDataLen, unsigned char *pucSign, unsigned int uiSignLen, unsigned char *pucPubKey, unsigned int uiPubKeyLen)
{
	int iRet = 0;
	EC_KEY *eckey = NULL;
	ECDSA_SIG *sig = NULL;
	unsigned char ucHash[32] = {0};

	// 获取EC_KEY结构的公钥
	iRet = GetSM2PublicECKey(&eckey, pucPubKey, uiPubKeyLen);
	if (iRet != 0)
	{
		iRet = -1;
		goto END;
	}
	// 获取签名值结构体
	if (d2i_ECDSA_SIG(&sig, (const unsigned char **)&pucSign, uiSignLen) == NULL)
	{
		iRet = -1;
		goto END;
	}
	// 对原文作SM3摘要
	iRet = GetSM3HashForSign(pucOriData, uiOriDataLen, (unsigned char *)SM2_DEFAULT_USER_ID, strlen(SM2_DEFAULT_USER_ID), eckey, ucHash);
	if (iRet != 0)
	{
		iRet = -1;
		goto END;
	}

	iRet = SM2Verify(ucHash, 32, sig, eckey);

END:
	if (eckey != NULL)
	{
		EC_KEY_free(eckey);
	}

	if (sig != NULL)
	{
		ECDSA_SIG_free(sig);
	}
	return iRet;
}

int SM2::GetSM2Group(EC_GROUP **group)
{
	BN_CTX *ctx = NULL;
	BIGNUM *p = NULL;
	BIGNUM *a = NULL;
	BIGNUM *b = NULL;

	EC_POINT *P = NULL;
	EC_POINT *Q = NULL;
	EC_POINT *R = NULL;

	BIGNUM *xG = NULL;
	BIGNUM *yG = NULL;
	BIGNUM *n = NULL;

	int iRet = 0;

	RAND_seed(rnd_seed, sizeof rnd_seed); /* or BN_generate_prime may fail */

	ctx = BN_CTX_new();
	if (!ctx)
	{
		iRet = -1;
		goto END;
	}
	p = BN_new();
	a = BN_new();
	b = BN_new();
	if (!p || !a || !b)
	{
		iRet = -1;
		goto END;
	}

	*group = EC_GROUP_new(EC_GFp_mont_method());
	if (!*group)
	{
		iRet = -1;
		goto END;
	}

	// 设置国密SM2推荐曲线参数
	if (!BN_hex2bn(&p, const_p))
	{
		iRet = -1;
		goto END;
	}
	if (1 != BN_is_prime_ex(p, BN_prime_checks, ctx, NULL))
	{
		iRet = -1;
		goto END;
	}
	if (!BN_hex2bn(&a, const_a))
	{
		iRet = -1;
		goto END;
	}
	if (!BN_hex2bn(&b, const_b))
	{
		iRet = -1;
		goto END;
	}
	if (!EC_GROUP_set_curve_GFp(*group, p, a, b, ctx))
	{
		iRet = -1;
		goto END;
	}

	// 创建曲线上3个点P、Q、R
	P = EC_POINT_new(*group);
	Q = EC_POINT_new(*group);
	R = EC_POINT_new(*group);
	if (!P || !Q || !R)
	{
		iRet = -1;
		goto END;
	}

	// 创建点的X、Y坐标和n值
	xG = BN_new();
	yG = BN_new();
	n = BN_new();
	if (!xG || !yG || !n)
	{
		iRet = -1;
		goto END;
	}

	if (!BN_hex2bn(&xG, const_xG))
	{
		iRet = -1;
		goto END;
	}
	if (!EC_POINT_set_compressed_coordinates_GFp(*group, P, xG, 0, ctx))
	{
		iRet = -1;
		goto END;
	}
	if (!EC_POINT_is_on_curve(*group, P, ctx))
	{
		iRet = -1;
		goto END;
	}
	if (!BN_hex2bn(&n, const_n))
	{
		iRet = -1;
		goto END;
	}
	if (!EC_GROUP_set_generator(*group, P, n, BN_value_one()))
	{
		iRet = -1;
		goto END;
	}
	if (!EC_POINT_get_affine_coordinates_GFp(*group, P, xG, yG, ctx))
	{
		iRet = -1;
		goto END;
	}
	/* G_y value taken from the standard: */
	if (!BN_hex2bn(&n, const_yG))
	{
		iRet = -1;
		goto END;
	}
	if (0 != BN_cmp(yG, n))
	{
		iRet = -1;
		goto END;
	}

	if (EC_GROUP_get_degree(*group) != 256)
	{
		iRet = -1;
		goto END;
	}

	if (!EC_GROUP_get_order(*group, n, ctx))
	{
		iRet = -1;
		goto END;
	}
	if (!EC_GROUP_precompute_mult(*group, ctx))
	{
		iRet = -1;
		goto END;
	}
	if (!EC_POINT_mul(*group, Q, n, NULL, NULL, ctx))
	{
		iRet = -1;
		goto END;
	}
	if (!EC_POINT_is_at_infinity(*group, Q))
	{
		iRet = -1;
		goto END;
	}
	iRet = 0;
END:
	if (ctx)
	{
		BN_CTX_free(ctx);
		ctx = NULL;
	}
	if (p)
	{
		BN_free(p);
		p = NULL;
	}
	if (a)
	{
		BN_free(a);
		a = NULL;
	}
	if (b)
	{
		BN_free(b);
		b = NULL;
	}
	if (P)
	{
		EC_POINT_free(P);
		P = NULL;
	}
	if (Q)
	{
		EC_POINT_free(Q);
		Q = NULL;
	}
	if (R)
	{
		EC_POINT_free(R);
		R = NULL;
	}
	if (xG)
	{
		BN_free(xG);
		xG = NULL;
	}
	if (yG)
	{
		BN_free(yG);
		yG = NULL;
	}
	if (n)
	{
		BN_free(n);
		n = NULL;
	}
	return iRet;
}

int SM2::GetSM2PublicECKey(EC_KEY **eckey, unsigned char *pucPubKey, unsigned int uiPubKeyLen)
{
	int iRet = 0;
	EC_GROUP *group = NULL;
	EC_POINT *point = NULL;
	SM2_PUBLIC_KEY *pubkey = NULL;

	// 解析公钥
	pubkey = d2i_SM2_PUBLIC_KEY(&pubkey, (const unsigned char **)&pucPubKey, uiPubKeyLen);
	if (pubkey == NULL)
	{
		iRet = -1;
		goto END;
	}

	// 获取国密SM2曲线
	GetSM2Group(&group);
	if (!group)
	{
		iRet = -1;
		goto END;
	}

	// 转换SM2公钥
	if ((*eckey = EC_KEY_new()) == NULL)
	{
		iRet = -1;
		goto END;
	}
	if (EC_KEY_set_group(*eckey, group) == 0)
	{
		iRet = -1;
		goto END;
	}
	point = EC_POINT_new(group);
	if (!point)
	{
		iRet = -1;
		goto END;
	}
	if (1 != EC_POINT_oct2point(group, point, pubkey->pubkey->data, pubkey->pubkey->length, NULL))
	{
		iRet = -1;
		goto END;
	}

	EC_KEY_set_public_key(*eckey, point);

	iRet = 0;
END:

	return iRet;
}

int SM2::GetSM2PrivateECKey(EC_KEY **eckey, unsigned char *pucPriKey, unsigned int uiPriKeylen)
{
	int iRet = 0;
	int num = 0;
	ASN1_TYPE *info = NULL;
	EC_GROUP *group = NULL;
	BIGNUM *n = NULL;
	SM2_PRIVATE_KEY *sm2PriKey = NULL;
	EC_POINT *p = NULL;
	STACK_OF(ASN1_TYPE) * pubkey;

	// 解析私钥为ASN1结构体
	sm2PriKey = d2i_SM2_PRIVATE_KEY(&sm2PriKey, (const unsigned char **)&pucPriKey, uiPriKeylen);
	if (sm2PriKey == NULL)
	{
		iRet = -1;
		goto END;
	}

	// 获取国密局定义的SM2曲线
	GetSM2Group(&group);
	if (!group)
	{
		iRet = -1;
		goto END;
	}

	// 创建EC_KEY
	if ((*eckey = EC_KEY_new()) == NULL)
	{
		iRet = -1;
		goto END;
	}
	if (EC_KEY_set_group(*eckey, group) == 0)
	{
		iRet = -1;
		goto END;
	}
	// 设置私钥
	n = ASN1_INTEGER_to_BN(sm2PriKey->prikey, n);
	if (!n)
	{
		iRet = -1;
		goto END;
	}
	EC_KEY_set_private_key(*eckey, n);

	// 设置公钥
	pubkey = sm2PriKey->pubkey;
	num = sk_ASN1_TYPE_num(pubkey);
	if (num > 1)
	{
		iRet = -1;
		goto END;
	}
	info = sk_ASN1_TYPE_value(pubkey, 0);
	p = EC_POINT_new(group);
	if (!p)
	{
		iRet = -1;
		goto END;
	}
	if (1 != EC_POINT_oct2point(group, p, info->value.bit_string->data, info->value.bit_string->length, NULL)) // 1表示成功
	{
		iRet = -1;
		goto END;
	}
	EC_KEY_set_public_key(*eckey, p);

	// 检测密钥对
	if (!EC_KEY_check_key(*eckey))
	{
		iRet = -1;
		goto END;
	}

	iRet = 0;

END:
	if (sm2PriKey != NULL)
	{
		SM2_PRIVATE_KEY_free(sm2PriKey);
		sm2PriKey = NULL;
	}
	if (group != NULL)
	{
		EC_GROUP_free(group);
		group = NULL;
	}
	if (n != NULL)
	{
		BN_free(n);
		n = NULL;
	}
	if (p != NULL)
	{
		EC_POINT_free(p);
		p = NULL;
	}
	return iRet;
}

int SM2::GetSM3HashForSign(unsigned char *pucOriData, unsigned int uiOriDataLen,
						   unsigned char *pucUserId, unsigned int uiUserIdLen, EC_KEY *eckey, unsigned char *pucHashData)
{
	// 计算步骤：
	// 1. 计算（ZA=H256(ENTLA||IDA||a||b||xG||yG||xA||yA)）的SM3摘要，得到摘要Za
	// 2. 计算(Za||原文)的SM3摘要，得到待签名的SM3摘要
	int iRet = 0;
	unsigned char ucZaSrc[512] = {0}; // 待计算Za的原始数据
	unsigned int uiZaSrcLen = 0;	  // 待计算Za的原始数据长度
	unsigned short usENTLLen = uiUserIdLen * 8;
	unsigned char ucPubKey[128] = {0}; // 公钥
	unsigned int uiPubKeyLen = 128;	   // 公钥长度
	unsigned char ucZa[32] = {0};	   // 计算出来的SM3摘要，长度固定为32
	unsigned char *pucZaM = NULL;	   // 带计算的摘要原文
	unsigned int uiZaMLen = 0;		   // 长度为摘要值+原文长度
	unsigned char ucA[128] = {0};
	unsigned char ucB[128] = {0};
	unsigned char ucXG[128] = {0};
	unsigned char ucYG[128] = {0};
	int len = 0;

	// 获取二进制的公钥数据
	uiPubKeyLen = EC_POINT_point2oct(eckey->group, eckey->pub_key, eckey->conv_form, ucPubKey, uiPubKeyLen, NULL);
	if (uiPubKeyLen == 0 || uiPubKeyLen == 128)
	{
		iRet = -1;
		goto END;
	}
	// 拷贝ENTLa，需要采用大端存放，只拷贝两个字节即可
	unsigned char *pENTLLen;
	pENTLLen = (unsigned char *)&usENTLLen;
	memcpy(ucZaSrc + uiZaSrcLen, pENTLLen + 1, 1);
	uiZaSrcLen += 1;
	memcpy(ucZaSrc + uiZaSrcLen, pENTLLen, 1);
	uiZaSrcLen += 1;
	// 拷贝USERID
	memcpy(ucZaSrc + uiZaSrcLen, pucUserId, uiUserIdLen);
	uiZaSrcLen += uiUserIdLen;
	// 拷贝a
	len = Hex2Bin(ucA, const_a);
	memcpy(ucZaSrc + uiZaSrcLen, ucA, len);
	uiZaSrcLen += len;
	// 拷贝b
	len = Hex2Bin(ucB, const_b);
	memcpy(ucZaSrc + uiZaSrcLen, ucB, len);
	uiZaSrcLen += len;
	// 拷贝xG
	len = Hex2Bin(ucXG, const_xG);
	memcpy(ucZaSrc + uiZaSrcLen, ucXG, len);
	uiZaSrcLen += len;
	// 拷贝yG
	len = Hex2Bin(ucYG, const_yG);
	memcpy(ucZaSrc + uiZaSrcLen, ucYG, len);
	uiZaSrcLen += len;
	// 拷贝公钥. 差别1的原因是，获取到的公钥为04+X+Y.这里只需要X+Y。
	memcpy(ucZaSrc + uiZaSrcLen, ucPubKey + 1, uiPubKeyLen - 1);
	uiZaSrcLen += uiPubKeyLen - 1;

	// 计算SM3摘要得到Za
	SM3::sm3_sum(ucZaSrc, uiZaSrcLen, ucZa);

	// 将Za||原文合并一起
	// 申请待摘要的原文内存
	uiZaMLen = 32 + uiOriDataLen;
	pucZaM = (unsigned char *)malloc(uiZaMLen);
	if (pucZaM == NULL)
	{
		iRet = -1;
		goto END;
	}
	memset(pucZaM, 0, uiZaMLen);
	memcpy(pucZaM, ucZa, 32);
	memcpy(pucZaM + 32, pucOriData, uiOriDataLen);

	// 计算SM3摘要
	SM3::sm3_sum(pucZaM, uiZaMLen, pucHashData);

END:

	if (pucZaM != NULL)
	{
		free(pucZaM);
		pucZaM = NULL;
	}

	return iRet;
}

int SM2::SM2Sign(const unsigned char *digest, int digestlen, EC_KEY *eckey, ECDSA_SIG **sig)
{
	int iRet = 0;
	int i;
	BN_CTX *ctx = NULL;
	BIGNUM *k = NULL; // 随机数
	BIGNUM *r = NULL; // 签名值中的r
	BIGNUM *s = NULL; // 签名值中的s

	BIGNUM *n = NULL;	// 阶
	BIGNUM *tmp = NULL; // 临时对象，用于计算过程中临时保存大数
	BIGNUM *m = NULL;	// 待签名的摘要值
	BIGNUM *x = NULL;	// 计算出来的x1
	BIGNUM *a = NULL;	// 以大数形式表示的1,用于计算s的过程中
	EC_POINT *point = NULL;
	const BIGNUM *priv_key;
	const EC_GROUP *group;

	// 从私钥结构中获取SM2曲线
	group = EC_KEY_get0_group(eckey);
	// 获取私钥
	priv_key = EC_KEY_get0_private_key(eckey);

	if (group == NULL || priv_key == NULL || digest == NULL || digestlen != 32)
	{
		return NULL;
	}

	if ((ctx = BN_CTX_new()) == NULL || (n = BN_new()) == NULL ||
		(tmp = BN_new()) == NULL || (m = BN_new()) == NULL ||
		(x = BN_new()) == NULL || (a = BN_new()) == NULL ||
		(r = BN_new()) == NULL || (s = BN_new()) == NULL ||
		(k = BN_new()) == NULL)
	{
		iRet = -1;
		goto err;
	}

	if (!EC_GROUP_get_order(group, n, ctx))
	{
		iRet = -1;
		goto err;
	}

	i = BN_num_bits(n);

	// 将摘要值转换为大数
	if (!BN_bin2bn(digest, digestlen, m))
	{
		iRet = -1;
		goto err;
	}

	while (true)
	{
		// 首先计算r
		// 产生随机数k在范围[1,n-1]内.
		if (!BN_rand_range(k, n))
		{
			goto err;
		}
		/*if (!BN_hex2bn(&k, "6CB28D99385C175C94F94E934817663FC176D925DD72B727260DBAAE1FB2F96F"))
		{
			iRet = -1;
			goto err;
		}*/
		// 计算(x1,y1) = [k]G
		point = EC_POINT_new(group);
		if (!EC_POINT_mul(group, point, k, NULL, NULL, ctx))
		{
			iRet = -1;
			goto err;
		}
		if (EC_METHOD_get_field_type(EC_GROUP_method_of(group)) == NID_X9_62_prime_field)
		{
			if (!EC_POINT_get_affine_coordinates_GFp(group, point, tmp, NULL, ctx))
			{
				iRet = -1;
				goto err;
			}
		}
		else /* NID_X9_62_characteristic_two_field */
		{
			if (!EC_POINT_get_affine_coordinates_GF2m(group, point, tmp, NULL, ctx))
			{
				iRet = -1;
				goto err;
			}
		}
		if (!BN_nnmod(x, tmp, n, ctx))
		{
			ECDSAerr(ECDSA_F_ECDSA_SIGN_SETUP, ERR_R_BN_LIB);
			goto err;
		}

		// 计算r , r = (e+x1) mod n
		if (!BN_mod_add_quick(r, m, x, n))
		{
			iRet = -1;
			goto err;
		}

		// r如果为0,则重新计算
		if (BN_is_zero(r))
		{
			continue;
		}
		// 如果r + k = n,则重新计算
		BN_add(tmp, r, k);
		if (BN_ucmp(tmp, n) == 0)
		{
			continue;
		}

		// 计算S. ((1/(1+dA)).(k-r.dA))mod n
		// 乘r.dA = tmp
		if (!BN_mod_mul(tmp, priv_key, r, n, ctx))
		{
			iRet = -1;
			goto err;
		}
		// k-r.dA = s
		if (!BN_mod_sub_quick(s, k, tmp, n))
		{
			iRet = -1;
			goto err;
		}
		// 设置a为1
		BN_one(a);

		// 1+dA = tmp
		if (!BN_mod_add_quick(tmp, priv_key, a, n))
		{
			iRet = -1;
			goto err;
		}
		// 1/1+dA = tmp
		if (!BN_mod_inverse(tmp, tmp, n, ctx))
		{
			iRet = -1;
			goto err;
		}
		// tmp mod n = s
		if (!BN_mod_mul(s, s, tmp, n, ctx))
		{
			iRet = -1;
			goto err;
		}
		// 如果s为0，重新计算，否则，计算完成
		if (!BN_is_zero(s))
		{
			break;
		}
	}

	// 创建签名值结构体
	*sig = ECDSA_SIG_new();

	(*sig)->r = BN_dup(r);
	(*sig)->s = BN_dup(s);
	iRet = 0;
err:
	if (ctx)
		BN_CTX_free(ctx);
	if (m)
		BN_clear_free(m);
	if (tmp)
		BN_clear_free(tmp);
	if (n)
		BN_free(n);
	if (k)
		BN_clear_free(k);
	if (x)
		BN_clear_free(x);
	if (a)
		BN_clear_free(a);
	if (r)
		BN_clear_free(r);
	if (s)
		BN_clear_free(s);
	if (point)
		EC_POINT_free(point);

	return iRet;
}

int SM2::SM2Verify(const unsigned char *digest, int digestlen, const ECDSA_SIG *sig, EC_KEY *eckey)
{
	int iRet = 0;
	BN_CTX *ctx = NULL;
	BIGNUM *n = NULL;
	BIGNUM *R = NULL;
	BIGNUM *m = NULL;
	BIGNUM *X = NULL;
	BIGNUM *t = NULL;
	EC_POINT *point = NULL;
	const EC_GROUP *group;
	const EC_POINT *pub_key;

	if (eckey == NULL || (group = EC_KEY_get0_group(eckey)) == NULL ||
		(pub_key = EC_KEY_get0_public_key(eckey)) == NULL || sig == NULL || digestlen != 32)
	{
		iRet = -1;
		goto err;
	}
	ctx = BN_CTX_new();
	if (!ctx)
	{
		iRet = -1;
		goto err;
	}
	BN_CTX_start(ctx);
	n = BN_CTX_get(ctx);
	R = BN_CTX_get(ctx);
	t = BN_CTX_get(ctx);
	m = BN_CTX_get(ctx);
	X = BN_CTX_get(ctx);
	if (!n || !R || !t || !m || !X)
	{
		iRet = -1;
		goto err;
	}
	if (!EC_GROUP_get_order(group, n, ctx))
	{
		iRet = -1;
		goto err;
	}

	// 将摘要值转换为大数
	if (!BN_bin2bn(digest, digestlen, m))
	{
		iRet = -1;
		goto err;
	}
	// 判断签名值r和s的合法性
	if (BN_is_zero(sig->r) || BN_is_negative(sig->r) ||
		BN_ucmp(sig->r, n) >= 0 || BN_is_zero(sig->s) ||
		BN_is_negative(sig->s) || BN_ucmp(sig->s, n) >= 0)
	{
		iRet = -1;
		goto err;
	}
	// t =(r+s) mod n
	if (!BN_mod_add_quick(t, sig->r, sig->s, n))
	{
		iRet = -1;
		goto err;
	}
	if (BN_is_zero(t))
	{
		iRet = -1;
		goto err;
	}

	// point = s*G+t*PA
	if ((point = EC_POINT_new(group)) == NULL)
	{
		iRet = -1;
		goto err;
	}
	if (!EC_POINT_mul(group, point, sig->s, pub_key, t, ctx))
	{
		iRet = -1;
		goto err;
	}
	if (EC_METHOD_get_field_type(EC_GROUP_method_of(group)) == NID_X9_62_prime_field)
	{
		if (!EC_POINT_get_affine_coordinates_GFp(group, point, X, NULL, ctx))
		{
			iRet = -1;
			goto err;
		}
	}
	else
	{
		if (!EC_POINT_get_affine_coordinates_GF2m(group, point, X, NULL, ctx))
		{
			iRet = -1;
			goto err;
		}
	}

	// R = m + X mod n
	if (!BN_mod_add_quick(R, m, X, n))
	{
		iRet = -1;
		goto err;
	}
	// 比较R和sig->r
	iRet = BN_ucmp(R, sig->r);
err:
	BN_CTX_end(ctx);
	BN_CTX_free(ctx);
	if (point)
	{
		EC_POINT_free(point);
	}
	return iRet;
}

int SM2::Hex2Bin(unsigned char *pbDest, const char *szSrc)
{
	int iRet = 0;
	BIGNUM *bg = NULL;
	bg = BN_new();
	if (!BN_hex2bn(&bg, szSrc))
	{
		iRet = 0;
		goto END;
	}

	iRet = BN_bn2bin(bg, pbDest);
END:
	if (bg != NULL)
	{
		BN_free(bg);
		bg = NULL;
	}

	return iRet;
}

int SM2::GetSM2PublicECKeyFromXY(EC_KEY **eckey, char *pucPubKey, int uiPubKeyLen)
{
	int iRet = 0;
	EC_GROUP *group = NULL;
	EC_POINT *point = NULL;
	unsigned char PubKey[256] = {0};
	unsigned int PubKeyLen = 256;

	if (0 == uiPubKeyLen || NULL == pucPubKey)
	{
		iRet = -1;
		goto END;
	}

	// 获取国密SM2曲线
	GetSM2Group(&group);
	if (!group)
	{
		iRet = -1;
		goto END;
	}

	// 转换SM2公钥
	if ((*eckey = EC_KEY_new()) == NULL)
	{
		iRet = -1;
		goto END;
	}
	if (EC_KEY_set_group(*eckey, group) == 0)
	{
		iRet = -1;
		goto END;
	}
	point = EC_POINT_new(group);
	if (!point)
	{
		iRet = -1;
		goto END;
	}
	switch (uiPubKeyLen)
	{
	case 65:
		memcpy(PubKey, pucPubKey, uiPubKeyLen);
		PubKeyLen = 65;
		break;
	case 128:
		break;
	case 130:
		PubKeyLen = Hex2Bin(PubKey, pucPubKey);
		break;
	default:
		iRet = -1;
		goto END;
	}

	if (1 != EC_POINT_oct2point(group, point, PubKey, PubKeyLen, NULL))
	{
		iRet = -1;
		goto END;
	}

	EC_KEY_set_public_key(*eckey, point);

	iRet = 0;
END:

	return iRet;
}

int SM2::GetSM2PrivateECKeyFromD(EC_KEY **eckey, char *pucPriKey, int uiPriKeylen)
{
	int iRet = 0;
	EC_GROUP *group = NULL;
	BIGNUM *n = NULL;
	EC_POINT *p = NULL;
	// unsigned char PubKey[256] = {0};
	// unsigned int PubKeyLen = 256;

	// 获取国密局定义的SM2曲线
	GetSM2Group(&group);
	if (!group)
	{
		iRet = -1;
		goto END;
	}

	// 创建EC_KEY
	if ((*eckey = EC_KEY_new()) == NULL)
	{
		iRet = -1;
		goto END;
	}
	if (EC_KEY_set_group(*eckey, group) == 0)
	{
		iRet = -1;
		goto END;
	}
	// 设置私钥
	// n = ASN1_INTEGER_to_BN(pucPriKey, n);
	BN_hex2bn(&n, pucPriKey);
	if (!n)
	{
		iRet = -1;
		goto END;
	}
	EC_KEY_set_private_key(*eckey, n);

	// 设置公钥
	p = EC_POINT_new(group);
	if (!p)
	{
		iRet = -1;
		goto END;
	}

	// PubKeyLen = Hex2Bin(PubKey,pucPubKey);
	if (!EC_POINT_mul(group, p, n, NULL, NULL, NULL))
	{
		iRet = -1;
		goto END;
	}
	// if (1 != EC_POINT_oct2point(group, p, PubKey, PubKeyLen, NULL)) // 1表示成功
	// {
	// 	iRet = -1;
	// 	goto END;
	// }
	EC_KEY_set_public_key(*eckey, p);

	// 检测密钥对
	if (!EC_KEY_check_key(*eckey))
	{
		iRet = -1;
		goto END;
	}

	iRet = 0;

END:

	if (group != NULL)
	{
		EC_GROUP_free(group);
		group = NULL;
	}
	if (n != NULL)
	{
		BN_free(n);
		n = NULL;
	}
	if (p != NULL)
	{
		EC_POINT_free(p);
		p = NULL;
	}
	return iRet;
}

int SM2::SM2SignByHexPrivKey(char *pucOriData, int uiOriDataLen, char *pucPriKey, int uiPriKeyLen, char *pucSign, int *puiSignLen)
{
	int iRet = 0;
	EC_KEY *eckey = NULL;
	ECDSA_SIG *s = NULL;
	char ucHash[32] = {0};

	// 将私钥转换为EC_KEY结构
	iRet = GetSM2PrivateECKeyFromD(&eckey, pucPriKey, uiPriKeyLen);
	if (iRet != 0)
	{
		goto END;
	}

	// SM3摘要
	iRet = GetSM3HashForSign((unsigned char *)pucOriData, (unsigned int)uiOriDataLen, (unsigned char *)SM2_DEFAULT_USER_ID, strlen(SM2_DEFAULT_USER_ID), eckey, (unsigned char *)ucHash);
	if (iRet != 0)
	{
		goto END;
	}

	RAND_seed(ucHash, 32);
	iRet = SM2Sign((const unsigned char *)ucHash, 32, eckey, &s);
	if (iRet != 0)
	{
		iRet = -1;
		goto END;
	}
	// printf("r:%s\ns:%s\n",BN_bn2hex(s->r),BN_bn2hex(s->s));
	sprintf((char *)pucSign, "%s%s", BN_bn2hex(s->r), BN_bn2hex(s->s));
	*puiSignLen = strlen((const char *)pucSign);
	iRet = 0;
END:

	if (eckey != NULL)
	{
		EC_KEY_free(eckey);
		eckey = NULL;
	}
	if (s != NULL)
	{
		ECDSA_SIG_free(s);
		s = NULL;
	}

	return iRet;
}

int SM2::SM2VerifyByHexPubKey(char *pucOriData, int uiOriDataLen, char *pucSign, int uiSignLen, char *pucPubKey, int uiPubKeyLen)
{
	int iRet = 0;
	EC_KEY *eckey = NULL;
	ECDSA_SIG *sig = NULL;
	BIGNUM *r = NULL;
	BIGNUM *s = NULL;
	char ucHash[32] = {0};
	char strHexR[64 + 1] = {0};
	char strHexS[64 + 1] = {0};

	// 获取EC_KEY结构的公钥
	iRet = GetSM2PublicECKeyFromXY(&eckey, pucPubKey, uiPubKeyLen);
	if (iRet != 0)
	{
		iRet = -1;
		goto END;
	}
	// 获取签名值结构体
	sig = ECDSA_SIG_new();
	memcpy(strHexR, pucSign, uiSignLen / 2);
	memcpy(strHexS, pucSign + (uiSignLen / 2), uiSignLen / 2);
	BN_hex2bn(&r, strHexR);
	BN_hex2bn(&s, strHexS);
	sig->r = BN_dup(r);
	sig->s = BN_dup(s);
	if (sig == NULL)
	{
		iRet = -1;
		goto END;
	}
	// if (d2i_ECDSA_SIG(&sig, (const unsigned char **)&pucSign, uiSignLen) == NULL)
	// {
	// 	iRet = -1;
	// 	goto END;
	// }
	// 对原文作SM3摘要
	iRet = GetSM3HashForSign((unsigned char *)pucOriData, (unsigned int)uiOriDataLen, (unsigned char *)SM2_DEFAULT_USER_ID, strlen(SM2_DEFAULT_USER_ID), eckey, (unsigned char *)ucHash);
	if (iRet != 0)
	{
		iRet = -1;
		goto END;
	}

	iRet = SM2Verify((const unsigned char *)ucHash, 32, sig, eckey);

END:
	if (eckey != NULL)
	{
		EC_KEY_free(eckey);
	}

	if (sig != NULL)
	{
		ECDSA_SIG_free(sig);
	}
	return iRet;
}

int SM2::SM2EncryptByHexPubKey(char *OriData, int OriDataLen, char *pucPubKey, int puiPubKeyLen, char *cipherData, int *cipherDataLen)
{
	int iRet = 0;
	EC_KEY *eckey = NULL;
	unsigned char *mCipherData = (unsigned char *)malloc(OriDataLen + 128);
	unsigned int mCipherDataLen = OriDataLen + 128;
	// 获取EC_KEY结构的公钥
	iRet = GetSM2PublicECKeyFromXY(&eckey, (char *)pucPubKey, puiPubKeyLen);
	if (iRet != 0)
	{
		iRet = -1;
		goto END;
	}

	iRet = SM2Encrypt((unsigned char *)OriData, OriDataLen, eckey, mCipherData, &mCipherDataLen);
	Bin2HexStr(mCipherData, mCipherDataLen, (unsigned char *)cipherData, (unsigned int *)cipherDataLen);

END:
	if (eckey != NULL)
	{
		EC_KEY_free(eckey);
	}
	return iRet;
}

int SM2::SM2DecryptByHexPrivKey(char *cipherData, int cipherDataLen, char *pucPriKey, int uiPriKeyLen, char *OriData, int *OriDataLen)
{
	int iRet = 0;
	EC_KEY *eckey = NULL;

	unsigned char *cipherBinData = (unsigned char *)malloc(cipherDataLen / 2 + 1);
	unsigned int cipherBinDataLen = cipherDataLen / 2 + 1;
	// 获取EC_KEY结构的公钥
	iRet = GetSM2PrivateECKeyFromD(&eckey, (char *)pucPriKey, uiPriKeyLen);
	if (iRet != 0)
	{
		iRet = -1;
		goto END;
	}

	HexStrBin((unsigned char *)cipherData, cipherDataLen, cipherBinData, &cipherBinDataLen);

	iRet = SM2Decrypt(cipherBinData, cipherBinDataLen, eckey, (unsigned char *)OriData, (unsigned int *)OriDataLen);

END:
	if (eckey != NULL)
	{
		EC_KEY_free(eckey);
	}
	return iRet;
}

int SM2::SM2Encrypt(unsigned char *OriData, unsigned int OriDataLen, EC_KEY *eckey, unsigned char *cipherData, unsigned int *cipherDataLen)
{
	int iRet = 0;
	unsigned char *t, *hm;
	BIGNUM *rand;
	EC_POINT *rG, *rK;
	BIGNUM *rKx, *rKy, *rGx, *rGy, *rGxTmp, *rGyTmp;

	BN_CTX *ctx = NULL;
	BIGNUM *n = NULL;
	EC_POINT *point = NULL;
	EC_GROUP *group;
	const EC_POINT *pub_key;

	// unsigned char cipherData[2014] = {0}; // C1||C2||C3
	unsigned char bK[65] = {0};
	unsigned char C3[33] = {0};

	if (eckey == NULL || (group = (EC_GROUP *)EC_KEY_get0_group(eckey)) == NULL ||
		(pub_key = EC_KEY_get0_public_key(eckey)) == NULL)
	{
		iRet = -1;
		goto END;
	}

	ctx = BN_CTX_new();
	if (!ctx)
	{
		iRet = -1;
		goto END;
	}
	BN_CTX_start(ctx);
	n = BN_CTX_get(ctx);
	rKx = BN_CTX_get(ctx);
	rKy = BN_CTX_get(ctx);
	rGx = BN_CTX_get(ctx);
	rGy = BN_CTX_get(ctx);
	rGxTmp = BN_CTX_get(ctx);
	rGyTmp = BN_CTX_get(ctx);

	if (!EC_GROUP_get_order(group, n, ctx))
	{
		iRet = -1;
		goto END;
	}
	point = EC_POINT_new(group);
	if (!point)
	{
		iRet = -1;
		goto END;
	}
	rK = EC_POINT_new(group);
	rand = BN_new();

	//随机数k∈[1,n-1]
	BN_rand_range(rand, n);

	//C1=[k]G=(x1,y1)
	point = EC_POINT_new(group);
	if (!EC_POINT_mul(group, point, rand, NULL, NULL, ctx))
	{
		iRet = -1;
		goto END;
	}
	if (EC_METHOD_get_field_type(EC_GROUP_method_of(group)) == NID_X9_62_prime_field)
	{
		if (!EC_POINT_get_affine_coordinates_GFp(group, point, rGxTmp, rGyTmp, ctx))
		{
			iRet = -1;
			goto END;
		}
	}
	else /* NID_X9_62_characteristic_two_field */
	{
		if (!EC_POINT_get_affine_coordinates_GF2m(group, point, rGxTmp, rGyTmp, ctx))
		{
			iRet = -1;
			goto END;
		}
	}
	if (!BN_nnmod(rGx, rGxTmp, n, ctx) || !BN_nnmod(rGy, rGyTmp, n, ctx))
	{
		ECDSAerr(ECDSA_F_ECDSA_SIGN_SETUP, ERR_R_BN_LIB);
		iRet = -1;
		goto END;
	}

	BN_bn2bin(rGx, cipherData);
	BN_bn2bin(rGy, &cipherData[32]);

	//[k]PB=(x2,y2)
	EC_POINT_mul(group, rK, NULL, pub_key, rand, ctx);

	rKx = BN_new();
	rKy = BN_new();
	if (!EC_POINT_get_affine_coordinates_GFp(group, rK, rKx, rKy, ctx))
	{
		iRet = -1;
		goto END;
	}

	//t=KDF(x2||y2, klen)
	BN_bn2bin(rKx, bK);
	BN_bn2bin(rKy, &bK[32]);

	t = (BYTE)malloc(OriDataLen + 1);
	memset(t, 0, OriDataLen + 1);

	KDF((char *)bK, 64, OriDataLen, (char *)t);

	for (int i = OriDataLen; i--;)
	{
		t[i] = t[i] ^ OriData[i];
	}

	//C3 = Hash(x2||M||y2)
	hm = (unsigned char *)malloc(OriDataLen + 65);
	memset(hm, 0, OriDataLen + 65);

	memcpy(hm, bK, 32);
	memcpy(&hm[32], OriData, OriDataLen);
	memcpy(&hm[OriDataLen + 32], &bK[32], 32);

	SM3::sm3_sum(hm, OriDataLen + 64, C3);

	//C = C1||C2||C3
	memcpy(&cipherData[64], t, OriDataLen);
	memcpy(&cipherData[64 + OriDataLen], C3, 32);
	*cipherDataLen = OriDataLen + 96;
END:

	if (t != NULL)
	{
		free(t);
		t = NULL;
	}
	if (hm != NULL)
	{
		free(hm);
		hm = NULL;
	}

	if (rK != NULL)
	{
		EC_POINT_free(rK);
		rK = NULL;
	}

	// if (group != NULL)
	// {
	// 	EC_GROUP_free(group);
	// 	group = NULL;
	// }

	if (point != NULL)
	{
		EC_POINT_free(point);
		point = NULL;
	}
	BN_CTX_end(ctx);
	BN_CTX_free(ctx);
	return iRet;
}

int SM2::SM2Decrypt(unsigned char *cipherData, unsigned int cipherDataLen, EC_KEY *eckey, unsigned char *OriData, unsigned int *OriDataLen)
{
	int iRet = 0;
	unsigned char *t, *c2, *hm;
	unsigned char bC1x[65] = {0};
	unsigned char bC1y[65] = {0};
	unsigned char bK[65] = {0};
	unsigned char u[33] = {0};

	unsigned int mlen, hm_len;

	EC_POINT *rG, *rK, *point;
	BIGNUM *C1x, *C1y, *rKx, *rKy;
	BN_CTX *ctx = NULL;
	EC_GROUP *group = NULL;

	if (eckey == NULL || (group = (EC_GROUP *)EC_KEY_get0_group(eckey)) == NULL)
	{
		iRet = -1;
		goto END;
	}

	ctx = BN_CTX_new();
	if (!ctx)
	{
		iRet = -1;
		goto END;
	}
	BN_CTX_start(ctx);

	point = EC_POINT_new(group);
	if (!point)
	{
		iRet = -1;
		goto END;
	}
	// 获取国密局定义的SM2曲线
	GetSM2Group(&group);
	if (!group)
	{
		iRet = -1;
		goto END;
	}
	//取出rG
	C1x = BN_new();
	C1y = BN_new();

	memcpy(&bC1x[32], cipherData, 32);
	memcpy(&bC1y[32], &cipherData[32], 32);

	BN_bin2bn(bC1x, 64, C1x);
	BN_bin2bn(bC1y, 64, C1y);

	rG = EC_POINT_new(group);
	if (!EC_POINT_set_affine_coordinates_GFp(group,
											 rG, C1x, C1y, ctx))
	{
		iRet = -1;
		goto END;
	}

	//求得rK
	rK = EC_POINT_new(group);
	EC_POINT_mul(group, rK, NULL, rG,
				 EC_KEY_get0_private_key(eckey), ctx);

	rKx = BN_new();
	rKy = BN_new();
	if (!EC_POINT_get_affine_coordinates_GFp(group,
											 rK, rKx, rKy, ctx))
	{
		iRet = -1;
		goto END;
	}

	//求取hv 解密
	BN_bn2bin(rKx, bK);
	BN_bn2bin(rKy, &bK[32]);

	mlen = cipherDataLen - 96;

	c2 = new unsigned char[mlen + 1];
	memset(c2, 0, mlen + 1);
	memcpy(c2, &cipherData[64], mlen);

	t = new unsigned char[mlen + 1];
	memset(t, 0, mlen + 1);
	KDF((char *)bK, 64, cipherDataLen - 96, (char *)t);

	for (int i = cipherDataLen - 96; i--;)
	{
		t[i] = t[i] ^ c2[i];
	}

	hm_len = mlen + 64;
	hm = new unsigned char[hm_len + 1];
	memset(hm, 0, hm_len + 1);

	BN_bn2bin(rKx, hm);
	memcpy(&hm[32], t, mlen);
	BN_bn2bin(rKy, &hm[32 + mlen]);

	//校验hash值
	SM3::sm3_sum(hm, hm_len, u);
	for (int i = 0; i < 32; i++)
	{
		if (u[i] != cipherData[cipherDataLen - 32 + i])
		{
			iRet = -1;
			goto END;
		}
	}

	memcpy(OriData, t, mlen);
	*OriDataLen = mlen;

END:
	if (rG != NULL)
	{
		EC_POINT_free(rG);
		rG = NULL;
	}

	if (rK != NULL)
	{
		EC_POINT_free(rK);
		rK = NULL;
	}

	if (t != NULL)
	{
		delete[] t;
		t = NULL;
	}

	if (c2 != NULL)
	{
		delete[] c2;
		c2 = NULL;
	}

	if (hm != NULL)
	{
		delete[] hm;
		hm = NULL;
	}

	if (group != NULL)
	{
		EC_GROUP_free(group);
		group = NULL;
	}

	return iRet;
}

int SM2::KDF(const char *cdata, int datalen, int keylen, char *retdata)
{
	int nRet = -1;
	unsigned char *pRet;
	unsigned char *pData;

	if (cdata == NULL || datalen <= 0 || keylen <= 0)
	{
		return nRet;
	}

	if (NULL == (pRet = (unsigned char *)malloc(keylen)))
	{
		if (pRet)
			free(pRet);
		return nRet;
	}

	if (NULL == (pData = (unsigned char *)malloc(datalen + 4)))
	{
		if (pRet)
			free(pRet);
		if (pData)
			free(pData);

		return nRet;
	}

	memset(pRet, 0, keylen);
	memset(pData, 0, datalen + 4);

	unsigned char cdgst[32] = {0}; //摘要
	unsigned char cCnt[4] = {0};   //计数器的内存表示值
	int nCnt = 1;				   //计数器
	int nDgst = 32;				   //摘要长度

	int nTimes = (keylen + 31) / 32; //需要计算的次数
	int i = 0;
	memcpy(pData, cdata, datalen);
	for (i = 0; i < nTimes; i++)
	{
		//cCnt
		{
			cCnt[0] = (nCnt >> 24) & 0xFF;
			cCnt[1] = (nCnt >> 16) & 0xFF;
			cCnt[2] = (nCnt >> 8) & 0xFF;
			cCnt[3] = (nCnt)&0xFF;
		}
		memcpy(pData + datalen, cCnt, 4);
		SM3::sm3_sum(pData, datalen + 4, cdgst);

		if (i == nTimes - 1) //最后一次计算，根据keylen/32是否整除，截取摘要的值
		{
			if (keylen % 32 != 0)
			{
				nDgst = keylen % 32;
			}
		}
		memcpy(pRet + 32 * i, cdgst, nDgst);

		i++;	//
		nCnt++; //
	}

	if (retdata != NULL)
	{
		memcpy(retdata, pRet, keylen);
	}

	nRet = 0;

	if (pRet)
		free(pRet);
	if (pData)
		free(pData);

	return nRet;
}

int SM2::Bin2HexStr(unsigned char *binData, unsigned int binDataLen, unsigned char *hexStrData, unsigned int *hexStrDataLen)
{
	for (int i = 0; i < binDataLen; i++)
	{
		sprintf((char *)hexStrData, "%s%02X", hexStrData, binData[i]);
	}
	*hexStrDataLen = 2 * binDataLen;
}

int SM2::HexStrBin(unsigned char *hexStrData, unsigned int hexStrDataLen, unsigned char *binData, unsigned int *binDataLen)
{
	if ((NULL == hexStrData) || (0 == hexStrDataLen) || (NULL == binData) || (0 != hexStrDataLen % 2))
	{
		return -1;
	}

	for (unsigned long ulIndex = 0; ulIndex < hexStrDataLen; ulIndex += 2)
	{
		unsigned char bHigh = ASC_CHAR_TO_HEX(hexStrData[ulIndex]);
		unsigned char bLow = ASC_CHAR_TO_HEX(hexStrData[ulIndex + 1]);
		if ((0xFF == bHigh) || (0xFF == bLow))
		{
			return -2;
		}
		binData[ulIndex / 2] = bHigh * 0x10 + bLow;
	}

	*binDataLen = hexStrDataLen / 2;

	return 0;
}

int SM2::SM2Sign_HexPriK_DerSigndata(char *pucOriData, int uiOriDataLen, char *pucPriKey, int uiPriKeyLen, char *pucSign, int *puiSignLen)
{
	int iRet = 0;
	EC_KEY *eckey = NULL;
	ECDSA_SIG *s = NULL;
	char ucHash[32] = {0};
	// 将私钥转换为EC_KEY结构
	iRet = SM2::GetSM2PrivateECKeyFromD(&eckey, pucPriKey, uiPriKeyLen);
	if (iRet != 0)
	{
		goto END;
	}

	// SM3摘要
	iRet = SM2::GetSM3HashForSign((unsigned char *)pucOriData, (unsigned int)uiOriDataLen, (unsigned char *)SM2_DEFAULT_USER_ID, strlen(SM2_DEFAULT_USER_ID), eckey, (unsigned char *)ucHash);
	if (iRet != 0)
	{
		goto END;
	}

	RAND_seed(ucHash, 32);
	iRet = SM2::SM2Sign((const unsigned char *)ucHash, 32, eckey, &s);
	if (iRet != 0)
	{
		iRet = -1;
		goto END;
	}

	*puiSignLen = i2d_ECDSA_SIG(s, (unsigned char **)&pucSign);

END:
	if (eckey != NULL)
	{
		EC_KEY_free(eckey);
		eckey = NULL;
	}
	if (s != NULL)
	{
		ECDSA_SIG_free(s);
		s = NULL;
	}

	return iRet;
}

int SM2::SM2Verify_HexPubk_DerSigndata(char *pucOriData, int uiOriDataLen, char *pucSign, int uiSignLen, char *pucPubKey, int uiPubKeyLen)
{
	int iRet = 0;
	EC_KEY *eckey = NULL;
	ECDSA_SIG *sig = NULL;
	unsigned char ucHash[32] = {0};

	// 获取EC_KEY结构的公钥
	iRet = GetSM2PublicECKeyFromXY(&eckey, pucPubKey, uiPubKeyLen);
	if (iRet != 0)
	{
		iRet = -1;
		goto END;
	}
	// 获取签名值结构体
	if (d2i_ECDSA_SIG(&sig, (const unsigned char **)&pucSign, uiSignLen) == NULL)
	{
		iRet = -1;
		goto END;
	}
	// 对原文作SM3摘要
	iRet = GetSM3HashForSign((unsigned char *)pucOriData, uiOriDataLen, (unsigned char *)SM2_DEFAULT_USER_ID, strlen(SM2_DEFAULT_USER_ID), eckey, ucHash);
	if (iRet != 0)
	{
		iRet = -1;
		goto END;
	}

	iRet = SM2Verify(ucHash, 32, sig, eckey);

END:
	if (eckey != NULL)
	{
		EC_KEY_free(eckey);
	}

	if (sig != NULL)
	{
		ECDSA_SIG_free(sig);
	}
	return iRet;
}

int SM2::SM2SignByP7_HexPriK(char *inData, int dataLen, char *cert, int certLen, char *pucPriKey, int uiPriKeyLen, char *p7SignData, int *p7SignDataLen)
{
	int iRet = 0;
	char rtSignature[512] = {0};
	int rtSignatureLen = 512;
	unsigned char pucP7SignData[4096 * 10] = {0};
	unsigned int puiP7SignDataLen = 4096 * 10;

	// 开始签名
	iRet = SM2Sign_HexPriK_DerSigndata(inData, dataLen, pucPriKey, uiPriKeyLen, rtSignature, &rtSignatureLen);
	if (iRet)
	{
		return -1;
	}

	iRet = MakeP7SignData((unsigned char *)inData, dataLen, (unsigned char *)rtSignature, rtSignatureLen, (unsigned char *)cert, certLen, pucP7SignData, &puiP7SignDataLen);
	if (iRet)
	{
		return -1;
	}
	memcpy(p7SignData, pucP7SignData, puiP7SignDataLen);
	*p7SignDataLen = puiP7SignDataLen;
	return iRet;
}

int SM2::SM2VerifyByP7(char *p7Data, int p7DataLen)
{
	int iRet = 0;
	char pubkey[512] = {0};
	int pubkeyLen = 512;
	unsigned char pucInData[4096 * 20] = {0};
	unsigned int puiInDataLen = 4096 * 20;
	unsigned char pucSignData[512] = {0};
	unsigned int puiSignDataLen = 512;
	unsigned char pucCert[4096 * 10] = {0};
	unsigned int puiCertLen = 4096 * 10;
	iRet = OpenP7SignData((unsigned char *)p7Data, p7DataLen, pucInData, &puiInDataLen, pucSignData, &puiSignDataLen, pucCert, &puiCertLen);
	if (iRet)
	{
		return -1;
	}

	// 解析证书  获取公钥
	iRet = GetDerPubkey((char *)pucCert, puiCertLen, pubkey, &pubkeyLen);
	if (iRet)
	{
		return -1;
	}
	// 验证签名
	return SM2Verify_HexPubk_DerSigndata((char *)pucInData, puiInDataLen, (char *)pucSignData, puiSignDataLen, pubkey, pubkeyLen);
}

int SM2::MakeP7SignData(unsigned char *pucInData, unsigned int uiInDataLen,
						unsigned char *pucSignData, unsigned int uiSignDataLen,
						unsigned char *pucCert, unsigned int uiCertLen,
						unsigned char *pucP7SignData, unsigned int *puiP7SignDataLen)
{
	long lResult = 0;
	PKCS7 *p7SignData = NULL;
	X509_ALGOR *mhash = NULL;
	PKCS7 *p7D = NULL;
	X509 *x = NULL;
	PKCS7_SIGNER_INFO *si = NULL;
	unsigned char *szDerP7 = NULL;

	p7SignData = PKCS7_new();
	unsigned char *szPtrP7;
	int iDataLen = 0;
	unsigned char *pCert = pucCert;
	if (p7SignData == NULL)
	{
		lResult = -1;
		goto END;
	}
	PKCS7_set_type(p7SignData, NID_pkcs7_signed);

	ASN1_OBJECT *typeASN1;
	typeASN1 = ASN1_OBJECT_new();
	typeASN1->sn = "pkcs7-signedData";
	typeASN1->ln = "pkcs7-signedData";
	typeASN1->nid = 0x16;
	typeASN1->length = 0x0A;
	typeASN1->data = (const unsigned char *)"\x2A\x81\x1C\xCF\x55\x06\x01\x04\x02\x02";
	typeASN1->flags = 0x00;
	p7SignData->type = typeASN1;

	PKCS7_set_detached(p7SignData, 1);

	// 设置摘要算法
	mhash = X509_ALGOR_new();
	if (mhash == NULL)
	{
		lResult = -1;
		goto END;
	}
	mhash->algorithm = OBJ_txt2obj(OID_SM3_ALG, 1);

	mhash->parameter = ASN1_TYPE_new();
	if (mhash->parameter == NULL)
	{
		lResult = -1;
		goto END;
	}
	mhash->parameter->type = V_ASN1_NULL;
	sk_X509_ALGOR_push(p7SignData->d.sign->md_algs, mhash);

	// 设置被签名的数据内容
	p7D = PKCS7_new();
	if (p7D == NULL)
	{
		lResult = -1;
		goto END;
	}
	// PKCS7_set_type(p7D,NID_pkcs7_data);

	PKCS7_set_type(p7D, NID_pkcs7_data);
	ASN1_OBJECT *p7DTypeASN1;
	p7DTypeASN1 = ASN1_OBJECT_new();
	p7DTypeASN1->sn = "pkcs7-data";
	p7DTypeASN1->ln = "pkcs7-data";
	p7DTypeASN1->nid = 0x15;
	p7DTypeASN1->length = 0x0A;
	p7DTypeASN1->data = (const unsigned char *)"\x2A\x81\x1C\xCF\x55\x06\x01\x04\x02\x01";
	p7DTypeASN1->flags = 0x00;
	p7D->type = p7DTypeASN1;

	ASN1_OCTET_STRING_set(p7D->d.data, pucInData, uiInDataLen);
	PKCS7_set_content(p7SignData, p7D);

	// 存放证书
	p7SignData->d.sign->cert = sk_X509_new_null();
	x = X509_new();
	if (p7SignData->d.sign->cert == NULL || x == NULL)
	{
		lResult = -1;
		goto END;
	}

	d2i_X509(&x, (const unsigned char **)&pCert, uiCertLen);
	sk_X509_push(p7SignData->d.sign->cert, x);

	// 存放SignerInfo
	si = PKCS7_SIGNER_INFO_new();
	if (si == NULL)
	{
		lResult = -1;
		goto END;
	}
	// 设置SignerInfo版本号
	ASN1_INTEGER_set(si->version, 1);
	// 设置SignerInfo证书颁发者别名
	X509_NAME_set(&si->issuer_and_serial->issuer, X509_get_issuer_name(x));
	// 设置SignerInfo证书颁发者序号
	si->issuer_and_serial->serial = M_ASN1_INTEGER_dup(X509_get_serialNumber(x));
	// 设置SignerInfo摘要算法
	si->digest_alg->algorithm = OBJ_txt2obj(OID_SM3_ALG, 1);

	si->digest_alg->parameter = ASN1_TYPE_new();
	if (si->digest_alg->parameter == NULL)
	{
		lResult = -1;
		goto END;
	}
	si->digest_alg->parameter->type = V_ASN1_NULL;

	si->digest_enc_alg->algorithm = OBJ_txt2obj(OID_P7SM2_ALG, 1);

	si->digest_enc_alg->parameter = ASN1_TYPE_new();
	if (si->digest_enc_alg->parameter == NULL)
	{
		lResult = -1;
		goto END;
	}
	si->digest_enc_alg->parameter->type = V_ASN1_NULL;
	// 设置SignerInfo签名值
	ASN1_OCTET_STRING_set(si->enc_digest, pucSignData, uiSignDataLen);
	sk_PKCS7_SIGNER_INFO_push(p7SignData->d.sign->signer_info, si);

	iDataLen = i2d_PKCS7(p7SignData, NULL);
	if (iDataLen <= 0)
	{
		lResult = -1;
		goto END;
	}
	szDerP7 = (unsigned char *)malloc(iDataLen);
	memset(szDerP7, 0, iDataLen);
	szPtrP7 = szDerP7;
	iDataLen = i2d_PKCS7(p7SignData, &szPtrP7);

	memcpy(pucP7SignData, szDerP7, iDataLen);
	*puiP7SignDataLen = iDataLen;
	lResult = 0;

	goto END;
END:
	if (p7SignData != NULL)
	{
		PKCS7_free(p7SignData);
		p7SignData = NULL;
	}

	if (szDerP7 != NULL)
	{
		free(szDerP7);
		szDerP7 = NULL;
	}

	return lResult;
}

int SM2::OpenP7SignData(unsigned char *pucP7SignData, unsigned int uiP7SignDataLen,
						unsigned char *pucInData, unsigned int *puiInDataLen,
						unsigned char *pucSignData, unsigned int *puiSignDataLen,
						unsigned char *pucCert, unsigned int *puiCertLen)
{
	long lTotleLen = uiP7SignDataLen;
	long lObjLen = 0;
	const unsigned char *p = NULL, *op = NULL;
	int tag = 0, xclass = 0, flag = 0, hl = 0;
	bool bIsPubObj = false;
	bool bIsSignDataObj = false;
	bool bIsPlaitDataObj = false;
	bool bSM2Sign = false;
	bool bGetSM2Sign = false;
	bool isRSASign = false;

	static unsigned char rsaAlgID[] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02};	  //rsa  1.2.840.113549.1.7.2
	static unsigned char sm2SignAlgID[] = {0x2A, 0x81, 0x1C, 0xCF, 0x55, 0x01, 0x82, 0x2D, 0x01}; //sm2 1.2.156.10197.1.301.1 SM2-1数字签名算法

	static unsigned char sm2AlgStandardID[] = {0x2A, 0x81, 0x1C, 0xCF, 0x55, 0x06, 0x01, 0x04, 0x02, 0x02};		//sm2 1.2.156.10197.6.1.4.2.2 SM2加密签名消息语法规范
	static unsigned char sm2AlgStandardID_BOC[] = {0x2A, 0x81, 0x1C, 0xCF, 0x55, 0x06, 0x01, 0x04, 0x02, 0x01}; //sm2 1.2.156.10197.6.1.4.2.1
	static unsigned char sm2ECCPubKeyID[] = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01};							//ecpubkey 1.2.840.10045.2.1

	//摘要算法
	static unsigned char SM3AlgID[] = {0x2A, 0x81, 0x1C, 0xCF, 0x55, 0x01, 0x83, 0x11};

	p = pucP7SignData;
	while (lTotleLen > 0)
	{
		if (isRSASign == true)
		{
			break;
		}
		op = p;
		flag = ASN1_get_object((const unsigned char **)&p, &lObjLen, &tag, &xclass, lTotleLen);
		if (-1 == flag)
		{
			break;
		}
		hl = p - op;
		lTotleLen -= hl;

		switch (tag)
		{
		case V_ASN1_EOC:
		{
			if (bGetSM2Sign == true)
			{
				memcpy(pucCert, p, lObjLen);
				*puiCertLen = lObjLen;

				bIsPubObj = false;
				bGetSM2Sign = false;
			}
		}
		break;
		case V_ASN1_OCTET_STRING:
		{
			if (true == bIsSignDataObj && bSM2Sign == true)
			{
				memcpy(pucSignData, p, lObjLen);
				*puiSignDataLen = lObjLen;
				bIsSignDataObj = false;
			}

			if (true == bIsPlaitDataObj && bSM2Sign == true)
			{
				memcpy(pucInData, p, lObjLen);
				*puiInDataLen = lObjLen;
				bIsPlaitDataObj = false;
				bGetSM2Sign = true;
			}
		}
		break;
		case V_ASN1_OBJECT:
		{
			//此时由于OBJID是SM2的特殊对象，所以没有必要将内存数据转换为对应的内部OID类型，直接比对内存即可
			if (0 == memcmp(p, sm2ECCPubKeyID, lObjLen))
			{
				bIsPubObj = true;
			}
			else if (0 == memcmp(p, sm2SignAlgID, lObjLen))
			{
				bIsSignDataObj = true;
			}
			else if (0 == memcmp(p, sm2AlgStandardID_BOC, lObjLen))
			{
				bIsPlaitDataObj = true;
			}
			else if (0 == memcmp(p, sm2AlgStandardID, lObjLen))
			{
				bSM2Sign = true;
			}
			else if (0 == memcmp(p, rsaAlgID, lObjLen))
			{
				isRSASign = true;
			}
			// else if (0 == memcmp(p,SM3AlgID,lObjLen)){
			// 	*piHashAlg = 6;
			// }
		}
		break;
		}
		//V_ASN1_EOC 为 context 显式为 0x80 隐式为 0xa0
		if (V_ASN1_SEQUENCE != tag && V_ASN1_EOC != tag && V_ASN1_SET != tag)
		{
			p += lObjLen;
			lTotleLen -= lObjLen;
		}
	}
	//以上只为将ASN1对象能够在一个数据结构体内扒出，不能直接对应至固定的内部对象结构
	if ((0 == puiCertLen || 0 == puiSignDataLen) && isRSASign == false)
	{
		return -1;
	}
	if (isRSASign == true)
	{
		unsigned char *pDerP7 = pucP7SignData;
		PKCS7 *p7;
		if ((p7 = d2i_PKCS7(NULL, (const unsigned char **)&pDerP7, uiP7SignDataLen)) == NULL)
		{
			return -1;
		}
		PKCS7_SIGNER_INFO *signInfo;
		STACK_OF(PKCS7_SIGNER_INFO) * sk;
		sk = p7->d.sign->signer_info;
		signInfo = sk_PKCS7_SIGNER_INFO_value(sk, 0);

		*puiInDataLen = ASN1_STRING_length(p7->d.sign->contents->d.data);
		memcpy(pucInData, ASN1_STRING_data(p7->d.sign->contents->d.data), *puiInDataLen);
		unsigned char *pCert = pucCert;
		X509 *cert = sk_X509_value(p7->d.sign->cert, 0);
		*puiCertLen = i2d_X509(cert, &pCert);
		*puiSignDataLen = ASN1_STRING_length(signInfo->enc_digest);
		memcpy(pucSignData, ASN1_STRING_data(signInfo->enc_digest), *puiSignDataLen);

		// // p7->d.sign->
		// char buf[128] = {0};
		// int buflen = OBJ_obj2txt(buf, 128, signInfo->digest_alg->algorithm, 0);
		// std::string strOid(buf, buflen);
		// if(strOid == OID_SM3_ALG)
		// {
		// 	*piHashAlg = ALGID_HASH_SM3;
		// }

		PKCS7_free(p7);
		p7 = NULL;
	}
	// if(*piHashAlg == 0){
	// 	return -1;
	// }

	return 0;
}

int SM2::GetDerPubkey(const char *stDerCert, int stDerCertLen, char *pubkey, int *pubkeyLen)
{
	int iRet = 0;
	void *pX509Cert = NULL;
	//unsigned char* pucDerCert = (unsigned char*)malloc(sizeof(unsigned char) * stDerCert.length());
	unsigned char pucDerCert[4096] = {0};
	memset(pucDerCert, 0, 4096);
	memcpy(pucDerCert, stDerCert, stDerCertLen);
	unsigned char *p = pucDerCert;

	if (NULL == pucDerCert)
	{
		iRet = -1;
		goto END;
	}

	pX509Cert = (void *)d2i_X509(NULL, (const unsigned char **)(&p), stDerCertLen);
	if (pX509Cert == NULL)
	{
		iRet = -1;
		goto END;
	}

	X509 *x509;
	x509 = (X509 *)pX509Cert;

	*pubkeyLen = x509->cert_info->key->public_key->length;
	if (*pubkeyLen >= 1024)
	{
		iRet = -1;
		goto END;
	}
	memcpy(pubkey, x509->cert_info->key->public_key->data, *pubkeyLen);

END:
	if (NULL != pX509Cert)
	{
		X509_free((X509 *)pX509Cert);
		pX509Cert = NULL;
	}
	return iRet;
}

int SM2::SM2CertGetPublicKey(char* cert, int certLen, char* hexPublicKeyStr, int* hexPublicKeyStrLen)
{
	char pubkey[512] = {0};
	int pubkeyLen = 512;
	int iRet = GetDerPubkey(cert, certLen, pubkey, &pubkeyLen);
	if (iRet)
	{
		memset(hexPublicKeyStr,0x0,*hexPublicKeyStrLen);
		*hexPublicKeyStrLen = 0;
		return -1;
	}

	return Bin2HexStr((unsigned char*)pubkey,pubkeyLen,(unsigned char*)hexPublicKeyStr,(unsigned int*)hexPublicKeyStrLen);

}