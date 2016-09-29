//	dtcsp for IC Card access control device

#ifndef _DTCSP_API_H_
#define _DTCSP_API_H_

#ifdef __cplusplus
extern "C" {
#endif

typedef unsigned int		DTCSP_UINT32;

#ifdef _WIN32
typedef __int64         DTCSP_INT64;
#else
typedef long long       DTCSP_INT64;
#endif

typedef unsigned short		DTCSP_UINT16;
typedef unsigned char		DTCSP_UCHAR;
typedef char			DTCSP_CHAR;
typedef int			DTCSP_INT32;
typedef short			DTCSP_INT16;
typedef void			DTCSP_VOID;
typedef long			DTCSP_LONG;
typedef unsigned long		DTCSP_ULONG;
typedef DTCSP_UINT32*		DTCSP_UINT32_PTR;
typedef DTCSP_UINT16*		DTCSP_UINT16_PTR;
typedef DTCSP_UCHAR*		DTCSP_UCHAR_PTR;
typedef DTCSP_CHAR*		DTCSP_CHAR_PTR;
typedef DTCSP_INT32*		DTCSP_INT32_PTR;
typedef DTCSP_INT16*		DTCSP_INT16_PTR;
typedef DTCSP_VOID*		DTCSP_VOID_PTR;
typedef DTCSP_INT32		DTCSP_HANDLE;
typedef DTCSP_LONG *		DTCSP_LONG_PTR;
typedef DTCSP_ULONG *		DTCSP_ULONG_PTR;

//	RSA modulus
#define MAX_RSA_MODULUS_LEN		256		//2048 bits
#define MAX_RSA_PRIME_LEN		128

//modified by LiuQiang 2008.07.25
#ifdef _SUPPORT_RSA_4096_
#define MAX_RSA_MODULUS_LEN_EX		512		//4096 bits
#define MAX_RSA_PRIME_LEN_EX		256
//add by chaiqing 2008.9.3 添加了宏_DT_SJY05D_HGD1E2_和_DT_SJY05B_HGB2B1B4_
#else 
//#if defined(_DT_SJY05C_HGC1D2_)||defined(_DT_SJY05D_HGD1E2_)||defined(_DT_SJY05B_HGB2B1B4_)||defined(_DT_THU_COMMON_)||defined(_DT_THU_HIGH_)

#define MAX_RSA_MODULUS_LEN_EX		256		//2048 bits
#define MAX_RSA_PRIME_LEN_EX		128
//#endif
//end add 2008.9.3
#endif
//end modified by LiuQiang 2008.07.25

#define	DTCSP_MAX_DEV_NUM		5

typedef struct
{
	DTCSP_INT32  DeviceCount;	// 1,2,3,4 card number
	DTCSP_HANDLE MultiCardHandle[DTCSP_MAX_DEV_NUM];
	DTCSP_HANDLE hBanlanceHandle;
	DTCSP_INT32  WaitIdleTimeOut;
	DTCSP_INT32  DeviceInitType;
}DTCSP_CONTEXT, *DTCSP_CONTEXT_PTR;

typedef struct
{
	DTCSP_HANDLE	MultiCardHandle[DTCSP_MAX_DEV_NUM];
	DTCSP_INT32	IsNotFirstTime;
}DTCSP_SHAREDMEMORY, *DTCSP_SHAREDMEMORY_PTR;

typedef struct
{
  unsigned int  bits;                 		/* length in bits of modulus */
  unsigned char modulus[MAX_RSA_MODULUS_LEN];  	/* modulus */
  unsigned char exponent[MAX_RSA_MODULUS_LEN]; 	/* public exponent */
} DTCSP_RSA_PUBLIC_KEY;

typedef struct 
{
  unsigned int  bits;                           	/* length in bits of modulus */
  unsigned char modulus[MAX_RSA_MODULUS_LEN];       	/* n */
  unsigned char publicExponent[MAX_RSA_MODULUS_LEN];	/* e */
  unsigned char exponent[MAX_RSA_MODULUS_LEN];      	/* d */
  unsigned char prime[2][MAX_RSA_PRIME_LEN];        	/* p,q */
  unsigned char primeExponent[2][MAX_RSA_PRIME_LEN];	/* dp,dq */
  unsigned char coefficient[MAX_RSA_PRIME_LEN];      	/* qInv */
} DTCSP_RSA_PRIVATE_KEY;

//modified by LiuQiang 2008.07.25
#ifdef _SUPPORT_RSA_4096_
typedef struct
{
  unsigned int  bits;                 		/* length in bits of modulus */
  unsigned char modulus[MAX_RSA_MODULUS_LEN_EX];  	/* modulus */
  unsigned char exponent[MAX_RSA_MODULUS_LEN_EX]; 	/* public exponent */
} DTCSP_RSA_PUBLIC_KEY_EX;

typedef struct 
{
  unsigned int  bits;                           	/* length in bits of modulus */
  unsigned char modulus[MAX_RSA_MODULUS_LEN_EX];       	/* n */
  unsigned char publicExponent[MAX_RSA_MODULUS_LEN_EX];	/* e */
  unsigned char exponent[MAX_RSA_MODULUS_LEN_EX];      	/* d */
  unsigned char prime[2][MAX_RSA_PRIME_LEN_EX];        	/* p,q */
  unsigned char primeExponent[2][MAX_RSA_PRIME_LEN_EX];	/* dp,dq */
  unsigned char coefficient[MAX_RSA_PRIME_LEN_EX];      	/* qInv */
} DTCSP_RSA_PRIVATE_KEY_EX;
#endif
//end modified by LiuQiang 2008.07.25

typedef struct
{
  unsigned int  bits;                 		/* length in bits of modulus */
  unsigned char modulus[MAX_RSA_MODULUS_LEN];  	/* modulus */
  unsigned char publicExponent[MAX_RSA_MODULUS_LEN]; 	/* public exponent */
  unsigned char cipherPrivateKey[MAX_RSA_PRIME_LEN*7];
} DTCSP_RSA_CIPHER_PRIVATE_KEY;

typedef struct{
	DTCSP_CHAR DesKey[8];
	DTCSP_CHAR Iv[8];
	DTCSP_INT32 Flag;
}DTCSP_DES_CBC_CONTEXT,*DTCSP_DES_CBC_CONTEXT_PTR;

typedef struct{
	DTCSP_CHAR DesKey[24];
	DTCSP_CHAR Iv[8];
	DTCSP_INT32 Flag;
}DTCSP_3DES_CBC_CONTEXT,*DTCSP_3DES_CBC_CONTEXT_PTR;

typedef struct{
	DTCSP_UCHAR  SCB2Key[32];
	DTCSP_UINT16 InBuf[8096];
	DTCSP_INT32 KeyLen;
	DTCSP_INT32 Flag;
}DTCSP_SCB2_ECB_CONTEXT,*DTCSP_SCB2_ECB_CONTEXT_PTR;

typedef struct{
	DTCSP_UCHAR		SCB2Key[32];
	DTCSP_UCHAR		Iv[16];
	DTCSP_UINT16	InBuf[8096];
	DTCSP_INT32		KeyLen;
	DTCSP_INT32		Flag;
}DTCSP_SCB2_CBC_CONTEXT,*DTCSP_SCB2_CBC_CONTEXT_PTR;

//For ECC hash

typedef struct{
	DTCSP_INT32		InitFlag;
	DTCSP_INT32	    CardIndex;
}DTCSP_SHA_CONTEXT,*DTCSP_SHA_CONTEXT_PTR;


typedef struct{
	DTCSP_INT32			InitFlag; 	
	DTCSP_INT32			Flag; 		
	DTCSP_UCHAR		 	pID[64];    	
	DTCSP_INT32     nIDLen;  
	DTCSP_INT32			CardIndex;
}DTCSP_SCH_CONTEXT,*DTCSP_SCH_CONTEXT_PTR;

// 椭圆曲线格式：
#define  MAX_ECC_PRIME_LEN		32	//256bits
typedef struct
{ 
	unsigned char primep[MAX_ECC_PRIME_LEN];//素数p
	unsigned char a[MAX_ECC_PRIME_LEN];			//参数a
	unsigned char b[MAX_ECC_PRIME_LEN];			//参数b
	unsigned char gx[MAX_ECC_PRIME_LEN];		//参数Gx	/* x coordinate of the base poDTCSP_INT32 G */
	unsigned char gy[MAX_ECC_PRIME_LEN];		//参数Gy	/* y coordinate of the base poDTCSP_INT32 G */
	unsigned char n[MAX_ECC_PRIME_LEN];			//阶N		  /* order n of the base poDTCSP_INT32 G */
	unsigned  short  len;						//参数位长Len，Len必须为160、192、224或256
	unsigned  short  type;					/*对应芯片手册曲线类型,开始时为0*/ 
} DTCSP_ECC_CURVE, *DTCSP_ECC_CURVE_PTR;

// ECC公钥结构体
typedef struct
{
	DTCSP_ECC_CURVE	curve; /* ECC curve */	//外部曲线为用户指定的，其它要对len赋值
	unsigned char	qx[MAX_ECC_PRIME_LEN];		/* x coordinate of the poDTCSP_INT32 Q */
	unsigned char	qy[MAX_ECC_PRIME_LEN];		/* y coordinate of the poDTCSP_INT32 Q */
} DTCSP_ECC_PUBLIC_KEY, *DTCSP_ECC_PUBLIC_KEY_PTR;

// ECC私钥结构体
typedef struct
{
	DTCSP_ECC_CURVE  curve; /* ECC curve */  //外部曲线为用户指定的，其它要对len赋值
	unsigned char qx[MAX_ECC_PRIME_LEN];     /* x coordinate of the poDTCSP_INT32 Q */
	unsigned char qy[MAX_ECC_PRIME_LEN];     /* y coordinate of the poDTCSP_INT32 Q */  
	unsigned char d[MAX_ECC_PRIME_LEN];      /* d */
}DTCSP_ECC_PRIVATE_KEY, *DTCSP_ECC_PRIVATE_KEY_PTR;

// 备份恢复ECC密钥对结构体
typedef  struct
{ 
	DTCSP_ECC_CURVE	curve;
	unsigned char	EccKey[96];	//EccKey只需要包含qx\qy和d即可
	unsigned char EccKeyMessage[32];//ch
}DTCSP_ECC_BKEY,*DTCSP_ECC_BKEY_PTR;

// 签名验证信息结构体
typedef  struct { 
	unsigned char  Rdata[32];
	unsigned char  Sdata[32];
}DTCSP_ECC_SIG,*DTCSP_ECC_SIG_PTR;

// SCE加解密密文结构体
typedef  struct  
{
	unsigned short  nC2Len;  //涉及c2
	unsigned char   c1[64];
	unsigned char   c2[136];
	unsigned char   c3[32];
}DTCSP_ECC_CIPHER,*DTCSP_ECC_CIPHER_PTR;


/*typedef  struct  
{
	unsigned short	 nCipherLen;// 密文长度,涉及c2
	unsigned char	 c1[64];
	unsigned char	 c3[32];
	unsigned char	 c2[8192];//[136];
	//unsigned char	 c3[32];
}DTCSP_ECC_CIPHER_Ex,*DTCSP_ECC_CIPHER_PTR_Ex;*/
//add for THU 2008.10.7
//清华卡加速参数结构体
typedef struct
{
	unsigned char c[136];
	unsigned char cs[136];
} RSACSP_RSA_KEY_C_CS,*RSACSP_RSA_KEY_C_CS_PTR;
//end add 2008.10.7
/////////////////////function/////////////////////////////
DTCSP_INT32	DTCSP_Init(
		DTCSP_VOID_PTR* pContext,
		DTCSP_CHAR_PTR 	pConfigureFileName,
		DTCSP_UCHAR_PTR pPassword);

DTCSP_INT32 DTCSP_End(DTCSP_VOID_PTR *pContext);

DTCSP_INT32 DTCSP_GetDTCSPVersion(DTCSP_UCHAR_PTR pVersion);

DTCSP_INT32 DTCSP_GetCardVersion(
		DTCSP_VOID_PTR	pContext,
		DTCSP_UCHAR_PTR	pCardVersion);
		
DTCSP_INT32 DTCSP_GetKeyStatus(
		DTCSP_VOID_PTR		pContext,
		DTCSP_UINT32    	nKeyType,
		DTCSP_UINT32        	nKeyNum,
		DTCSP_UINT32_PTR	pKeyTag);
		
DTCSP_INT32 DTCSP_GetCardStatus(
		DTCSP_VOID_PTR		pContext,
		DTCSP_UCHAR_PTR		pRunStatus);
				
DTCSP_INT32 DTCSP_InitFlash(DTCSP_VOID_PTR pContext);

DTCSP_INT32 DTCSP_DisableAllInit(DTCSP_VOID_PTR pContext);

DTCSP_INT32 DTCSP_EnableInit(DTCSP_VOID_PTR pContext);

DTCSP_INT32 DTCSP_InitManagerBegin(
		DTCSP_VOID_PTR 	pContext,
		DTCSP_INT32  	nManagerCount);
		
DTCSP_INT32 DTCSP_InitManagerPassword(
		DTCSP_VOID_PTR	pContext,
		DTCSP_INT32	nManagerNumber);
		
DTCSP_INT32 DTCSP_InitManagerEnd(DTCSP_VOID_PTR pContext);

DTCSP_INT32 DTCSP_GetManagerCount(
		DTCSP_VOID_PTR	 pContext,
		DTCSP_INT32_PTR  pManagerCount);
		
DTCSP_INT32 DTCSP_AddOneManager(
		DTCSP_VOID_PTR		pContext,
		DTCSP_INT32		nManagerNumber);
		
DTCSP_INT32 DTCSP_DelOneManager(
      		DTCSP_VOID_PTR  pContext,
		DTCSP_INT32	nManagerNumber);
		
DTCSP_INT32 DTCSP_ManagerLogin(
		DTCSP_VOID_PTR  	pContext,
		DTCSP_INT32_PTR  	pManagerNumber);
		
DTCSP_INT32 DTCSP_ManagerLogout(DTCSP_VOID_PTR pContext);

DTCSP_INT32 DTCSP_ChangeManagerPassword(
		DTCSP_VOID_PTR 	pContext,
		DTCSP_INT32_PTR	pManagerNumber);
		
DTCSP_INT32 DTCSP_InitOperatorPassword(DTCSP_VOID_PTR  pContext);
DTCSP_INT32 DTCSP_AddOneOperator(DTCSP_VOID_PTR  pContext);
DTCSP_INT32 DTCSP_OperatorLogin(DTCSP_VOID_PTR  pContext);
DTCSP_INT32 DTCSP_OperatorLogout(DTCSP_VOID_PTR  pContext);

DTCSP_INT32 DTCSP_InitICCard(DTCSP_VOID_PTR  pContext);
DTCSP_INT32 DTCSP_BackupICCardBegin(DTCSP_VOID_PTR pContext);
DTCSP_INT32 DTCSP_BackupICCardEnd(DTCSP_VOID_PTR pContext);

DTCSP_INT32 DTCSP_PutSymmetricKey(
			DTCSP_VOID_PTR	pContext,
			DTCSP_INT32     nSymKeyNum,
			DTCSP_UCHAR_PTR pSymKey,
			DTCSP_INT32     nSymKeyLen);
			
DTCSP_INT32 DTCSP_GetSymmetricKey(
				DTCSP_VOID_PTR  pContext,
				DTCSP_INT32     nSymKeyNum,
				DTCSP_UCHAR_PTR pSymKey,
				DTCSP_INT32 *   nSymKeyLen);
				
DTCSP_INT32 DTCSP_DelSymmetricKey(
				DTCSP_VOID_PTR  pContext,
				DTCSP_INT32     nSymKeyNum);
				
DTCSP_INT32 DTCSP_SetSystemMasterKey(DTCSP_VOID_PTR pContext);

DTCSP_INT32 DTCSP_SetDeviceMasterKey(
				DTCSP_VOID_PTR	pContext,
				DTCSP_CHAR_PTR	pDeviceMasterKey,
				DTCSP_INT32	nDeviceMasterKeyLen);
				
DTCSP_INT32 DTCSP_GetRSAPublicKey(
				DTCSP_VOID_PTR	pContext,
				DTCSP_INT32		nKeyNumber,
				DTCSP_RSA_PUBLIC_KEY	*pPublicKey);
				
DTCSP_INT32	DTCSP_PutRSAKeyPair(
				DTCSP_VOID_PTR	pContext,
				DTCSP_INT32		nDstKeyNumber,
				DTCSP_RSA_PUBLIC_KEY	pPublicKey,
				DTCSP_RSA_PRIVATE_KEY	pPrivateKey);
				
DTCSP_INT32	DTCSP_CopyRSAKeyPair(
				DTCSP_VOID_PTR	pContext,
				DTCSP_INT32		nSrcKeyNumber,
				DTCSP_INT32		nDstKeyNumber);
DTCSP_INT32 DTCSP_GetCurSystemKey(
				DTCSP_VOID_PTR  pContext,
				DTCSP_UCHAR_PTR pCurSystemKey,
				DTCSP_INT32 *   nCurSystemKeyLen);
								
DTCSP_INT32	DTCSP_DelRSAKeyPair(
				DTCSP_VOID_PTR	pContext,
				DTCSP_INT32	nKeyNumber);
				
DTCSP_INT32 DTCSP_PutOldSystemKey(
				DTCSP_VOID_PTR	pContext,
				DTCSP_CHAR_PTR	pOldSystemKey);
				
DTCSP_INT32 DTCSP_PutCurSystemKey(
				DTCSP_VOID_PTR	pContext,
				DTCSP_CHAR_PTR	pCurSystemKey);

DTCSP_INT32 DTCSP_GetRSAPrivateKey(
				DTCSP_VOID_PTR	pContext,
				DTCSP_INT32		nKeyNumber,
				DTCSP_RSA_PRIVATE_KEY	*pPrivateKey);

//modified by LiuQiang 2008.07.25
#ifdef _SUPPORT_RSA_4096_
DTCSP_INT32	DTCSP_DelRSAKeyPairEx(
				DTCSP_VOID_PTR	pContext,
				DTCSP_INT32		nKeyNumber);

DTCSP_INT32	DTCSP_CopyRSAKeyPairEx(
				DTCSP_VOID_PTR	pContext,
				DTCSP_INT32		nSrcKeyNumber,
				DTCSP_INT32		nDstKeyNumber);

DTCSP_INT32	DTCSP_PutRSAKeyPairEx(
				DTCSP_VOID_PTR	pContext,
				DTCSP_INT32		nDstKeyNumber,
				DTCSP_RSA_PUBLIC_KEY_EX	pPublicKey,
				DTCSP_RSA_PRIVATE_KEY_EX	pPrivateKey);

DTCSP_INT32 DTCSP_GetRSAPublicKeyEx(
				DTCSP_VOID_PTR	pContext,
				DTCSP_INT32		nKeyNumber,
				DTCSP_RSA_PUBLIC_KEY_EX	*pPublicKey);

DTCSP_INT32 DTCSP_GetRSAPrivateKeyEx(
				DTCSP_VOID_PTR	pContext,
				DTCSP_INT32		nKeyNumber,
				DTCSP_RSA_PRIVATE_KEY_EX	*pPrivateKey);
#endif			
//end modified by LiuQiang 2008.07.25	
			
DTCSP_INT32 DTCSP_GetOldSystemKey(
				DTCSP_VOID_PTR  pContext,
				DTCSP_UCHAR_PTR pOldSystemKey,
				DTCSP_INT32 *   nOldSystemKeyLen);								

DTCSP_INT32 DTCSP_GenerateTrueRandData(
		DTCSP_VOID_PTR	pContext,
		DTCSP_INT32	nRandomDataLen,
		DTCSP_UCHAR_PTR	pRandomData);

DTCSP_INT32	DTCSP_GenerateRSAKeyPair(
				DTCSP_VOID_PTR	pContext,
				DTCSP_INT32	nKeyNumber,
				DTCSP_INT32	nModulusLen,
				DTCSP_UCHAR_PTR	pPublicExponent,
				DTCSP_INT32	nPublicExponentLen,		
				DTCSP_RSA_PUBLIC_KEY *	pPublicKey,
				DTCSP_RSA_PRIVATE_KEY *	pPrivateKey);
				
DTCSP_INT32	DTCSP_GenerateCRSAKeyPair(
				DTCSP_VOID_PTR	pContext,
				DTCSP_INT32	nKeyNumber,
				DTCSP_INT32	nModulusLen,
				DTCSP_UCHAR_PTR	pPublicExponent,
				DTCSP_INT32		nPublicExponentLen,
				DTCSP_RSA_PUBLIC_KEY   *pPublicKey,
				DTCSP_RSA_CIPHER_PRIVATE_KEY  *pCPrivateKey);
				
DTCSP_INT32 DTCSP_RSAPublicRaw(
				DTCSP_VOID_PTR	pContext,
				DTCSP_INT32		nKeyNumber,
				DTCSP_RSA_PUBLIC_KEY*	pPublicKey,
				DTCSP_UCHAR_PTR	pInData,
				DTCSP_INT32		nInDataLen,
				DTCSP_UCHAR_PTR	pOutData,
				DTCSP_INT32 *		pOutDataLen);
				
DTCSP_INT32	DTCSP_RSAPrivateRaw(
				DTCSP_VOID_PTR	pContext,
				DTCSP_INT32		nKeyNumber,
				DTCSP_RSA_PRIVATE_KEY*	pPrivateKey,
				DTCSP_UCHAR_PTR	pInData,
				DTCSP_INT32		nInDataLen,
				DTCSP_UCHAR_PTR	pOutData,
				DTCSP_INT32 *	pOutDataLen);
				
DTCSP_INT32	DTCSP_CRSAPrivateRaw(
				DTCSP_VOID_PTR	pContext,
				DTCSP_INT32		nKeyNumber,
				DTCSP_RSA_CIPHER_PRIVATE_KEY*	pCipherPrivateKey,
				DTCSP_UCHAR_PTR	pInData,
				DTCSP_INT32		nInDataLen,
				DTCSP_UCHAR_PTR	pOutData,
				DTCSP_INT32_PTR	pOutDataLen);
				
DTCSP_INT32	DTCSP_RSAPublicKeyEncrypt(
				DTCSP_VOID_PTR	pContext,
				DTCSP_INT32		nKeyNumber,
				DTCSP_RSA_PUBLIC_KEY	pPublicKey,
				DTCSP_UCHAR_PTR	pInData,
				DTCSP_INT32		nInDataLen,
				DTCSP_UCHAR_PTR	pOutData,
				DTCSP_INT32 *		pOutDataLen);
				
DTCSP_INT32	DTCSP_RSAPublicKeyDecrypt(
				DTCSP_VOID_PTR	pContext,
				DTCSP_INT32		nKeyNumber,
				DTCSP_RSA_PUBLIC_KEY	pPublicKey,
				DTCSP_UCHAR_PTR	pInData,
				DTCSP_INT32		nInDataLen,
				DTCSP_UCHAR_PTR	pOutData,
				DTCSP_INT32 *		pOutDataLen);
				
DTCSP_INT32	DTCSP_RSAPrivateKeyEncrypt(
				DTCSP_VOID_PTR	pContext,
				DTCSP_INT32		nKeyNumber,
				DTCSP_RSA_PRIVATE_KEY	pPrivateKey,
				DTCSP_UCHAR_PTR	pInData,
				DTCSP_INT32		nInDataLen,
				DTCSP_UCHAR_PTR	pOutData,
				DTCSP_INT32 *		nOutDataLen);
				
DTCSP_INT32	DTCSP_RSAPrivateKeyDecrypt(
				DTCSP_VOID_PTR	pContext,
				DTCSP_INT32		nKeyNumber,
				DTCSP_RSA_PRIVATE_KEY	pPrivateKey,
				DTCSP_UCHAR_PTR	pInData,
				DTCSP_INT32		nInDataLen,
				DTCSP_UCHAR_PTR	pOutData,
				DTCSP_INT32 *		pOutDataLen);
				
DTCSP_INT32	DTCSP_CRSAPrivateKeyDecrypt(
				DTCSP_VOID_PTR	pContext,
				DTCSP_INT32		nKeyNumber,
				DTCSP_RSA_CIPHER_PRIVATE_KEY	pCipherPrivateKey,
				DTCSP_UCHAR_PTR	pInData,
				DTCSP_INT32		nInDataLen,
				DTCSP_UCHAR_PTR	pOutData,
				DTCSP_INT32_PTR	pOutDataLen);
				
DTCSP_INT32	DTCSP_CRSAPrivateKeyEncrypt(
				DTCSP_VOID_PTR	pContext,
				DTCSP_INT32		nKeyNumber,
				DTCSP_RSA_CIPHER_PRIVATE_KEY	pCipherPrivateKey,
				DTCSP_UCHAR_PTR	pInData,
				DTCSP_INT32		nInDataLen,
				DTCSP_UCHAR_PTR	pOutData,
				DTCSP_INT32_PTR	pOutDataLen);

DTCSP_INT32 DTCSP_SymmetricKeyEncrypt(
		DTCSP_VOID_PTR		pContext,
		DTCSP_UINT32		nAlgorithm,
		DTCSP_INT32		nKeyNumber,
		DTCSP_UCHAR_PTR		pSymmetricKey,
		DTCSP_INT32		nSymmetricKeyLen,
		DTCSP_UCHAR_PTR		pInData,
		DTCSP_INT32		nInDataLen,
		DTCSP_UCHAR_PTR		pOutData,
		DTCSP_INT32 *		pOutDataLen);

DTCSP_INT32 DTCSP_SymmetricKeyDecrypt(
		DTCSP_VOID_PTR 		pContext,
		DTCSP_UINT32		nAlgorithm,
		DTCSP_INT32		nKeyNumber,
		DTCSP_UCHAR_PTR		pSymmetricKey,
		DTCSP_INT32		nSymmetricKeyLen,
		DTCSP_UCHAR_PTR		pInData,
		DTCSP_INT32		nInDataLen,
		DTCSP_UCHAR_PTR		pOutData,
		DTCSP_INT32_PTR		pOutDataLen);

DTCSP_INT32 DTCSP_SSF33EncryptStd(
		DTCSP_VOID_PTR	pContext,
		DTCSP_INT32	bKeyChangeFlag,
		DTCSP_UCHAR_PTR	pKey33,
		DTCSP_INT32	nKeyLen,
		DTCSP_UCHAR_PTR	pInData,
		DTCSP_INT32	nInDataLen,
		DTCSP_UCHAR_PTR	pOutData,
		DTCSP_INT32_PTR	pOutDataLen);

DTCSP_INT32 DTCSP_SSF33DecryptStd(
		DTCSP_VOID_PTR	pContext,
		DTCSP_INT32	bKeyChangeFlag,
		DTCSP_UCHAR_PTR	pKey33,
		DTCSP_INT32	nKeyLen,
		DTCSP_UCHAR_PTR	pInData,
		DTCSP_INT32	nInDataLen,
		DTCSP_UCHAR_PTR	pOutData,
		DTCSP_INT32_PTR	pOutDataLen);

DTCSP_INT32 DTCSP_EncMsgSystemMasterKeyCur(
		DTCSP_VOID_PTR		pContext,
		DTCSP_UCHAR_PTR		pIndata,
		DTCSP_INT32		nIndataLen,
		DTCSP_UCHAR_PTR		pOutdata,
		DTCSP_INT32_PTR		pOutdataLen);

DTCSP_INT32 DTCSP_DecMsgSystemMasterKeyCur(
		DTCSP_VOID_PTR		pContext,
		DTCSP_UCHAR_PTR		pIndata,
		DTCSP_INT32		nIndataLen,
		DTCSP_UCHAR_PTR		pOutdata,
		DTCSP_INT32_PTR		pOutdataLen);

DTCSP_INT32 DTCSP_EncMsgSystemMasterKeyOld(
			DTCSP_VOID_PTR	pContext,
			DTCSP_UCHAR_PTR	pIndata,
			DTCSP_INT32	nIndataLen,
			DTCSP_UCHAR_PTR	pOutdata,
			DTCSP_INT32_PTR	pOutdataLen);

DTCSP_INT32 DTCSP_DecMsgSystemMasterKeyOld(
		DTCSP_VOID_PTR		pContext,
		DTCSP_UCHAR_PTR		pIndata,
		DTCSP_INT32		nIndataLen,
		DTCSP_UCHAR_PTR		pOutdata,
		DTCSP_INT32_PTR		pOutdataLen);

DTCSP_INT32	DTCSP_BackupCardInfoBeginEx(
				DTCSP_VOID_PTR	pContext);

DTCSP_INT32	DTCSP_BackupCardInfoExportSecretKeyPartEx(
				DTCSP_VOID_PTR	pContext,
				DTCSP_INT32	nICCardNumber);

DTCSP_INT32 DTCSP_BackupCardInfoEndEx(
		DTCSP_VOID_PTR	pContext,
		DTCSP_INT32	nEncFlag,
		DTCSP_UCHAR_PTR	pBackupFileName);

DTCSP_INT32	DTCSP_RestoreCardInfoBeginEx(
				DTCSP_VOID_PTR	pContext);

DTCSP_INT32	DTCSP_RestoreCardInfoImportSecretKeyPartEx(DTCSP_VOID_PTR	pContext, 
						DTCSP_INT32_PTR pICCardNumber);
DTCSP_INT32	DTCSP_RestoreImportCardInfoEx(
				DTCSP_VOID_PTR	pContext,
				DTCSP_UCHAR_PTR	pRestoreFileName,
				DTCSP_INT32 nFlag,
				DTCSP_INT32 nKeyNumber);

DTCSP_INT32	DTCSP_RestoreImport03BCardInfo(
				DTCSP_VOID_PTR	pContext,
				DTCSP_UCHAR_PTR	pRestoreFileName,
				DTCSP_INT32 nFlag,
				DTCSP_INT32 nKeyNumber);

DTCSP_INT32	DTCSP_RestoreCardInfoEndEx(DTCSP_VOID_PTR	pContext);

DTCSP_INT32 DTCSP_UserReadFlashByChar(
		DTCSP_VOID_PTR	pContext,
		DTCSP_INT32	nOffset,
		DTCSP_UCHAR_PTR	pOutdata,
		DTCSP_INT32	nOutdataLen);

DTCSP_INT32 DTCSP_UserWriteFlashByChar(
		DTCSP_VOID_PTR	pContext,
		DTCSP_INT32	nOffset,
		DTCSP_UCHAR_PTR	pIndata,
		DTCSP_INT32	nIndataLen);

DTCSP_UINT32 DTCSP_DESCBCInit(DTCSP_VOID_PTR pContext,
				DTCSP_DES_CBC_CONTEXT_PTR pDesContext, 
				DTCSP_UCHAR_PTR pIv,
				DTCSP_UCHAR_PTR pKey,
				DTCSP_INT32 nKeyLen,
				DTCSP_INT32 nEncryptFlag);

DTCSP_INT32 DTCSP_DESCBCUpdate(DTCSP_VOID_PTR pContext,
				   DTCSP_DES_CBC_CONTEXT_PTR pDesContext,
				   DTCSP_UCHAR_PTR pInData,
				   DTCSP_INT32 nInLen,
				   DTCSP_UCHAR_PTR pOutData,
				   DTCSP_INT32_PTR pnOutLen);

DTCSP_INT32 DTCSP_DESCBCFinalize(DTCSP_VOID_PTR pContext,
			DTCSP_DES_CBC_CONTEXT_PTR pDesContext);

DTCSP_INT32 DTCSP_3DESCBCInit(DTCSP_VOID_PTR pContext,
				DTCSP_3DES_CBC_CONTEXT_PTR p3DesContext,
				DTCSP_UCHAR_PTR pIv,
				DTCSP_UCHAR_PTR pKey,
				DTCSP_INT32 nKeyLen,
				DTCSP_INT32 nEncryptFlag);

DTCSP_INT32 DTCSP_3DESCBCUpdate(DTCSP_VOID_PTR pContext,
				DTCSP_3DES_CBC_CONTEXT_PTR p3DesContext,
				DTCSP_UCHAR_PTR pInData,
				DTCSP_INT32 nInLen,
				DTCSP_UCHAR_PTR pOutData,
				DTCSP_INT32_PTR pnOutLen);

DTCSP_INT32 DTCSP_3DESCBCFinalize(DTCSP_VOID_PTR pContext,
				DTCSP_3DES_CBC_CONTEXT_PTR p3DesContext);

DTCSP_INT32	DTCSP_RSAPublicKeyPkcs1Encrypt(
				DTCSP_VOID_PTR	pContext,
				DTCSP_INT32		nKeyNumber,
				DTCSP_RSA_PUBLIC_KEY* PublicKey,
				DTCSP_UCHAR_PTR	pInData,
				DTCSP_INT32		nInDataLen,
				DTCSP_UCHAR_PTR	pOutData,
				DTCSP_INT32 *	pOutDataLen);

DTCSP_INT32	DTCSP_RSAPublicKeyPkcs1Decrypt(
				DTCSP_VOID_PTR	pContext,
				DTCSP_INT32		nKeyNumber,
				DTCSP_RSA_PUBLIC_KEY*	PublicKey,
				DTCSP_UCHAR_PTR	pInData,
				DTCSP_INT32		nInDataLen,
				DTCSP_UCHAR_PTR	pOutData,
				DTCSP_INT32 *	pOutDataLen);

DTCSP_INT32	DTCSP_RSAPrivateKeyPkcs1Encrypt(
				DTCSP_VOID_PTR	pContext,
				DTCSP_INT32		nKeyNumber,
				DTCSP_RSA_PRIVATE_KEY*	PrivateKey,
				DTCSP_UCHAR_PTR	pInData,
				DTCSP_INT32		nInDataLen,
				DTCSP_UCHAR_PTR	pOutData,
				DTCSP_INT32 *	pOutDataLen);

DTCSP_INT32	DTCSP_RSAPrivateKeyPkcs1Decrypt(
				DTCSP_VOID_PTR	pContext,
				DTCSP_INT32		nKeyNumber,
				DTCSP_RSA_PRIVATE_KEY*	PrivateKey,
				DTCSP_UCHAR_PTR	pInData,
				DTCSP_INT32		nInDataLen,
				DTCSP_UCHAR_PTR	pOutData,
				DTCSP_INT32 *	pOutDataLen);

DTCSP_INT32	DTCSP_CRSAPrivateKeyPkcs1Encrypt(
				DTCSP_VOID_PTR	pContext,
				DTCSP_INT32		nKeyNumber,
				DTCSP_RSA_CIPHER_PRIVATE_KEY*	CipherPrivateKey,
				DTCSP_UCHAR_PTR	pInData,
				DTCSP_INT32		nInDataLen,
				DTCSP_UCHAR_PTR	pOutData,
				DTCSP_INT32_PTR	pOutDataLen);

DTCSP_INT32	DTCSP_CRSAPrivateKeyPkcs1Decrypt(
				DTCSP_VOID_PTR	pContext,
				DTCSP_INT32		nKeyNumber,
				DTCSP_RSA_CIPHER_PRIVATE_KEY*	CipherPrivateKey,
				DTCSP_UCHAR_PTR	pInData,
				DTCSP_INT32		nInDataLen,
				DTCSP_UCHAR_PTR	pOutData,
				DTCSP_INT32_PTR	pOutDataLen);
				
//For SCB2
//Add by pph @ 2006-05-16				
DTCSP_INT32 DTCSP_SCB2ECBEncrypt(
								 DTCSP_VOID_PTR	pContext,
								 DTCSP_INT32		nKeynum,
								 DTCSP_UCHAR_PTR	pKey,
								 DTCSP_INT32		nKeyLen,
								 DTCSP_UCHAR_PTR	pInData,
								 DTCSP_INT32		nInDataLen,
								 DTCSP_UCHAR_PTR	pOutData,
								 DTCSP_INT32_PTR	pOutDataLen);

DTCSP_INT32 DTCSP_SCB2ECBDecrypt(
								 DTCSP_VOID_PTR	pContext,
								 DTCSP_INT32		nKeynum,
								 DTCSP_UCHAR_PTR	pKey,
								 DTCSP_INT32		nKeyLen,
								 DTCSP_UCHAR_PTR	pInData,
								 DTCSP_INT32		nInDataLen,
								 DTCSP_UCHAR_PTR	pOutData,
								 DTCSP_INT32_PTR	pOutDataLen);

DTCSP_INT32 DTCSP_SCB2CBCEncrypt(
								 DTCSP_VOID_PTR	pContext,
								 DTCSP_INT32		nKeynum,
								 DTCSP_UCHAR_PTR	pKey,
								 DTCSP_INT32		nKeyLen,
								 DTCSP_UCHAR_PTR pIv,
								 DTCSP_UCHAR_PTR	pInData,
								 DTCSP_INT32		nInDataLen,
								 DTCSP_UCHAR_PTR	pOutData,
								 DTCSP_INT32_PTR	pOutDataLen);

DTCSP_INT32 DTCSP_SCB2CBCDecrypt(
								 DTCSP_VOID_PTR	pContext,
								 DTCSP_INT32		nKeynum,
								 DTCSP_UCHAR_PTR	pKey,
								 DTCSP_INT32		nKeyLen,
								 DTCSP_UCHAR_PTR pIv,
								 DTCSP_UCHAR_PTR	pInData,
								 DTCSP_INT32		nInDataLen,
								 DTCSP_UCHAR_PTR	pOutData,
								 DTCSP_INT32_PTR	pOutDataLen);
								 
//add by tfc 2008.10.8 supporting SM1	
DTCSP_INT32 DTCSP_SM1ECBEncrypt(
									   DTCSP_VOID_PTR	pContext,
									   DTCSP_INT32		nKeynum,
									   DTCSP_UCHAR_PTR	pKey,
									   DTCSP_INT32		nKeyLen,
									   DTCSP_UCHAR_PTR	pInData,
									   DTCSP_INT32		nInDataLen,
									   DTCSP_UCHAR_PTR	pOutData,
									   DTCSP_INT32_PTR	pOutDataLen);

DTCSP_INT32 DTCSP_SM1ECBDecrypt(
								DTCSP_VOID_PTR	pContext,
								DTCSP_INT32		nKeynum,
								DTCSP_UCHAR_PTR	pKey,
								DTCSP_INT32		nKeyLen,
								DTCSP_UCHAR_PTR	pInData,
								DTCSP_INT32		nInDataLen,
								DTCSP_UCHAR_PTR	pOutData,
								DTCSP_INT32_PTR	pOutDataLen);

DTCSP_INT32 DTCSP_SM1CBCEncrypt(
							DTCSP_VOID_PTR	pContext,
							DTCSP_INT32		nKeynum,
							DTCSP_UCHAR_PTR	pKey,
							DTCSP_INT32		nKeyLen,
							DTCSP_UCHAR_PTR pIv,
							DTCSP_UCHAR_PTR	pInData,
							DTCSP_INT32		nInDataLen,
							DTCSP_UCHAR_PTR	pOutData,
							DTCSP_INT32_PTR	pOutDataLen);

DTCSP_INT32 DTCSP_SM1CBCDecrypt(
							DTCSP_VOID_PTR	pContext,
							DTCSP_INT32		nKeynum,
							DTCSP_UCHAR_PTR	pKey,
							DTCSP_INT32		nKeyLen,
							DTCSP_UCHAR_PTR pIv,
							DTCSP_UCHAR_PTR	pInData,
							DTCSP_INT32		nInDataLen,
							DTCSP_UCHAR_PTR	pOutData,
							DTCSP_INT32_PTR	pOutDataLen);	
//end add 2008.10.8
									  							 
////////////////////////////////////////////////////////////////////////////////////
//////////////                                            //////////////////////////
//////////////    以下接口为兼容二代卡，不推荐使用        //////////////////////////
//////////////                                            //////////////////////////
////////////////////////////////////////////////////////////////////////////////////
DTCSP_INT32 DTCSP_GetCardRunStatus(
		DTCSP_VOID_PTR		pContext,
		DTCSP_UCHAR_PTR		pRunStatus);

DTCSP_INT32 DTCSP_GetCardRunStatusEx(
		DTCSP_VOID_PTR		pContext,
		DTCSP_UCHAR_PTR		pRunStatus);

DTCSP_INT32 DTCSP_SSF33Encrypt_NoLLimit(
		DTCSP_VOID_PTR	pContext,
		DTCSP_INT32		bKeyChangeFlag,
		DTCSP_UCHAR_PTR	Key33,
		DTCSP_INT32		KeyLen,
		DTCSP_UCHAR_PTR	InData,
		DTCSP_INT32		InDataLen,
		DTCSP_UCHAR_PTR	OutData,
		DTCSP_INT32_PTR	OutDataLen);

DTCSP_INT32 DTCSP_SSF33Decrypt_NoLLimit(
		DTCSP_VOID_PTR	pContext,
		DTCSP_INT32		bKeyChangeFlag,
		DTCSP_UCHAR_PTR	Key33,
		DTCSP_INT32		KeyLen,
		DTCSP_UCHAR_PTR	InData,
		DTCSP_INT32		InDataLen,
		DTCSP_UCHAR_PTR	OutData,
		DTCSP_INT32_PTR	OutDataLen);

DTCSP_INT32 DTCSP_SSF33Encrypt(
		DTCSP_VOID_PTR	pContext,
		DTCSP_INT32		bKeyChangeFlag,
		DTCSP_UCHAR_PTR	pKey33,
		DTCSP_INT32		nKeyLen,
		DTCSP_UCHAR_PTR	pInData,
		DTCSP_INT32		nInDataLen,
		DTCSP_UCHAR_PTR	pOutData,
		DTCSP_INT32_PTR	pOutDataLen);

DTCSP_INT32 DTCSP_SSF33Decrypt(
		DTCSP_VOID_PTR	pContext,
		DTCSP_INT32		bKeyChangeFlag,
		DTCSP_UCHAR_PTR	pKey33,
		DTCSP_INT32		nKeyLen,
		DTCSP_UCHAR_PTR	pInData,
		DTCSP_INT32		nInDataLen,
		DTCSP_UCHAR_PTR	pOutData,
		DTCSP_INT32_PTR	pOutDataLen);
		
DTCSP_INT32 DTCSP_3DESEncrypt(
		DTCSP_VOID_PTR   pContext,
		DTCSP_INT32      nKeyNum,
		DTCSP_UCHAR_PTR  pDesKey,
		DTCSP_ULONG      nDesKeyLen,
		DTCSP_UCHAR_PTR  pInData,
		DTCSP_ULONG      nInDataLen,
		DTCSP_UCHAR_PTR  pOutData,
		DTCSP_ULONG_PTR  pOutDataLen);
		
DTCSP_INT32 DTCSP_3DESDecrypt(
		DTCSP_VOID_PTR       pContext,
		DTCSP_INT32            nKeyNum,
		DTCSP_UCHAR_PTR pDesKey,
		DTCSP_ULONG  nDesKeyLen,
		DTCSP_UCHAR_PTR pInData,
		DTCSP_ULONG  nInDataLen,
		DTCSP_UCHAR_PTR pOutData,
		DTCSP_ULONG_PTR pOutDataLen);
		
DTCSP_INT32 DTCSP_DESEncrypt(
		DTCSP_VOID_PTR   pContext,
		DTCSP_INT32      nKeyNum,
		DTCSP_UCHAR_PTR  pDesKey,
		DTCSP_INT32      nDesKeyLen,
		DTCSP_UCHAR_PTR  pInData,
		DTCSP_INT32      nInDataLen,
		DTCSP_UCHAR_PTR  pOutData,
		DTCSP_INT32_PTR  pOutDataLen);
		
DTCSP_INT32 DTCSP_DESDecrypt(
		DTCSP_VOID_PTR         pContext,
		DTCSP_INT32            nKeyNum,
		DTCSP_UCHAR_PTR		   pDesKey,
		DTCSP_INT32            nDesKeyLen,
		DTCSP_UCHAR_PTR		   pInData,
		DTCSP_INT32            nInDataLen,
		DTCSP_UCHAR_PTR		   pOutData,
		DTCSP_INT32_PTR        pOutDataLen);

DTCSP_INT32	DTCSP_GetRsaKeyFlag(
		DTCSP_VOID_PTR	pContext,
		DTCSP_INT32		nKeyNumber,
		DTCSP_INT32*	pKeyFlag);

DTCSP_INT32 DTCSP_EncMsgSystemMasterKeyNew (
		DTCSP_VOID_PTR	pContext,
		DTCSP_UCHAR_PTR	pIndata,
		DTCSP_INT32		nIndataLen,
		DTCSP_UCHAR_PTR	pOutdata,
		DTCSP_INT32_PTR	pOutdataLen);

DTCSP_INT32 DTCSP_DecMsgSystemMasterKeyNew (
		DTCSP_VOID_PTR	pContext,
		DTCSP_UCHAR_PTR	pIndata,
		DTCSP_INT32		nIndataLen,
		DTCSP_UCHAR_PTR	pOutdata,
		DTCSP_INT32_PTR	pOutdataLen);

DTCSP_INT32 DTCSP_SetSystemMasterKeyBegin(DTCSP_VOID_PTR pContext);
DTCSP_INT32 DTCSP_SetSystemMasterKeyEnd(DTCSP_VOID_PTR pContext);
DTCSP_INT32 DTCSP_BackupCardInfoBegin(DTCSP_VOID_PTR pContext);

DTCSP_INT32 DTCSP_BackupCardInfoEnd(
		DTCSP_VOID_PTR	pContext,
		DTCSP_CHAR_PTR	pBackupFileName);

DTCSP_INT32 DTCSP_BackupCardInfoExportSecretKeyPart(
		DTCSP_VOID_PTR	pContext,
		DTCSP_INT32		nICCardNumber);

DTCSP_INT32 DTCSP_RestoreCardInfoBegin(DTCSP_VOID_PTR	pContext);

DTCSP_INT32 DTCSP_RestoreCardInfoEnd(
		DTCSP_VOID_PTR	pContext,
		DTCSP_CHAR_PTR	pRestoreFileName);

DTCSP_INT32 DTCSP_RestoreCardInfoImportSecretKeyPart(
		DTCSP_VOID_PTR	pContext);

DTCSP_INT32 DTCSP_UserReadFlash(
		DTCSP_VOID_PTR	pContext,
		DTCSP_INT32		nFlashOffsetLong,
		DTCSP_ULONG_PTR	pOutdata,
		DTCSP_INT32		nOutdataLenLong);

DTCSP_INT32 DTCSP_UserWriteFlash(
		DTCSP_VOID_PTR	pContext,
		DTCSP_INT32		nFlashOffsetLong,
		DTCSP_ULONG_PTR	pIndata,
		DTCSP_INT32		nIndataLenLong);

//add @ 2006-05-17
DTCSP_INT32 DTCSP_SCB2CBCInit(
	 DTCSP_VOID_PTR								pContext,
	 DTCSP_SCB2_CBC_CONTEXT_PTR  	pScb2Context,
	 DTCSP_INT32									nKeynum,
	 DTCSP_UCHAR_PTR							pKey,
	 DTCSP_INT32									nKeyLen,
	 DTCSP_UCHAR_PTR							pIv,
	 DTCSP_INT32	    						nFlag);

DTCSP_INT32 DTCSP_SCB2CBCUpdate(
		DTCSP_VOID_PTR				pContext,
		DTCSP_SCB2_ECB_CONTEXT_PTR	pScb2Context,
		DTCSP_UCHAR_PTR			pInData,
		DTCSP_INT32				nInDataLen,
		DTCSP_UCHAR_PTR			pOutData,
		DTCSP_INT32_PTR			pOutDataLen);

DTCSP_INT32 DTCSP_SCB2CBCEnd(
		   DTCSP_VOID_PTR	pContext
		   );

//ECC 运算

DTCSP_INT32  DTCSP_SCEMng_SetChipID(	
				DTCSP_VOID_PTR	 	pContext,
				DTCSP_UCHAR_PTR	 	pID,     
				DTCSP_INT32     	nIDLen);

DTCSP_INT32  DTCSP_SCEMng_GetChipID(
				DTCSP_VOID_PTR		pContext,
				DTCSP_UCHAR_PTR		pID,     
				DTCSP_INT32       *pIDLen);
				
DTCSP_INT32 DTCSP_SHA1_Initialize(
				DTCSP_VOID_PTR 				pContext,
				DTCSP_SHA_CONTEXT_PTR pSHA1Context); 
				
DTCSP_INT32  DTCSP_SHA1_Update (
				DTCSP_VOID_PTR				pContext,
				DTCSP_SHA_CONTEXT_PTR	pSHA1Context,
				DTCSP_UCHAR_PTR 			pInData,       	
				DTCSP_INT32        		nInDataLen);
				
DTCSP_INT32  DTCSP_SHA1_UpdateEx (
				DTCSP_VOID_PTR				pContext,
				DTCSP_SHA_CONTEXT_PTR	pSHA1Context,
				DTCSP_UCHAR_PTR 			pInData,       	
				DTCSP_INT32        		nInDataLen);
				
DTCSP_INT32  DTCSP_SHA1_Finalize(
				DTCSP_VOID_PTR 		pContext, 
				DTCSP_SHA_CONTEXT_PTR	pSHA1Context,
				DTCSP_UCHAR_PTR		pOutData,     
				DTCSP_INT32 *			pOutDataLen );		
DTCSP_INT32  DTCSP_SHA1_Finalize_NoPadding(
				DTCSP_VOID_PTR 		pContext, 
				DTCSP_SHA_CONTEXT_PTR	pSHA1Context,
				DTCSP_UCHAR_PTR		pOutData,     
				DTCSP_INT32 *			pOutDataLen );				
DTCSP_INT32 DTCSP_SHA256_Initialize(
				DTCSP_VOID_PTR pContext,
				DTCSP_SHA_CONTEXT_PTR pSHA256Context);		
				
DTCSP_INT32  DTCSP_SHA256_Update (
				DTCSP_VOID_PTR				pContext,
				DTCSP_SHA_CONTEXT_PTR	pSHA256Context,
				DTCSP_UCHAR_PTR 			pInData,       	
				DTCSP_INT32        		nInDataLen);	
				
DTCSP_INT32  DTCSP_SHA256_UpdateEx (
				DTCSP_VOID_PTR				pContext,
				DTCSP_SHA_CONTEXT_PTR	pSHA256Context,
				DTCSP_UCHAR_PTR 			pInData,       	
				DTCSP_INT32        		nInDataLen);
				
DTCSP_INT32  DTCSP_SHA256_Finalize(
				DTCSP_VOID_PTR 					pContext, 
				DTCSP_SHA_CONTEXT_PTR		pSHA256Context,
				DTCSP_UCHAR_PTR 				pOutData,     
				DTCSP_INT32 *     			pOutDataLen);
DTCSP_INT32  DTCSP_SHA256_Finalize_NoPadding(
								   DTCSP_VOID_PTR 	pContext, 
								   DTCSP_SHA_CONTEXT_PTR			pSHA256Context,
								   DTCSP_UCHAR_PTR pOutData,     
								   DTCSP_INT32 *     pOutDataLen );
				
DTCSP_INT32  DTCSP_SCH_Initialize (DTCSP_VOID_PTR			pContext, 
								   DTCSP_SCH_CONTEXT_PTR	pSCHContext,
								   DTCSP_INT32				nFlag,      
								   DTCSP_UCHAR_PTR 			pID, 
								   DTCSP_INT32           	nIDLen,
								   DTCSP_INT32              nStoreLocation,
								   DTCSP_INT32  			nEccCurveFlag,
								   DTCSP_ECC_PUBLIC_KEY_PTR	pEccPublicKey);
				
DTCSP_INT32  DTCSP_SCH_Update(
				DTCSP_VOID_PTR					pContext,
				DTCSP_SCH_CONTEXT_PTR		pSCHContext,
				DTCSP_UCHAR_PTR 				pInData,       	
				DTCSP_INT32        			nInDataLen);
				
DTCSP_INT32  DTCSP_SCH_UpdateEx (
				DTCSP_VOID_PTR				pContext,
				DTCSP_SCH_CONTEXT_PTR	pSCHContext,
				DTCSP_UCHAR_PTR 			pInData,       	
				DTCSP_INT32        		nInDataLen);
				
DTCSP_INT32  DTCSP_SCH_Finalize(
				DTCSP_VOID_PTR 				pContext, 
				DTCSP_SCH_CONTEXT_PTR	pSCHContext,
				DTCSP_INT32 					nOutDataLen,
				DTCSP_UCHAR_PTR				pOutData);
				
DTCSP_INT32 DTCSP_RNG_GetRamdom(
				DTCSP_VOID_PTR	pContext,
				DTCSP_INT32		nRandomDataLen,
				DTCSP_UCHAR_PTR	pRandomData);

DTCSP_INT32 DTCSP_ECC_Initialize(
				DTCSP_VOID_PTR 		pContext,
				DTCSP_INT32  		nEccCurveFlag, 
				DTCSP_ECC_CURVE_PTR	pEccCurve);

DTCSP_INT32 DTCSP_ECC_GenKeyPair(
				DTCSP_VOID_PTR				pContext,
				DTCSP_INT32					nStoreLocation,
				DTCSP_ECC_PUBLIC_KEY_PTR	pEccPublicKey,
				DTCSP_ECC_PRIVATE_KEY_PTR	pEccPrivateKey);

DTCSP_INT32 DTCSP_ECC_GenKeyPairEx(
                                   DTCSP_VOID_PTR				pContext,
                                   DTCSP_INT32					nStoreLocation,
                                   DTCSP_INT32  		nEccCurveFlag,
                                   DTCSP_ECC_CURVE_PTR	pEccCurve, 
                                   DTCSP_ECC_PUBLIC_KEY_PTR	pEccPublicKey,
                                   DTCSP_ECC_PRIVATE_KEY_PTR	pEccPrivateKey);

DTCSP_INT32 DTCSP_GetPrivateKeyAccessData(
    DTCSP_VOID_PTR      pContext,
    DTCSP_INT32         keynmber,
    DTCSP_UCHAR_PTR     pAccessData,
    DTCSP_INT32_PTR     nAccessDataLen);

DTCSP_INT32  DTCSP_GetPrivateKeyAccessRight(
    DTCSP_VOID_PTR	 	pContext,
    DTCSP_INT32         keynmber,
    DTCSP_UCHAR_PTR	    AccessRightData,     
    DTCSP_INT32     	nAccessRightDataLen);

DTCSP_INT32	DTCSP_ReleasePrivateKeyAccessRight(
    DTCSP_VOID_PTR	    pContext,
    DTCSP_INT32         keynmber);  

DTCSP_INT32 DTCSP_ECC_LoadPriKey(
				DTCSP_VOID_PTR				pContext,
				DTCSP_INT32					nStoreLocation,
				DTCSP_ECC_PRIVATE_KEY_PTR	pEccPrivateKey);

DTCSP_INT32 DTCSP_ECC_LoadPubKey(
				DTCSP_VOID_PTR				pContext,
				DTCSP_INT32					nStoreLocation,
				DTCSP_ECC_PUBLIC_KEY_PTR	pEccPublicKey);

DTCSP_INT32 DTCSP_ECC_GetPubKey(
			DTCSP_VOID_PTR				pContext,
			DTCSP_INT32					nStoreLocation,
			DTCSP_ECC_PUBLIC_KEY_PTR	pEccPublicKey);

DTCSP_INT32 DTCSP_ECC_DestroyKeyPair(
			DTCSP_VOID_PTR	pContext,
			DTCSP_INT32		nStoreLocation);

DTCSP_INT32 DTCSP_ECC_BackupKeyPair(
			DTCSP_VOID_PTR		pContext,
			DTCSP_INT32			nStoreLocation,
			DTCSP_ECC_BKEY_PTR	pEccKey);

DTCSP_INT32 DTCSP_ECC_RestoreKeyPair(
			DTCSP_VOID_PTR		pContext,
			DTCSP_INT32			nStoreLocation,
			DTCSP_ECC_BKEY_PTR	pEccKey);

DTCSP_INT32 DTCSP_ECDSA_Sign(
			DTCSP_VOID_PTR				pContext,
			DTCSP_INT32  				nStoreLocation,
			DTCSP_ECC_PRIVATE_KEY_PTR	pEccPrivateKey,
			DTCSP_UCHAR_PTR				pInDataMes,
			DTCSP_INT32					nInDataMesLen,
			DTCSP_ECC_SIG_PTR			pOutDataSign);

DTCSP_INT32 DTCSP_ECDSA_Verify(
			DTCSP_VOID_PTR				pContext,
			DTCSP_INT32					nStoreLocation,
			DTCSP_ECC_PUBLIC_KEY_PTR	pEccPublicKey,
			DTCSP_UCHAR_PTR				pInDataMes,
			DTCSP_INT32					nInDataMesLen,
			DTCSP_ECC_SIG_PTR			pInDataSign,
			DTCSP_INT32_PTR				result);

DTCSP_INT32 DTCSP_SCE_Sign(
			DTCSP_VOID_PTR				pContext,
			DTCSP_INT32					nStoreLocation,
			DTCSP_ECC_PRIVATE_KEY_PTR	pEccPrivateKey,
			DTCSP_UCHAR_PTR				pInDataMes,
			DTCSP_INT32					nInDataMesLen,
			DTCSP_ECC_SIG_PTR			pOutDataSign);

DTCSP_INT32 DTCSP_SCE_Verify(
			DTCSP_VOID_PTR				pContext,
			DTCSP_INT32					nStoreLocation,
			DTCSP_ECC_PUBLIC_KEY_PTR	pEccPublicKey,
			DTCSP_UCHAR_PTR				pInDataMes,
			DTCSP_INT32					nInDataMesLen,
			DTCSP_ECC_SIG_PTR			pInDataSign,
			DTCSP_INT32_PTR				result);
			

DTCSP_INT32 DTCSP_SCE_Encrypt(
			DTCSP_VOID_PTR				pContext,
			DTCSP_INT32					nStoreLocation,
			DTCSP_ECC_PUBLIC_KEY_PTR	pEccPublicKey,
			DTCSP_UCHAR_PTR				pInData,
			DTCSP_INT32					nInDataLen,  
			DTCSP_ECC_CIPHER_PTR		pOutData);

DTCSP_INT32 DTCSP_SCE_Decrypt(
			DTCSP_VOID_PTR				pContext,
			DTCSP_INT32					nStoreLocation,
			DTCSP_ECC_PRIVATE_KEY_PTR	pEccPrivateKey,
			DTCSP_ECC_CIPHER_PTR		pInData,
			DTCSP_UCHAR_PTR				pOutData,
			DTCSP_INT32*				nOutDataLen);

DTCSP_INT32  DTCSP_SM3_Initialize (DTCSP_VOID_PTR			pContext, 
								   DTCSP_SCH_CONTEXT_PTR	pSCHContext,
								   DTCSP_INT32				nFlag,      
								   DTCSP_UCHAR_PTR 			pID, 
								   DTCSP_INT32           	nIDLen,
								   DTCSP_INT32              nStoreLocation,
								   DTCSP_INT32  			nEccCurveFlag,
								   DTCSP_ECC_PUBLIC_KEY_PTR	pEccPublicKey);
								   
DTCSP_INT32  DTCSP_SM3_Update(DTCSP_VOID_PTR			pContext,
							  DTCSP_SCH_CONTEXT_PTR		pSCHContext,
							  DTCSP_UCHAR_PTR 			pInData,       	
							  DTCSP_INT32        		nInDataLen);
							  
DTCSP_INT32  DTCSP_SM3_UpdateEx (
								 DTCSP_VOID_PTR			pContext,
								 DTCSP_SCH_CONTEXT_PTR	pSCHContext,
								 DTCSP_UCHAR_PTR 		pInData,       	
								DTCSP_INT32        		nInDataLen);
								
DTCSP_INT32  DTCSP_SM3_Finalize(DTCSP_VOID_PTR 	pContext, 
								DTCSP_SCH_CONTEXT_PTR				pSCHContext,
								DTCSP_INT32 						nOutDataLen,
								DTCSP_UCHAR_PTR						pOutData);


DTCSP_INT32 DTCSP_SM2_1_Sign(
			DTCSP_VOID_PTR				pContext,
			DTCSP_INT32					nStoreLocation,
			DTCSP_ECC_PRIVATE_KEY_PTR	pEccPrivateKey,
			DTCSP_UCHAR_PTR				pInDataMes,
			DTCSP_INT32					nInDataMesLen,
			DTCSP_ECC_SIG_PTR			pOutDataSign);
			
DTCSP_INT32 DTCSP_SM2_1_Verify(
			DTCSP_VOID_PTR				pContext,
			DTCSP_INT32					nStoreLocation,
			DTCSP_ECC_PUBLIC_KEY_PTR	pEccPublicKey,
			DTCSP_UCHAR_PTR				pInDataMes,
			DTCSP_INT32					nInDataMesLen,
			DTCSP_ECC_SIG_PTR			pInDataSign,
			DTCSP_INT32_PTR				result);
						
DTCSP_INT32 DTCSP_SM2_3_Encrypt(
			DTCSP_VOID_PTR				pContext,
			DTCSP_INT32					nStoreLocation,
			DTCSP_ECC_PUBLIC_KEY_PTR	pEccPublicKey,
			DTCSP_UCHAR_PTR				pInData,
			DTCSP_INT32					nInDataLen,  
			DTCSP_ECC_CIPHER_PTR		pOutData);
			
DTCSP_INT32 DTCSP_SM2_3_Decrypt(
			DTCSP_VOID_PTR				pContext,
			DTCSP_INT32					nStoreLocation,
			DTCSP_ECC_PRIVATE_KEY_PTR	pEccPrivateKey,
			DTCSP_ECC_CIPHER_PTR		pInData,
			DTCSP_UCHAR_PTR				pOutData,
			DTCSP_INT32*				nOutDataLen);			

DTCSP_INT32	DTCSP_ECDH_KeyAgreement(
			DTCSP_VOID_PTR				pContext,
			DTCSP_INT32					nStoreLocation,
			DTCSP_ECC_PRIVATE_KEY_PTR	pOrgTempPriKey,
			DTCSP_ECC_PUBLIC_KEY_PTR	pRespoTempPubKey,
			DTCSP_UCHAR_PTR				pOutKey,
			DTCSP_INT32*				nOutKeyLen);

DTCSP_INT32 DTCSP_SCE_KeyAgreement (
			DTCSP_VOID_PTR				pContext,
			DTCSP_INT32  				nStoreLocation,
			DTCSP_ECC_PRIVATE_KEY_PTR	pOrgEccPrivateKey,
			DTCSP_ECC_PRIVATE_KEY_PTR	pOrgTempPriKey,
			DTCSP_ECC_PUBLIC_KEY_PTR	pRespoPubKey,
			DTCSP_ECC_PUBLIC_KEY_PTR	pRespoTempPubKey,
      DTCSP_INT32         nflag,
			DTCSP_INT32					nKeyLen,
			DTCSP_UCHAR_PTR			pOrgID,
			DTCSP_INT32					nOrgIDLen,
			DTCSP_UCHAR_PTR			pRespoID,
			DTCSP_INT32					nRespoIDLen,
			DTCSP_UCHAR_PTR			pOutKey);

DTCSP_INT32 DTCSP_SM2_2_KeyAgreement (
			DTCSP_VOID_PTR				pContext,
			DTCSP_INT32  				nStoreLocation,
			DTCSP_ECC_PRIVATE_KEY_PTR	pOrgEccPrivateKey,
			DTCSP_ECC_PRIVATE_KEY_PTR	pOrgTempPriKey,
			DTCSP_ECC_PUBLIC_KEY_PTR	pRespoPubKey,
			DTCSP_ECC_PUBLIC_KEY_PTR	pRespoTempPubKey,
			DTCSP_INT32                 nflag,
			DTCSP_INT32					nKeyLen,
			DTCSP_UCHAR_PTR				pOrgID,
			DTCSP_INT32					nOrgIDLen,
			DTCSP_UCHAR_PTR				pRespoID,
			DTCSP_INT32					nRespoIDLen,
			DTCSP_UCHAR_PTR				pOutKey);

DTCSP_INT32	DTCSP_CopyECCKeyPair(
								 DTCSP_VOID_PTR	pContext,
								 DTCSP_INT32		nSrcKeyNumber,
								 DTCSP_INT32		nDstKeyNumber);

DTCSP_INT32	DTCSP_PutECCKeyPair(
								DTCSP_VOID_PTR	pContext,
								DTCSP_INT32		nDstKeyNumber,
								DTCSP_ECC_PUBLIC_KEY	pPublicKey,
								DTCSP_ECC_PRIVATE_KEY	pPrivateKey);

DTCSP_INT32 DTCSP_GetSessionKeyEmptyNumber(
								  DTCSP_VOID_PTR  pContext,
								  DTCSP_INT32 *   nSymKeyNum);		
////////////////扩展ECC运算///////////////////////////////////////////////////////////////////////////////

typedef struct {
	DTCSP_UINT32 flag[8];                                   
	DTCSP_UINT32 num[2];                                   
	DTCSP_UCHAR data[64];                         
} DTCSP_SM3_CONTEXT,*DTCSP_SM3_CONTEXT_PTR;

DTCSP_INT32 DTCSP_ECCEx_GenKeyPair(
				DTCSP_VOID_PTR				pContext,
				DTCSP_INT32  		        nStoreLocation,
				DTCSP_ECC_PUBLIC_KEY_PTR	pEccPublicKey,
				DTCSP_ECC_PRIVATE_KEY_PTR	pEccPrivateKey);//生成ECC密钥							   
							   
DTCSP_INT32 DTCSP_SM2_1_SignEx(
			DTCSP_VOID_PTR				pContext,
			DTCSP_INT32  		        nStoreLocation,
			DTCSP_ECC_PRIVATE_KEY_PTR	pEccPrivateKey,
			DTCSP_UCHAR_PTR				pInDataMes,
			DTCSP_INT32					nInDataMesLen,
			DTCSP_ECC_SIG_PTR			pOutDataSign);//SM2-1签名
			
			
DTCSP_INT32 DTCSP_SM2_1_VerifyEx(
			DTCSP_VOID_PTR				pContext,
			DTCSP_INT32  		        nStoreLocation,
			DTCSP_ECC_PUBLIC_KEY_PTR	pEccPublicKey,
			DTCSP_UCHAR_PTR				pInDataMes,
			DTCSP_INT32					nInDataMesLen,
			DTCSP_ECC_SIG_PTR			pInDataSign,
			DTCSP_INT32_PTR				result);// SM2-1验证							   
							   				   
DTCSP_INT32 DTCSP_SM2_2_KeyAgreementEx(
		    DTCSP_VOID_PTR				pContext,
		    DTCSP_INT32  				nStoreLocation,
		    DTCSP_ECC_PRIVATE_KEY_PTR	pOrgEccPrivateKey,
		    DTCSP_ECC_PRIVATE_KEY_PTR	pOrgTempPriKey,
		    DTCSP_ECC_PUBLIC_KEY_PTR	pRespoPubKey,
		    DTCSP_ECC_PUBLIC_KEY_PTR	pRespoTempPubKey,
		    DTCSP_INT32                 nflag,
		    DTCSP_INT32					nKeyLen,
		    DTCSP_UCHAR_PTR				pOrgID,
		    DTCSP_INT32					nOrgIDLen,
		    DTCSP_UCHAR_PTR				pRespoID,
		    DTCSP_INT32					nRespoIDLen,
			DTCSP_UCHAR_PTR				pOutKey);
DTCSP_INT32 DTCSP_SM2_3_EncryptEx(
		    DTCSP_VOID_PTR				pContext,
		    DTCSP_INT32					nStoreLocation,
		    DTCSP_ECC_PUBLIC_KEY_PTR	pEccPublicKey,
		    DTCSP_UCHAR_PTR				pInData,
		    DTCSP_INT32					nInDataLen,  
			DTCSP_ECC_CIPHER_PTR		pOutData);
DTCSP_INT32 DTCSP_SM2_3_DecryptEx(
		    DTCSP_VOID_PTR				pContext,
		    DTCSP_INT32					nStoreLocation,
		    DTCSP_ECC_PRIVATE_KEY_PTR	pEccPrivateKey,
		    DTCSP_ECC_CIPHER_PTR		pInData,
		    DTCSP_UCHAR_PTR				pOutData,
			DTCSP_INT32*				nOutDataLen);
	
DTCSP_INT32 DTCSP_SM3_Ex_Init(DTCSP_VOID_PTR pContext, 
					   DTCSP_SM3_CONTEXT_PTR pSM3Context,
					   DTCSP_INT32				nFlag,      
					   DTCSP_UCHAR_PTR 			pID, 
					   DTCSP_INT32           	nIDLen,
					   DTCSP_INT32              nStoreLocation,
					   DTCSP_INT32  			nEccCurveFlag,
					   DTCSP_ECC_PUBLIC_KEY_PTR	pEccPublicKey);
DTCSP_INT32 DTCSP_SM3_Ex_Update(DTCSP_VOID_PTR pContext, DTCSP_SM3_CONTEXT_PTR pSM3Context, DTCSP_UCHAR_PTR pInData, DTCSP_INT32 nInDataLen);
DTCSP_INT32 DTCSP_SM3_Ex_Final (DTCSP_VOID_PTR pContext, DTCSP_SM3_CONTEXT_PTR pSM3Context, DTCSP_INT32 nOutDataLen, DTCSP_UCHAR_PTR pOutData);
////////////////////Error code//////////////////////////////////////
#define DTCSP_SUCCESS					0x0000
#define DTCSP_ERR_COMMAND_CODE			0xEEEE
#define	NO_SUPPORT_FUNC                 0xEFFF
#define DTCSP_ERR_LOADBALANCE_INIT		0xEE01
#define DTCSP_ERR_LOADBALANCE_GET		0xEE02
#define DTCSP_ERR_LOADBALANCE_REL		0xEE03
#define DTCSP_ERR_LOADBALANCE_GETALL	0xEE04
#define DTCSP_ERR_LOADBALANCE_RELALL	0xEE05
#define DTCSP_ERR_FAILED				0xFFFF


//	communication
#define DTCSP_ERR_PARAMENT				0xEE20
#define	DTCSP_ERR_OPEN_FILE				0xEE21

//	For Config File
#define	DTCSP_ERR_CONFIG_FILE			0xEE30
#define	DTCSP_ERR_CONFIG_KEY			0xEE31


//PKCS#1 pad

#define DTCSP_ERR_PKCS1_BTERR			0xE030
#define DTCSP_ERR_PKCS1_BLOCKTYPE		0xE031
#define DTCSP_ERR_DATA_TOO_LONG			0xE032
#define DTCSP_ERR_NOERROR				0xE033
#define DTCSP_ERR_IVALID_PKCS1BLOCK		0xE034
#define DTCSP_ERR_PSERROR				0xE035
#define DTCSP_ERR_SPERROR				0xE036
#define DTCSP_ERR_DATA_LENGTH			0xE038		

//  for Card Version
#define DTCSP_ERR_DSPVERSION_DIFFER    0xEE40
#define DTCSP_ERR_DSPVERSION_LOW       0xEE41
#define ERR_PARAMENT                     0xEE20

/* transfer 
#define ERR_USB_TRANSFER_BAG             0xE010  // Only For USB Device
#define ERR_USB_TRANSFER_MAXLEN          0xE011  // Only For USB Device
*/
#define ERR_TRANSFER_LENGTH              0xE011  // Only For PCI Device

/* Management & operation */
#define ERR_MANAGEMENT_DENY              0xE000  // 管理权限不满足
#define ERR_OPERATION_DENY               0xE001  // 操作权限不满足

#define ERR_MNG_NUM_LIMIT                0xE051  // 管理员数目已极限,不能增加或删除
#define ERR_MNG_NOT_EXIST                0xE052  // 该管理员不存在
#define ERR_OPR_NOT_EXIST                0xE055	 // 不存在操作员
#define ERR_MNG_ALREADY_EXIST            0xE057  // 该管理员已存在
#define ERR_FLASH_INIT_FORBID            0xE060  // 禁止初始化FLASH
#define ERR_CONFIGKEY_NOT_EXIST          0xE063  // 系统/(当前及备份)设备主密钥不存在
#define ERR_OPRPASS_NOT_EXIST            0xE064	 // 未初始化操作员口令
#define ERR_MNG_NUMBER_ILLEGAL           0xE065  // 管理员数目/号码不合法

#define ERR_PASSWD_VERIFY                0xE070  // 口令/密码验证失败

#define ERR_DEVIVE_STATUS                0xE080  // 当前设备状态不满足现有操作
         
//for RSA cipher
#define ERR_KEY_NUMBER                   0xE100  // 指定的密钥号错误
#define ERR_RSA_MODULUSLENGTH            0xE101  // RSA密钥模长错误或与待操作数据模长不符
#define ERR_KEY_NOT_EXIST                0xE102  // 指定的密钥不存在
#define ERR_SYMC_KEY_LENGTH              0xE103  // 对称密钥长度出错/不能满足操作
 
 /* IC Card Read/Write */
#define ERR_IC_READER_STATUS             0xE501  // 未安装读卡器/读卡器连接失败
#define ERR_NO_IC_CARD                   0xE502  // 读卡器内未插入IC卡
#define ERR_DSP_MPU_COMM_CHECK           0xE503  // DSP<->MPU通信数据校验失败
#define ERR_IC_CARD_STATUS               0xE504  // 该IC卡不能读写/使用了非法卡
#define ERR_MNG_IC_CARD                  0xE511  // 错误的管理员卡

/* OTHERS */
#define ERR_CHECK_SUM                    0xE700  // 校验和出错 
/*  
//MPU 
#define DTCSP_ERR_WRITE_MPU_TIMEOUT            0xE200
#define DTCSP_ERR_READ_MPU_TIMEOUT             0xE201
#define DTCSP_ERR_READ_MPU_LENGTH              0xE202
    
//DPRAM33
#define DTCSP_ERR_DPRAM33_LENGTH_LIMITED       0xE300
    
//Key flash operation error
#define	DTCSP_ERR_FLASH_ADDRESS                0xE400
#define DTCSP_ERR_USER_FLASH_BLOCK_ID          0xE401
#define DTCSP_ERR_USER_FLASH_BLOCK_OFFSET      0xE402
#define DTCSP_ERR_USER_FLASH_BLOCK_LENGTH      0xE403
#define DTCSP_ERR_FLAHS_BLOCK_NUMBER           0xE404
#define DTCSP_ERR_FLASH_BLOCK_PART_NUMBER      0xE405 
*/    


//OTHERS
#define DTCSP_ERR_CHECK_SUM              0xE700

//Backup restore
#define ERR_BR_IC_NUMBER                 0xE800  // 输出的密钥分量号不对
#define ERR_BR_BAK_BEGIN                 0xE801  // Backup Begin不成功或没做
#define ERR_BR_EXPORT_KEY                0xE802  // 密钥分量没有全部输出
#define ERR_BR_BLOCK_NO                  0xE803  // 块号不对
#define ERR_BR_IMPORT_KEY                0xE804  // 输入的密钥分量不对或数目不够
#define ERR_BR_RST_BEGIN                 0xE805  // Restore Begin不成功或没做
//DTRTL
#define ERR_SUCCESS		         0x0000
#define ERR_SYSDIR			 0xE901
#define ERR_WR_RD_FILE          	 0xE902
#define ERR_OPEN_CLOSE_DEV      	 0xE903
#define ERR_WR_RD_DEV           	 0xE905
#define ERR_CREATE_DEL_SEM      	 0xE907
#define ERR_CREATE_DEL_SHAREMEM 	 0xE909
#define ERR_V_P                 	 0xE911
#define ERR_MAP_UNMAP_MEM       	 0xE913
#define ERR_FindPCI             	 0xE915
#define ERR_LoadBalance         	 0xE916
#define ERR_REBOOT              0xE917

#ifdef __cplusplus
}
#endif

#endif
