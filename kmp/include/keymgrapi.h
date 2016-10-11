#ifndef _KMP_API_H_
#define _KMP_API_H_

#ifdef __cplusplus
extern "C" {
#endif

//-----------------------------------------------------------------------------------
//哈希算法类型
#define HASH_ALGO_MD2			1 //
#define HASH_ALGO_MD5			2 //
#define HASH_ALGO_SHA1			3 //
#define HASH_ALGO_SHA224		4 //
#define HASH_ALGO_SHA256		5 //
#define HASH_ALGO_SHA384		6 //
#define HASH_ALGO_SHA512		7 //
#define HASH_ALGO_SM3			8 //

#define PIN_BLOCK_TYPE0			0			//帐号不参与的PIN运算模式，仅限对称转加密函数使用
#define PIN_BLOCK_TYPE1			1			//帐号参与的PIN运算模式
#define PIN_BLOCK_TYPE5			5			//帐号不参与的PIN运算模式
#define PIN_BLOCK_TYPE6			6			//帐号不参与的PIN运算模式

//-----------------------------------------------------------------------------------
//密钥算法一重密钥、两重密钥、三重密钥
#define ALGO_SINGLE_DES			1
#define ALGO_DOUBLE_DES			2
#define ALGO_TRIPLE_DES			3
#define ALGO_SM_1				4
#define ALGO_SM_4				5

/////////////////////////////////////////////////////////////////////////////////////
//-----------------------------------------------------------------------------------
//工作密钥类型 
#define KEY_TYPE_PIK			1
#define KEY_TYPE_MAK			2
#define KEY_TYPE_ENC			3
#define KEY_TYPE_DAC			4
#define KEY_TYPE_ALL			9
//-----------------------------------------------------------------------------------
//密钥状态类型
#define KEY_INIT_STATUS			0
#define KEY_WORK_STATUS			1
#define KEY_REVOKE_STATUS		2
#define KEY_RESET_STATUS		3
#define KEY_ID_NOEXIST			4

//连接类型定义
#define LINK_TYPE_POOL      0    //连接池方式.此模式下客户端与服务器建立
//的连接具有线程保护、负载均衡和自动修复
//的功能，平台连接句柄可以多线程共享使用，建议
//在长连接的调用机制下使用该连接类型。


#define LINK_TYPE_NOT_POOL         1    //非连接池方式.此模式下客户端与服务器建立的连接
//不具有线程保护和自动修
//复的功能,平台连接句柄只能在单线程使用，
//建议在短连接的调用机制下使用该连接类型。

//----------------------------------------------------------------------------------
//平台返回错误码定义
#define DTCSP_SUCCESS                           0
#define DTCSP_ERROR                             1
#define CM_SUCCESS                              0
#define CM_ERROR                                1
#define CM_BASE_ERR                             4000
#define CM_REQUESTTYPE_ERR						CM_BASE_ERR+1		//请求类型错误
#define CM_MAKECHILDPROC_ERR					CM_BASE_ERR+2		//创建子进程错误
#define CM_CREATEPIPE_ERR                       CM_BASE_ERR+3		//创建父子进程通信管道错误
#define CM_DERDECODE_RECVMSG_ERR                CM_BASE_ERR+4		//解码接收的报文错误
#define DA_ESQLDB_OPENCURSOR_ERR                CM_BASE_ERR+5		//打开游标错误
#define DA_ESQLDB_FETCHBYCURSOR_ERR             CM_BASE_ERR+6		//通过游标获取数据错误
#define CM_MALLOC_ERR                           CM_BASE_ERR+7		//分配内存错误
#define CMPub_OpenConfigFile_Error              CM_BASE_ERR+8		//打开配置文件错误
#define CMPub_WriteConfigFile_Error             CM_BASE_ERR+9		//写配置文件错误
#define CMPUB_GETCONFIGITEM_ERR                 CM_BASE_ERR+10	//从配置文件中读取配置信息错误
#define DA_ESQLDB_POOLINIT_ERR                  CM_BASE_ERR+11	//数据库连接池初始化错误

#define	CMMSG_PACK_ERR                          CM_BASE_ERR+12	//报文打包错误
#define CMMSG_UNPACK_ERR                        CM_BASE_ERR+13	//报文解包错误
#define CMMSG_WORKKEY_TYPE_ERR                  CM_BASE_ERR+14	//工作密钥类型错误
#define CMMSG_REQ_NOT_SUPPORT					CM_BASE_ERR+15	//请求暂不支持错误
#define CMMSG_MAC_VERIFY_ERR					CM_BASE_ERR+16	//MAC值校验错误
#define CMPUB_GETDEVICEINFO_ERR                 CM_BASE_ERR+17	//获取设备信息错误
#define CMMSG_INPUT_PARA_ERR					CM_BASE_ERR+18	//请求参数错误
#define CMMSG_DB_CONGET_ERR						CM_BASE_ERR+19	//获取数据库连接错误
#define CMMSG_KEY_LEN_ERR                       CM_BASE_ERR+20	//密钥长度错误
#define CMMSG_HSM_CONNGET_ERR					CM_BASE_ERR+21	//获取加密机连接错误
#define CMMSG_SOCKCRYPT_ERR						CM_BASE_ERR+22	//调用加密机进行其他运算错误
#define CMMSG_SOCKCRYPT_POS_ERR                 CM_BASE_ERR+23	//调用加密机进行对称运算错误
#define CMMSG_DBDEAL_ERR                        CM_BASE_ERR+24	//数据库操作错误
#define CMMSG_INITSHM_ERR                       CM_BASE_ERR+25	//共享内存初始化错误
#define CMMSG_SHMDEAL_ERR                       CM_BASE_ERR+26  //共享内存操作错误
#define CMMSG_INITFILE_ERR						CM_BASE_ERR+27	//文件存储初始化错误
#define CMMSG_FILEDEAL_ERR						CM_BASE_ERR+28  //文件存储操作错误
#define CMMSG_SM2VERIFY_ERR						CM_BASE_ERR+29  //SM2验证错误
#define CMMSG_DEALSOCKET_ERR                    CM_BASE_ERR+30  //密钥下发通信错误
#define CMMSG_REQUESTZMK_ERR                    CM_BASE_ERR+31  //zmk密钥下发错误
#define CMMSG_REQUESTWK_ERR                     CM_BASE_ERR+32  //wk密钥下发错误
#define CMMSG_GETCERTPUBKEY_ERR					CM_BASE_ERR+33  //获取证书中公钥错误
#define CMMSG_SYNKEY_ERR						CM_BASE_ERR+34  //同步服务同步密钥错误
#define DT_CREATEMSGQ_ERR						CM_BASE_ERR+35  //创建消息队列错误
#define CMMSG_PINBLOCK_TYPE_ERR					CM_BASE_ERR+36  //PIN格式错误
#define CMMSG_HEADCMIP_NUM_ERR					CM_BASE_ERR+37  //总行IP数量错误
#define CMMSG_HSMGET_ERR						CM_BASE_ERR+38  //加密机信息获取错误
#define CMMSG_INITFILEDATA_ERR					CM_BASE_ERR+39  //文件内容未初始化
#define CMMSG_GETFILEDATA_ERR					CM_BASE_ERR+40  //文件内容获取错误
#define CMMSG_SETFILEDATA_ERR					CM_BASE_ERR+41  //文件内容设置错误
#define CMMSG_SOCKMASTERKEY_ERR					CM_BASE_ERR+42  //系统主密钥远程获取错误
#define DT_WRITEMSGQ_ERR						CM_BASE_ERR+43  //发送消息队列错误
#define DT_READMSGQ_ERR							CM_BASE_ERR+44  //接受消息队列错误
#define CMMSG_OLDMACTIMEOUT_ERR					CM_BASE_ERR+45  //旧MAC验证超过时间窗口错误
#define CMMSG_INITUNLINKLIST_ERR				CM_BASE_ERR+46  //
#define CMMSG_KEYSYNALARM_ERR					CM_BASE_ERR+47  //密钥同步报警错误
#define CMMSG_KEYSYNLOCAL_CONN_ERR				CM_BASE_ERR+48  //本地密钥同步连接错误
#define CMMSG_KEYSYNLOCAL_SEND_ERR				CM_BASE_ERR+49  //本地密钥同步发送错误
#define CMMSG_KEYSYNLOCAL_RECV_ERR				CM_BASE_ERR+50  //本地密钥同步接收错误

#define CMMSG_HEADBRANCH_CONN_ERR				CM_BASE_ERR+51  //总行和省行密管平台连接失败
#define CMMSG_HEADBRANCH_SEND_ERR				CM_BASE_ERR+52  //总行和省行密管平台发送错误
#define CMMSG_HEADBRANCH_RECV_ERR				CM_BASE_ERR+53  //总行和省行密管平台接收错误

#define CMMSG_HEADBRANCH_ROLLBACK_ERR			CM_BASE_ERR+54  //总行和省行密管对方回滚密钥错误

#define CMNSYN_BASE_ERR							5000
#define CMNSYN_NOKEY_ERR						CMNSYN_BASE_ERR+1 //在非同步状态下，返回的当前密钥为空
#define CMNSYN_IMPORTWK_ERR						CMNSYN_BASE_ERR+2 //在非同步状态下，无法导入密钥
#define CMNSYN_UPDATEZMK_ERR					CMNSYN_BASE_ERR+3 //在非同步状态下，无法更新、生成和下发ZMK
#define CMNSYN_BRANCH_RECVWK_ERR				CMNSYN_BASE_ERR+4 //在非同步状态下，省行接受工作密钥下发错误
#define CMNSYN_BRANCH_RECVZMK_ERR				CMNSYN_BASE_ERR+5 //在非同步状态下，省行接受加密传输密钥下发错误
#define CMNSYN_OLDWK_ERR						CMNSYN_BASE_ERR+6 //在非同步状态下，无法回滚工作密钥

//-----------------------------------------------------------------------------------
//外联接口错误码
#define KMP_SUCCESS                             0
#define KMP_ERROR                               1
/*----------------------------net error code----------------------------*/
#define INIT_SOCKET_ERROR			0xf100      //61696
#define CLOSE_SOCKET_ERROR			0xf101      //61697
#define CONNECT_ERROR				0xf102      //61698
#define SEND_ERROR					0xf103      //61699
#define RECV_ERROR					0xf104      //61700
#define SELECT_ERROR				0xf105      //61701
#define REPAIR_SOCKET_ERROR			0xf106      //61702
#define SERVER_LOG_MSG_ERROR		0xf107      //61703
#define SERVER_COUNT_ERROR			0xf108      //61704
#define GETSERVERIP_ERROR			0xf109      //61705
#define PASSWORD_ERROR				0xf110      //61712
#define SOCK_RECV_ERR				0xf111      //61713
#define SOCK_SEND_ERR				0xf112      //61714
	/*----------------------------pack error code----------------------------*/
#define PACK_VALUE_ERROR 			0xf201      //61953
#define UNPACK_VALUE_ERROR			0xf202      //61954
#define PACK_DATA_ERROR 			0xf203      //61956
#define UNPACK_DATA_ERROR 			0xf204      //61957
#define MSG_TYPE_ERR				0xf205      //61958
	/*----------------------------shm sem error code------------------------*/
#define CREATE_SEM_ERROR			0xf301      //62209
#define CREATE_SHM_ERROR			0xf302      //62210
#define SEM_P_ERROR					0xf303      //62211
#define SEM_V_ERROR					0xf304      //62212
#define MAP_SHM_ERROR				0xf305      //62213
#define UNMAP_SHM_ERROR				0xf306      //62214
	/*----------------------------init error code----------------------------*/
#define READ_CONFIG_FILE_ERROR		0xf400      //62464
#define DEVICE_TYPE_ERROR			0xf401      //62465
#define PASSWD_ERROR				0xf402      //62466
#define CHECK_VERSION_ERROR			0xf403      //62467
	/*----------------------------Load Balance error code--------------------*/
#define LOAD_BALANCE_START_ERROR	0xf500      //62720
#define LOAD_BALANCE_END_ERROR		0xf501      //62721
	/*----------------------------other error code---------------------------*/

#define INPUT_LEN_ERROR				0xf600      //61976
#define OUTPUT_LEN_ERROR			0xf601      //61977
#define SSF33_KEY_LEN_ERROR			0xf602      //61978
#define RSA_MODULUS_LEN_ERROR		0xf603      //61979
#define RSA_KEY_NUMBER_ERROR		0xf604      //61980

#define API_PARAM_ERROR     		0xf610      //62992 接口API参数错误
#define BUF_SIZE_ERROR     		    0xf611      //62993 传递给接口API的缓冲区大小错误
#define CONN_LIMIT_ERROR     		0xf612      //62994 连接数限制错误
#define NO_AVAILABLE_SERV_ERROR     0xf613      //62995 没有可用的服务器
#define CONFIG_ERROR				0xf615      //配置项配置错误
#define API_MALLOC_ERROR			0xf616      //接口malloc错误	

    //----------------------------------------------------------------------------------
    //RSA密钥相关
#define MAX_RSA_MODULUS_LEN			256	
#define MAX_RSA_PRIME_LEN			128
    typedef struct
    {
        unsigned int  bits;             		/* length in bits of modulus */
        unsigned char modulus[MAX_RSA_MODULUS_LEN]; 	/* modulus */
        unsigned char exponent[MAX_RSA_MODULUS_LEN]; /* public exponent */
    } PSBC_RSA_PUBLIC_KEY;

    typedef struct 
    {
        unsigned int  bits;                    	/* length in bits of modulus */
        unsigned char modulus[MAX_RSA_MODULUS_LEN];       	/* n */
        unsigned char publicExponent[MAX_RSA_MODULUS_LEN];	/* e */
        unsigned char exponent[MAX_RSA_MODULUS_LEN];      	/* d */
        unsigned char prime[2][MAX_RSA_PRIME_LEN];        		/* p,q */
        unsigned char primeExponent[2][MAX_RSA_PRIME_LEN];	/* dp,dq */
        unsigned char coefficient[MAX_RSA_PRIME_LEN];      	/* qInv */
    } PSBC_RSA_PRIVATE_KEY;

    //----------------------------------------------------------------------------------
    //SM2密钥相关
#define MAX_ECC_PRIME_LEN           32 

    // ECC曲线结构体
    typedef struct
    {
        unsigned char        primep[MAX_ECC_PRIME_LEN];       //素数p
        unsigned char        a[MAX_ECC_PRIME_LEN];            //参数a
        unsigned char        b[MAX_ECC_PRIME_LEN];            //参数b
        unsigned char        gx[MAX_ECC_PRIME_LEN];           //参数Gx   x coordinate of the base poKMP_INT32 G 
        unsigned char        gy[MAX_ECC_PRIME_LEN];           //参数Gy   y coordinate of the base poKMP_INT32 G 
        unsigned char        n[MAX_ECC_PRIME_LEN];            //阶N     order n of the base poKMP_INT32 G 
        short        				 len;                             //参数位长Len，Len必须为160、192、224或256
        short        				 type;                            //对应芯片手册曲线类型,开始时为0*/
    } PSBC_ECC_CURVE;

    // ECC公钥结构体
    typedef struct{
        PSBC_ECC_CURVE curve; /* ECC curve */          //外部曲线为用户指定的，其它要对len赋值
        unsigned char        qx[MAX_ECC_PRIME_LEN];       //x coordinate of the poKMP_INT32 Q 
        unsigned char        qy[MAX_ECC_PRIME_LEN];       //y coordinate of the poKMP_INT32 Q 
    } PSBC_ECC_PUBLIC_KEY;

    // ECC私钥结构体
    typedef struct{
        PSBC_ECC_CURVE curve; /* ECC curve */          //外部曲线为用户指定的，其它要对len赋值
        unsigned char        qx[MAX_ECC_PRIME_LEN];       // x coordinate of the poKMP_INT32 Q 
        unsigned char        qy[MAX_ECC_PRIME_LEN];       // y coordinate of the poKMP_INT32 Q 
        unsigned char        d[MAX_ECC_PRIME_LEN];        // d 
    }PSBC_ECC_PRIVATE_KEY;

    // ECC签名结构体
    typedef  struct {
        unsigned char        Rdata[32];
        unsigned char        Sdata[32];
    }PSBC_ECC_SIG;

    // ECC加密结构体
    typedef  struct  {
        short        				nC2Len;
        unsigned char        c1[64];
        unsigned char        c2[136];
        unsigned char        c3[32];
    }PSBC_ECC_CIPHER;

    //----------------------------------------------------------------------------------
    //联接函数定义

    int KMP_Initialize( void **ppKmpHandle,int linkType,unsigned char *cfgFilePath);

    int KMP_Finalize(void ** ppKmpHandle);

    //-----------------------------------------------------------------------------
    //摘要函数定义
    int KMP_MsgDigest(void *pKmpHandle,int algoType,unsigned char *msg,int msgLen,
        unsigned char *digest,int	*digestLen);

    int KMP_MsgDigest_Ex(void *pKmpHandle,int algoType,unsigned char *msg,int msgLen,
        unsigned char *digest,int	*digestLen);
    //-----------------------------------------------------------------------------

    //随机数生成函数定义
    int KMP_GenRandom(void	*pKmpHandle,int randomLen,unsigned char *random);

    //----------------------------------------------------------------------------------
    //RSA非对称密钥函数体系

    int KMP_RSAPKCS1Sign (void * pKmpHandle,
        unsigned char *keyLabel,int keyLabelLen,
        PSBC_RSA_PRIVATE_KEY *priKey,
        unsigned char  *msg,int msgLen, 
        int hashAlgo, 
        unsigned  char *sign,int *signLen);
    int KMP_RSAPKCS1Verify (void *pKmpHandle,
        unsigned char *keyLabel,int  keyLabelLen,
        PSBC_RSA_PUBLIC_KEY *pubKey,
        unsigned char  *msg,int msgLen,
        int hashAlgo, 
        unsigned  char *sign,int signLen);

    //-----------------------------------------------------------------------------
    //
    int KMP_RSAPubKeyEnc(void * pKmpHandle,
        unsigned char *keyLabel,int keyLabelLen,
        PSBC_RSA_PUBLIC_KEY	*pubKey,
        unsigned char  *plain,int plainLen,
        unsigned  char *cipher,int *cipherLen);

    int KMP_RSAPriKeyDec(void * pKmpHandle,
        unsigned char *keyLabel,int keyLabelLen,
        PSBC_RSA_PRIVATE_KEY *priKey,
        unsigned  char *cipher,int cipherLen, 
        unsigned char  *plain,int 	*plainLen);

    //-----------------------------------------------------------------------------
    //
    int	KMP_RSADecAndHash(
        void 			*pKmpHandle,
        int			hashAlgo,
        unsigned char *keyLabel,int keyLabelLen,
        unsigned char *salt,int saltLen,
        unsigned char *encData,int encDataLen,
        unsigned char *hashData,int *hashDataLen);
    //-----------------------------------------------------------------------------
    //
    int KMP_RSAToSymExPin(void *pKmpHandle,
        int 	pinType,
        unsigned char *keyLabel, int keyLabelLen,
        unsigned char *subjectID,int subjectIDLen,
        unsigned char *rsaEncPin,int rsaEncPinLen,
        unsigned char *account,int accountLen,
        unsigned char *symEncPin,int *symEncPinLen);

    //----------------------------------------------------------------------------------
    //SM2非对称密钥函数体系

    int KMP_SM2Sign (
        void 		* pKmpHandle,
        unsigned char *keyLabel,
        int			  keyLabelLen,
        PSBC_ECC_PRIVATE_KEY 		*priKey,
        unsigned char  *msg,
        int 			  msgLen,
        int			  hashAlgo,
        unsigned char *signData,
        int			*signDataLen);

    int KMP_SM2Verify (
        void 		* pKmpHandle,
        unsigned char *keyLabel,
        int			  keyLabelLen,
        PSBC_ECC_PUBLIC_KEY	*pubKey,
        unsigned char  *msg,
        int 			  msgLen,
        int			  hashAlgo,
        unsigned char *signData,
        int           signDataLen);
    //-----------------------------------------------------------------------------
    //
    int KMP_SM2PubKeyEnc(
        void 		* pKmpHandle,
        unsigned char *keyLabel,
        int			  keyLabelLen,
        PSBC_ECC_PUBLIC_KEY	*pubKey,
        unsigned char  *plain,
        int 			  plainLen,
        unsigned char *cipherData,
        int			*cipherDataLen);

    int KMP_SM2PriKeyDec(
        void 		* pKmpHandle,
        unsigned char *keyLabel,
        int			  keyLabelLen,
        PSBC_ECC_PRIVATE_KEY 		*priKey,
        unsigned char *cipherData,
        int			  cipherDataLen,
        unsigned char  *plain,
        int 			  *plainLen);

    //-----------------------------------------------------------------------------
    //
    int	KMP_SM2DecAndHash(
        void 		*pKmpHandle,
        int			hashAlgo,
        unsigned char *keyLabel,int keyLabelLen,
        unsigned char *salt,int saltLen,
        unsigned char *sm2EncData ,
        int			  sm2EncDataLen,
        unsigned char *hashData,int *hashDataLen);

    //-----------------------------------------------------------------------------
    //
    int KMP_SM2ToSymExPin(
        void *pKmpHandle,
        int 	pinType,
        unsigned char *keyLabel, int keyLabelLen,
        unsigned char *subjectID,int subjectIDLen,
        unsigned char *sm2EncPin ,int sm2EncPinLen,
        unsigned char *account,int accountLen,
        unsigned char *symEncPin,int *symEncPinLen);

    //----------------------------------------------------------------------------------
    //对称密钥函数体系

    int KMP_RequestPlatWorkKey(
        void 			*pKmpHandle,
        int				algoType,
        int  			workKeyType,
        unsigned char 	*preOutId,
        int				preOutIdLen,
        unsigned char 	*orgId,
        int				orgIdLen);
    //-----------------------------------------------------------------------------
    //
    int KMP_ImportPlatWorkKey(
        void 			*pKmpHandle,
        int				algoType,
        int  			workKeyType,
        unsigned char 	*preOutId,
        int				preOutIdLen,
        unsigned char 	*orgId,
        int				orgIdLen,
        unsigned char 	*workKey,
        int  			workKeyLen,
        unsigned char	*verifyKey,
        int				verifyKeyLen);
    //-----------------------------------------------------------------------------
    //
    int KMP_GetPlatWorkKey(
        void 			*pKmpHandle,
        int 			algoType,
        int  			workKeyType,
        unsigned char 	*preOutId,
        int				preOutIdLen,
        unsigned char 	*orgId,
        int 			orgIdLen,
        unsigned char 	*workKey,
        int  			*workKeyLen,
        unsigned char	*verifyKey,
        int				*verifyKeyLen);
    //-----------------------------------------------------------------------------
    //
    int KMP_EncryptSubjectPIN(
        void 		   *pKmpHandle,
        int			   algoType,
        int 			pinType,
        unsigned char  *subjectID,
        int			   subjectIDLen,
        unsigned char  *userAccount,
        int			   userAccountLen,
        unsigned char  *userPIN,
        int 		   userPINLen,
        unsigned char  *encryptPIN,
        int			   *encryptPINLen);
    //-----------------------------------------------------------------------------

    //-----------------------------------------------------------------------------			
    //
    int KMP_ExEncrytSubjectPIN(
        void 			*pKmpHandle,
        int			 	srcAlgoType,
        int 		 	srcPinType,
        unsigned char  *srcSubjectID,
        int			  srcSubjectIDLen,
        int 			destAlgoType,
        int 			destPinType,
        unsigned char  *destSubjectID,
        int			  destSubjectIDLen ,
        unsigned char  *userAccount,
        int 			 userAccountLen,
        unsigned char  *srcPIN,
        int 			  srcPINLen ,
        unsigned char  *destPIN,
        int			 *destPINLen);

    //-----------------------------------------------------------------------------

    //-----------------------------------------------------------------------------			

		int KMP_DecryptSubjectPIN(
						  void 				*pKmpHandle,
						  int				algoType,
						  int 				pinType,
						  unsigned char		*subjectID,
						  int				subjectIDLen,
						  unsigned char		*userAccount,
						  int				userAccountLen,
						  unsigned char		*EncUserPIN,
						  int 				EncUserPINLen,
						  unsigned char		*userPIN,
						  int 				*userPINLen);
    //-----------------------------------------------------------------------------
    //
    int	KMP_DecryptSubjectPINAndHash(
        void 			*pKmpHandle,
        int			algoType,
        int 		pinType,
        int			hashAlgo,
        unsigned char  *subjectID,
        int			   subjectIDLen,
        unsigned char *salt,int saltLen,
        unsigned char  *userAccount,
        int 			   userAccountLen,
        unsigned char  *EncSubjectPIN,
        int 			   EncSubjectPINLen,
        unsigned char *hashPIN,int *hashPINLen);

    int	KMP_DecryptSubjectPINAndHash_Ex(
        void 			*pKmpHandle,
        int			algoType,
        int 		pinType,
        int			hashAlgo,
        unsigned char  *subjectID,
        int			   subjectIDLen,
        unsigned char *salt,int saltLen,
        unsigned char  *userAccount,
        int 			   userAccountLen,
        unsigned char  *EncSubjectPIN,
        int 			   EncSubjectPINLen,
        unsigned char *hashPIN,int *hashPINLen);

    //-----------------------------------------------------------------------------
    //
    int KMP_GenMac(
        void 			*pKmpHandle,
        int			algoType,
        unsigned char  *subjectID,
        int			subjectIDLen,
        unsigned char  *userData,
        int 			userDataLen,
        unsigned char  *macData,
        int			*macDataLen);
    //-----------------------------------------------------------------------------
    //
    int KMP_VerifyMac(
        void 		   *pKmpHandle,
        int			   algoType,
        unsigned char  *subjectID,
        int			   subjectIDLen,
        unsigned char  *macData,
        int 		   macDataLen,
        unsigned char  *userData,
        int			   userDataLen);
    //-----------------------------------------------------------------------------

    int	KMP_GenCvn(
        void 			*pKmpHandle,
        unsigned char  *subjectID,
        int			   subjectIDLen,
        unsigned char  *subjectEncID,
        int			   subjectEncIDLen,
        unsigned char  *userAccount,
        int 			userAccountLen,
        unsigned char  *inDate,
        int 			inDateLen,
        unsigned char  *serveNo,
        int 			serveNoLen,
        unsigned char *cvnData,int *cvnDataLen);

    //-----------------------------------------------------------------------------
    //
    int	KMP_GenPvn(
        void 			*pKmpHandle,
        int				nKeyNum,
        unsigned char  *userAccount,
        int 			userAccountLen,
        unsigned char  *userPIN,
        int 			userPINLen,
        unsigned char *pvnData,int *pvnDataLen);
    //-----------------------------------------------------------------------------

    int	KMP_GenPassbookVN(
        void 			*pKmpHandle,
        unsigned char  *subjectID,
        int			   subjectIDLen,
        unsigned char  *userAccount,//用户账号
        int 			userAccountLen,
        unsigned char  *date,//开户日期
        int 			dateLen,
        unsigned char  *printNo,//印刷号
        int 			printNoLen,
        unsigned char *pvnData,
        int *pvnDataLen);
    //-----------------------------------------------------------------------------
    //
    int KMP_GenMacByPin(
        void 			*pKmpHandle,
        int			algoType,
        unsigned char  *subjectID,
        int			subjectIDLen,
        unsigned char  *userData,
        int 			userDataLen,
        unsigned char  *macData,
        int			*macDataLen);
    //-----------------------------------------------------------------------------
    //
    int KMP_VerifyMacByPin(
        void 		   *pKmpHandle,
        int			   algoType,
        unsigned char  *subjectID,
        int			   subjectIDLen,
        unsigned char  *macData,
        int 		   macDataLen,
        unsigned char  *userData,
        int			   userDataLen);
	int KMP_GenDac(
				 void 			*pKmpHandle,
				 int			algoType,
				 unsigned char  *subjectID,
				 int			subjectIDLen,
				 unsigned char  *userData,
				 int 			userDataLen,
				 unsigned char  *dacData,
				 int			*dacDataLen);
	//-----------------------------------------------------------------------------
	//
	int KMP_VerifyDac(
				void 		   *pKmpHandle,
				int			   algoType,
				unsigned char  *subjectID,
				int			   subjectIDLen,
				unsigned char  *dacData,
				int 		   dacDataLen,
				unsigned char  *userData,
				int			   userDataLen);


	int KMP_TransportData( 
		void *pKmpHandle,
		unsigned char *DataToServer, 
		int DataToServerLen,
		unsigned char *DataFromServer, 
		int *pDataFromServerLen);

	int KMP_TransportDataWk( 
		void *pKmpHandle,
		unsigned char *DataToServer, 
		int DataToServerLen,
		unsigned char *DataFromServer, 
		int *pDataFromServerLen);

    int KMP_GenMacByKey(
        void 			*pKmpHandle,
        int				algoType,
        unsigned char	*subjectID,
        int				subjectIDLen,
        unsigned char	*encKey,
        int				encKeyLen,
        unsigned char	*userData,
        int				userDataLen,
        unsigned char	*macData,
        int				*macDataLen);

    int KMP_VerifyMacByKey(
        void				*pKmpHandle,
        int				algoType,
        unsigned char	*subjectID,
        int				subjectIDLen,
        unsigned char	*encKey,
        int				encKeyLen,
        unsigned char	*macData,
        int				macDataLen,
        unsigned char	*userData,
        int				userDataLen);
    
		int KMP_GenPIN(
        void            *pKmpHandle,
        int             algoType,
        int			  pinType,
        int			  hashAlgo,
        int			  pinLen,
        unsigned char   *subjectID,
        int             subjectIDLen,
        unsigned char   *salt,
        int 		  saltLen,
        unsigned char   *userAccount,
        int 		  userAccountLen,
        unsigned char   *encryptPIN,
        int			  *encryptPINLen,
        unsigned char   *hashPIN,
        int 		  *hashPINLen);
    int KMP_GetPlatZmk(
				void				*pKmpHandle,
				int						algoType,
				unsigned char *preOutId,
				int						preOutIdLen,
				unsigned char *zmkId,
				int 					zmkIdLen,
				unsigned char *zmkKey,
				int 					*zmkKeyLen,
				unsigned char *verifyKey,
				int 					*verifyKeyLen);
		int KMP_EncryptSubjectData(
								void 		* pKmpHandle,
								int			algoType,
								int     algoMode,
								unsigned char  *subjectID,
								int			  subjectIDLen,
								unsigned char *iv,
								int            ivLen,
								unsigned char  *subjectData,
								int 			  subjectDataLen,
								unsigned char  *encryptData,
								int			 *encryptDataLen);
		int KMP_DecryptSubjectENC(
								void 		* pKmpHandle,
								int			algoType,
								int     algoMode,
								unsigned char  *subjectID,
								int			  subjectIDLen,
								unsigned char *iv,
								int            ivLen,
								unsigned char  * encSubjectData,
								int 			  encSubjectDataLen,
								unsigned char  * subjectData,
								int 			 * subjectDataLen);
		int KMP_GenMacEx(
								void    *pKmpHandle,
                int      algoType,
                int     macType,
                int     padType,
                unsigned char   *subjectID,
                int             subjectIDLen,
                unsigned char   *userData,
                int             userDataLen,
                unsigned char   *macData,
                int             *macDataLen);
    int KMP_VerifyMacEx(
                    void            *pKmpHandle,
                    int             algoType,
                    int    					macType,
                		int     				padType,
                    unsigned char   *subjectID,
                    int             subjectIDLen,
                    unsigned char   *macData,
                    int             macDataLen,
                    unsigned char   *userData,
                    int             userDataLen);
    int KMP_EncryptSubjectData_Pad(
								void 		* pKmpHandle,
								int			algoType,
								int     algoMode,
              	int							padType,								
								unsigned char    			*pad1,
                int     				pad1Len,
								unsigned char    			*pad2,
                int     				pad2Len,
								unsigned char  *subjectID,
								int			  subjectIDLen,
								unsigned char *iv,
								int            ivLen,
								unsigned char  *subjectData,
								int 			  subjectDataLen,
								unsigned char  *encryptData,
								int			 *encryptDataLen);
		int KMP_DecryptSubjectENC_Pad(
								void 		* pKmpHandle,
								int			algoType,
								int     algoMode,
								int							padType, 
								unsigned char    			*pad1,
                int     				pad1Len,
								unsigned char    			*pad2,
                int     				pad2Len,               
								unsigned char  *subjectID,
								int			  subjectIDLen,
								unsigned char *iv,
								int            ivLen,
								unsigned char  * encSubjectData,
								int 			  encSubjectDataLen,
								unsigned char  * subjectData,
								int 			 * subjectDataLen);
		int KMP_ExGetPlatWorkKey(
								void      *pKmpHandle,
								int       srcalgoType,
								int       desalgoType,
								unsigned char   *srcpreOutId,
								int       srcpreOutIdLen,
								unsigned char   *destpreOutId,
								int       destpreOutIdLen,
								unsigned char   *srcworkKey,
								int         srcworkKeyLen,
								unsigned char		* destworkKey,
								int       * destworkKeyLen,
								unsigned char   *verifyKey,
								int        *verifyKeyLen);					
		int KMP_GetInitCDK(
						void 		* pKmpHandle,
						int			algoType,
						unsigned char *terminalID,
						int			  terminalIDLen	,
						int 			 keyLen,
						unsigned char *mkIndex,
						int			  mkIndexLen,
						unsigned char  *cdk,
						int 			  *cdkLen,
						unsigned  char *cdkVerifyKey,
						int 			  *cdkVerifyKeyLen);
		int KMP_GenTerminalKeys(
					void		  *pKmpHandle,
					int			  algoType,
					unsigned char *terminalID,
					int			  terminalIDLen,
					unsigned char *curCDKVerifyKey,
					int			   curCDKVerifyKeyLen,
					unsigned char *newCDK,
					int			  *newCDKLen,
					unsigned char *newCDKVerifyKey,
					int			  *newCDKVerifyKeyLen,
				 int			  pikLen,
					unsigned char *newPik,
					int			  *newPikLen,
					unsigned char *newPikVerifyKey,
					int			  *newPikVerifyKeyLen,
				 int 			  makLen,
					unsigned char *newMak,
					int			  *newMakLen,
					unsigned char *newMakVerifyKey,
					int			  *newMakVerifyKeyLen,					
				unsigned char *reqTime);
		int KMP_EncryptSubjectPIN_Pos(
								void 		* pKmpHandle,
								int			typeFlag,
								int			algoType,
								int 			pinType,
								unsigned char  *subjectID,
								int			  subjectIDLen	,
								unsigned char  *userAccount,
								int 			   userAccountLen,
								unsigned char  *subjectPIN,
								int 			  subjectPINLen,
								unsigned char  *encryptPIN,
								int			 *encryptPINLen);
		int KMP_ExEncrytSubjectPIN_Pos(
							void 			* pKmpHandle,
							int			typeFlag,
							int			 srcAlgoType,
							int 			 srcPinType,
							unsigned char  *srcSubjectID,
							int			  srcSubjectIDLen,
							int 			 destAlgoType,
							int 			 destPinType,
							unsigned char  *destSubjectID,
							int			  destSubjectIDLen ,
							unsigned char  *userAccount,
							int 			 userAccountLen,
							unsigned char  *srcPIN,
							int 			  srcPINLen ,
							unsigned char  *destPIN,
							int			 *destPINLen);
		int KMP_DecryptSubjectPINAndHash_Pos(
                 	void 			*pKmpHandle,
									int			typeFlag,
									int			   algoType,
									int 				pinType,
									int			   hashAlgo,
									unsigned char  *subjectID,
									int			   subjectIDLen,
									unsigned char  *salt,
									int 				saltLen,
									unsigned char  *userAccount,
									int 			   userAccountLen,
									unsigned char  *EncSubjectPIN,
									int 			   EncSubjectPINLen,
									unsigned char  *hashPIN,
									int 			   *hashPINLen);
		int	KMP_GenMac_Pos(
						void 			*pKmpHandle,
						int			typeFlag,
						int				algoType,
						unsigned char  *subjectID,
						int			 	subjectIDLen,
						unsigned char  *userData,
						int 			 	userDataLen,
						unsigned char  *macData,
						int			 	*macDataLen);
		int  KMP_VerifyMac_Pos(
						void 			*pKmpHandle,
						  int			typeFlag,
						int			algoType,
						unsigned char  *subjectID,
						int			 subjectIDLen,
						unsigned char  *macData,
						int 			 macDataLen,
						unsigned char  *userData,
						int			 userDataLen);
		int KMP_GenMacByKey_Pos(
							void 			*pKmpHandle,
							int				typeFlag,
							int				algoType,
							unsigned char  * preOutId,
							int			 	preOutIdLen,
							unsigned char  * encKey,
							int			 	encKeyLen,
							unsigned char  *userData,
							int 			 	userDataLen,
							unsigned char  *macData,
							int			 	*macDataLen);
		int KMP_VerifyMacByKey_Pos(
								void 			*pKmpHandle,
								 int				typeFlag,
								int			algoType,
								unsigned char  * preOutId,
								int			 preOutIdLen,
								unsigned char  * encKey,
								int			 encKeyLen,
								unsigned char  *macData,
								int 			 macDataLen,
								unsigned char  *userData,
								int			 userDataLen);																													
		int KMP_EncryptSubjectData_Pad_Pos(
											void 		* pKmpHandle,
											 int			typeFlag,
											int			algoType,
											int			algoMode,
											int			 padType,
											unsigned char  *pad1,
											int			pad1Len,
											unsigned char  *pad2,
											int			pad2Len,
											unsigned char  *subjectID,
											int			  subjectIDLen	,
											unsigned char	  *iv,
											int			  ivLen,
											unsigned char  *subjectData,
											int 			  subjectDataLen,
											unsigned char  *encryptData,
											int			 *encryptDataLen);
		int KMP_DecryptSubjectENC_Pad_Pos(
										void 			*pKmpHandle,
										int			typeFlag,
										int    		algoType,
										int			algoMode,
										int			padType,
										unsigned char  *pad1,
										int          pad1Len,
										unsigned char  *pad2,
										int          pad2Len,
										unsigned char  *subjectID,
										int			  subjectIDLen,
										unsigned char   *iv,
										int			  ivLen,
										unsigned char  * encSubjectData,
										int 			  encSubjectDataLen,
										unsigned char  * subjectData,
										int 			 * subjectDataLen);
		int KMP_GenCvn_SM4(
							void 			*pKmpHandle,
							unsigned char  *subjectID,
							int			   subjectIDLen,
							unsigned char  * subjectEncID,
							int			   subjectEncIDLen,
							unsigned char  *userAccount,
							int 			  userAccountLen,
							unsigned char  *inDate,
							int 			  inDateLen,
							unsigned char  *serveNo,
							int 			  serveNoLen,
							unsigned char *cvnData,int *cvnDataLen);
		int	KMP_GenPvn_SM4(
                void            *pKmpHandle,
                int             nKeyNum,
                unsigned char   *userAccount,
                int             userAccountLen,
                unsigned char   *userPIN,
                int             userPINLen,
                unsigned char   *pvnData,
                int             *pvnDataLen);
    int	KMP_GenPassbookVN_SM4(
                      void           *pKmpHandle,
                      unsigned char  *subjectID,
                      int            subjectIDLen,
                      unsigned char  *userAccount,//用户账号
                      int            userAccountLen,
                      unsigned char  *date,//开户日期
                      int            dateLen,
                      unsigned char  *printNo,//印刷号
                      int            printNoLen,
                      unsigned char  *pvnData,
					  					int            *pvnDataLen);
	
	
		int KMP_GetCipherKeyboardZMK(
					   void 			*pKmpHandle,
					   int 				asymType,
					   int  			algoType,
					   unsigned char	*subjectID,
					   int				subjectIDLen,
					   unsigned char 	*pubKeyData,
					   int				pubKeyDataLen,
					   unsigned char 	*encZMKData,
					   int  			*encZMKDataLen,
					   unsigned char	*verifyKey,
					   int				*verifyKeyLen);
					   
		int KMP_GetCipherKeyboardWK(
					   void 			*pKmpHandle,
					   int 				algoType,
					   int 				workKeyType,
					   unsigned char	*subjectID,
					   int				subjectIDLen,				   
					   unsigned char 	*encWKData,
					   int  			*encWKDataLen,
					   unsigned char	*verifyKey,
					   int				*verifyKeyLen);
					   
		int	KMP_CipherKeyboardRevokeKey(
             void           *pKmpHandle,
             unsigned char  *subjectID,
             int            subjectIDLen);
    //add pos zpj 2016.01.12      
		int KMP_GetKeyStatus_Pos (
				void 			* pKmpHandle,
				int				type,
				unsigned char	*terminalID,
				int				terminalIDLen,
				unsigned char  *outStatus,
				int            *outStatusLen);
				
		int KMP_RevokeKey_Pos (
				void 			* pKmpHandle,
				unsigned char	*terminalID,
				int				terminalIDLen);	
		//add over	
		//zxt add 2016/7/11
		int KMP_ExEncrytSubjectPIN_Hexin(
						   void 			*pKmpHandle,
						   int				srcAlgoType,
						   int 		 		srcPinType,
						   unsigned char  *srcUserAccount,
						   int 				srcUserAccountLen,
						   unsigned char	*srcSubjectID,
						   int				srcSubjectIDLen,
						   int				destAlgoType,
						   int 				destPinType,
						   unsigned char  *destUserAccount,
						   int 				destUserAccountLen,
						   unsigned char	*destSubjectID,
						   int				destSubjectIDLen ,
						   unsigned char	*srcPIN,
						   int 				srcPINLen ,
						   unsigned char	*destPIN,
						   int				*destPINLen);															
		//zxt add end									   			   													            		            
#ifdef __cplusplus
}
#endif

#endif
