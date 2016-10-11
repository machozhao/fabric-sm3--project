#ifndef _KMP_API_H_
#define _KMP_API_H_

#ifdef __cplusplus
extern "C" {
#endif

//-----------------------------------------------------------------------------------
//��ϣ�㷨����
#define HASH_ALGO_MD2			1 //
#define HASH_ALGO_MD5			2 //
#define HASH_ALGO_SHA1			3 //
#define HASH_ALGO_SHA224		4 //
#define HASH_ALGO_SHA256		5 //
#define HASH_ALGO_SHA384		6 //
#define HASH_ALGO_SHA512		7 //
#define HASH_ALGO_SM3			8 //

#define PIN_BLOCK_TYPE0			0			//�ʺŲ������PIN����ģʽ�����޶Գ�ת���ܺ���ʹ��
#define PIN_BLOCK_TYPE1			1			//�ʺŲ����PIN����ģʽ
#define PIN_BLOCK_TYPE5			5			//�ʺŲ������PIN����ģʽ
#define PIN_BLOCK_TYPE6			6			//�ʺŲ������PIN����ģʽ

//-----------------------------------------------------------------------------------
//��Կ�㷨һ����Կ��������Կ��������Կ
#define ALGO_SINGLE_DES			1
#define ALGO_DOUBLE_DES			2
#define ALGO_TRIPLE_DES			3
#define ALGO_SM_1				4
#define ALGO_SM_4				5

/////////////////////////////////////////////////////////////////////////////////////
//-----------------------------------------------------------------------------------
//������Կ���� 
#define KEY_TYPE_PIK			1
#define KEY_TYPE_MAK			2
#define KEY_TYPE_ENC			3
#define KEY_TYPE_DAC			4
#define KEY_TYPE_ALL			9
//-----------------------------------------------------------------------------------
//��Կ״̬����
#define KEY_INIT_STATUS			0
#define KEY_WORK_STATUS			1
#define KEY_REVOKE_STATUS		2
#define KEY_RESET_STATUS		3
#define KEY_ID_NOEXIST			4

//�������Ͷ���
#define LINK_TYPE_POOL      0    //���ӳط�ʽ.��ģʽ�¿ͻ��������������
//�����Ӿ����̱߳��������ؾ�����Զ��޸�
//�Ĺ��ܣ�ƽ̨���Ӿ�����Զ��̹߳���ʹ�ã�����
//�ڳ����ӵĵ��û�����ʹ�ø��������͡�


#define LINK_TYPE_NOT_POOL         1    //�����ӳط�ʽ.��ģʽ�¿ͻ��������������������
//�������̱߳������Զ���
//���Ĺ���,ƽ̨���Ӿ��ֻ���ڵ��߳�ʹ�ã�
//�����ڶ����ӵĵ��û�����ʹ�ø��������͡�

//----------------------------------------------------------------------------------
//ƽ̨���ش����붨��
#define DTCSP_SUCCESS                           0
#define DTCSP_ERROR                             1
#define CM_SUCCESS                              0
#define CM_ERROR                                1
#define CM_BASE_ERR                             4000
#define CM_REQUESTTYPE_ERR						CM_BASE_ERR+1		//�������ʹ���
#define CM_MAKECHILDPROC_ERR					CM_BASE_ERR+2		//�����ӽ��̴���
#define CM_CREATEPIPE_ERR                       CM_BASE_ERR+3		//�������ӽ���ͨ�Źܵ�����
#define CM_DERDECODE_RECVMSG_ERR                CM_BASE_ERR+4		//������յı��Ĵ���
#define DA_ESQLDB_OPENCURSOR_ERR                CM_BASE_ERR+5		//���α����
#define DA_ESQLDB_FETCHBYCURSOR_ERR             CM_BASE_ERR+6		//ͨ���α��ȡ���ݴ���
#define CM_MALLOC_ERR                           CM_BASE_ERR+7		//�����ڴ����
#define CMPub_OpenConfigFile_Error              CM_BASE_ERR+8		//�������ļ�����
#define CMPub_WriteConfigFile_Error             CM_BASE_ERR+9		//д�����ļ�����
#define CMPUB_GETCONFIGITEM_ERR                 CM_BASE_ERR+10	//�������ļ��ж�ȡ������Ϣ����
#define DA_ESQLDB_POOLINIT_ERR                  CM_BASE_ERR+11	//���ݿ����ӳس�ʼ������

#define	CMMSG_PACK_ERR                          CM_BASE_ERR+12	//���Ĵ������
#define CMMSG_UNPACK_ERR                        CM_BASE_ERR+13	//���Ľ������
#define CMMSG_WORKKEY_TYPE_ERR                  CM_BASE_ERR+14	//������Կ���ʹ���
#define CMMSG_REQ_NOT_SUPPORT					CM_BASE_ERR+15	//�����ݲ�֧�ִ���
#define CMMSG_MAC_VERIFY_ERR					CM_BASE_ERR+16	//MACֵУ�����
#define CMPUB_GETDEVICEINFO_ERR                 CM_BASE_ERR+17	//��ȡ�豸��Ϣ����
#define CMMSG_INPUT_PARA_ERR					CM_BASE_ERR+18	//�����������
#define CMMSG_DB_CONGET_ERR						CM_BASE_ERR+19	//��ȡ���ݿ����Ӵ���
#define CMMSG_KEY_LEN_ERR                       CM_BASE_ERR+20	//��Կ���ȴ���
#define CMMSG_HSM_CONNGET_ERR					CM_BASE_ERR+21	//��ȡ���ܻ����Ӵ���
#define CMMSG_SOCKCRYPT_ERR						CM_BASE_ERR+22	//���ü��ܻ����������������
#define CMMSG_SOCKCRYPT_POS_ERR                 CM_BASE_ERR+23	//���ü��ܻ����жԳ��������
#define CMMSG_DBDEAL_ERR                        CM_BASE_ERR+24	//���ݿ��������
#define CMMSG_INITSHM_ERR                       CM_BASE_ERR+25	//�����ڴ��ʼ������
#define CMMSG_SHMDEAL_ERR                       CM_BASE_ERR+26  //�����ڴ��������
#define CMMSG_INITFILE_ERR						CM_BASE_ERR+27	//�ļ��洢��ʼ������
#define CMMSG_FILEDEAL_ERR						CM_BASE_ERR+28  //�ļ��洢��������
#define CMMSG_SM2VERIFY_ERR						CM_BASE_ERR+29  //SM2��֤����
#define CMMSG_DEALSOCKET_ERR                    CM_BASE_ERR+30  //��Կ�·�ͨ�Ŵ���
#define CMMSG_REQUESTZMK_ERR                    CM_BASE_ERR+31  //zmk��Կ�·�����
#define CMMSG_REQUESTWK_ERR                     CM_BASE_ERR+32  //wk��Կ�·�����
#define CMMSG_GETCERTPUBKEY_ERR					CM_BASE_ERR+33  //��ȡ֤���й�Կ����
#define CMMSG_SYNKEY_ERR						CM_BASE_ERR+34  //ͬ������ͬ����Կ����
#define DT_CREATEMSGQ_ERR						CM_BASE_ERR+35  //������Ϣ���д���
#define CMMSG_PINBLOCK_TYPE_ERR					CM_BASE_ERR+36  //PIN��ʽ����
#define CMMSG_HEADCMIP_NUM_ERR					CM_BASE_ERR+37  //����IP��������
#define CMMSG_HSMGET_ERR						CM_BASE_ERR+38  //���ܻ���Ϣ��ȡ����
#define CMMSG_INITFILEDATA_ERR					CM_BASE_ERR+39  //�ļ�����δ��ʼ��
#define CMMSG_GETFILEDATA_ERR					CM_BASE_ERR+40  //�ļ����ݻ�ȡ����
#define CMMSG_SETFILEDATA_ERR					CM_BASE_ERR+41  //�ļ��������ô���
#define CMMSG_SOCKMASTERKEY_ERR					CM_BASE_ERR+42  //ϵͳ����ԿԶ�̻�ȡ����
#define DT_WRITEMSGQ_ERR						CM_BASE_ERR+43  //������Ϣ���д���
#define DT_READMSGQ_ERR							CM_BASE_ERR+44  //������Ϣ���д���
#define CMMSG_OLDMACTIMEOUT_ERR					CM_BASE_ERR+45  //��MAC��֤����ʱ�䴰�ڴ���
#define CMMSG_INITUNLINKLIST_ERR				CM_BASE_ERR+46  //
#define CMMSG_KEYSYNALARM_ERR					CM_BASE_ERR+47  //��Կͬ����������
#define CMMSG_KEYSYNLOCAL_CONN_ERR				CM_BASE_ERR+48  //������Կͬ�����Ӵ���
#define CMMSG_KEYSYNLOCAL_SEND_ERR				CM_BASE_ERR+49  //������Կͬ�����ʹ���
#define CMMSG_KEYSYNLOCAL_RECV_ERR				CM_BASE_ERR+50  //������Կͬ�����մ���

#define CMMSG_HEADBRANCH_CONN_ERR				CM_BASE_ERR+51  //���к�ʡ���ܹ�ƽ̨����ʧ��
#define CMMSG_HEADBRANCH_SEND_ERR				CM_BASE_ERR+52  //���к�ʡ���ܹ�ƽ̨���ʹ���
#define CMMSG_HEADBRANCH_RECV_ERR				CM_BASE_ERR+53  //���к�ʡ���ܹ�ƽ̨���մ���

#define CMMSG_HEADBRANCH_ROLLBACK_ERR			CM_BASE_ERR+54  //���к�ʡ���ܹܶԷ��ع���Կ����

#define CMNSYN_BASE_ERR							5000
#define CMNSYN_NOKEY_ERR						CMNSYN_BASE_ERR+1 //�ڷ�ͬ��״̬�£����صĵ�ǰ��ԿΪ��
#define CMNSYN_IMPORTWK_ERR						CMNSYN_BASE_ERR+2 //�ڷ�ͬ��״̬�£��޷�������Կ
#define CMNSYN_UPDATEZMK_ERR					CMNSYN_BASE_ERR+3 //�ڷ�ͬ��״̬�£��޷����¡����ɺ��·�ZMK
#define CMNSYN_BRANCH_RECVWK_ERR				CMNSYN_BASE_ERR+4 //�ڷ�ͬ��״̬�£�ʡ�н��ܹ�����Կ�·�����
#define CMNSYN_BRANCH_RECVZMK_ERR				CMNSYN_BASE_ERR+5 //�ڷ�ͬ��״̬�£�ʡ�н��ܼ��ܴ�����Կ�·�����
#define CMNSYN_OLDWK_ERR						CMNSYN_BASE_ERR+6 //�ڷ�ͬ��״̬�£��޷��ع�������Կ

//-----------------------------------------------------------------------------------
//�����ӿڴ�����
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

#define API_PARAM_ERROR     		0xf610      //62992 �ӿ�API��������
#define BUF_SIZE_ERROR     		    0xf611      //62993 ���ݸ��ӿ�API�Ļ�������С����
#define CONN_LIMIT_ERROR     		0xf612      //62994 ���������ƴ���
#define NO_AVAILABLE_SERV_ERROR     0xf613      //62995 û�п��õķ�����
#define CONFIG_ERROR				0xf615      //���������ô���
#define API_MALLOC_ERROR			0xf616      //�ӿ�malloc����	

    //----------------------------------------------------------------------------------
    //RSA��Կ���
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
    //SM2��Կ���
#define MAX_ECC_PRIME_LEN           32 

    // ECC���߽ṹ��
    typedef struct
    {
        unsigned char        primep[MAX_ECC_PRIME_LEN];       //����p
        unsigned char        a[MAX_ECC_PRIME_LEN];            //����a
        unsigned char        b[MAX_ECC_PRIME_LEN];            //����b
        unsigned char        gx[MAX_ECC_PRIME_LEN];           //����Gx   x coordinate of the base poKMP_INT32 G 
        unsigned char        gy[MAX_ECC_PRIME_LEN];           //����Gy   y coordinate of the base poKMP_INT32 G 
        unsigned char        n[MAX_ECC_PRIME_LEN];            //��N     order n of the base poKMP_INT32 G 
        short        				 len;                             //����λ��Len��Len����Ϊ160��192��224��256
        short        				 type;                            //��ӦоƬ�ֲ���������,��ʼʱΪ0*/
    } PSBC_ECC_CURVE;

    // ECC��Կ�ṹ��
    typedef struct{
        PSBC_ECC_CURVE curve; /* ECC curve */          //�ⲿ����Ϊ�û�ָ���ģ�����Ҫ��len��ֵ
        unsigned char        qx[MAX_ECC_PRIME_LEN];       //x coordinate of the poKMP_INT32 Q 
        unsigned char        qy[MAX_ECC_PRIME_LEN];       //y coordinate of the poKMP_INT32 Q 
    } PSBC_ECC_PUBLIC_KEY;

    // ECC˽Կ�ṹ��
    typedef struct{
        PSBC_ECC_CURVE curve; /* ECC curve */          //�ⲿ����Ϊ�û�ָ���ģ�����Ҫ��len��ֵ
        unsigned char        qx[MAX_ECC_PRIME_LEN];       // x coordinate of the poKMP_INT32 Q 
        unsigned char        qy[MAX_ECC_PRIME_LEN];       // y coordinate of the poKMP_INT32 Q 
        unsigned char        d[MAX_ECC_PRIME_LEN];        // d 
    }PSBC_ECC_PRIVATE_KEY;

    // ECCǩ���ṹ��
    typedef  struct {
        unsigned char        Rdata[32];
        unsigned char        Sdata[32];
    }PSBC_ECC_SIG;

    // ECC���ܽṹ��
    typedef  struct  {
        short        				nC2Len;
        unsigned char        c1[64];
        unsigned char        c2[136];
        unsigned char        c3[32];
    }PSBC_ECC_CIPHER;

    //----------------------------------------------------------------------------------
    //���Ӻ�������

    int KMP_Initialize( void **ppKmpHandle,int linkType,unsigned char *cfgFilePath);

    int KMP_Finalize(void ** ppKmpHandle);

    //-----------------------------------------------------------------------------
    //ժҪ��������
    int KMP_MsgDigest(void *pKmpHandle,int algoType,unsigned char *msg,int msgLen,
        unsigned char *digest,int	*digestLen);

    int KMP_MsgDigest_Ex(void *pKmpHandle,int algoType,unsigned char *msg,int msgLen,
        unsigned char *digest,int	*digestLen);
    //-----------------------------------------------------------------------------

    //��������ɺ�������
    int KMP_GenRandom(void	*pKmpHandle,int randomLen,unsigned char *random);

    //----------------------------------------------------------------------------------
    //RSA�ǶԳ���Կ������ϵ

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
    //SM2�ǶԳ���Կ������ϵ

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
    //�Գ���Կ������ϵ

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
        unsigned char  *userAccount,//�û��˺�
        int 			userAccountLen,
        unsigned char  *date,//��������
        int 			dateLen,
        unsigned char  *printNo,//ӡˢ��
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
                      unsigned char  *userAccount,//�û��˺�
                      int            userAccountLen,
                      unsigned char  *date,//��������
                      int            dateLen,
                      unsigned char  *printNo,//ӡˢ��
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
