#include <syslog.h>
#include <ctype.h>

#include "nd_restapi_func.h"
#include <time.h>
#include <assert.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
// #include <openssl/core_names.h>
#include <curl/curl.h>
#include <stdbool.h>
#include <locale.h>
#include <iconv.h>

#include "../common.h"
#include "nd_utils.h"
#include "nd_nix_logs.h"

// 기존 strdup 호출을 my_strdup으로 재정의
#define strdup(s) nd_strdup(s)

/*
        //
*/
void MakeRdmURL(const char *ip, int port, char *rdmURL, size_t rdmURLSize, int httpsUse)
{

        // Buffer declaration for creating a URL
        char url[1024]; // Set the buffer to an appropriate size (adjust the size if necessary)
        httpsUse = 1;
        // Determine whether to use HTTP or HTTPS
        if (httpsUse == 0)
        {
                snprintf(url, sizeof(url), "http://%s:%d%s", ip, port, STRING_RANDOM_KEY_URI);
        }
        else
        {
                snprintf(url, sizeof(url), "https://%s:%d%s", ip, port, STRING_RANDOM_KEY_URI);
        }

        // Copy the generated URL to rdmURL
        strncpy(rdmURL, url, rdmURLSize - 1);
        rdmURL[rdmURLSize - 1] = '\0'; // Add a null termination character at the end

        /**/
        nd_log(NDLOG_DBG, "Generating Random Key Request URL: %s", rdmURL);
}

/*
        //
*/
void MakeLoginURL(const char *ip, int port, char *loginURL, size_t loginURLSize, int httpsUse)
{

        // Buffer declaration for creating a URL
        char url[1024]; // Set the buffer to an appropriate size (adjust the size if necessary)

        // Determine whether to use HTTP or HTTPS
        if (httpsUse == 0)
        {
                snprintf(url, sizeof(url), "http://%s:%d%s", ip, port, STRING_LOGIN_URI);
        }
        else
        {
                snprintf(url, sizeof(url), "https://%s:%d%s", ip, port, STRING_LOGIN_URI);
        }

        // Copy the generated URL to rdmURL
        strncpy(loginURL, url, loginURLSize - 1);
        loginURL[loginURLSize - 1] = '\0'; // Add a null termination character at the end

        /**/
        nd_log(NDLOG_DBG, "Generating HIWARE login Request URL: %s", loginURL);
}

void MakeUserLoginURL(const char *ip, int port, char *loginURL, size_t loginURLSize, int httpsUse)
{

        char url[1024];

        if (httpsUse == 0)
        {
                snprintf(url, sizeof(url), "http://%s:%d%s", ip, port, STRING_USERLOGIN_URI);
        }
        else
        {
                snprintf(url, sizeof(url), "https://%s:%d%s", ip, port, STRING_USERLOGIN_URI);
        }

        // Copy the generated URL to rdmURL
        strncpy(loginURL, url, loginURLSize - 1);
        loginURL[loginURLSize - 1] = '\0'; // Add a null termination character at the end

        /**/
        nd_log(NDLOG_DBG, "Generating HIWARE User login Request URL: %s", loginURL);
}

void MakeTwofactOtpLoginURL(const char *ip, int port, char *loginURL, size_t loginURLSize, int httpsUse)
{

        char url[1024];

        if (httpsUse == 0)
        {
                snprintf(url, sizeof(url), "http://%s:%d%s", ip, port, STRING_TWOFACT_OTP_URI);
        }
        else
        {
                snprintf(url, sizeof(url), "https://%s:%d%s", ip, port, STRING_TWOFACT_OTP_URI);
        }

        // Copy the generated URL to rdmURL
        strncpy(loginURL, url, loginURLSize - 1);
        loginURL[loginURLSize - 1] = '\0'; // Add a null termination character at the end

        /**/
        nd_log(NDLOG_DBG, "Generating HIWARE Twofact login Request URL: %s", loginURL);
}

/*
        //"https://192.168.15.205:11200/hiware/api/v1/auth/randomKey";
*/
const char *GetRdmURL()
{

        char *auth_server_ip = get_value_from_inf(g_sConfFilePath, "SERVER_INFO", "AUTH_SERVER_IP");
        char *auth_server_port = get_value_from_inf(g_sConfFilePath, "SERVER_INFO", "AUTH_SERVER_PORT");

        MakeRdmURL((const char *)auth_server_ip, atoi(auth_server_port), g_sDataRandomUrl, sizeof(g_sDataRandomUrl), (strcmp(CONF_VALUE_YES, CONF_VALUE_YES) ? 1 : 0));

        if (strlen(g_sDataRandomUrl) <= 0)
                return NULL;

        /**/
        nd_log(NDLOG_DBG, "Retrieve Stored Random Key Request URL: %s", g_sDataRandomUrl);

        return g_sDataRandomUrl;
}

/*
        //https://127.0.0.1:11200/hiware/api/v1/auth/pam/login
*/
const char *GetUserLoginURL()
{

        if (strlen(g_sDataUserLoginUrl) <= 0)
        {
                char *auth_server_ip = get_value_from_inf(g_sConfFilePath, "SERVER_INFO", "AUTH_SERVER_IP");
                char *auth_server_port = get_value_from_inf(g_sConfFilePath, "SERVER_INFO", "AUTH_SERVER_PORT");
                char *auth_server_usessl = CONF_VALUE_YES;

                MakeUserLoginURL((const char *)auth_server_ip, atoi(auth_server_port), g_sDataUserLoginUrl, sizeof(g_sDataUserLoginUrl), (strcmp(auth_server_usessl, CONF_VALUE_YES) ? 0 : 1));
        }

        /**/
        nd_log(NDLOG_DBG, "Retrieve Stored User Login Request URL: %s", g_sDataUserLoginUrl ? g_sDataUserLoginUrl : "null");

        if (strlen(g_sDataUserLoginUrl) <= 0)
                return NULL;

        return g_sDataUserLoginUrl;
}

/*
        //https://127.0.0.1:11200/hiware/api/v1/auth/pam/login
*/
const char *GetTwoFact_OtpURL()
{

        if (strlen(g_sDataTwoFactLoginIrl) <= 0)
        {
                char *auth_server_ip = get_value_from_inf(g_sConfFilePath, "SERVER_INFO", "AUTH_SERVER_IP");
                char *auth_server_port = get_value_from_inf(g_sConfFilePath, "SERVER_INFO", "AUTH_SERVER_PORT");
                char *auth_server_usessl = CONF_VALUE_YES;

                MakeTwofactOtpLoginURL((const char *)auth_server_ip, atoi(auth_server_port), g_sDataTwoFactLoginIrl, sizeof(g_sDataTwoFactLoginIrl), (strcmp(auth_server_usessl, CONF_VALUE_YES) ? 0 : 1));
        }

        /**/
        nd_log(NDLOG_DBG, "Retrieve Stored Twofact Login Request URL: %s", g_sDataTwoFactLoginIrl ? g_sDataTwoFactLoginIrl : "null");

        if (strlen(g_sDataTwoFactLoginIrl) <= 0)
                return NULL;

        return g_sDataTwoFactLoginIrl;
}

/*
        //
*/
void setIssueKey_to_struct(Worker *worker, const char *key)
{

        worker->issueKey = strdup(key);
}

/*
        //
*/
void setRandomKey_to_struct(Worker *worker, const char *key)
{

        worker->randomKey = strdup(key);
}

/*
        //
*/
const char *getSecretKey()
{

        return g_sDataSecretKey; // a function that returns the secret key
}

/*
        //
*/
void setSeretKey(char *secret_key)
{

        g_sDataSecretKey = strdup(secret_key);
}

/*
        //
*/
const char *getIssueKey()
{

        return g_sDataIssueKey;
}

/*
        //
*/
void setIssueKey(char *issue_key)
{

        g_sDataIssueKey = strdup(issue_key);
}

/*
        //
*/
const char *getRandomKey()
{
        return g_sDataRandomKey;
}

/*
        //
*/
void setRandomKey(char *rand_key)
{

        g_sDataRandomKey = strdup(rand_key);
}

/*
        //
*/
const char *getAuthKey()
{
        return g_sDataAuthKey;
}

/*
        //
*/
void setAuthKey(char *auth_key)
{

        g_sDataAuthKey = strdup(auth_key);
}

/*
        //
*/
const char *getUserNumber()
{
        return g_sUserNumber;
}

void setUserLoginResult(char *loginResult)
{
        g_sDataUserLoginResult = strdup(loginResult);
}

const char *getUserLoginResult()
{
        return g_sDataUserLoginResult;
}

void setTemporaryAccessKey(char *TempAccKey)
{
        g_sDataTemporaryAccessKey = strdup(TempAccKey);
}

const char *getTemporaryAccessKey()
{
        return g_sDataTemporaryAccessKey;
}

void setHiwareUserNumber(char *userNumber)
{
        g_sDataHiwareUserNumber = strdup(userNumber);
}

const char *getHiwareUserNumber()
{
        return g_sDataHiwareUserNumber;
}

/*
        //
*/
void setUserNumber(char *user_number)
{
        g_sUserNumber = strdup(user_number);
}

/*
        //
*/
char *base64UrlSafeEncode(const unsigned char *input, int length)
{

        BIO *bio, *b64;
        BUF_MEM *bufferPtr;

        b64 = BIO_new(BIO_f_base64());
        bio = BIO_new(BIO_s_mem());
        bio = BIO_push(b64, bio);
        BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); // Remove line breaks

        BIO_write(bio, input, length);
        BIO_flush(bio);
        BIO_get_mem_ptr(bio, &bufferPtr);
        BIO_set_close(bio, BIO_NOCLOSE);
        BIO_free_all(bio);

        // URL-safe conversion
        char *encoded = (char *)malloc(bufferPtr->length + 1);
        memcpy(encoded, bufferPtr->data, bufferPtr->length);
        encoded[bufferPtr->length] = '\0';

        // Replace '+' with '-' and '/' with '_'.
        for (int i = 0; i < bufferPtr->length; i++)
        {
                if (encoded[i] == '+')
                {

                        encoded[i] = '-';
                }
                else if (encoded[i] == '/')
                {

                        encoded[i] = '_';
                }
        }

        return encoded;
}

/*
        //
*/
char *base64_encode(const unsigned char *input, int length)
{

        BIO *bio, *b64;
        BUF_MEM *bufferPtr;

        b64 = BIO_new(BIO_f_base64());
        bio = BIO_new(BIO_s_mem());
        bio = BIO_push(b64, bio);
        BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); // No new line

        BIO_write(bio, input, length);
        BIO_flush(bio);
        BIO_get_mem_ptr(bio, &bufferPtr);
        BIO_set_close(bio, BIO_NOCLOSE);
        BIO_free_all(bio);

        char *output = (char *)malloc(bufferPtr->length + 1);
        memcpy(output, bufferPtr->data, bufferPtr->length);
        output[bufferPtr->length] = '\0'; // Null-terminate the string

        return output;
}

/*
        //
*/
char *encPassword(const char *p_sStr, const char *p_sKey)
{

        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        assert(ctx != NULL);

        unsigned char key[16];      // AES-128 key size
        unsigned char iv[16] = {0}; // Initialization vector (IV)
        memcpy(key, p_sKey, 16);    // Assuming p_sKey is at least 16 bytes

        // Prepare the plaintext
        size_t plain_len = strlen(p_sStr);
        unsigned char *encrypted = (unsigned char *)malloc(plain_len + EVP_MAX_BLOCK_LENGTH);
        int len;
        int ciphertext_len;

        // Initialize the encryption operation
        EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);

        // Provide the message to be encrypted, and obtain the encrypted output
        EVP_EncryptUpdate(ctx, encrypted, &len, (unsigned char *)p_sStr, plain_len);
        ciphertext_len = len;

        // Finalize the encryption
        EVP_EncryptFinal_ex(ctx, encrypted + len, &len);
        ciphertext_len += len;

        // Base64 encode the encrypted data
        char *sData = base64_encode(encrypted, ciphertext_len);

        // Clean up
        free(encrypted);
        EVP_CIPHER_CTX_free(ctx);

        return sData;
}

/*
        //
*/
char *GetSignature(const char *sMethod, const char *url, const char *sData)
{

        const char *secretKey = getSecretKey();
        if (secretKey == NULL || strlen(secretKey) == 0)
        {
                /**/
                nd_log(NDLOG_ERR, "GetSignature::secretKey is null.");
                return NULL;
        }

        // sSrcData 생성
        size_t srcDataSize = strlen(sMethod) + strlen(url) + strlen(sData) + 3; // 3 is a space and a null character.
        char *sSrcData = (char *)malloc(srcDataSize);
        snprintf(sSrcData, srcDataSize, "%s %s%s", sMethod, url, sData);

        // Remove line breaks
        char *newlinePos;
        while ((newlinePos = strchr(sSrcData, '\n')) != NULL)
        {
                *newlinePos = '\0'; // Remove line breaks
        }

        unsigned char sHash[EVP_MAX_MD_SIZE];
        unsigned int len;

        // HMAC calc
        HMAC(EVP_sha256(), secretKey, strlen(secretKey), (unsigned char *)sSrcData, strlen(sSrcData), sHash, &len);
        // Encode hash data to Base64 URL-safe
        char *sEncodeData_new = base64UrlSafeEncode(sHash, len);

        free(sSrcData);
        return sEncodeData_new; // The caller must free the memory
}

/*
        // callback function to store response data
*/
size_t callback_write_memory(void *ptr, size_t size, size_t nmemb, ApiHttpRes *res)
{

	if (!res)
	{
		nd_log(LOG_ERR, "callback_write_memory: res is NULL, skipping write.");
		return 0; // Segfault 방지
	}

	if (!ptr)
	{
		nd_log(LOG_ERR, "callback_write_memory: ptr is NULL, skipping write.");
		return 0;
	}

	size_t realsize = size * nmemb;

	// 메모리 재할당 전, NULL 포인터 체크
	void *new_mem = realloc(res->m_data, res->size + realsize + 1);
	if (!new_mem)
	{
		nd_log(LOG_ERR, "realloc failed: memory alloc failed ...");
		return 0;
	}

	res->m_data = (char *)new_mem;
	memcpy(&(res->m_data[res->size]), ptr, realsize);
	res->size += realsize;
	res->m_data[res->size] = '\0'; // end of string

	return realsize;

#ifdef _OLD_SRC_

        size_t realsize = size * nmemb;
        res->m_data = realloc(res->m_data, res->size + realsize + 1);
        if (res->m_data == NULL)
        {
                // memory alloc fail

                //
                ///
                nd_log(LOG_ERR, "realloc failed . memory alloc failed ...");
                return 0;
        }
        memcpy(&(res->m_data[res->size]), ptr, realsize);
        res->size += realsize;
        res->m_data[res->size] = '\0'; // end of string

        return realsize;
#endif 
}

/*
        // login ID , login PW
*/
int getRandomKey_Request(Worker *worker)
{
        ApiHttpRes httpRes;

	nd_log(NDLOG_TRC, "SendGetDataWithDefaults ...");
        SendGetDataWithDefaults(&httpRes, GetRdmURL());

        if (httpRes.m_data == NULL)
        {
                /**/
                nd_log(NDLOG_ERR, "[HIW-AGT-PAM-NERR-000002] No response value for Random key request.");

                return -1;
        }

        nd_log(NDLOG_TRC, "Response value for Random Key request: %s", httpRes.m_data);

        int result = parse_JsonResponse_from_ramdom_request(httpRes.m_data, worker);
        if (result == RET_SUCCESS)
        {
                /**/
                nd_log(NDLOG_TRC, "# Issue Key: %s", worker->issueKey);
                nd_log(NDLOG_TRC, "# Random Key: %s", worker->randomKey);

                setIssueKey(worker->issueKey);
                setRandomKey(worker->randomKey);
        }
        else
        {
                /**/
                nd_log(NDLOG_ERR, "parse_JsonResponse_from_ramdom_request failed.., Error occurred while parsing JSON.");
                return -1;
        }

        return 0;
}

/*
        //
*/
int SendGetData(ApiHttpRes *pRes, const char *url, const char *sSessID, const char *sSignature, const char *authKey, int iHttpsUse)
{
        CURL *curl;
        CURLcode res;
        struct curl_slist *slist = NULL;
        int bResult = 1; // Flag Indicating Success

        pRes->m_data = NULL; // initialize
        pRes->size = 0;


        curl = curl_easy_init();
        if (!curl)
        {
             nd_log (NDLOG_ERR,"cURL initialization failed!");
        }	

        if (curl)
        {
                if (iHttpsUse == 1)
                {

                        slist = curl_slist_append(slist, STRING_CURL_HEADER_USER_AGENT); /* "User-Agent: hi-dev-checker" */

                        if (authKey && strlen(authKey) > 0)
                        {
                                char strAuth[256];
                                snprintf(strAuth, sizeof(strAuth), STRING_CURL_HEADER_API_TOKEN, authKey); /* "API-Token: %s" */
                                slist = curl_slist_append(slist, strAuth);
                        }

                        if (sSignature && strlen(sSignature) > 0)
                        {
                                char sTemp[256];
                                snprintf(sTemp, sizeof(sTemp), STRING_CURL_HEADER_SIGNATURE, sSignature); /*"Signature: %s"*/
                                slist = curl_slist_append(slist, sTemp);
                        }

                        if (sSessID && strlen(sSessID) > 0)
                        {
                                char sTemp[256];
                                snprintf(sTemp, sizeof(sTemp), STRING_CURL_HEADER_HANDSHAKE_SID, sSessID); /*"Handshake-Session-Id: %s"*/
                                slist = curl_slist_append(slist, sTemp);
                        }

                        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, slist);
                        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
                        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
                }
                else
                {

                        slist = curl_slist_append(slist, "Accept: */*");
                        slist = curl_slist_append(slist, "charset: utf-8");
                        slist = curl_slist_append(slist, STRING_CURL_HEADER_USER_AGENT); /*"User-Agent: hi-dev-checker"*/

                        if (authKey && strlen(authKey) > 0)
                        {
                                char strAuth[256];
                                snprintf(strAuth, sizeof(strAuth), STRING_CURL_HEADER_API_TOKEN, authKey); /*"API-Token: %s"*/
                                slist = curl_slist_append(slist, strAuth);
                        }

                        if (sSignature && strlen(sSignature) > 0)
                        {
                                char sTemp[256];
                                snprintf(sTemp, sizeof(sTemp), STRING_CURL_HEADER_SIGNATURE, sSignature); /*"Signature: %s"*/
                                slist = curl_slist_append(slist, sTemp);
                        }

                        if (sSessID && strlen(sSessID) > 0)
                        {
                                char sTemp[256];
                                snprintf(sTemp, sizeof(sTemp), STRING_CURL_HEADER_HANDSHAKE_SID, sSessID); /*"Handshake-Session-Id: %s"*/
                                slist = curl_slist_append(slist, sTemp);
                        }

                        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, slist);
                        curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
                        curl_easy_setopt(curl, CURLOPT_HEADER, 0);
                }

                curl_easy_setopt(curl, CURLOPT_URL, url);
                curl_easy_setopt(curl, CURLOPT_WRITEDATA, pRes);
                curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, callback_write_memory);
                curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
                curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
                curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
                curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);


                res = curl_easy_perform(curl);
                if (res != CURLE_OK)
                {
                        /**/
                        nd_log(NDLOG_ERR, "CURL request failed: %s (Error code: %d)", curl_easy_strerror(res), res);

                        bResult = 0; // 실패
                }
                else
                {

                        if (pRes->size <= 0)
                        {

                                /**/
                                nd_log(NDLOG_ERR, "CURL request succeeded but no response message found.");

                                bResult = 0; // failed
                        }
                }

                curl_slist_free_all(slist);
                curl_easy_cleanup(curl);
        }
        else
        {

                bResult = 0; // CURL Initialization Failed
        }

        return bResult;
}

/*
        //
*/
bool SendPostData(const char *p_sContents, ApiHttpRes *pRes, const char *url, const char *sSignature, const char *sSessID, const char *authKey, int iHttpsUse)
{
        bool bResult = true;
        CURL *curl;
        CURLcode res;

        curl_global_init(CURL_GLOBAL_DEFAULT);
        curl = curl_easy_init();
        if (curl)
        {
                struct curl_slist *slist = NULL;

                // setting HTTP header
                if (iHttpsUse == 1)
                {
                        slist = curl_slist_append(slist, STRING_CURL_HEADER_CONTENT_TYPE); /*"Content-Type: application/json"*/
                        slist = curl_slist_append(slist, STRING_CURL_HEADER_USER_AGENT);   /*"User-Agent: hi-dev-checker"*/

                        if (authKey && strlen(authKey) > 0)
                        {
                                char strAuth[256];
                                snprintf(strAuth, sizeof(strAuth), STRING_CURL_HEADER_API_TOKEN, authKey); /*"API-Token: %s"*/
                                slist = curl_slist_append(slist, strAuth);
                        }

                        if (sSignature && strlen(sSignature) > 0)
                        {
                                char sTemp[256];
                                snprintf(sTemp, sizeof(sTemp), STRING_CURL_HEADER_SIGNATURE, sSignature); /*"Signature: %s"*/
                                slist = curl_slist_append(slist, sTemp);
                        }

                        if (sSessID && strlen(sSessID) > 0)
                        {
                                char sTemp[256];
                                snprintf(sTemp, sizeof(sTemp), STRING_CURL_HEADER_HANDSHAKE_SID, sSessID); /*"Handshake-Session-Id: %s*"*/
                                slist = curl_slist_append(slist, sTemp);
                        }

                        struct curl_slist *current = slist;
                        while (current)
                        {

                                current = current->next;
                        }

                        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, slist);
                        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
                        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
                }
                else
                {
                        slist = curl_slist_append(slist, "Accept: */*");
                        slist = curl_slist_append(slist, STRING_CURL_HEADER_CONTENT_TYPE); /*"Content-Type: application/json"*/
                        slist = curl_slist_append(slist, "charset: utf-8");

                        if (authKey && strlen(authKey) > 0)
                        {
                                char strAuth[256];
                                snprintf(strAuth, sizeof(strAuth), "API-Token: %s", authKey);
                                slist = curl_slist_append(slist, strAuth);
                        }

                        if (sSignature && strlen(sSignature) > 0)
                        {
                                char sTemp[256];
                                snprintf(sTemp, sizeof(sTemp), STRING_CURL_HEADER_SIGNATURE, sSignature); /*"Signature: %s"*/
                                slist = curl_slist_append(slist, sTemp);
                        }

                        if (sSessID && strlen(sSessID) > 0)
                        {
                                char sTemp[256];
                                snprintf(sTemp, sizeof(sTemp), STRING_CURL_HEADER_HANDSHAKE_SID, sSessID); /*"Handshake-Session-Id: %s"*/
                                slist = curl_slist_append(slist, sTemp);
                        }

                        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, slist);
                        curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
                        curl_easy_setopt(curl, CURLOPT_HEADER, 0);
                }

                curl_easy_setopt(curl, CURLOPT_URL, url);
                curl_easy_setopt(curl, CURLOPT_POSTFIELDS, p_sContents);

                // Response Data Processing Settings
                pRes->m_data = malloc(1); // initialize
                pRes->m_data[0] = '\0';
                pRes->size = 0;
                curl_easy_setopt(curl, CURLOPT_WRITEDATA, pRes);
                curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, callback_write_memory);

                // time out setting
                curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
                curl_easy_setopt(curl, CURLOPT_POST, 1L);

                curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L); // disable certificate verification
                curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L); // disable host verification

                // Request Execution
                res = curl_easy_perform(curl);
                if (res != CURLE_OK)
                {
                        fprintf(stderr, "HTTP PERFORM ERROR: %s\n", curl_easy_strerror(res));

                        //
                        ///
                        nd_log(NDLOG_ERR, "CURL request failed: %s (Error code: %d)", curl_easy_strerror(res), res);

                        bResult = false;
                }
                else
                {
                        if (pRes->size <= 0)
                        {
                                fprintf(stderr, "HTTP RETURN Success, But Not Find Response Msg.\n");
                                bResult = false;

                                //
                                ///
                                nd_log(NDLOG_ERR, "CURL request succeeded but no response message found.");
                        }
                }

                // Always Organize
                curl_slist_free_all(slist);
                curl_easy_cleanup(curl);
        }
        else
        {

                bResult = false;
        }

        curl_global_cleanup();

        return bResult;
}

/*
        //
*/
int parse_JsonResponse_from_login_request(const char *res_doc, st_user_login_result *plogin_result)
{

        struct json_object *parsed_json = NULL, *resultCode = NULL, *content = NULL,
                           *userNumberItem = NULL, *bool_result = NULL, *temporaryAccessKey = NULL,
                           *errorCode = NULL, *ret_message = NULL, *hi_loginResult = NULL,
                           *userId = NULL, *userNumber = NULL, *currentStep = NULL, *numberOfSteps = NULL, *factors = NULL, *attributes = NULL,
                           *contentSimpleType = NULL;

        const char *userNumberStr = "";

        if (res_doc == NULL || plogin_result == NULL)
        {

                //
                ///
                nd_log(NDLOG_ERR, "Invalid input parameters.");
                return EXCEPTION;
        }

        parsed_json = json_tokener_parse(res_doc);
        if (parsed_json == NULL)
        {

                //
                ///
                nd_log(NDLOG_ERR, "Failed to parse JSON response.");
                return EXCEPTION;
        }

        nd_log(NDLOG_DBG, "Response data for HIWARE login request : %s", res_doc);

        // resultCode 추출
        if (!json_object_object_get_ex(parsed_json, "resultCode", &resultCode))
        {
                //
                ///
                nd_log(NDLOG_ERR, "Failed to extract the \'resultCode\' value from json.");

                json_object_put(parsed_json);
                return EXCEPTION;
        }

        int rCode = json_object_get_int(resultCode);
        plogin_result->resultCode = rCode;

        // too much information
        /*
        nd_log(NDLOG_DBG, "Extracting \'resultCode\' from JSON response data. | resultCode: %d", rCode);
        */

        if (!json_object_object_get_ex(parsed_json, "contentSimpleType", &contentSimpleType))
        {
                //
                ///
                nd_log(NDLOG_ERR, "Failed to extract the \'resultCode\' value from json.");

                json_object_put(parsed_json);
                return EXCEPTION;
        }

        // content 추출
        if (!json_object_object_get_ex(parsed_json, "content", &content))
        {

                //
                ///
                nd_log(NDLOG_ERR, "Failed to extract the \'content\' value from json.");

                json_object_put(parsed_json);
                return EXCEPTION;
        }
        const char *contentSimpleType_Str = json_object_get_string(contentSimpleType);

        nd_log(NDLOG_DBG, "Extracting \'contentSimpleType\' from JSON response data. | contentSimpleType_Str: %s", contentSimpleType_Str);

        if (rCode != 200 /* || (strcmp (PAM_JSON_KEY_VALUE_RET_SUCCESS, contentSimpleType_Str) != 0 ) */)
        {

                if (!json_object_object_get_ex(content, "errorCode", &errorCode))
                {
                        /**/
                        nd_log(NDLOG_WAN, "response status code is not 200.- Failed to extract the \'errorCode\' value from json.");
                        json_object_put(parsed_json);
                }

                const char *error_message = NULL;
                if (!json_object_object_get_ex(content, "message", &ret_message))
                {
                    // ERROR MSG
                }else
                {
                    error_message = json_object_get_string(ret_message);
                }
             

                const char *error_str = json_object_get_string(errorCode);

                nd_log(NDLOG_DBG, "Error code received from the authentication server. | errorCode: %s", error_str);

                // 05
                if ((strcmp(error_str, ERR_USER_ID_NOT_FOUND) == 0) ||
                    (strcmp(error_str, ERR_PASSWORD_ALGORITHM_NOT_FOUND) == 0) ||
                    (strcmp(error_str, ERR_USER_INFO_NOT_FOUND) == 0) ||
                    (strcmp(error_str, ERR_INVALID_CREDENTIALS) == 0))
                {

                        // 05
                        // PAM_SVR_FAIL_HI_AUTH_FAIL
                        snprintf(plogin_result->svrConnFailRsnCode, sizeof(plogin_result->svrConnFailRsnCode), PAM_SVR_FAIL_HI_AUTH_FAIL);

                        plogin_result->message = nd_strdup("HIWARE Account ID or password mismatch");
                }

                // 06
                else if ((strcmp(error_str, ERR_SECOND_AUTH_POLICY_NOT_FOUND) == 0) ||
                         (strcmp(error_str, ERR_SECOND_AUTH_STEP_NOT_FOUND) == 0) ||
                         (strcmp(error_str, ERR_INVALID_AUTH_PARAMETER) == 0) ||
                         (strcmp(error_str, ERR_NO_AVAILABLE_SECOND_AUTH) == 0) ||
                         (strcmp(error_str, ERR_ADMIN_SECOND_AUTH_INFO_NOT_FOUND) == 0) ||
                         (strcmp(error_str, ERR_ADMIN_SECOND_AUTH_POLICY_NOT_FOUND) == 0) ||
                         (strcmp(error_str, ERR_SECEND_AUTH_FAILED) == 0) ||
                         (strcmp(error_str, ERR_SECOND_AUTH_PROCESSING_ERROR) == 0))
                {
                        // 06
                        // PAM_SVR_FAIL_TF_AUTH_FAIL
                        snprintf(plogin_result->svrConnFailRsnCode, sizeof(plogin_result->svrConnFailRsnCode), PAM_SVR_FAIL_TF_AUTH_FAIL);

                        plogin_result->message = nd_strdup("Additional authentication failed");
                }

                // 09
                else if ((strcmp(error_str, ERR_ACCESS_TIME_DENIED) == 0) ||
                         (strcmp(error_str, ERR_ACCESS_PERIOD_DENIED) == 0)||
			 (strcmp(error_str, ERR_USER_NOT_AUTHORIZED) ==0))                {
                        // 09
                        // PAM_SVR_FAIL_UNAUTH_ACCES
                        snprintf(plogin_result->svrConnFailRsnCode, sizeof(plogin_result->svrConnFailRsnCode), PAM_SVR_FAIL_UNAUTH_ACCESS);

                        plogin_result->message = nd_strdup("Unauthorized access");
                }

                // 11
                else if (
                    (strcmp(error_str, ERR_DEVICE_NUMBER_NOT_FOUND) == 0) ||
                    (strcmp(error_str, ERR_ACCESS_PERIOD_POLICY_DB_ERROR) == 0) ||
                    (strcmp(error_str, ERR_ACCESS_DAY_POLICY_DB_ERROR) == 0) ||
                    (strcmp(error_str, ERR_SECOND_AUTH_INFO_DB_ERROR) == 0) ||
                    (strcmp(error_str, ERR_DEVICE_NUMBER_DB_ERROR) == 0) ||
                    (strcmp(error_str, ERR_INVALID_RANDOM_KEY) == 0) ||
                    (strcmp(error_str, ERR_CRYPTO_GENERATION_FAILED) == 0) ||
                    (strcmp(error_str, ERR_INVALID_RANDOM_KEY_IP) == 0) ||
                    (strcmp(error_str, ERR_NO_AVAILABLE_SECOND_AUTH) == 0) ||
                    (strcmp(error_str, ERR_ADMIN_SECOND_AUTH_POLICY_NOT_FOUND) == 0) ||
                    (strcmp(error_str, ERR_DEFAULT_POLICY_NOT_FOUND) == 0) ||
                    (strcmp(error_str, ERR_TEMP_AUTH_KEY_INVALID) == 0) ||
                    (strcmp(error_str, ERR_TEMP_AUTH_KEY_INVALID_IP) == 0) ||
                    (strcmp(error_str, ERR_INTERNAL_ERROR) == 0) ||
                    (strcmp(error_str, ERR_PASSWORD_DECRYPTION_FAILED) == 0) ||
                    (strcmp(error_str, ERR_LOGIN_POLICY_DB_ERROR) == 0) ||
                    (strcmp(error_str, ERR_PASSWORD_ENCRYPTION_FAILED) == 0) ||
                    (strcmp(error_str, ERR_USER_INFO_DB_QUERY_FAILED) == 0) ||
                    (strcmp(error_str, ERR_SECOND_AUTH_POLICY_DB_QUERY_FAILED) == 0) ||
                    (strcmp(error_str, ERR_ASSET_MANAGER_INFO_DB_ERROR) == 0))
                {

                        // 11
                        // PAM_SVR_FAIL_UNAUTHORIZED_CONNECT_FAIL
                        snprintf(plogin_result->svrConnFailRsnCode, sizeof(plogin_result->svrConnFailRsnCode), PAM_SVR_FAIL_UNAUTHORIZED_CONNECT_FAIL);

                        plogin_result->message = nd_strdup("An internal engine error has occurred");
                }

                // 13
                else if (
                    (strcmp(error_str, ERR_SECOND_AUTH_STEP_CONFIG_NOT_FOUND) == 0) ||
                    (strcmp(error_str, ERR_SECOND_AUTH_POLICY_NOT_FOUND_AGAIN) == 0))
                {

                        // 13
                        // PAM_SVR_FAIL_UNREG_OTP
                        snprintf(plogin_result->svrConnFailRsnCode, sizeof(plogin_result->svrConnFailRsnCode), PAM_SVR_FAIL_UNREG_OTP);

                        plogin_result->message = nd_strdup("Secondary authentication policy not found");
                }

                if (rCode == 401)
                {
                        if (json_object_object_get_ex(content, "attributes", &attributes))
                        {

                                if (json_object_object_get_ex(attributes, "userNumber", &userNumber))
                                {
                                        userNumberStr = json_object_get_string(userNumber);
                                }
                                snprintf(plogin_result->userNumber, sizeof(plogin_result->userNumber), "%s", userNumberStr);

                                nd_log(NDLOG_DBG, "Extracting \'userNumber\' from JSON response data. | userNumberStr: %s", userNumberStr);
                        }
                }

                if (plogin_result->message == NULL && error_message != NULL )
                {
                    plogin_result->message = nd_strdup(error_message);
                }

                //
                ///
                nd_log(NDLOG_ERR, "parse_JsonResponse_from_login_request  operation failed.- Error code: [---]");
                json_object_put(parsed_json);
                return EXCEPTION;
        }
        else if (rCode == 200 && strcmp(PAM_JSON_KEY_VALUE_RET_SUCCESS, contentSimpleType_Str) != 0)
        {
                if (strcmp(PAM_JSON_KEY_VALUE_RET_REQREG, contentSimpleType_Str) == 0)
                {
                        plogin_result->resultCode = rCode;
                        plogin_result->message = nd_strdup("The current HIWARE account has no OTP registered. Please register an OTP before use.");

                        snprintf(plogin_result->svrConnFailRsnCode, sizeof(plogin_result->svrConnFailRsnCode), "13");

                        // userNo
                        if (json_object_object_get_ex(content, "userNo", &userNumber))
                        {
                                userNumberStr = json_object_get_string(userNumber);
                        }
                        snprintf(plogin_result->userNumber, sizeof(plogin_result->userNumber), "%s", userNumberStr);

                        nd_log(NDLOG_DBG, "Extracting \'userNumber\' from JSON response data. | userNumberStr: %s", userNumberStr);

                        nd_log(NDLOG_ERR, "The current HIWARE account has no OTP registered. Please register an OTP before use.");
                        json_object_put(parsed_json);

                        return EXCEPTION;
                }
        }

        // Extract additional fields safely
        const char *loginResult = "";
        const char *userIdStr = "";
        const char *temporaryAccessKeyStr = "";
        const char *currentStepStr = "";
        const char *numberOfStepsStr = "";
        const char *certTpCodeStr = "";
        int numberStepsCnt = 0;

        if (json_object_object_get_ex(content, "loginResult", &hi_loginResult))
        {
                loginResult = json_object_get_string(hi_loginResult);
        }
        snprintf(plogin_result->loginResult, sizeof(plogin_result->loginResult), "%s", loginResult);

        nd_log(NDLOG_DBG, "Extracting \'loginResult\' from JSON response data. | loginResult: %s", loginResult);

        if (json_object_object_get_ex(content, "userId", &userId))
        {
                userIdStr = json_object_get_string(userId);
        }
        snprintf(plogin_result->userId, sizeof(plogin_result->userId), "%s", userIdStr);
        nd_log(NDLOG_DBG, "Extracting \'userId\' from JSON response data. | userId: %s", userIdStr);

        if (json_object_object_get_ex(content, "userNumber", &userNumber))
        {
                userNumberStr = json_object_get_string(userNumber);
        }
        snprintf(plogin_result->userNumber, sizeof(plogin_result->userNumber), "%s", userNumberStr);
        nd_log(NDLOG_DBG, "Extracting \'userNumber\' from JSON response data. | userNumber: %s", userNumberStr);

        if (json_object_object_get_ex(content, "currentStep", &currentStep))
        {
                currentStepStr = json_object_get_string(currentStep);
        }
        snprintf(plogin_result->certStepSeqNo, sizeof(plogin_result->certStepSeqNo), "%s", currentStepStr ? currentStepStr : "0");
        nd_log(NDLOG_DBG, "Extracting \'currentStep\' from JSON response data. | currentStep: %s", currentStepStr);

        if (json_object_object_get_ex(content, "numberOfSteps", &numberOfSteps))
        {
                numberStepsCnt = json_object_get_int(numberOfSteps);
        }

        snprintf(plogin_result->certTpCode, sizeof(plogin_result->certTpCode), "");

        if (numberStepsCnt > 0)
        {
                int nCurrentStepNm = atoi(currentStepStr);
                if (json_object_object_get_ex(content, "factors", &factors) &&
                    json_object_get_type(factors) == json_type_array)
                {
                        int array_len = json_object_array_length(factors);
                        const char *certTpCodeStr = "";

                        for (int i = 0; i < array_len; i++)
                        {
                                struct json_object *factor = json_object_array_get_idx(factors, i);
                                struct json_object *code = NULL;
                                if (numberStepsCnt == (i + 1))
                                {
                                        if (json_object_object_get_ex(factor, "code", &code))
                                        {
                                                certTpCodeStr = json_object_get_string(code);
                                                snprintf(plogin_result->certTpCode, sizeof(plogin_result->certTpCode), "%s", certTpCodeStr ? certTpCodeStr : "0");
                                        }
                                        else
                                                snprintf(plogin_result->certTpCode, sizeof(plogin_result->certTpCode), "");

                                        nd_log(NDLOG_DBG, "Extracting \'code\' from JSON response data. | code: %s", plogin_result->certTpCode);

                                        break;
                                }
                        }
                }
        }

        if (json_object_object_get_ex(content, "temporaryAccessKey", &temporaryAccessKey))
        {
                temporaryAccessKeyStr = json_object_get_string(temporaryAccessKey);
        }
        snprintf(plogin_result->temporaryAccessKey, sizeof(plogin_result->temporaryAccessKey), "%s", temporaryAccessKeyStr);

        nd_log(NDLOG_DBG, "Extracting \'temporaryAccessKey\' from JSON response data. | temporaryAccessKey: %s", plogin_result->temporaryAccessKey);

        // Handle boolean loginResult if temporaryAccessKey is empty
        if (strlen(plogin_result->temporaryAccessKey) == 0)
        {
                if (json_object_object_get_ex(content, "loginResult", &bool_result))
                {
                        snprintf(plogin_result->loginResult, sizeof(plogin_result->loginResult),
                                 "%s", json_object_get_boolean(bool_result) ? "true" : "false");

                        nd_log(NDLOG_DBG, "Extracting \'loginResult\' from JSON response data. | temporaryAccessKey: %s", plogin_result->loginResult);
                }
                else
                {

                        //
                        ///
                        nd_log(NDLOG_ERR, "[JSON] Key \'loginResult\' not found in JSON object.");
                        json_object_put(parsed_json);
                        return EXCEPTION;
                }
        }

        // free memory
        json_object_put(parsed_json);
        return 0;
}

char *int_to_str_and_dup(int value)
{
        char buffer[32]; // Temporary buffer to hold the string
        snprintf(buffer, sizeof(buffer), "%d", value);
        return strdup(buffer); // Duplicate the string
}

int parse_JsonResponse_from_twofact_otp_request(const char *res_doc, st_hiauth_twofact_login_result *plogin_result)
{

        struct json_object *parsed_json = NULL, *resultCode = NULL, *content = NULL, *bool_result = NULL,
                           *ret_message = NULL, *errorCode = NULL, *hi_loginResult = NULL,
                           *userId = NULL, *userNumber = NULL, *events = NULL, *attributes = NULL;

        const char *userNumberStr = "";

        if (res_doc == NULL || plogin_result == NULL)
        {

                //
                ///
                nd_log(NDLOG_ERR, "Invalid input parameters.");
                return EXCEPTION;
        }

        /**/
        nd_log(NDLOG_DBG, "Response data for HIWARE twofact login request : %s", res_doc);

        parsed_json = json_tokener_parse(res_doc);
        if (parsed_json == NULL)
        {

                /**/
                nd_log(NDLOG_ERR, "Failed to parse JSON string.");

                return EXCEPTION;
        }

        // resultCode 추출
        if (!json_object_object_get_ex(parsed_json, "resultCode", &resultCode))
        {

                /**/
                nd_log(NDLOG_ERR, "Failed to extract the \'resultCode\' value from json.");

                json_object_put(parsed_json);
                return EXCEPTION;
        }

        int rCode = json_object_get_int(resultCode);
        plogin_result->resultCode = rCode;

        // content 추출
        if (!json_object_object_get_ex(parsed_json, "content", &content))
        {

                //
                ///
                nd_log(NDLOG_ERR, "Failed to extract the \'content\' value from json.");

                json_object_put(parsed_json);
                return EXCEPTION;
        }

        nd_log(NDLOG_DBG, "Extracting \'resultCode\' from JSON response data. | resultCode: %d", rCode);

        if (rCode != 200)
        {

                const char *message_str = "";
                const char *error_str = "";
                if (json_object_object_get_ex(content, "message", &ret_message))
                {
                        message_str = json_object_get_string(ret_message);

                        nd_log(NDLOG_DBG, "Extracting \'message\' from JSON response data. | message: %d", message_str);
                }

                if (json_object_object_get_ex(content, "errorCode", &errorCode))
                {
                        error_str = json_object_get_string(errorCode);

                        nd_log(NDLOG_DBG, "Extracting \'errorCode\' from JSON response data. | errorCode: %s", error_str);
                }

                if (json_object_object_get_ex(content, "attributes", &attributes))
                {

                        if (json_object_object_get_ex(attributes, "userNumber", &userNumber))
                        {
                                userNumberStr = json_object_get_string(userNumber);
                        }
                        snprintf(plogin_result->userNumber, sizeof(plogin_result->userNumber), "%s", userNumberStr);

                        nd_log(NDLOG_DBG, "Extracting \'userNumber\' from JSON response data. | userNumber: %s", userNumberStr);
                }

                plogin_result->message = strdup(message_str);
                plogin_result->errorcode = strdup(error_str);
                json_object_put(parsed_json);

                //
                ///
                nd_log(NDLOG_ERR, "The two-factor authentication login attempt has failed - Error code: [%s]", plogin_result->errorcode);

                return EXCEPTION;
        }

        // Extract additional fields safely
        const char *loginResult = "";
        const char *userIdStr = "";
        // const char *userNumberStr = "";

        if (json_object_object_get_ex(content, "loginResult", &hi_loginResult))
        {
                loginResult = json_object_get_string(hi_loginResult);
        }
        snprintf(plogin_result->loginResult, sizeof(plogin_result->loginResult), "%s", loginResult);
        nd_log(NDLOG_DBG, "Extracting \'loginResult\' from JSON response data. | loginResult: %s", loginResult);

        if (json_object_object_get_ex(content, "userId", &userId))
        {
                userIdStr = json_object_get_string(userId);
        }
        snprintf(plogin_result->userId, sizeof(plogin_result->userId), "%s", userIdStr);
        nd_log(NDLOG_DBG, "Extracting \'userId\' from JSON response data. | userId: %s", userIdStr);

        if (json_object_object_get_ex(content, "userNumber", &userNumber))
        {
                userNumberStr = json_object_get_string(userNumber);
        }
        snprintf(plogin_result->userNumber, sizeof(plogin_result->userNumber), "%s", userNumberStr);
        nd_log(NDLOG_DBG, "Extracting \'userNumber\' from JSON response data. | userNumber: %s", userNumberStr);

        // Extract events array
        if (json_object_object_get_ex(content, "events", &events) &&
            json_object_get_type(events) == json_type_array)
        {
                int array_len = json_object_array_length(events);

                for (int i = 0; i < array_len; i++)
                {
                        struct json_object *event = json_object_array_get_idx(events, i);
                        struct json_object *stepNumber = NULL, *chosenFactor = NULL, *failover = NULL, *stateName = NULL, *code = NULL;

                        const char *certStepSeqNo = "";
                        const char *certAppTpCode = "";
                        const char *certSucesFailYn = "";
                        const char *certTpCode = "";

                        if (json_object_object_get_ex(event, "stepNumber", &stepNumber))
                        {
                                certStepSeqNo = json_object_get_string(stepNumber);
                        }
                        snprintf(plogin_result->certStepSeqNo, sizeof(plogin_result->certStepSeqNo), "%s", certStepSeqNo);
                        nd_log(NDLOG_DBG, "Extracting \'stepNumber\' from JSON response data. | stepNumber: %s", certStepSeqNo);

                        if (json_object_object_get_ex(event, "failover", &failover))
                        {
                                certAppTpCode = strcmp(json_object_get_string(failover), "false") == 0 ? "0" : "1";
                        }
                        snprintf(plogin_result->certAppTpCode, sizeof(plogin_result->certAppTpCode), "%s", certAppTpCode);
                        nd_log(NDLOG_DBG, "Extracting \'failover\' from JSON response data. | failover: %s", certAppTpCode);

                        if (json_object_object_get_ex(event, "stateName", &stateName))
                        {
                                certSucesFailYn = strcmp(json_object_get_string(stateName), "Succeed") == 0 ? "1" : "0";
                        }
                        snprintf(plogin_result->certSucesFailYn, sizeof(plogin_result->certSucesFailYn), "%s", certSucesFailYn);
                        nd_log(NDLOG_DBG, "Extracting \'stateName\' from JSON response data. | stateName: %s", certSucesFailYn);

                        if (json_object_object_get_ex(event, "chosenFactor", &chosenFactor) &&
                            json_object_object_get_ex(chosenFactor, "code", &code))
                        {
                                certTpCode = json_object_get_string(code);
                        }
                        snprintf(plogin_result->certTpCode, sizeof(plogin_result->certTpCode), "%s", certTpCode);
                        nd_log(NDLOG_DBG, "Extracting \'chosenFactor\' from JSON response data. | chosenFactor: %s", certTpCode);
                }
        }

        // free memory
        json_object_put(parsed_json);
        return 0;
}

/*
        //
*/
int parse_JsonResponse_from_ramdom_request(const char *json_str, Worker *worker)
{

        struct json_object *parsed_json;
        struct json_object *resultCode_obj;
        struct json_object *content_obj;
        struct json_object *issueKey_obj;
        struct json_object *randomKey_obj;

        // Parse the JSON response
        parsed_json = json_tokener_parse(json_str);
        if (parsed_json == NULL)
        {
                /**/
                nd_log(NDLOG_ERR, "Failed to parse json response.");

                return EXCEPTION;
        }

        // Get resultCode from the JSON
        if (!json_object_object_get_ex(parsed_json, "resultCode", &resultCode_obj))
        {
                /**/
                nd_log(NDLOG_ERR, "Failed to retrieve key 'resultCode' from parsed JSON object.");

                json_object_put(parsed_json);
                return EXCEPTION;
        }

        int resultCode = json_object_get_int(resultCode_obj);
        if (resultCode != 200)
        {
                json_object_put(parsed_json);

                /**/
                nd_log(NDLOG_ERR, "Request failed: resultCode = %d", resultCode);

                return EXCEPTION;
        }

        // Get content object
        if (!json_object_object_get_ex(parsed_json, "content", &content_obj))
        {

                /**/
                nd_log(NDLOG_ERR, "Failed to extract the \'content\' value from json.");

                json_object_put(parsed_json);
                return EXCEPTION;
        }

        // Get issueKey from the content object
        if (!json_object_object_get_ex(content_obj, "issueKey", &issueKey_obj))
        {
                /**/
                nd_log(NDLOG_ERR, "Cannot find issueKey in \'content\'object.");

                json_object_put(parsed_json);
                return EXCEPTION;
        }

        const char *issueKey = json_object_get_string(issueKey_obj);
        if (strcmp(issueKey, "NULL") == 0)
        {

                /**/
                nd_log(NDLOG_ERR, "Cannot get issueKey in \'content\'object.- issueKey is null");

                json_object_put(parsed_json);
                return EXCEPTION;
        }

        // Get randomKey from the content object
        if (!json_object_object_get_ex(content_obj, "randomKey", &randomKey_obj))
        {

                /**/
                nd_log(NDLOG_ERR, "Cannot find randomKey in \'content\'object.");
                json_object_put(parsed_json);
                return EXCEPTION;
        }

        const char *randomKey = json_object_get_string(randomKey_obj);
        if (strcmp(randomKey, "NULL") == 0)
        {

                /**/
                nd_log(NDLOG_ERR, "Cannot get randomKey in \'randomKey\'object.- randomKey is null");

                json_object_put(parsed_json);
                return EXCEPTION;
        }

        // Set issueKey and randomKey in the worker
        setIssueKey_to_struct(worker, issueKey);
        setRandomKey_to_struct(worker, randomKey);

        // Clean up
        json_object_put(parsed_json);
        return RET_SUCCESS;
}

/*
        //
*/
int requestOSAuthToApiServer(const char *username, const char *password, struct st_hiauth_os_login_result *result)
{
        return HI_AUTH_RET_SUCCEED;
}

/*
        //
*/
int requestHiwareAuthToApiServer(const char *username, const char *passwd, const char *agt_auth_no, const char *agent_id, struct st_hiauth_hiware_login_result *result)
{
        int retval = 0;
        Worker worker;
        ApiHttpRes response;
        // st_user_login_result *log_result = malloc (sizeof (st_user_login_result));
        st_user_login_result log_result = {
            .resultCode = 0, // 기본 값 설정
            .userId = "",
            .temporaryAccessKey = "",
            .loginResult = "",
            .userNumber = "",
            .certTpCode = "",
            .certAppTpCode = "",
            .certSucesFailYn = "",
            .certStepSeqNo = "",
            .svrConnFailRsnCode = "",
            .errorcode = NULL, // 포인터 NULL 초기화
            .message = NULL    // 포인터 NULL 초기화
        };

        memset(result, 0x00, sizeof(struct st_hiauth_hiware_login_result));

        response.m_data = malloc(1); // initialize
        response.m_data[0] = '\0';
        response.size = 0;

	nd_log (NDLOG_ERR, "requestHiwareAuthToApiServer...");

        if (username == NULL || passwd == NULL ||
            strlen(username) <= 0 || strlen(passwd) <= 0)
        {
                free(response.m_data);

                //
                ///
                nd_log(NDLOG_ERR, "input parameters are invalid.");
                return -1;
        }

	nd_log (NDLOG_ERR, "requestHiwareAuthToApiServer...getRandomKey_Request CALL");
        retval = getRandomKey_Request(&worker);
        if (retval != 0)
        {
                // free (response.m_data);

                //
                ///
                nd_log(NDLOG_ERR, "Random Key request failed.");

                return -1;
        }

        // GetUserLoginURL

	nd_log (NDLOG_ERR, "requestHiwareAuthToApiServer...encPassword CALL");
        char *encPwd = encPassword(passwd, worker.randomKey);

        // create JSON object
        struct json_object *root = json_object_new_object();
        if (!root)
        {
                free(encPwd);
                free(response.m_data);

                //
                ///
                nd_log(NDLOG_ERR, "Failed to create a new JSON object in \'json_object_new_object()\'.");

                return -1;
        }

        char local_ip[INET_ADDRSTRLEN];
        get_local_ip(local_ip, sizeof(local_ip));

        // add data to  JSON object
        json_object_object_add(root, "issueKey", json_object_new_string(worker.issueKey));
        json_object_object_add(root, "userId", json_object_new_string(username));
        json_object_object_add(root, "password", json_object_new_string(encPwd));
        json_object_object_add(root, "authorityId", json_object_new_string(agt_auth_no));
        json_object_object_add(root, "agentId", json_object_new_string(agent_id));
        json_object_object_add(root, "ipAddress", json_object_new_string(local_ip));

        // convert to JSON string
        const char *sData = json_object_to_json_string(root);
        // const char* sJsonData = json_object_to_json_string_ext(root, JSON_C_TO_STRING_PRETTY);
        nd_log(NDLOG_TRC, "sand auth data : [%s]", sData);
        if (sData == NULL)
        {

                //
                ///
                nd_log(NDLOG_ERR, "Failed to convert JSON object to string in \'json_object_to_json_string()\'.");

                json_object_put(root); // free memory
                free(encPwd);
                free(response.m_data);
                return -1; // except
        }

        retval = SendPostDataWithDefaults(sData, &response, GetUserLoginURL());
        if (retval && strlen(response.m_data) > 0)
        {

                retval = parse_JsonResponse_from_login_request(response.m_data, &log_result);
                if (retval != 0)
                {

                        //
                        ///
                        nd_log(NDLOG_ERR, "Failed to parse JSON response from login request in \'parse_JsonResponse_from_login_request()\'.");

                        result->ret = log_result.resultCode; // strdup (log_result.resultCode);
                        if (log_result.message)
                                result->message = strdup(log_result.message);

                        nd_log(NDLOG_ERR, "retcode %d/ error message:%s", result->ret, result->message);

                        snprintf(result->certStepSeqNo, sizeof(result->certStepSeqNo), "%s", log_result.certStepSeqNo);
                        snprintf(result->certTpCode, sizeof(result->certTpCode), "%s", log_result.certTpCode);
                        snprintf(result->svrConnFailRsnCode, sizeof(result->svrConnFailRsnCode), "%s", log_result.svrConnFailRsnCode);
                        snprintf(result->userNumber, sizeof(result->userNumber), "%s", log_result.userNumber);

                        setHiwareUserNumber(log_result.userNumber);
                        json_object_put(root);
                        free(encPwd);
                        free(response.m_data);
                        return -1;
                }

                result->ret = log_result.resultCode;
                if (log_result.message)
                                result->message = strdup(log_result.message);

                setUserLoginResult(log_result.loginResult);
                setTemporaryAccessKey(log_result.temporaryAccessKey);
                setHiwareUserNumber(log_result.userNumber);

                snprintf(result->certStepSeqNo, sizeof(result->certStepSeqNo), "%s", log_result.certStepSeqNo);
                snprintf(result->certTpCode, sizeof(result->certTpCode), "%s", log_result.certTpCode);
        }

        json_object_put(root);
        free(encPwd);
        free(response.m_data);

        return HI_AUTH_RET_SUCCEED;
}

/*
        //
*/
int requestTwoFactAuthToApiserver(const char *type, const char *temporaryAccessKey, const char *stepNumber, const char *authCode, const char *langCode, const char *agent_id, st_hiauth_twofact_login_result *result)
{
        int retval = 0;
        st_hiauth_twofact_login_result log_result;
        // Worker  worker;
        ApiHttpRes response;

        response.m_data = malloc(1); // initialize
        response.m_data[0] = '\0';
        response.size = 0;

        struct json_object *root = json_object_new_object();
        if (!root)
        {

                //
                ///
                nd_log(NDLOG_ERR, "Failed to create a new JSON object using \'json_object_new_object()\'.");

                free(response.m_data);
                return -1;
        }

        // add data to  JSON object
        json_object_object_add(root, "type", json_object_new_string(type));
        json_object_object_add(root, "temporaryAccessKey", json_object_new_string(temporaryAccessKey));
        json_object_object_add(root, "stepNumber", json_object_new_string(stepNumber));

        struct json_object *parameters = json_object_new_object();
        if (!parameters)
        {

                //
                ///
                nd_log(NDLOG_ERR, "Failed to create a new JSON object for \'parameters\' using \'json_object_new_object()\'.");

                json_object_put(root);
                free(response.m_data);
                return -1;
        }

        json_object_object_add(parameters, "authCode", json_object_new_string(authCode));
        json_object_object_add(parameters, "agentId", json_object_new_string(agent_id));

        // Add the "parameters" object to the root
        json_object_object_add(root, "parameters", parameters);

        // Add "langCode" to the root JSON object
        json_object_object_add(root, "langCode", json_object_new_string(langCode));

        // convert to JSON string
        const char *sData = json_object_to_json_string(root);
        if (sData == NULL)
        {

                //
                ///
                nd_log(NDLOG_ERR, "Failed to convert JSON object \'root\' to string - \'json_object_to_json_string()\' returned NULL.");

                json_object_put(root); // free memory
                free(response.m_data);
                return -1; // except
        }

        nd_log(NDLOG_TRC, "send OTP Request Data : %s", sData);

        retval = SendPostDataWithDefaults(sData, &response, GetTwoFact_OtpURL());
        if (retval && strlen(response.m_data) > 0)
        {

                retval = parse_JsonResponse_from_twofact_otp_request(response.m_data, &log_result);

                if (retval != 0)
                {

                        //
                        ///
                        nd_log(NDLOG_ERR, "Failed to parse JSON response from two-factor OTP request in \'parse_JsonResponse_from_twofact_otp_request()\' - Return value is non-zero.");

                        result->resultCode = log_result.resultCode; // strdup (log_result.resultCode);
                        result->message = strdup(log_result.message);
                        result->errorcode = strdup(log_result.errorcode);

                        nd_log(NDLOG_TRC, "log_result.certStepSeqNo:%s | log_result.certTpCode :%s", log_result.certStepSeqNo, log_result.certTpCode);

                        snprintf(result->certStepSeqNo, sizeof(result->certStepSeqNo), "%s", log_result.certStepSeqNo);
                        snprintf(result->certTpCode, sizeof(result->certTpCode), "%s", log_result.certTpCode);
                        setHiwareUserNumber(log_result.userNumber);

                        json_object_put(root);
                        free(response.m_data);
                        return -1;
                }

                result->resultCode = log_result.resultCode;
                setUserLoginResult(log_result.loginResult);
                setTemporaryAccessKey(log_result.temporaryAccessKey);
                setHiwareUserNumber(log_result.userNumber);

                snprintf(result->certTpCode, sizeof(result->certTpCode), "%s", log_result.certTpCode);
                snprintf(result->certAppTpCode, sizeof(result->certAppTpCode), "%s", log_result.certAppTpCode);
                snprintf(result->certSucesFailYn, sizeof(result->certSucesFailYn), "%s", log_result.certSucesFailYn);
                snprintf(result->certStepSeqNo, sizeof(result->certStepSeqNo), "%s", log_result.certStepSeqNo);
        }

        json_object_put(root);
        free(response.m_data);

        return HI_AUTH_RET_SUCCEED;
}

/*
        //st_hiauth_su_login_result
*/
int requestSuAuthToApiServer(const char *username, const char *password, struct st_hiauth_su_login_result *result)
{
        return HI_AUTH_RET_SUCCEED;
}

/*
        //
*/
int requestSuAccessPermissionsToApiServer(const char *current_user, const char *switch_user, struct st_hiauth_su_access_perm_result *result)
{
        return HI_AUTH_RET_SUCCEED;
}
