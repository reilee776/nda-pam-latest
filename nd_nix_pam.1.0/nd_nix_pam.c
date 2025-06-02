#define _POSIX_C_SOURCE 200809L
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <syslog.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <pwd.h>
#include <shadow.h>
#include <crypt.h>
#include "common.h"
#include <errno.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <pthread.h>
#include <sys/time.h>
#include <sys/file.h>
#include <uuid/uuid.h>
#include "./libsrc/nd_utils.h"
#include "./libsrc/nd_nix_logs.h"
#include "./libsrc/nd_restapi_func.h"
#include <json-c/json.h>
#include <curl/curl.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <dlfcn.h>

/*
////////////
*/
typedef RSA *(*RSA_NEW_FUNC)(void);
typedef BIGNUM *(*BN_NEW_FUNC)(void);
typedef int (*RSA_GEN_FUNC)(RSA *, int, BIGNUM *, void *);
typedef void (*RSA_FREE_FUNC)(RSA *);
typedef void (*BN_FREE_FUNC)(BIGNUM *);
typedef int (*PEM_WRITE_BIO_PRIV_FUNC)(BIO *, RSA *);

#define RSA_KEY_BITS 2048

#define _SUPP_DATE_

int g_nFailCnt = 0;
int g_nDataSshPort = 0;

char *g_sDataIssueKey;
char *g_sDataRandomKey;
char *g_sDataAuthKey;
char *g_sDataSecretKey;
char *g_sUserNumber;

char *g_sDataUserLoginResult;
char *g_sDataTemporaryAccessKey;
char *g_sDataHiwareUserNumber;

char g_sDataRandomUrl[MAX_URL_LEN];
char g_sDataUserLoginUrl[MAX_URL_LEN];
char g_sDataSystemLoginUrl[MAX_URL_LEN];
char g_sDataTwoFactLoginIrl[MAX_URL_LEN];

char *g_sDataProductNm;
char *g_sDataRootDir;
char *g_sConfFilePath;

char g_sDataAgentId[2];

pthread_mutex_t session_id_mutex;

/*
 */
#define PAM_HIWARE_SSH_SERVER_IP "HIWARE_SSH_CLIENT_IP"
#define PAM_HIWARE_SSH_SERVER_PORT "HIWARE_SSH_SERVER_PORT"
#define PAM_HIWARE_SSH_CLIENT_IP "HIWARE_SSH_CLIENT_IP"
#define PAM_HIWARE_SSH_CLIENT_PORT "HIWARE_SSH_CLIENT_PORT"

// nd_pam_sulog
#define nd_sulog(level, fmt, ...) nd_pam_sulog(level, __FILENAME__, __LINE__, fmt, ##__VA_ARGS__)

// 기존 strdup 호출을 my_strdup으로 재정의
#define strdup(s) nd_strdup(s)

char g_sAccount[256];
char g_szLoginUserOrgName[1024];
char g_szHiwareAccount[256];

#define ESC "\033"
#define MAX_ATTEMPTS 3

bool g_isLogin = false;

int authentication_failed = 0;

struct st_hiauth_item nd_hiauth_item[] = {
	{HIAUTH_ID, "HIWARE ID: "},
	{HIAUTH_PW, "HIWARE PW: "},
};

struct st_log_level nd_log_level[] = {
	{NDLOG_NON, "NONE"},
	{NDLOG_INF, "INF"},
	{NDLOG_WAN, "WAN"},
	{NDLOG_DBG, "DBG"},
	{NDLOG_TRC, "TRC"},
	{NDLOG_ERR, "ERR"},
};

struct st_sesslog_type nd_slog_type[] = {
	{NDSLOG_LOGIN, "NDLOGIN"},
	{NDSLOG_LOGOFF, "NDLOGOFF"},
};

/*
	//It is an optional parameter that is a function pointer used for cleaning up the data.
	//It is called when the PAM session ends.
*/
static void cleanup_func(pam_handle_t *pamh, void *data, int error_status)
{
	(void)pamh;			// Mark pamh as unused
	(void)error_status; // Mark error_status as unused

	free(data);
}

/*
	//Banner image displayed upon successful authentication.
*/
void print_nd_banner(void)
{
	printf("\n\n");
	printf("\x1b[31m     NNNN              NNNN  DDDDDDDDDDDDDDDDD                       \033[0m\n");
	printf("\x1b[32m     NNNN  NNNN        NNNN                  DDDDD   nn    nn  eeeeeee  tttttttt     a      nn    nn   ddddddd   \033[0m\n");
	printf("\x1b[33m     NNNN   NNNN       NNNN                  DDDDD   nnn   nn  ee          tt       aaa     nnn   nn   dd    dd  \033[0m\n");
	printf("\x1b[34m     NNNN    NNNN      NNNN                  DDDDD   nnnn  nn  ee          tt      aa aa    nnnn  nn   dd     dd \033[0m\n");
	printf("     NNNN     NNNN     NNNN                  DDDDD   nn nn nn  eeeeeee     tt     aa   aa   nn nn nn   dd     dd \033[0m\n");
	printf("     NNNN      NNNN    NNNN                  DDDDD   nn  nnnn  ee          tt    aaaaa  aa  nn  nnnn   dd     dd \n");
	printf("     NNNN       NNNN   NNNN                  DDDDD   nn   nnn  ee          tt    aaaaaa aa  nn   nnn   dd    dd  \n");
	printf("     NNNNNNNNN   NNNN  NNNN                  DDDDD   nn    nn  eeeeeee     tt    aa     aa  nn    nn   ddddddd   \n");
	printf("     NNNNNNNNNNN    NNNNNNN  DDDDDDDDDDDDDDDDDD                      \n");
	printf("     NNNN             NNNNN  DDDDDDDDDDDDDDD                 \n");

	printf("\n\n");
}

/*
	//Banner image displayed upon successful authentication. TEMP
*/
void print_nd_banner_type2(void)
{
	printf("\n\n");
	printf("::::::::::::::::::::::::::::::::::::::::::: #\tWelcome to the Secure Login System! \n");
	printf(":::::       ::::::::::             :::::::: \n");
	printf(":::::    :   :::::::::    :::::::   ::::::: #\tHello, and welcome to Netand's secure environment. \n");
	printf(":::::    ::    :::::::    :::::::::   ::::: #\tPlease be mindful of your security at all times as you access this system.  \n");
	printf(":::::    ::::   ::::::    ::::::::::   :::: #\tWe strive to maintain the highest levels of protection for your data and privacy. \n");
	printf(":::::    :::::   :::::    ::::::::::   :::: \n");
	printf(":::::    ::::::   ::::    ::::::::::   :::: \n");
	printf(":::::    :::::::   :::    ::::::::::   :::: \n");
	printf(":::::       .::::   ::    ::::::::::   :::: \n");
	printf(":::::         ::::        :::::::::   ::::: \n");
	printf(":::::           ::::      ::::::::   :::::: \n");
	printf(":::::    ::::::::::::               ::::::: \n");
	printf("::::::::::::::::::::::::::::::::::::::::::: \n");
	printf("\n\n");
}

/*
	//Welcome message displayed upon successful authentication.
*/
void print_nd_warnning_msg(void)
{
	printf("#\tWelcome to the Secure Login System!\n");
	printf("#\n");
	printf("#\tHello, and welcome to Netand's secure environment. \n");
	printf("#\tPlease be mindful of your security at all times as you access this system. \n");
	printf("#\tWe strive to maintain the highest levels of protection for your data and privacy.\n");
	printf("#\n");
	printf("#\tThis is a secure login system designed to protect your credentials and sensitive information. \n");
	printf("#\tUnauthorized access is strictly prohibited, and all activities are logged and monitored for your safety.\n");
	printf("#\tPlease ensure that you are accessing this system for authorized purposes only. \n");
	printf("#\tMisuse of this system could result in severe penalties, including suspension of access.\n");
	printf("#\n");
	printf("#\t\x1b[31m⚠️ Attention: Network security is our top priority. Any suspicious activity will be flagged and reported to the \033[0m\n#\t\x1b[31mappropriate authorities.\033[0m\n");
	printf("#\n");
	printf("#\tRemember, safeguarding your login credentials is your responsibility. Always keep them private and secure.\n");

	printf("#\tThank you for choosing Netand. Stay vigilant and proceed with caution. Secure your connection and have a \n#\tproductive session!\n\n");
}

/*
	//Function to retrieve the failure count stored locally.
*/
int read_fail_count(const char *username)
{

	FILE *file = fopen(COUNTER_FILE, "r");
	if (!file)
	{
		return 0;
	}

	char line[256];
	while (fgets(line, sizeof(line), file))
	{
		char user[256];
		int count;
		sscanf(line, "%s %d", user, &count);
		if (strcmp(user, username) == 0)
		{
			fclose(file);
			return count;
		}
	}
	fclose(file);
	return 0;
}

/*
	//Function to retrieve the failure count stored locally.
*/
void increment_fail_count(const char *username)
{

	FILE *file = fopen(COUNTER_FILE, "r+");
	if (!file)
	{
		return;
	}

	char line[256];
	int found = 0;
	int count = 0;

	while (fgets(line, sizeof(line), file))
	{
		char user[256];
		sscanf(line, "%s %d", user, &count);
		if (strcmp(user, username) == 0)
		{
			found = 1;
			count++;
			break;
		}
	}

	rewind(file);

	if (found)
	{
		fprintf(file, "%s %d\n", username, count);
	}
	else
	{
		fprintf(file, "%s %d\n", username, 1);
	}

	fclose(file);
}

/*
	//"Function to reset the authentication failure count.
*/
void reset_fail_count(const char *username)
{

	FILE *file = fopen(COUNTER_FILE, "r");
	if (!file)
	{
		return;
	}

	char temp_file[] = "/tmp/pam_fail_count.tmp";
	FILE *temp = fopen(temp_file, "w");
	char line[256];

	while (fgets(line, sizeof(line), file))
	{
		char user[256];
		int count;
		sscanf(line, "%s %d", user, &count);
		if (strcmp(user, username) != 0)
		{
			fprintf(temp, "%s %d\n", user, count);
		}
	}

	fclose(file);
	fclose(temp);

	rename(temp_file, COUNTER_FILE);
}

int read_pam_config(const char *filename, pam_config *config)
{

	FILE *file = fopen(filename, "r");
	if (file == NULL)
	{
		perror("Failed to open file");
		return -1; // 파일 열기 실패
	}

	char line[MAX_LINE_LENGTH];
	while (fgets(line, sizeof(line), file) != NULL)
	{
		// 줄 끝의 개행 문자 제거
		line[strcspn(line, "\n")] = 0;

		// Practice키-값 분리
		char *key = strtok(line, "=");
		char *value = strtok(NULL, "=");

		// PAM_MODE 설정
		if (key && value)
		{
			if (strcmp(key, "PAM_MODE") == 0)
			{
				strncpy(config->pam_mode, value, sizeof(config->pam_mode) - 1);
				config->pam_mode[sizeof(config->pam_mode) - 1] = '\0'; // null-terminate
			}
			else if (strcmp(key, "PAM_SU_CONTROL") == 0)
			{
				strncpy(config->pam_su_control, value, sizeof(config->pam_su_control) - 1);
				config->pam_su_control[sizeof(config->pam_su_control) - 1] = '\0'; // null-terminate
			}
		}
	}

	fclose(file);
	return 0; // 성공적으로 읽음
}

/*
	//
*/
void get_user_info(struct pam_user_info *user_info, pam_handle_t *pamh)
{

	char *crypted;
	const char *input_passwd;
	const char *current_user;
	const char *switch_user;
	struct st_hiauth_su_login_result su_login_ret;
	//struct st_hiauth_su_access_perm_result su_access_perm;
	bool bJumpPwd = false;
	bool bIsSuFailed = false;
	int retval = 0;

	const char *sDataHomeDir = pam_getenv(pamh, ENV_HIWARE_HOME);
	if (sDataHomeDir == NULL)
		sDataHomeDir = strdup(PRODUCT_NM);

	if (g_sConfFilePath == NULL)
		g_sConfFilePath = strdup(getPamConfFilePath(sDataHomeDir));

	nd_log(NDLOG_INF, "====================================================================");
	nd_log(NDLOG_INF, "[get pam session user information]");
	nd_log(NDLOG_INF, "--------------------------------------------------------------------");

	char *authsvr_emergency_act = get_value_from_inf(g_sConfFilePath, SECTION_NM_PAM_CONF, PAM_AUTHSVR_EMERGENCY_ACTION); // PAM_AUTHSVR_EMERGENCY_ACTION

	if (user_info == NULL || pamh == NULL)
	{

		nd_log(NDLOG_ERR, "The input parameter information of the function is not valid.");
		return;
	}

	/*
		// Retrieving the current service name from PAM (Pluggable Authentication Module).
		//service
	*/
	retval = pam_get_item(pamh, PAM_SERVICE, (const void **)&user_info->service);
	if (retval != PAM_SUCCESS && !user_info->service)
	{
		nd_log(LOG_LEVEL_ERR, "[PREFIX-ERR CODE] Failed to retrieve the service name related to the PAM session.");
	}

	nd_log(NDLOG_TRC, "\t- service name      :%s", user_info->service);

	if (strcmp(user_info->service, STR_SU) == 0 || strcmp(user_info->service, STR_SUL) == 0)
	{
		nd_log(NDLOG_TRC, "\t- session type      :su");
		if (pam_get_user(pamh, &switch_user, NULL) == PAM_SUCCESS && switch_user != NULL)
		{

			strncpy(user_info->switchusernname, switch_user ? switch_user : "unknown-user", sizeof(user_info->switchusernname) - 1);
			user_info->switchusernname[sizeof(user_info->switchusernname) - 1] = '\0';

			strncpy(user_info->switchuserActualNm, getenv(ND_HIWARE_ACTUALNM_KEY) ? getenv(ND_HIWARE_ACTUALNM_KEY) : "", sizeof(user_info->switchuserActualNm));
		}

		nd_log(NDLOG_TRC, "\t- switchusernname   :%s", user_info->switchusernname);

		/*
			// Reading the name of the currently logged-in user set in the environment variable.
		*/
		const char *envuser = NULL;
		current_user = getenv("USER");
		sprintf(user_info->username, envuser ? current_user : "unknow user");
		user_info->bNeedtoEnvUpdata = false;
		/*
				retval = requestSuAuthToApiServer(user_info->username, user_info->realpwd, &su_login_ret);
				if (retval !=  HI_AUTH_RET_SUCCEED)
				{
					user_info->switch_allow = PAM_SWITCH_DENY;
					user_info->login_status = 1;
					bIsSuFailed = true;
					return;
				}

				retval = requestSuAccessPermissionsToApiServer(user_info->username, user_info->switchusernname, &su_access_perm );
				if (retval == HI_AUTH_RET_SUCCEED)
				{
					user_info->bNeedtoEnvUpdata = true;
					user_info->switch_allow = PAM_SWITCH_ALLOW;
					user_info->login_status = 0;
					bJumpPwd = true;

					goto password_next;
				}
				else
				{
					if (strcmp (authsvr_emergency_act, SET_MODE_BYPASS) == 0 )
					{
						goto password_next;
					}

					user_info->switch_allow = PAM_SWITCH_DENY;
					user_info->login_status = 1;
					bIsSuFailed = true;
					return;
				}
		*/
	}
	else
	{
		if (pam_get_user(pamh, &current_user, NULL) == PAM_SUCCESS && current_user != NULL)
		{

			strncpy(user_info->username, current_user, sizeof(user_info->username) - 1);
			user_info->username[sizeof(user_info->username) - 1] = '\0';
		}

		nd_log(NDLOG_INF, "\t- current_user      :%s", user_info->username);
	}

	/*
		// Getting the user input password.
	*/
	retval = pam_get_authtok(pamh, PAM_AUTHTOK, &input_passwd, NULL);
	if (retval != PAM_SUCCESS)
	{

		nd_log(NDLOG_ERR, "[HIW-AGT-PAM-CONF-000001] failed to get user password...");
		return;
	}

	strncpy(user_info->realpwd, input_passwd, sizeof(user_info->realpwd));
password_next:

	/*
		//Determining the login type of the current session (distinguishing between console login and terminal login).
	*/
	user_info->isConsole = false;
	pam_get_item(pamh, PAM_TTY, (const void **)&user_info->tty);
	if (user_info->tty)
	{

		if (strncmp(user_info->tty, "tty", 3) == 0)
		{
			user_info->isConsole = true;
		}
	}

	nd_log(NDLOG_INF, "\t- is console        :%d", user_info->isConsole);

	/*
		//Receives a username and returns the corresponding user's password hash.
	*/
	user_info->encrypted_password = get_encrypted_password_from_shadow(current_user);
	if (!user_info->encrypted_password)
	{
		return;
	}

	nd_log(NDLOG_INF, "\t- user enc pwd      :%s", user_info->encrypted_password);

	/*
		//Calls the crypt function using the user input password (input_passwd) along with the user's password hash (user_info->encrypted_password).
	*/
	if (bJumpPwd == false)
	{
		crypted = crypt(input_passwd, user_info->encrypted_password);
		if (strcmp(crypted, user_info->encrypted_password) == 0)
		{

			user_info->login_status = 0;
		}
		else
		{

			user_info->login_status = 1;
		}
	}
	else
	{
		if (!bIsSuFailed)
			user_info->login_status = 0;
	}

	/*
		// Getting the UID and GID
	*/
	struct passwd *pw = getpwnam(user_info->username);
	if (pw != NULL)
	{

		user_info->uid = pw->pw_uid;
		user_info->gid = pw->pw_gid;
		strncpy(user_info->home_directory, pw->pw_dir, sizeof(user_info->home_directory) - 1);
		user_info->home_directory[sizeof(user_info->home_directory) - 1] = '\0';
		strncpy(user_info->shell, pw->pw_shell, sizeof(user_info->shell) - 1);
		user_info->shell[sizeof(user_info->shell) - 1] = '\0';
	}

	/*
		// Authentication Method (ex: password)
	*/
	strncpy(user_info->auth_method, "password", sizeof(user_info->auth_method) - 1);
	user_info->auth_method[sizeof(user_info->auth_method) - 1] = '\0';

	/*
		// The IP address cannot be retrieved directly in the PAM environment.
	*/
	if (user_info->isConsole == false)
	{
		retval = pam_get_item(pamh, PAM_RHOST, (const void **)&user_info->ip_address);
		if (retval != PAM_SUCCESS && !user_info->ip_address)
		{
			// need to log message
		}
	}

	/*
		// login time
	*/
	user_info->login_time = time(NULL);
	nd_log(NDLOG_INF, "\t- user login time   :%d", user_info->login_time);

	/*
		// session ID (ex: Generate UUID or Unique Session ID)
	*/
	strncpy(user_info->session_id, "session1234", sizeof(user_info->session_id) - 1);
	user_info->session_id[sizeof(user_info->session_id) - 1] = '\0';

	/*
		// Authentication Failure count (initial value)
	*/
	user_info->auth_fail_count = 0; // initial value

	/*
		// Additional Authentication Information
	*/
	strncpy(user_info->mfa_info, "none", sizeof(user_info->mfa_info) - 1);
	user_info->mfa_info[sizeof(user_info->mfa_info) - 1] = '\0';
}

int get_pam_data(pam_handle_t *pamh, const char *data_name, const void **data_out)
{

	if (pamh == NULL || data_name == NULL || data_out == NULL)
	{

		return PAM_BUF_ERR;
	}

	int retval = pam_get_data(pamh, data_name, data_out);
	if (retval != PAM_SUCCESS)
	{

		*data_out = NULL;
	}

	return retval;
}

/*
	//su control get  who commond output data
*/
pam_client_info get_su_master_info(pam_handle_t *pamh)
{
	const char *tty;
	// bool bFinded 	= false;
	bool found = false;
	int retval = 0;
	pam_client_info clientInfo;
	const char *ssh_connection = getenv("SSH_CONNECTION");

	strcpy(clientInfo.ip, NONE_STRING);
	strcpy(clientInfo.port, NONE_STRING);
	strcpy(clientInfo.tty, NONE_STRING);

	if (ssh_connection)
	{

		// SSH_CONNECTION format: "client_ip client_port server_ip server_port"
		char *token = strtok((char *)ssh_connection, " ");
		if (token != NULL)
		{

			strncpy(clientInfo.ip, token, INET_ADDRSTRLEN);
			clientInfo.ip[INET_ADDRSTRLEN - 1] = '\0'; // null-terminate
			token = strtok(NULL, " ");

			if (token != NULL)
			{
				strncpy(clientInfo.port, token, sizeof(clientInfo.port));
				clientInfo.port[sizeof(clientInfo.port) - 1] = '\0';
			}
		}
		found = true;
	}
	else
	{

		retval = pam_get_item(pamh, PAM_TTY, (const void **)&tty);
		if (retval == PAM_SUCCESS)
		{
			strncpy(clientInfo.tty, tty, sizeof(clientInfo.tty));
			clientInfo.tty[sizeof(clientInfo.tty) - 1] = '\0';

			FILE *fp = popen("who", "r");
			if (fp != NULL)
			{
				char buffer[256];
				while (fgets(buffer, sizeof(buffer), fp) != NULL)
				{
					strtok(buffer, " ");
					char *tty1 = strtok(NULL, " ");
					strtok(NULL, " ");
					strtok(NULL, " ");
					char *ip = strtok(NULL, " ");

					if (ip != NULL && ip[0] == '(')
					{
						ip++;
						char *end = strchr(ip, ')');
						if (end != NULL)
						{
							*end = '\0';
						}
					}

					if (strcmp(tty1, clientInfo.tty) == 0)
					{

						strncpy(clientInfo.ip, ip, INET_ADDRSTRLEN);
						clientInfo.ip[INET_ADDRSTRLEN - 1] = '\0';
						found = true;
						break;
					}
				}

				pclose(fp);
			}
		}
	}

	if (!found)
	{

		strcpy(clientInfo.ip, NONE_STRING);
		strcpy(clientInfo.port, NONE_STRING);
	}

	return clientInfo;
}

/*
	//
*/
struct st_hiauth_input_data *OperateHiAuth(pam_handle_t *pamh)
{
	int retval = 0, style = PAM_PROMPT_ECHO_ON;
	char *pHiAuthData = NULL;
	struct st_hiauth_input_data *input_data = malloc(sizeof(struct st_hiauth_input_data));

	if (input_data == NULL)
	{

		return NULL;
	}

	for (int i = 0; i < HIAUTH_MAX; i++)
	{
		if (nd_hiauth_item[i].index == HIAUTH_PW)
			style = PAM_PROMPT_ECHO_OFF;
		else
			style = PAM_PROMPT_ECHO_ON;

		retval = pam_prompt(pamh, style, &pHiAuthData, nd_hiauth_item[i].item);
		if (retval == PAM_SUCCESS && pHiAuthData)
		{

			if (nd_hiauth_item[i].index == HIAUTH_ID)
				snprintf(input_data->sHiAuthId, sizeof(input_data->sHiAuthId), pHiAuthData);
			else if (nd_hiauth_item[i].index == HIAUTH_PW)
				snprintf(input_data->sHiAuthPw, sizeof(input_data->sHiAuthPw), pHiAuthData);
			else
			{
			}
		}

		free(pHiAuthData);
	}

	return input_data;
}

/*
	//
*/
int check_session_type(pam_handle_t *pamh, const char *tty, const char *service)
{
	// Validate input arguments
	if (tty == NULL || service == NULL)
	{
		return -1;
	}

	const char *ruser = NULL; // Original user who initiated the session
	const char *current_tty = NULL;

	// Get the original user (RUSER)
	if (pamh != NULL)
	{
		if (pam_get_item(pamh, PAM_RUSER, (const void **)&ruser) != PAM_SUCCESS)
		{
			ruser = "unknown"; // Default to "unknown" if retrieval fails
		}

		// Get the current TTY (PAM_TTY)
		if (pam_get_item(pamh, PAM_TTY, (const void **)&current_tty) != PAM_SUCCESS)
		{
			current_tty = "unknown"; // Default to "unknown" if retrieval fails
		}
	}
	else
	{
	}

	/*
	// Log the retrieved information
	syslog(LOG_INFO, "Session check: TTY=%s, Service=%s, RUSER=%s",
		current_tty ? current_tty : "NULL",
		service,
		ruser ? ruser : "NULL");
	*/
	// Determine session type based on TTY
	if (strncmp(tty, "tty", 3) == 0)
	{
		return AUTH_PURPOS_CONSOLE; // Console login
	}
	else if (strncmp(tty, "/pts/", 5) == 0)
	{
		if (ruser && strcmp(ruser, "root") != 0)
		{
			return AUTH_PURPOS_SU; // User switching via su
		}
		return AUTH_PURPOS_TERMINAL; // Regular terminal login
	}

	// Determine session type based on service
	if (strcmp(service, "su") == 0 || strcmp(service, "sul") == 0)
	{
		return AUTH_PURPOS_SU;
	}

	// syslog(LOG_ERR, "[ERR] Unable to determine session type\n");
	return -1; // Default case
}

int nd_pam_authenticate_user(char *uuid_str, SessionInfo *user_info, pam_handle_t *pamh)
{
	int authsvr_port = 0;
	int retval = 0;
    	int remain_count = 3;
	unsigned int flags = 0;

	bool bRetPamPolicy = false, bRetSamPolicy = false, bHiwareAuthRet = false;

	struct _archive_log logItem, *logitem;

	char *hiwareTwoFactData = NULL;
	char sTwoFactString[128];
	char sDataEnv_var[MAX_ENV_STR_LEN];

	char *sam_env = NULL;
    	char *pam_env = NULL;

	memset(&logItem, 0x00, sizeof(struct _archive_log));

	sprintf(sTwoFactString, "OTP(One-Time Password): ");

	sprintf(logItem.pamCertDtlAuthCode, "%s", PAM_CERT_DTL_AUTH_OS);
	snprintf(logItem.svrConnRstTpCode, sizeof(logItem.svrConnRstTpCode), "%s", PAM_AUTH_SUCCESS);

	/**/
	nd_log(NDLOG_TRC, "Session started for %s from IP %s - Policy comparison function start", user_info->current_user);

	struct st_hiauth_input_data *hiauth_input_data;
	st_hiauth_twofact_login_result hi_twofact_ret;
	struct st_hiauth_hiware_login_result hi_hiwareauth_ret;

	memset(&hi_hiwareauth_ret, 0x00, sizeof(hi_hiwareauth_ret));

	struct _msg_header_ header = {
		.iMsgVer = 0,
		.iMsgTotalSize = 0};

	header.iMsgType = 0;
	header.iMsgCode = 0;

	const char *sDataHomeDir = pam_getenv(pamh, ENV_HIWARE_HOME);
	if (sDataHomeDir == NULL)
		sDataHomeDir = strdup(PRODUCT_NM);

	if (g_sConfFilePath == NULL)
		g_sConfFilePath = strdup(getPamConfFilePath(sDataHomeDir));

	/**/
	nd_log(NDLOG_DBG, "Collection of operationg environment information | Home Dir: %s | Config File Path: %s", sDataHomeDir, g_sConfFilePath);

	if (validate_json_exceptionConnection(getPamRuleFilePath(sDataHomeDir), user_info->remote_host) == 1)
	{
		/**/
		nd_log(NDLOG_DBG, "The current session complies with the exception access settings. | Remote Host: %s | Result = 1", user_info->remote_host);
		return PAM_SUCCESS;
	}

	int pam_opermode = is_pam_oper_mode(sDataHomeDir);
	int sam_opermode = is_sam_oper_mode(sDataHomeDir);

	nd_log(NDLOG_DBG, "Get Operation mode | pam_opermode = %d", pam_opermode);

	/*
		// Retrieve the server connection information from the configuration file.
	*/
	char *auth_server_ip = get_value_from_inf(g_sConfFilePath, "SERVER_INFO", "AUTH_SERVER_IP");
	char *auth_server_port = get_value_from_inf(g_sConfFilePath, "SERVER_INFO", "AUTH_SERVER_PORT");
	char *authsvr_emergency_act = get_value_from_inf(g_sConfFilePath, "AGENT_INFO", "AUTH_EMERGENCY_BYPASS_ON");

	/**/
	nd_log(NDLOG_DBG, "====================================================================");
	nd_log(NDLOG_DBG, "[Reading Configuration Information]");
	nd_log(NDLOG_DBG, "Auth Server IP           : [%s]", auth_server_ip);
	nd_log(NDLOG_DBG, "Auth Server Port         : [%s]", auth_server_port);
	nd_log(NDLOG_DBG, "Emergency Action         : [%s]", authsvr_emergency_act);
	nd_log(NDLOG_DBG, "--------------------------------------------------------------------");

	/*
		// convert server port
	*/
	authsvr_port = auth_server_port ? atoi(auth_server_port) : PAM_HIAUTH_DEFAULT_PORT;

	/**/
	nd_log(NDLOG_TRC, "Checking connection to the API server.- server ip:[%s], server port:[%d]", auth_server_ip, authsvr_port);

	int pam_pri_no, pam_action, pam_logging, sam_pri_no, sam_action, sam_logging;
	char *agt_auth_no, *ndshell_agtAuthNo;
	char *agent_id = get_value_as_string(getPamRuleFilePath(sDataHomeDir), "agtNo");

	if (agent_id == NULL)
		retval = PAM_AUTH_ERR;

	/**/
	nd_log(NDLOG_DBG, "Retrieving the AgtNo value from the policy file. | agent_id: %s | retval: %d", agent_id, retval);

	snprintf(logItem.agtNo, sizeof(logItem.agtNo), "%s", agent_id);

	/*
		// server connect check
	*/
	bool bisAlive_server = check_server_connection(auth_server_ip, authsvr_port);
	if (bisAlive_server != true)
	{
		for (int i = 0; i < 3; i++)
		{
			/**/
			nd_log(NDLOG_DBG, "check_server_connection :: retry cnt (%d/3)", i);
			bisAlive_server = check_server_connection(auth_server_ip, authsvr_port);
			if (bisAlive_server)
			{
				sleep(3);
				break;
			}
		}
	}

	/**/
	nd_log(NDLOG_TRC, "Conducting communication checks with the authentication server. | bisAlive_server: %d ", bisAlive_server);

	/**/
	nd_log(NDLOG_DBG, "API server connection check result %d | authsvr_emergency_act = %s", bisAlive_server, authsvr_emergency_act);

	/*
		// Exception Handling Based on Configuration Settings
	*/
	if (bisAlive_server != true)
	{
		bool isBypass = false;

		if (strcmp(authsvr_emergency_act, "1") == 0)
		{
			isBypass = true;

			memset(sDataEnv_var, 0x00, sizeof(sDataEnv_var));

			snprintf(sDataEnv_var, sizeof(sDataEnv_var), HIWARE_NOT_CONNECTAPI_FORMAT, "BYPASS");
			pam_putenv(pamh, sDataEnv_var);

			memset(sDataEnv_var, 0x00, sizeof(sDataEnv_var));

			// nd_log (NDLOG_TRC, "Due to an emergency situation where the server cannot be accessed, logging in will proceed without policy enforcement.");

#ifdef _BAK_NEED_LOG
			// snprintf(svrConnSessKey, sizeof(svrConnSessKey), "%s", uuid_str);
			snprintf(agtNo, sizeof(agtNo), "%s", agent_id ? agent_id : "");
			snprintf(agtConnFormTpCode, sizeof(agtConnFormTpCode), "%s", (user_info->type == 1) ? PAM_CONN_CONSOLE : PAM_CONN_BYPASS);
			snprintf(userIp, sizeof(userIp), "%s", user_info->remote_host);
			snprintf(securStepNo, sizeof(securStepNo), "%s", PAM_SECUR_STEP_PAM);
			snprintf(svrConnSessKey, sizeof(svrConnSessKey), "%s", uuid_str);
			snprintf(connAcctId, sizeof(connAcctId), "%s", user_info->current_user);
			snprintf(pamCertDtlCode, sizeof(pamCertDtlCode), "%s", PAM_LOGIN);

			pam_logging = LOGGING_ON;
			//
			///
			retval = PAM_SUCCESS;
			goto nd_pam_authenticate_user_fin;
#endif
			/**/
			nd_log(NDLOG_DBG, "Uncontrolled processing due to communication failure with the authentication server. | Server IP: %s | Server Port: %d | Emergency Mode: %s ", auth_server_ip, authsvr_port, authsvr_emergency_act);

			/**/
			nd_log(NDLOG_INF, "[NDA-PAM] Unable to connect to the API server. Info = %s:%d, emergency mode = %s", auth_server_ip, authsvr_port, authsvr_emergency_act);

			return PAM_SUCCESS;
		}
		else if (strcmp(authsvr_emergency_act, "0") == 0)
		{
			/**/
                        nd_log(NDLOG_ERR, "[HIW-AGT-PAM-NERR-000001] Unable to connect to the API server. Info = %s:%d, emergency mode = %s", auth_server_ip, authsvr_port, authsvr_emergency_act);
                        return PAM_AUTH_ERR;
		}
		else if (strcmp(authsvr_emergency_act, SET_MODE_BLOCK) == 0)
		{
			/**/
			nd_log(NDLOG_ERR, "[HIW-AGT-PAM-NERR-000001] Unable to connect to the API server. Info = %s:%d, emergency mode = %s", auth_server_ip, authsvr_port, authsvr_emergency_act);
			return PAM_AUTH_ERR;
		}
		else
		{
			/**/
			nd_log(NDLOG_INF, "[NDA-PAM] Unable to connect to the API server.");
			return PAM_SUCCESS;
		}
	}

	/**/
	nd_log(NDLOG_DBG, "[nd_pam_authenticate_user]::[Checking connection to the API server.| bisAlive_server = true|]");
	snprintf(logItem.agtNo, sizeof(logItem.agtNo), "%s", agent_id ? agent_id : "");
	snprintf(logItem.agtConnFormTpCode, sizeof(logItem.agtConnFormTpCode), "%s", (user_info->type == 1) ? PAM_CONN_CONSOLE : PAM_CONN_BYPASS);
	snprintf(logItem.userIp, sizeof(logItem.userIp), "%s", user_info->remote_host);
	snprintf(logItem.securStepNo, sizeof(logItem.securStepNo), "%s", PAM_SECUR_STEP_PAM);
	snprintf(logItem.svrConnSessKey, sizeof(logItem.svrConnSessKey), "%s", uuid_str);
	snprintf(logItem.connAcctId, sizeof(logItem.connAcctId), "%s", user_info->current_user);
	snprintf(logItem.pamCertDtlCode, sizeof(logItem.pamCertDtlCode), "%s", PAM_LOGIN);

	//
	///
	nd_log(NDLOG_TRC, "start checking sam policy.");

#ifdef _SUPP_DATE_
	time_t current_time = time(NULL);
	struct tm *tm_info = localtime(&current_time);
	int current_wday = tm_info->tm_wday == 0 ? 7 : tm_info->tm_wday; // Adjust for Sunday being 7

	if (sam_opermode == 1 && is_pam_user_ndshell(pamh) &&
		validate_json_sampolicy(getPamRuleFilePath(sDataHomeDir), user_info->remote_host, user_info->current_user, current_time, current_wday, &ndshell_agtAuthNo, &sam_action, &sam_logging) == 1)
#else  //_SUPP_DATE_
	if (sam_opermode == 1 && is_pam_user_ndshell(pamh) &&
		validate_json_sampolicy_without_date(getPamRuleFilePath(sDataHomeDir), user_info->remote_host, user_info->current_user, &ndshell_agtAuthNo, &sam_action, &sam_logging) == 1)
#endif //_SUPP_DATE_
	{

		nd_log(NDLOG_DBG, "user's session is executed in ndshell. Checking the SAM policy. [account:%s]", user_info->current_user);

		if (sam_action == PAM_ACT_RULE_DENY)
		{
			snprintf(logItem.svrConnFailRsnCode, sizeof(logItem.svrConnFailRsnCode), PAM_SVR_FAIL_UNAUTH_ACCESS);
			snprintf(logItem.svrConnRstTpCode, sizeof(logItem.svrConnRstTpCode), "%s", PAM_AUTH_FAIL);
			snprintf(logItem.securStepNo, sizeof(logItem.securStepNo), "%s", PAM_SECUR_STEP_NDSHELL);
			snprintf(logItem.pamCertDtlAuthCode, sizeof(logItem.pamCertDtlAuthCode), "%s", PAM_CERT_DTL_AUTH_SAM_RULE);
			snprintf(logItem.agtAuthNo, sizeof(logItem.agtAuthNo), "%s", ndshell_agtAuthNo ? ndshell_agtAuthNo : "");

			/**/
			nd_log(NDLOG_DBG, "Connection is blocked as the sam policy action setting is set to block.[ip addr:%s/account:%s][%d]", user_info->remote_host, user_info->current_user, sam_logging);

			/**/
			nd_log(NDLOG_ERR, "[HIW-AGT-PAM-PMER-000001] Access denied due to SAM-policy | User: %s | Remote Host: %s", user_info->current_user, user_info->remote_host);

			pam_logging = sam_logging;

			retval = PAM_PERM_DENIED;
			goto nd_pam_authenticate_user_fin;
		}
		else
		{
			snprintf(logItem.svrConnRstTpCode, sizeof(logItem.svrConnRstTpCode), "%s", PAM_AUTH_SUCCESS);
			snprintf(logItem.securStepNo, sizeof(logItem.securStepNo), "%s", PAM_SECUR_STEP_NDSHELL);

			bRetSamPolicy = true;

			/**/
			nd_log(NDLOG_DBG, "Connection is allowed as the sam policy action setting is set to allow.[ip addr:%s/account:%s]", user_info->remote_host, user_info->current_user);

			/**/
			nd_log(NDLOG_INF, "[NDA-PAM] Access granted by SAM-policy | User: %s | Remote Host: %s", user_info->current_user, user_info->remote_host);

			retval = PAM_SUCCESS;
		}

		snprintf(logItem.agtAuthNo, sizeof(logItem.agtAuthNo), "%s", ndshell_agtAuthNo ? ndshell_agtAuthNo : "");

		memset(sDataEnv_var, 0x00, sizeof(sDataEnv_var));

		snprintf(sDataEnv_var, sizeof(sDataEnv_var), HIWARE_SU_SAM_AGT_AUTHNO_FORMAT, ndshell_agtAuthNo ? ndshell_agtAuthNo : "");
		pam_putenv(pamh, sDataEnv_var);

		sam_env = malloc(strlen(PAM_BAK_SAM_AGT_AUTHNO_FORMAT) + strlen(logItem.agtAuthNo));
		if (sam_env) {

			sprintf(sam_env, PAM_BAK_SAM_AGT_AUTHNO_FORMAT, logItem.agtAuthNo);
			int ret = pam_putenv(pamh, sam_env);

			flags |= FLAG_SAM_AUTHNO;
		}
		free (sam_env);

		/**/
		nd_log(NDLOG_TRC, "The current session matches SAM-policy with AuthNo (%s)", logItem.agtAuthNo);
	}

	if (pam_opermode == 0)
	{

		memset(sDataEnv_var, 0x00, sizeof(sDataEnv_var));

		snprintf(sDataEnv_var, sizeof(sDataEnv_var), HIWARE_NOT_CONNECTAPI_FORMAT, "BYPASS");
		pam_putenv(pamh, sDataEnv_var);

		memset(sDataEnv_var, 0x00, sizeof(sDataEnv_var));

		snprintf(sDataEnv_var, sizeof(sDataEnv_var), HIWARE_SESSION_KEY_FORMAT, uuid_str ? uuid_str : "");
		pam_putenv(pamh, sDataEnv_var);

		retval = PAM_SUCCESS;

		pam_logging = sam_logging;

		nd_log(NDLOG_TRC, "PAM operating mode is off, the login is successful without additional authentication.");

		goto nd_pam_authenticate_user_fin;
	}

	/**/
	nd_log(NDLOG_TRC, "[nd_pam_authenticate_user]::[start checking pam policy. |remote host = %s | current user =%s]", user_info->remote_host, user_info->current_user);
	if (check_pam_policy(getPamRuleFilePath(sDataHomeDir), user_info->remote_host, user_info->current_user, current_time, current_wday, &agt_auth_no, &pam_action, &pam_logging) == 1)
	{

		/**/
		nd_log(NDLOG_TRC, "Policy check result: Complies with the policy. | agt_auth_no = %s | pam_action = %d | pam_logging = %d )", agt_auth_no, pam_action, pam_logging);

		if (pam_action == PAM_ACT_RULE_DENY)
		{
			snprintf(logItem.svrConnFailRsnCode, sizeof(logItem.svrConnFailRsnCode), PAM_SVR_FAIL_UNAUTH_ACCESS);
			snprintf(logItem.svrConnRstTpCode, sizeof(logItem.svrConnRstTpCode), "%s", PAM_AUTH_FAIL);
			snprintf(logItem.pamCertDtlAuthCode, sizeof(logItem.pamCertDtlAuthCode), "%s", PAM_CERT_DTL_AUTH_PAM_RULE);
			snprintf(logItem.securStepNo, sizeof(logItem.securStepNo), "%s", PAM_SECUR_STEP_PAM);
			snprintf(logItem.pamAgtAuthNo, sizeof(logItem.pamAgtAuthNo), "%s", agt_auth_no ? agt_auth_no : "");

			/**/
			nd_log(NDLOG_DBG, "Connection is blocked as the pam policy action setting is set to block.[ip addr:%s/account:%s]", user_info->remote_host, user_info->current_user);

			/**/
			nd_log(NDLOG_ERR, "[HIW-AGT-PAM-PMER-000002] Access denied due to PAM-policy | User: %s | Remote Host: %s", user_info->current_user, user_info->remote_host);

			retval = PAM_PERM_DENIED;
			goto nd_pam_authenticate_user_fin;
		}
		else
		{
			snprintf(logItem.svrConnRstTpCode, sizeof(logItem.svrConnRstTpCode), "%s", PAM_AUTH_SUCCESS);
			snprintf(logItem.securStepNo, sizeof(logItem.securStepNo), "%s", PAM_SECUR_STEP_PAM);
			bRetPamPolicy = true;

			/**/
			nd_log(NDLOG_DBG, "Connection is allowed as the pam policy action setting is set to allow.[ip addr:%s/account:%s]", user_info->remote_host, user_info->current_user);

			/**/
			nd_log(NDLOG_INF, "[NDA-PAM] Access granted by PAM-policy | User: %s | Remote Host: %s", user_info->current_user, user_info->remote_host);

			retval = PAM_SUCCESS;
		}

		snprintf(logItem.pamAgtAuthNo, sizeof(logItem.pamAgtAuthNo), "%s", agt_auth_no ? agt_auth_no : "");

		memset(sDataEnv_var, 0x00, sizeof(sDataEnv_var));

		snprintf(sDataEnv_var, sizeof(sDataEnv_var), HIWARE_SU_PAM_AGT_AUTHNO_FORMAT, agt_auth_no ? agt_auth_no : "");
		pam_putenv(pamh, sDataEnv_var);

		pam_env = malloc(strlen(PAM_BAK_PAM_AGT_AUTHNO_FORMAT) + strlen(logItem.pamAgtAuthNo));
		if (pam_env) {
			sprintf(pam_env, PAM_BAK_PAM_AGT_AUTHNO_FORMAT, logItem.pamAgtAuthNo);
			pam_putenv(pamh, pam_env);

			flags |= FLAG_PAM_AUTHNO;
		}

		free (pam_env);
	}

	if (bRetPamPolicy == false && bRetSamPolicy == false)
	{
		/**/
		nd_log(NDLOG_TRC, "Does not comply with the policy - Accepting login without performing additional actions as per the policy.");

		/**/
		nd_log(NDLOG_INF, "[NDA-PAM] Does not comply with the policy - Accepting login without performing additional actions as per the policy.");
		snprintf(logItem.svrConnSessKey, sizeof(logItem.svrConnSessKey), "%s", uuid_str ? uuid_str : "");

		memset(sDataEnv_var, 0x00, sizeof(sDataEnv_var));
		snprintf(sDataEnv_var, sizeof(sDataEnv_var), HIWARE_SESSION_KEY_FORMAT, uuid_str ? uuid_str : "");

		pam_putenv(pamh, sDataEnv_var);

		return PAM_SUCCESS;
	}

	//nd_log(NDLOG_TRC, "Check the current status of the PAM policy : pam_opermode = OFF");

	if (bRetPamPolicy == false)
	{
		nd_log(NDLOG_TRC, "[nd_pam_authenticate_user]::[get current status : pam_opermode = OFF]");

		memset(sDataEnv_var, 0x00, sizeof(sDataEnv_var));
		snprintf(sDataEnv_var, sizeof(sDataEnv_var), HIWARE_NOT_CONNECTAPI_FORMAT, "BYPASS");
		pam_putenv(pamh, sDataEnv_var);

		memset(sDataEnv_var, 0x00, sizeof(sDataEnv_var));
		snprintf(sDataEnv_var, sizeof(sDataEnv_var), HIWARE_SESSION_KEY_FORMAT, uuid_str ? uuid_str : "");
		pam_putenv(pamh, sDataEnv_var);

		retval = PAM_SUCCESS;

		pam_logging = sam_logging;

		nd_log(NDLOG_TRC, "Due to the current status of the session's PAM policy being 'off', additional authentication will not be performed.");

		goto nd_pam_authenticate_user_fin;
	}

	/**/
	nd_log(NDLOG_TRC, "Current status of the session's PAM policy is TRUE, additional authentication steps will be performed.");

	nd_log(NDLOG_TRC, "Starting the process to receive input values (ID/PW) for HIWARE authentication.");

    remain_count = 3;
	for (int i = 0; i < 3; i++)
	{
		if (bHiwareAuthRet == true)
			break;

		hiauth_input_data = OperateHiAuth(pamh);
		if ((hiauth_input_data->sHiAuthId == NULL || strlen(hiauth_input_data->sHiAuthPw) <= 0) ||
			(hiauth_input_data->sHiAuthPw == NULL || strlen(hiauth_input_data->sHiAuthPw) <= 0))
		{
			/**/
			//nd_log(NDLOG_DBG, "Authentication failed: Invalid input. Attempt count: %d/3", i+1);
            nd_log(NDLOG_DBG, "Authentication failed for user %s: attempt %d of 3", logItem.connAcctId, i+1);
            pam_error(pamh, "Invalid credentials. You have %d attempt(s) remaining.", 3 - (i+1));

            remain_count --;

            if (remain_count == 0 )
            {
                bHiwareAuthRet = false;
                pam_error(pamh, "Too many failed attempts. Access denied.");
            }

			continue;
		}
		else
		{
			bHiwareAuthRet = true;
		}
	}

	if (bHiwareAuthRet == false)
	{

		nd_log(NDLOG_DBG, "HIWARE authentication has failed. | svrConnFailRsnCode = %s | svrConnRstTpCode = %s | pamCertDtlAuthCode = %s", PAM_SVR_FAIL_HI_AUTH_FAIL, PAM_AUTH_FAIL, PAM_CERT_DTL_AUTH_HIWAREAUTH);

		snprintf(logItem.svrConnFailRsnCode, sizeof(logItem.svrConnFailRsnCode), PAM_SVR_FAIL_HI_AUTH_FAIL);
		snprintf(logItem.svrConnRstTpCode, sizeof(logItem.svrConnRstTpCode), "%s", PAM_AUTH_FAIL);
		snprintf(logItem.pamCertDtlAuthCode, sizeof(logItem.pamCertDtlAuthCode), "%s", PAM_CERT_DTL_AUTH_HIWAREAUTH);

		retval = PAM_AUTH_ERR;
		goto nd_pam_authenticate_user_fin;
	}

	nd_log(NDLOG_TRC, "====================================================================");
	nd_log(NDLOG_TRC, "[INPUT HIWARE user information]");
	nd_log(NDLOG_TRC, "--------------------------------------------------------------------");
	nd_log(NDLOG_DBG, "# hiware user account        :%s", hiauth_input_data->sHiAuthId);
	//nd_log(NDLOG_DBG, "# hiware user password       :%s", hiauth_input_data->sHiAuthPw);
	nd_log(NDLOG_TRC, "--------------------------------------------------------------------");
	nd_log(NDLOG_TRC, "====================================================================");

	/*
		// Send the hiware account information to the API server to perform authentication.
	*/

	//
	///
	nd_log(NDLOG_TRC, "Starting the authentication process with the API server for HIWARE authentication.");

	snprintf(logItem.pamCertDtlAuthCode, sizeof(logItem.pamCertDtlAuthCode), "%s", PAM_CERT_DTL_AUTH_HIWAREAUTH);

	retval = requestHiwareAuthToApiServer(hiauth_input_data->sHiAuthId, hiauth_input_data->sHiAuthPw, agt_auth_no, agent_id, &hi_hiwareauth_ret);
	if (retval != HI_AUTH_RET_SUCCEED || hi_hiwareauth_ret.ret != 200)
	{
		if (strlen(hi_hiwareauth_ret.svrConnFailRsnCode) > 0)
		{
			snprintf(logItem.svrConnFailRsnCode, sizeof(logItem.svrConnFailRsnCode), hi_hiwareauth_ret.svrConnFailRsnCode);
		}
		else
		{
			snprintf(logItem.svrConnFailRsnCode, sizeof(logItem.svrConnFailRsnCode), PAM_SVR_FAIL_HI_AUTH_FAIL);
		}

		snprintf(logItem.svrConnRstTpCode, sizeof(logItem.svrConnRstTpCode), "%s", PAM_AUTH_FAIL);
		snprintf(logItem.pamCertDtlAuthCode, sizeof(logItem.pamCertDtlAuthCode), "%s", PAM_CERT_DTL_AUTH_HIWAREAUTH);

		if (strlen(hi_hiwareauth_ret.userNumber) > 0)
		{
			snprintf(logItem.userNo, sizeof(logItem.userNo), "%s", hi_hiwareauth_ret.userNumber);
		}

		/**/
		nd_log(NDLOG_DBG, "HIWARE authentication request result: failure");

		/**/
		nd_log(NDLOG_ERR, "[HIW-AGT-PAM-AUTH-000002] Failed to start the authentication process with the API server for HIWARE authentication. [account:%s/ hiware account:%s/ retcode:%d]", user_info->current_user, hiauth_input_data->sHiAuthId, hi_hiwareauth_ret);

		if (hi_hiwareauth_ret.message != NULL)
			pam_error(pamh, hi_hiwareauth_ret.message);

		retval = PAM_AUTH_ERR;
		goto nd_pam_authenticate_user_fin;
	}

	snprintf(logItem.certTpCode, sizeof(logItem.certTpCode), "%s", hi_hiwareauth_ret.certTpCode);
	snprintf(logItem.certAppTpCode, sizeof(logItem.certAppTpCode), "0");
	snprintf(logItem.certStepSeqNo, sizeof(logItem.certStepSeqNo), "%s", hi_hiwareauth_ret.certStepSeqNo);

	/**/
	nd_log(NDLOG_TRC, "HIWARE authentication request result: success. | certTpCode = %s | certAppTpCode = %s | certStepSeqNo = %s | g_sDataTemporaryAccessKey = %s",
		       	logItem.certTpCode, logItem.certAppTpCode, logItem.certStepSeqNo, g_sDataTemporaryAccessKey);

	if (strlen(g_sDataTemporaryAccessKey) > 0)
	{
		snprintf(logItem.pamCertDtlAuthCode, sizeof(logItem.pamCertDtlAuthCode), "%s", PAM_CERT_DTL_AUTH_TWOFACT);

		/**/
		nd_log(NDLOG_INF, "HIWARE account authentication task with the authentication server succeeded.");

		/**/
		nd_log(NDLOG_TRC, "Starting additional authentication process");

		retval = pam_prompt(pamh, PAM_PROMPT_ECHO_OFF, &hiwareTwoFactData, sTwoFactString);

		/**/
		nd_log(NDLOG_DBG, "OTP value entered by the user is [%s]. | g_sDataTemporaryAccessKey =%s | hiwareTwoFactData = %s | agent_id = %s", 
				hiwareTwoFactData, g_sDataTemporaryAccessKey, hiwareTwoFactData, agent_id);

		/*
			// Send the OTP information to the API server to perform authentication.
		*/
		retval = requestTwoFactAuthToApiserver("08", g_sDataTemporaryAccessKey, "1", hiwareTwoFactData, "", agent_id, &hi_twofact_ret);
		if (retval != HI_AUTH_RET_SUCCEED)
		{
			snprintf(logItem.svrConnFailRsnCode, sizeof(logItem.svrConnFailRsnCode), PAM_SVR_FAIL_TF_AUTH_FAIL);
			snprintf(logItem.svrConnRstTpCode, sizeof(logItem.svrConnRstTpCode), "%s", PAM_AUTH_FAIL);
			snprintf(logItem.pamCertDtlAuthCode, sizeof(logItem.pamCertDtlAuthCode), "%s", PAM_CERT_DTL_AUTH_TWOFACT);
			snprintf(logItem.certSucesFailYn, sizeof(logItem.certSucesFailYn), "0");

			/**/
			nd_log(NDLOG_DBG, "additional authentication process has failed. | logItem.svrConnFailRsnCode = %s | logItem.svrConnRstTpCode = %s | logItem.pamCertDtlAuthCode = %s | logItem.certSucesFailYn = %s",
				   logItem.svrConnFailRsnCode, logItem.svrConnRstTpCode, logItem.certSucesFailYn);

			pam_error(pamh, "Additional authentication failed.");

			retval = PAM_AUTH_ERR;
			goto nd_pam_authenticate_user_fin;
		}

		nd_log(NDLOG_TRC, "Additional authentication process was successful.");

		snprintf(logItem.svrConnRstTpCode, sizeof(logItem.svrConnRstTpCode), "%s", PAM_AUTH_SUCCESS);
		snprintf(logItem.certTpCode, sizeof(logItem.certTpCode), "%s", hi_twofact_ret.certTpCode);
		snprintf(logItem.certAppTpCode, sizeof(logItem.certAppTpCode), "%s", hi_twofact_ret.certAppTpCode);
		snprintf(logItem.certSucesFailYn, sizeof(logItem.certSucesFailYn), "%s", hi_twofact_ret.certSucesFailYn);
		snprintf(logItem.certStepSeqNo, sizeof(logItem.certStepSeqNo), "%s", hi_twofact_ret.certStepSeqNo);

		nd_log(NDLOG_DBG, "Detailed results of additional authentication. | logItem.svrConnRstTpCode = %s | logItem.certTpCode = %s | logItem.certAppTpCode = %s | logItem.certSucesFailYn = %s | logItem.certStepSeqNo",
			   logItem.svrConnRstTpCode, logItem.certTpCode, logItem.certAppTpCode, logItem.certSucesFailYn, logItem.certStepSeqNo);

		retval = PAM_SUCCESS;
	}
	else
	{
		if (g_sDataUserLoginResult == NULL || strcmp(g_sDataUserLoginResult, PAM_LOGIN_RESULT_FALSE) == 0)
		{
			nd_log(NDLOG_TRC, "Additional authentication process has failed.");
			snprintf(logItem.svrConnFailRsnCode, sizeof(logItem.svrConnFailRsnCode), PAM_SVR_FAIL_TF_AUTH_FAIL);
			snprintf(logItem.svrConnRstTpCode, sizeof(logItem.svrConnRstTpCode), "%s", PAM_AUTH_FAIL);
			snprintf(logItem.pamCertDtlAuthCode, sizeof(logItem.pamCertDtlAuthCode), "%s", PAM_CERT_DTL_AUTH_TWOFACT);

			retval = PAM_AUTH_ERR;

			nd_log(NDLOG_DBG, "Detailed results of additional authentication. | logItem.svrConnFailRsnCode = %s | logItem.svrConnRstTpCode = %s | logItem.pamCertDtlAuthCode = %s ",logItem.svrConnFailRsnCode, logItem.svrConnRstTpCode, logItem.pamCertDtlAuthCode);

			goto nd_pam_authenticate_user_fin;
		}
	}

	retval = PAM_SUCCESS;

	/*
	 *
	 */
	memset(sDataEnv_var, 0x00, sizeof(sDataEnv_var));
	if (g_sDataHiwareUserNumber)
	{
		snprintf(logItem.userNo, ND_AGENTID_MAX_LEN, "%s", g_sDataHiwareUserNumber);
		snprintf(sDataEnv_var, sizeof(sDataEnv_var), HIWARE_USER_NUMBER_FORMAT, g_sDataHiwareUserNumber);
		pam_putenv(pamh, sDataEnv_var);

		nd_log(NDLOG_DBG, "Save the HIWARE user number locally. | sDataEnv_var = %s", sDataEnv_var);
	}

	memset(sDataEnv_var, 0x00, sizeof(sDataEnv_var));
	snprintf(sDataEnv_var, sizeof(sDataEnv_var), HIWARE_SESSION_KEY_FORMAT, uuid_str);
	pam_putenv(pamh, sDataEnv_var);

	nd_log(NDLOG_DBG, "Save the HIWARE Session Key locally. | sDataEnv_var = %s", sDataEnv_var);

nd_pam_authenticate_user_fin:
	if (pam_logging == LOGGING_ON)
	{
		if (pam_opermode == 1)
			flags |= FLAG_OPERATION_MODE;

		flags |= FLAG_PAM_LOGGING;
		if (sam_logging == 1)
			flags |= FLAG_SAM_LOGGING;

		char flag_str[16];
    		snprintf(flag_str, sizeof(flag_str), "RECODE_FLAG=%u", flags);
		int ret = pam_putenv(pamh, flag_str);
		if (ret != PAM_SUCCESS)	{
			const char *error_msg = pam_strerror(pamh, ret);
                        nd_log(NDLOG_TRC, "pam_putenv error: %s\n", error_msg);
		}

		memset(sDataEnv_var, 0x00, sizeof(sDataEnv_var));
		snprintf(sDataEnv_var, sizeof(sDataEnv_var), HIWARE_LAST_AUTH_CODE_FORMAT, logItem.pamCertDtlAuthCode);
		pam_putenv(pamh, sDataEnv_var);

		memset(sDataEnv_var, 0x00, sizeof(sDataEnv_var));
		snprintf(sDataEnv_var, sizeof(sDataEnv_var), HIWARE_PAM_BAK_SESSIONTYPE_FORMAT, logItem.agtConnFormTpCode);
		pam_putenv(pamh, sDataEnv_var);

		if (strcmp(logItem.pamCertDtlCode, PAM_SU_LOGIN) == 0 || strcmp(logItem.pamCertDtlCode, PAM_SU_LOGOUT) == 0)
			snprintf(logItem.pamCertDtlAuthCode, sizeof(logItem.pamCertDtlAuthCode), PAM_CERT_DTL_AUTH_SU_RULE);

		logitem = create_archive_log(logItem.svrConnStartTime,
									 logItem.svrConnEndTime,
									 logItem.svrConnRstTpCode,
									 logItem.svrConnFailRsnCode,
									 logItem.agtNo,
									 logItem.agtConnFormTpCode,
									 logItem.agtAuthNo,
									 logItem.portNo,
									 logItem.userIp,
									 logItem.securStepNo,
									 logItem.svrConnSessKey,
									 logItem.svrConnSuSessKeyNo,
									 logItem.svrConnPreSuSessKeyNo,
									 logItem.connAcctId,
									 logItem.switchAcctId,
									 logItem.pamAgtAuthNo,
									 logItem.userNo,
									 logItem.pamCertDtlCode,
									 logItem.pamCertDtlAuthCode,
									 logItem.certTpCode,
									 logItem.certAppTpCode,
									 logItem.certSucesFailYn,
									 logItem.certStepSeqNo);

		nd_pam_archive_log(header, *logitem, (char *)sDataHomeDir);
		free_archive_log(logitem);
	}

	if (agent_id)
		free(agent_id);
	if (agt_auth_no)
		free(agt_auth_no);

	return retval;
}

void print_session_info(const SessionInfo *info)
{

	if (!info)
	{
		// syslog (LOG_ERR, "print_session_info param is null");
		return;
	}

	syslog(LOG_ERR, "Type: %d\n", info->type);
	syslog(LOG_ERR, "Current User: %s\n", info->current_user ? info->current_user : "(null)");
	syslog(LOG_ERR, "Target User: %s\n", info->target_user ? info->target_user : "(null)");
	syslog(LOG_ERR, "Remote Host: %s\n", info->remote_host ? info->remote_host : "(null)");
	syslog(LOG_ERR, "TTY: %s\n", info->tty ? info->tty : "(null)");
}

/*
	//
*/
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags,
								   int argc, const char **argv)
{
	(void)flags;
	(void)argc;
	(void)argv;

	int retval = 0; //, sock = 0;
	bool isSuSession = false;
	bool isNdShell = false;
	struct st_pam_conf pam_conf;
	char *uuid_str; //= malloc(ND_UUID_LENGTH + 1);
	char *su_uuid_str;
	struct _archive_log *logitem = NULL, logItem = {
											 0,
										 };
	char *ndshell_agtAuthNo = NULL;
#ifdef _USE_BITMASK_BACKUP_
	char *sam_env = NULL;
        char *pam_env = NULL;
#endif //_USE_BITMASK_BACKUP_
	bool bRetPamPolicy = false, bRetSamPolicy = false;

	char *crypted;
	const char *encrypt_passwd;
	const char *input_passwd;
	const char *current_user;

	int pam_pri_no, pam_action, pam_logging, sam_action, sam_logging, login_status = 0;
#ifdef _USE_BITMASK_BACKUP_
	unsigned int envflags = 0;
#endif //_USE_BITMASK_BACKUP_
	char *agt_auth_no;

	/*
		// log item
	*/
	char sUserAccount[MAX_ACCOUNT_LEN];
	char sSwitchAccount[MAX_ACCOUNT_LEN];
	char sIpAddress[IPV4_BUFFER_SIZE];
	char sDataCollectLog[MAX_STRING_LENGTH];
	char sDataEnv_var[MAX_ENV_STR_LEN];
	char local_ip[INET_ADDRSTRLEN];
	char pamCertTpCode[4] = {
		0,
	};

	nd_log(NDLOG_TRC, "Starting the process of verifying the user's identity.");

	/*
				// get pam config
		*/
	char *user_shell = NULL;
	const char *sDataHomeDir = pam_getenv(pamh, ENV_HIWARE_HOME);
	if (!sDataHomeDir)
	{
		sDataHomeDir = PRODUCT_NM;
	}

	if (sDataHomeDir != NULL)
		g_sDataRootDir = strdup(sDataHomeDir);

	if (g_sConfFilePath == NULL)
		g_sConfFilePath = strdup(getPamConfFilePath(sDataHomeDir));

	getpamconf(&pam_conf);
	char *pam_op_mode = get_value_as_string(getPamRuleFilePath(sDataHomeDir), "pamCertYn");

	int pam_opermode = is_pam_oper_mode(sDataHomeDir);
	int sam_opermode = is_sam_oper_mode(sDataHomeDir);

	struct _msg_header_ header = {
		.iMsgVer = 0,
		.iMsgTotalSize = 0};

	header.iMsgType = 0;
	header.iMsgCode = 0;

	char *agent_id = get_value_as_string(getPamRuleFilePath(sDataHomeDir), "agtNo");
	g_nDataSshPort = get_ssh_listening_port();

	nd_log(NDLOG_DBG, "Gathering essential data for product functionality.");
	nd_log(NDLOG_DBG, "# Home Directory: %s", sDataHomeDir);
	nd_log(NDLOG_DBG, "# Product Config File: %s", g_sConfFilePath);
	nd_log(NDLOG_DBG, "# Get PAM Operation Mode: %d", pam_opermode);
	nd_log(NDLOG_DBG, "# Get NdShell Operation Mode: %d", sam_opermode);

	/**/
	nd_log(NDLOG_DBG, "# get agent id : [%s]", agent_id);

	/**/
	nd_log(NDLOG_DBG, "# get sshd listening port : [%d]", g_nDataSshPort);

	/**/
	nd_log(NDLOG_INF, "[NDA-PAM] Authentication process has started.");

	if (g_sConfFilePath == NULL)
		g_sConfFilePath = strdup(getPamConfFilePath(sDataHomeDir));

	/*
		// Initialization of necessary variables for authentication tasks
	*/
	initializeAuthVariables();

	get_local_ip(local_ip, sizeof(local_ip));

	const void *rhost_item = NULL;
	const char *rhost = NULL;

	if (pam_get_item(pamh, PAM_RHOST, &rhost_item) == PAM_SUCCESS)
	{

		rhost = (const char *)rhost_item;
		if (rhost != NULL && rhost[0] != '\0')
		{
			nd_log(NDLOG_DBG, "Remote host detected: %s", rhost);
			nd_log(NDLOG_TRC, "Exception connection validation of the session.");
			if (validate_json_exceptionConnection(getPamRuleFilePath(sDataHomeDir), rhost) == 1)
			{
				nd_log(NDLOG_INF, "exception connection validation result of the connection session is exceptional, no additional authentication will be performed.");
				return PAM_SUCCESS;
			}
		}
		else
		{
			// nd_log(NDLOG_WAN, "Failed to retrieve the IP address of the connection session.");
		}
	}

	/*
		// creat new uuid
	*/
	uuid_str = generate_uuid();

	/**/
	nd_log(NDLOG_DBG, "local ip address : [%s]", local_ip);

	/**/
	nd_log(NDLOG_DBG, "generate session key : [%s]", uuid_str);

	if (pam_get_user(pamh, &current_user, NULL) == PAM_SUCCESS && current_user != NULL)
	{
		// nd_log(NDLOG_WAN, "Failed to retrieve the username of the connection session");
	}

	/**/
	nd_log(NDLOG_INF, "[NDA-PAM] User attempting authentication: %s", current_user);

	/*
				// Getting the user input password.
	*/
	retval = pam_get_authtok(pamh, PAM_AUTHTOK, &input_passwd, NULL);
	if (retval != PAM_SUCCESS)
	{

		/**/
		nd_log(NDLOG_TRC, "[pam_sm_authenticate]::[failed to get user password...[pam_get_authtok]]");

		/**/
		nd_log(NDLOG_ERR, "[HIW-AGT-PAM-CONF-000001] failed to get user password");
		return;
	}

	/*
		// check os login result
	*/
	encrypt_passwd = get_encrypted_password_from_shadow(current_user);
	if (!encrypt_passwd)
	{

		/**/
		nd_log(NDLOG_TRC, "[pam_sm_authenticate]::[failed to get encrypted password from shadow file..(%s)]", current_user);

		/**/
		nd_log(NDLOG_INF, "[HIW-AGT-PAM-CONF-000001] failed to get encrypted password from shadow file.");
		return;
	}

	nd_log(NDLOG_INF, "Starting the OS login process.");
	/*
			//Calls the crypt function using the user input password (input_passwd) along with the user's password hash (user_info->encrypted_password).
	*/
	crypted = crypt(input_passwd, encrypt_passwd);
	if (strcmp(crypted, encrypt_passwd) == 0)
	{
		login_status = 0;
	}
	else
	{

		login_status = 1;
	}

	if (login_status != 0) // success 0, failed 1
	{
		/**/
		nd_log(NDLOG_TRC, "Login attempt failed for system account %s.", current_user);

		/**/
		nd_log(NDLOG_ERR, "[HIW-AGT-PAM-AUTH-000001] Authentication failed for user: %s", current_user);

		return PAM_AUTH_ERR;
	}

	/**/
	nd_log(NDLOG_TRC, "Login attempt successful for system account. %s", current_user);

	/**/
	nd_log(NDLOG_INF, "[NDA-PAM] Authentication successful for user: %s", current_user);

	/*
		//
	*/
	snprintf(logItem.agtNo, sizeof(logItem.agtNo), "%s", agent_id ? agent_id : "");

	snprintf(logItem.securStepNo, sizeof(logItem.securStepNo), "%s", PAM_SECUR_STEP_PAM);
	snprintf(logItem.svrConnSessKey, sizeof(logItem.svrConnSessKey), "%s", uuid_str);
	snprintf(logItem.pamCertDtlCode, sizeof(logItem.pamCertDtlCode), "%s", PAM_LOGIN);

	/*
		 // get login type (su? terminal, console)
	*/
	SessionInfo *info = NULL;
	const char *tty = get_pam_item_str(pamh, PAM_TTY);

	/**/
	nd_log(NDLOG_TRC, "Collecting connection session information. | tty= %s", tty);

	if (tty && strstr(tty, "ssh"))
	{

		/**/
		nd_log(NDLOG_TRC, "Current session type is terninal (ssh)");

		info = get_ssh_session_info(pamh);

		nd_log(NDLOG_DBG, "SSH connection session information collection result.");
		nd_log(NDLOG_DBG, "# current_user: %s | remote_host: %s | target_user: %s | type: %d", info->current_user, info->remote_host, info->target_user, info->type);

		if (validate_json_exceptionConnection(getPamRuleFilePath(sDataHomeDir), info->remote_host) == 1)
		{
			nd_log(NDLOG_DBG, "The current session complies with the exception access settings. | Remote Host: %s | Result = 1", info->remote_host);
			return PAM_SUCCESS;
		}

		/**/
		nd_log(NDLOG_INF, "[NDA-PAM] SSH session started | User: %s | Remote Host: %s | Terminal: %s", info->current_user, info->remote_host, tty);

		snprintf(logItem.userIp, sizeof(logItem.userIp), "%s", info->remote_host);
		snprintf(logItem.connAcctId, sizeof(logItem.connAcctId), "%s", info->current_user);

		nd_log(NDLOG_TRC, "====================================================================");
		nd_log(NDLOG_TRC, "[get ssh session information]");
		nd_log(NDLOG_TRC, "--------------------------------------------------------------------");
		nd_log(NDLOG_TRC, "# nsession type : terminal");
		nd_log(NDLOG_DBG, "# agtConnForm : %s", logItem.agtConnFormTpCode);
		nd_log(NDLOG_DBG, "# userIp : %s", logItem.userIp);
		nd_log(NDLOG_DBG, "# connAcctId : %s", logItem.connAcctId);
		nd_log(NDLOG_TRC, "--------------------------------------------------------------------");

		// TEMP CODE
		sprintf(pam_conf.authsvr_linkage, "%s", CONF_VALUE_YES);
		if (strcmp(pam_conf.authsvr_linkage, CONF_VALUE_YES) == 0)
		{
			retval = nd_pam_authenticate_user(uuid_str, info, pamh);
			if (retval != PAM_SUCCESS)
			{
				//
				///
				nd_log(NDLOG_ERR, "[HIW-AGT-PAM-AUTH-000003] Failed to perform user authentication.");
				return retval;
			}
		}
		else
		{
			// BYPASS MODE
			memset(sDataEnv_var, 0x00, sizeof(sDataEnv_var));

			snprintf(sDataEnv_var, sizeof(sDataEnv_var), HIWARE_SESSION_KEY_FORMAT, uuid_str ? uuid_str : "");
			pam_putenv(pamh, sDataEnv_var);
		}

		char bak_sess_pol_dir[1024] = {0,};
		char sess_pol_file[1024] = {0,};
		sprintf (bak_sess_pol_dir, "/%s/rule/%s", sDataHomeDir, uuid_str);
		sprintf (sess_pol_file, "/%s/rule/%s", sDataHomeDir,COMMON_RULE_FILE);

#if 0
		nd_log(NDLOG_DBG, "output patn - bak_sess_pol_dir[%s]", bak_sess_pol_dir);
		nd_log(NDLOG_DBG, "output patn - sess_pol_file[%s]", sess_pol_file);
		nd_log(NDLOG_DBG, "Create Dir :[%s] and copy org rule file result: [%d]", bak_sess_pol_dir,  copy_file_to_folder (sess_pol_file, bak_sess_pol_dir));
#endif //0
		// If the check value(pam_opermode) is not 1, no further action is taken. << (expected)
		copy_file_to_folder (sess_pol_file, bak_sess_pol_dir);
		

		nd_log(NDLOG_TRC, "Create Session Key [%s]", uuid_str);
		snprintf(pamCertTpCode, sizeof(pamCertTpCode), "%s", PAM_LOGIN);

		// test
		pam_logging = LOGGING_ON;

		/**/
		nd_log(NDLOG_TRC, "Additional authentication was successful, and the overall login process was completed successfully.");

		/**/
		nd_log(NDLOG_INF, "[NDA-PAM] Additional authentication was successful, and the overall login process was completed successfully.");
		return retval;
	}
	else if (tty && strstr(tty, "pts"))
	{ // SU
		info = get_su_session_info(pamh);
		
		snprintf(logItem.agtConnFormTpCode, sizeof(logItem.agtConnFormTpCode), "%s", PAM_CONN_CONSOLE);
		snprintf(logItem.userIp, sizeof(logItem.userIp), "%s", info->remote_host);
		snprintf(logItem.connAcctId, sizeof(logItem.connAcctId), "%s", info->target_user);
		snprintf(logItem.switchAcctId, sizeof(logItem.switchAcctId), "%s", info->current_user);

		nd_log(NDLOG_INF, "[NDA-PAM] su session started | User: %s | Terminal: %s", logItem.connAcctId, tty);

		/*
		 *  	실 계정 보정
		 */
		char *real_account = get_current_user_by_getuid();
		if (real_account != NULL && strcmp(logItem.connAcctId, real_account) != 0)
		{
			snprintf(logItem.connAcctId, sizeof(logItem.connAcctId), "%s", real_account);
		}

		snprintf(logItem.securStepNo, sizeof(logItem.securStepNo), "%s", PAM_SECUR_STEP_PAM);
		snprintf(logItem.pamCertDtlCode, sizeof(logItem.pamCertDtlCode), "%s", PAM_SU_LOGIN);
		sprintf(logItem.pamCertDtlAuthCode, "%s", PAM_CERT_DTL_AUTH_PAM_RULE);

		/*
		 *	세션 키 처리
		 */
		const char *sessionkey = pam_getenv(pamh, ENV_HIWARE_SESSIONKEY);
		if (sessionkey == NULL)
			sessionkey = getenv(ENV_HIWARE_SESSIONKEY);

		nd_log(NDLOG_DBG, "Get Origin session key: %s", sessionkey);
		snprintf(logItem.svrConnSessKey, sizeof(logItem.svrConnSessKey), "%s", sessionkey ? sessionkey : "");

		if (uuid_str == NULL)
			uuid_str = malloc(sizeof(logItem.svrConnSessKey)+ 1);

		if (uuid_str)
		{
			memset(uuid_str, 0x00, sizeof(logItem.svrConnSessKey));
			snprintf(uuid_str, sizeof(logItem.svrConnSessKey), "%s", sessionkey ? sessionkey : "");
		}

		const char *presessionkey = pam_getenv(pamh, ENV_HIWARE_SU_SESSIONKEY);
		if (presessionkey == NULL)
			presessionkey = getenv(ENV_HIWARE_SU_SESSIONKEY);

		if (presessionkey != NULL)
		{
			memset(sDataEnv_var, 0x00, sizeof(sDataEnv_var));
			snprintf(sDataEnv_var, sizeof(sDataEnv_var), HIWARE_PRE_SU_SESSION_KEY_FORMAT, presessionkey ? presessionkey : "");
			pam_putenv(pamh, sDataEnv_var);

			snprintf(logItem.svrConnPreSuSessKeyNo, sizeof(logItem.svrConnPreSuSessKeyNo), "%s", presessionkey ? presessionkey : "");
		}

		// CREATE NEW SU SESSION KEY
		su_uuid_str = generate_uuid();
		snprintf(logItem.svrConnSuSessKeyNo, sizeof(logItem.svrConnSuSessKeyNo), "%s", su_uuid_str ? su_uuid_str : "");

		nd_log(NDLOG_DBG, "Create new su session key: %s", su_uuid_str);

		memset(sDataEnv_var, 0x00, sizeof(sDataEnv_var));
		snprintf(sDataEnv_var, sizeof(sDataEnv_var), HIWARE_SU_SESSION_KEY_FORMAT, su_uuid_str ? su_uuid_str : "");
		pam_putenv(pamh, sDataEnv_var);

		nd_log(NDLOG_DBG, "Save the HIWARE new Session key. | [%s]", sDataEnv_var);

		const char *master_session_type = pam_getenv(pamh, HIWARE_PAM_BAK_SESSIONTYPE);
#if 0
		if (master_session_type)
   			put_env_with_log(pamh, HIWARE_PAM_BAK_SESSIONTYPE_FORMAT, master_session_type, "Copy original HIWARE Session Type");
#endif

		if (master_session_type == NULL)
			master_session_type = getenv(HIWARE_PAM_BAK_SESSIONTYPE);

		if (master_session_type != NULL)
		{
			snprintf(sDataEnv_var, sizeof(sDataEnv_var), HIWARE_PAM_BAK_SESSIONTYPE_FORMAT, master_session_type);
			pam_putenv(pamh, sDataEnv_var);

			nd_log(NDLOG_DBG, "Copy the Origin HIWARE Session Type to New Session. | [%s]", sDataEnv_var);
		}
		// const char *
		// HIWARE_RUN_MODE
		const char *sam_run_mode = pam_getenv(pamh, HIWARE_SAM_BAK_RUNMODE);
		if (sam_run_mode == NULL)
			sam_run_mode = getenv(HIWARE_SAM_BAK_RUNMODE);

		if (sam_run_mode != NULL)
		{
			memset(sDataEnv_var, 0x00, sizeof(sDataEnv_var));
			snprintf(sDataEnv_var, sizeof(sDataEnv_var), HIWARE_SAM_BAK_RUNMODE_FORMAT, sam_run_mode);
			pam_putenv(pamh, sDataEnv_var);

			nd_log(NDLOG_DBG, "Copy the origin NdShell run mode to the new session. | [%s]", sDataEnv_var);
		}

		nd_log(NDLOG_TRC, "====================================================================");
		nd_log(NDLOG_TRC, "[get su session information]");
		nd_log(NDLOG_TRC, "--------------------------------------------------------------------");
		nd_log(NDLOG_DBG, "# session type : su");
		nd_log(NDLOG_DBG, "# agtConnFormTpCode : %s", logItem.agtConnFormTpCode);
		nd_log(NDLOG_DBG, "# user Ip : %s", logItem.userIp);
		nd_log(NDLOG_DBG, "# connAcctId : %s", logItem.connAcctId);
		nd_log(NDLOG_DBG, "# switchAcctId : %s", logItem.switchAcctId);
		nd_log(NDLOG_DBG, "# securStepNo : %s", logItem.securStepNo);
		nd_log(NDLOG_DBG, "# pamCertDtlCode : %s", logItem.pamCertDtlCode);
		nd_log(NDLOG_DBG, "# pamCertDtlAuthCode : %s", logItem.pamCertDtlAuthCode);
		nd_log(NDLOG_TRC, "--------------------------------------------------------------------");

		isSuSession = true;

		if (strcmp(info->remote_host, "localhost") == 0)
		{
			pid_t parent_pid = getppid();
			const char *parent_clientIp = read_env_variable(parent_pid, "HIWARE_SSH_CLIENT_IP");

			if (parent_clientIp != NULL)
			{
				strcpy(info->remote_host, parent_clientIp);
			}
			else
			{
				strcpy(info->remote_host, "127.0.0.1");
			}
		}

		const char *su_pam_agt_authno = pam_getenv(pamh, PAM_BAK_SU_PAM_AGT_AUTHNO);
		if (su_pam_agt_authno == NULL)
		{
			su_pam_agt_authno = getenv(PAM_BAK_SU_PAM_AGT_AUTHNO);
#if 0
			if (su_pam_agt_authno != NULL)
			{
				nd_log(NDLOG_DBG, "Get the Origin PAM AuthNo to the Env: %s", su_pam_agt_authno);

				pam_env = malloc(strlen(PAM_BAK_PAM_AGT_AUTHNO_FORMAT) + strlen(su_pam_agt_authno) + 1);
				if (pam_env) {
					sprintf(pam_env, PAM_BAK_PAM_AGT_AUTHNO_FORMAT, su_pam_agt_authno);
					pam_putenv(pamh, pam_env);
					envflags |= FLAG_PAM_AUTHNO;
				}
				free (pam_env);
			}
#endif
		}

		const char *su_sam_agt_authno = pam_getenv(pamh, PAM_BAK_SU_SAM_AGT_AUTHNO);
		if (su_sam_agt_authno == NULL)
		{
			su_sam_agt_authno = getenv(PAM_BAK_SU_SAM_AGT_AUTHNO);

			nd_log(NDLOG_DBG, "Get the Origin SAM AuthNo to the Env: %s", su_pam_agt_authno);


		}

		time_t current_time = time(NULL);
		struct tm *tm_info = localtime(&current_time);
		int current_wday = tm_info->tm_wday == 0 ? 7 : tm_info->tm_wday; // Adjust for Sunday being 7

		nd_log(NDLOG_DBG, "Retrieving time data for policy inspection. | time: %s | wday: %d", ctime(&current_time), current_wday);

		if (su_sam_agt_authno)
		{
			//snprintf(logItem.agtAuthNo, sizeof(logItem.agtAuthNo), "%s", su_sam_agt_authno);
#if 0			
			if (!check_sam_su_policy(getPamRuleFilePath(sDataHomeDir), logItem.switchAcctId, su_sam_agt_authno, current_time, current_wday, &sam_logging))
#endif
			if (!check_sam_su_policy(getPamSessionBakRuleFilePath(sDataHomeDir, logItem.svrConnSessKey), 
						logItem.switchAcctId, su_sam_agt_authno, current_time, current_wday, &sam_logging))				 
			{
				snprintf(logItem.svrConnFailRsnCode, sizeof(logItem.svrConnFailRsnCode), PAM_SVR_FAIL_OS_AUTH_FAIL);
				snprintf(logItem.securStepNo, sizeof(logItem.securStepNo), "%s", PAM_SECUR_STEP_NDSHELL);
				snprintf(logItem.svrConnRstTpCode, sizeof(logItem.svrConnRstTpCode), "%s", PAM_AUTH_FAIL);
				snprintf(logItem.pamCertDtlAuthCode, sizeof(logItem.pamCertDtlAuthCode), "%s", PAM_CERT_DTL_AUTH_SAM_RULE);

				/**/
				nd_log(NDLOG_TRC, "PAM policy verification completed - Blocked by SAM policy.(%s)", info->current_user);

				/**/
				nd_log(NDLOG_ERR, "[HIW-AGT-PAM-PMER-000001] Access denied due to SAM-policy | User: %s | Remote Host: %s | Terminal: %s | AuthNo: %s", 
						info->current_user, logItem.userIp, tty, su_sam_agt_authno);

				retval = PAM_PERM_DENIED;
				goto pam_sm_auth_ex;
			}

			snprintf(logItem.agtAuthNo, sizeof(logItem.agtAuthNo), "%s", su_sam_agt_authno);
			snprintf(logItem.svrConnRstTpCode, sizeof(logItem.svrConnRstTpCode), "%s", PAM_AUTH_SUCCESS);
			snprintf(logItem.securStepNo, sizeof(logItem.securStepNo), "%s", PAM_SECUR_STEP_NDSHELL);
			bRetSamPolicy = true;

			/**/
			nd_log(NDLOG_TRC, "PAM policy verification completed - Allowed by PAM & SAM policy.(%s)", info->current_user);

			/**/
			nd_log(NDLOG_INF, "[NDA-PAM] Access granted by SAM-policy | User: %s | Remote Host: %s | Terminal: %s | AuthNo: %s", 
					info->current_user, logItem.userIp, tty, su_sam_agt_authno);

			memset(sDataEnv_var, 0x00, sizeof(sDataEnv_var));

			snprintf(sDataEnv_var, sizeof(sDataEnv_var), HIWARE_SU_SAM_AGT_AUTHNO_FORMAT, su_sam_agt_authno ? su_sam_agt_authno : "");
			pam_putenv(pamh, sDataEnv_var);
#ifdef _USE_BITMASK_BACKUP_
			sam_env = malloc(strlen(PAM_BAK_SAM_AGT_AUTHNO_FORMAT) + strlen(logItem.agtAuthNo));
			if (sam_env) {
				sprintf(sam_env, PAM_BAK_SAM_AGT_AUTHNO_FORMAT, logItem.agtAuthNo);
				int ret = pam_putenv(pamh, sam_env);
				envflags |= FLAG_SAM_AUTHNO;
			}                                                                                                                                                                              free (sam_env);
#endif //_USE_BITMASK_BACKUP_
			retval = PAM_SUCCESS;
		}

		if (su_pam_agt_authno)
		{
			snprintf(logItem.pamAgtAuthNo, sizeof(logItem.pamAgtAuthNo), "%s", su_pam_agt_authno);
#if 0
			if (!check_pam_su_policy(getPamRuleFilePath(sDataHomeDir), info->current_user, su_pam_agt_authno, current_time, current_wday, &pam_logging))
#endif
			if (!check_pam_su_policy(getPamSessionBakRuleFilePath(sDataHomeDir, logItem.svrConnSessKey), 
						info->current_user, su_pam_agt_authno, current_time, current_wday, &pam_logging))
			{
				snprintf(logItem.svrConnFailRsnCode, sizeof(logItem.svrConnFailRsnCode), PAM_SVR_FAIL_OS_AUTH_FAIL);
				snprintf(logItem.securStepNo, sizeof(logItem.securStepNo), "%s", PAM_SECUR_STEP_PAM);
				snprintf(logItem.svrConnRstTpCode, sizeof(logItem.svrConnRstTpCode), "%s", PAM_AUTH_FAIL);
				snprintf(logItem.pamCertDtlAuthCode, sizeof(logItem.pamCertDtlAuthCode), "%s", PAM_CERT_DTL_AUTH_PAM_RULE);

				/**/
				nd_log(NDLOG_TRC, "PAM Policy verification failed. - Blocked by PAM policy.(%s)", info->current_user);

				/**/
				nd_log(NDLOG_ERR, "[HIW-AGT-PAM-PMER-000002] Access denied due to PAM-policy | User: %s | Remote Host: %s | Terminal: %s | AuthNo: %s", 
						info->current_user, logItem.userIp, tty, su_pam_agt_authno);

				pam_logging = true;

				retval = PAM_PERM_DENIED;
				goto pam_sm_auth_ex;
			}

			snprintf(logItem.svrConnRstTpCode, sizeof(logItem.svrConnRstTpCode), "%s", PAM_AUTH_SUCCESS);
			snprintf(logItem.securStepNo, sizeof(logItem.securStepNo), "%s", PAM_SECUR_STEP_PAM);

			bRetPamPolicy = true;

			/**/
			nd_log(NDLOG_INF, "[NDA-PAM] Access granted by PAM-policy | User: %s | Remote Host: %s | Terminal: %s | AuthNo: %s", 
					info->current_user, logItem.userIp, tty, su_pam_agt_authno);

			memset(sDataEnv_var, 0x00, sizeof(sDataEnv_var));
			snprintf(sDataEnv_var, sizeof(sDataEnv_var), HIWARE_SU_PAM_AGT_AUTHNO_FORMAT, su_pam_agt_authno ? su_pam_agt_authno : "");
			pam_putenv(pamh, sDataEnv_var);
#ifdef _USE_BITMASK_BACKUP_
			pam_env = malloc(strlen(PAM_BAK_PAM_AGT_AUTHNO_FORMAT) + strlen(logItem.pamAgtAuthNo));
			if (pam_env) {
				sprintf(pam_env, PAM_BAK_PAM_AGT_AUTHNO_FORMAT, logItem.pamAgtAuthNo);
				pam_putenv(pamh, pam_env);

				envflags |= FLAG_PAM_AUTHNO;
			}

			free (pam_env);
#endif //_USE_BITMASK_BACKUP_
			retval = PAM_SUCCESS;
		}

		snprintf(pamCertTpCode, sizeof(pamCertTpCode), "%s", PAM_SU_LOGIN);

		/**/
		nd_log(NDLOG_INF, "[NDA-PAM] 'su' operation successful | User switched to: %s | Terminal: %s | Remote Host: %s", 
				logItem.connAcctId, tty, logItem.userIp);
#ifdef _USE_BITMASK_BACKUP_
		char flag_str[16];
                snprintf(flag_str, sizeof(flag_str), "RECODE_FLAG=%u", envflags);
                int ret = pam_putenv(pamh, flag_str);
#endif //_USE_BITMASK_BACKUP_

		retval = PAM_SUCCESS;

		nd_log(NDLOG_TRC, "[PAM POLICY] SESSION KEY OUTPUT LAST AFTER: %s", sessionkey);
		goto pam_sm_auth_ex;
	}
	else
	{
		/**/
		nd_log(NDLOG_TRC, "Session Type Detected: CONSOLE. The current session is operating in console mode with interactive privileges.");

		info = get_console_session_info(pamh);
		snprintf(logItem.userIp, sizeof(logItem.userIp), "%s", info->remote_host);
		snprintf(logItem.connAcctId, sizeof(logItem.connAcctId), "%s", info->current_user);
		snprintf(logItem.agtNo, sizeof(logItem.agtNo), "%s", agent_id);
		snprintf(logItem.agtConnFormTpCode, sizeof(logItem.agtConnFormTpCode), "%s", PAM_CONN_CONSOLE);
		snprintf(logItem.securStepNo, sizeof(logItem.securStepNo), "%s", PAM_SECUR_STEP_PAM);
		snprintf(logItem.pamCertDtlCode, sizeof(logItem.pamCertDtlCode), "%s", PAM_SU_LOGIN);

		/**/
		nd_log(NDLOG_INF, "[NDA-PAM] Console session started | User: %s | Terminal: %s", logItem.connAcctId, tty);

		const char *service;
		retval = pam_get_item(pamh, PAM_SERVICE, (const void **)&service);
		if (retval != PAM_SUCCESS)
		{

			/**/
			nd_log(NDLOG_TRC, "failed to get service information...[pam_get_item:service]");

			/**/
			nd_log(NDLOG_ERR, "[HIW-AGT-PAM-CONF-000002] ERROR: Failed to retrieve service using pam_get_item(). Error code: %d", retval);
			return retval;
		}

		/*
			// Proceed with processing if the entered command is either 'su' or 'su -l'. Detect both cases based on the usage of the 'su' command.
		*/
		nd_log(NDLOG_TRC, "Proceed with processing if the entered command is either 'su' or 'su -l'. Detect both cases based on the usage of the 'su' command.");
		if (service != NULL && (strcmp(service, STR_SU) == 0 || strcmp(service, STR_SUL) == 0))
		{
			/*
			 *	retrieve master session key from environment variable
			 */
			const char *sessionkey = pam_getenv(pamh, ENV_HIWARE_SESSIONKEY);
			if (sessionkey == NULL)
				sessionkey = getenv(ENV_HIWARE_SESSIONKEY);

			nd_log(NDLOG_DBG, "Get the Origin session key to the Env: %s", sessionkey);

			/*
			 *	create a session key for the new su login context
			 */
			snprintf(logItem.svrConnSessKey, sizeof(logItem.svrConnSessKey), "%s", sessionkey ? sessionkey : "");
			memset(uuid_str, 0x00, sizeof(logItem.svrConnSessKey));
			snprintf(uuid_str, sizeof(logItem.svrConnSessKey), "%s", sessionkey);

			/*
			 *	retrieve pre-su-session key from environment variable 
			 */
			const char *presessionkey = pam_getenv(pamh, ENV_HIWARE_SU_SESSIONKEY);
			if (presessionkey == NULL)
				presessionkey = getenv(ENV_HIWARE_SU_SESSIONKEY);

			/*
			 *	check for existing su session key and save it as pre-su-session key in the environment
			 */
			if (presessionkey != NULL)
			{
				memset(sDataEnv_var, 0x00, sizeof(sDataEnv_var));
				snprintf(sDataEnv_var, sizeof(sDataEnv_var), HIWARE_PRE_SU_SESSION_KEY_FORMAT, presessionkey ? presessionkey : "");
				pam_putenv(pamh, sDataEnv_var);

				nd_log(NDLOG_DBG, "Get the Origin pre session key to the Env: %s", presessionkey);

				snprintf(logItem.svrConnPreSuSessKeyNo, sizeof(logItem.svrConnPreSuSessKeyNo), "%s", presessionkey ? presessionkey : "");
			}

			const char *master_session_type = pam_getenv(pamh, HIWARE_PAM_BAK_SESSIONTYPE);
			if (master_session_type == NULL)
				master_session_type = getenv(HIWARE_PAM_BAK_SESSIONTYPE);

			if (master_session_type != NULL)
			{
				memset(sDataEnv_var, 0x00, sizeof(sDataEnv_var));
				snprintf(sDataEnv_var, sizeof(sDataEnv_var), HIWARE_PAM_BAK_SESSIONTYPE_FORMAT, master_session_type);
				pam_putenv(pamh, sDataEnv_var);

				nd_log(NDLOG_DBG, "Get the Origin pam session type to the Env: %s", master_session_type);
			}

			const char *su_pam_agt_authno = pam_getenv(pamh, PAM_BAK_SU_PAM_AGT_AUTHNO);
			if (su_pam_agt_authno == NULL)
			{
				su_pam_agt_authno = getenv(PAM_BAK_SU_PAM_AGT_AUTHNO);
			}

			if (su_pam_agt_authno != NULL)
			{
				nd_log(NDLOG_DBG, "Get the Origin pam agtno to the Env: %s", su_pam_agt_authno);
			}

			const char *su_sam_agt_authno = pam_getenv(pamh, PAM_BAK_SU_SAM_AGT_AUTHNO);
			if (su_sam_agt_authno == NULL)
			{
				su_sam_agt_authno = getenv(PAM_BAK_SU_SAM_AGT_AUTHNO);
			}

			if (su_sam_agt_authno != NULL)
			{
				nd_log(NDLOG_DBG, "Get the Origin sam agtno to the Env: %s", su_sam_agt_authno);
			}

			time_t current_time = time(NULL);
			struct tm *tm_info = localtime(&current_time);
			int current_wday = tm_info->tm_wday == 0 ? 7 : tm_info->tm_wday; // Adjust for Sunday being 7

			nd_log(NDLOG_DBG, "Retrieving time data for policy inspection. | time: %s | wday: %d", ctime(&current_time), current_wday);

			if (su_sam_agt_authno)
			{
				//PAM_BAK_SAM_AGT_AUTHNO
				snprintf(logItem.agtAuthNo, sizeof(logItem.agtAuthNo), "%s", su_sam_agt_authno);
				if (!check_sam_su_policy(getPamRuleFilePath(sDataHomeDir), info->current_user, su_sam_agt_authno, 
							current_time, current_wday, &sam_logging))
				{
					snprintf(logItem.svrConnFailRsnCode, sizeof(logItem.svrConnFailRsnCode), PAM_SVR_FAIL_OS_AUTH_FAIL);
					snprintf(logItem.securStepNo, sizeof(logItem.securStepNo), "%s", PAM_SECUR_STEP_NDSHELL);
					snprintf(logItem.svrConnRstTpCode, sizeof(logItem.svrConnRstTpCode), "%s", PAM_AUTH_FAIL);
					snprintf(logItem.pamCertDtlAuthCode, sizeof(logItem.pamCertDtlAuthCode), "%s", PAM_CERT_DTL_AUTH_SAM_RULE);

					/**/
					nd_log(NDLOG_INF, 
						"PAM policy verification completed - Blocked by SAM policy.(%s)", 
						info->current_user);

					/**/
					nd_log(NDLOG_ERR, 
						"[HIW-AGT-PAM-PMER-000001] Access denied due to SAM-policy | User: %s | Remote Host: %s | Terminal: %s | AuthNo: %s", 
						info->current_user, "127.0.0.1", "su", su_sam_agt_authno);

					retval = PAM_PERM_DENIED;
					goto pam_sm_auth_ex;
				}

				snprintf(logItem.svrConnRstTpCode, sizeof(logItem.svrConnRstTpCode), "%s", PAM_AUTH_SUCCESS);
				snprintf(logItem.securStepNo, sizeof(logItem.securStepNo), "%s", PAM_SECUR_STEP_NDSHELL);
				bRetSamPolicy = true;

				/**/
				nd_log(NDLOG_TRC, "PAM policy verification completed - Allowed by PAM & SAM policy.(%s)", info->current_user);

				/**/
				nd_log(NDLOG_INF, "[HIW-AGT-PAM-PMER-000002] Access granted by PAM-policy | User: %s | Remote Host: %s | Terminal: %s | AuthNo: %s", 
						info->current_user, "127.0.0.1", "su", su_sam_agt_authno);

				retval = PAM_SUCCESS;
			}

			if (su_pam_agt_authno)
			{
				snprintf(logItem.pamAgtAuthNo, sizeof(logItem.pamAgtAuthNo), "%s", su_pam_agt_authno);
				if (!check_pam_su_policy(getPamRuleFilePath(sDataHomeDir), info->current_user, su_pam_agt_authno, current_time, current_wday, &pam_logging))
				{
					snprintf(logItem.svrConnFailRsnCode, sizeof(logItem.svrConnFailRsnCode), PAM_SVR_FAIL_OS_AUTH_FAIL);
					snprintf(logItem.svrConnRstTpCode, sizeof(logItem.svrConnRstTpCode), "%s", PAM_AUTH_FAIL);
					snprintf(logItem.pamCertDtlAuthCode, sizeof(logItem.pamCertDtlAuthCode), "%s", PAM_CERT_DTL_AUTH_PAM_RULE);

					/**/
					nd_log(NDLOG_TRC, "PAM Policy verification failed. - Blocked by PAM policy.(%s)", info->current_user);

					/**/
					nd_log(NDLOG_ERR, "[HIW-AGT-PAM-PMER-000002] Access denied due to PAM-policy | User: %s | Remote Host: %s | Terminal: %s | AuthNo: %s", info->current_user, "127.0.0.1", "su", su_pam_agt_authno);

					retval = PAM_PERM_DENIED;
					goto pam_sm_auth_ex;
				}

				snprintf(logItem.svrConnRstTpCode, sizeof(logItem.svrConnRstTpCode), "%s", PAM_AUTH_SUCCESS);
				snprintf(logItem.securStepNo, sizeof(logItem.securStepNo), "%s", PAM_SECUR_STEP_PAM);

				bRetPamPolicy = true;

				/**/
				nd_log(NDLOG_TRC, "PAM Policy verification was successful.(%s)", info->current_user);

				/**/
				nd_log(NDLOG_INF, "[NDA-PAM] Access granted by PAM-policy | User: %s | Remote Host: %s | Terminal: %s | AuthNo: %s", 
						info->current_user, "127.0.0.1", "su", su_pam_agt_authno);

				retval = PAM_SUCCESS;
			}

			// CREATE NEW SU SESSION KEY
			su_uuid_str = generate_uuid();
			snprintf(logItem.svrConnSuSessKeyNo, sizeof(logItem.svrConnSuSessKeyNo), "%s", su_uuid_str ? su_uuid_str : "");
			memset(sDataEnv_var, 0x00, sizeof(sDataEnv_var));

			snprintf(sDataEnv_var, sizeof(sDataEnv_var), HIWARE_SU_SESSION_KEY_FORMAT, su_uuid_str ? su_uuid_str : "");
			pam_putenv(pamh, sDataEnv_var);

			/**/
			nd_log(NDLOG_TRC, "Create new su session key: %s", logItem.svrConnSessKey);

			/**/
			nd_log(NDLOG_INF, "[PAM] Authentication successful | User: %s | Remote Host: %s | Terminal: %s", logItem.connAcctId, "127.0.0.1", "su");
		}
		else
		{
			retval = nd_pam_authenticate_user(uuid_str, info, pamh);
			if (retval != PAM_SUCCESS)
			{
				/**/
				nd_log(NDLOG_ERR, "[HIW-AGT-PAM-AUTH-000003] pam_sm_authenticate::nd_pam_authenticate_user failed...");
				return retval;
			}

			/**/
			nd_log(NDLOG_INF, "[console] Additional authentication was successful, and the overall login process was completed successfully.");

			char bak_sess_pol_dir[1024] = {0,};
			char sess_pol_file[1024] = {0,};
			sprintf (bak_sess_pol_dir, "/%s/rule/%s", sDataHomeDir, uuid_str);
			sprintf (sess_pol_file, "/%s/rule/%s", sDataHomeDir,COMMON_RULE_FILE);

			// If the check value(pam_opermode) is not 1, no further action is taken  << (expected)
			copy_file_to_folder (sess_pol_file, bak_sess_pol_dir);

			retval = PAM_SUCCESS;
		}
	}

pam_sm_auth_ex:

	if (pam_logging == LOGGING_ON)
	{
#ifdef _USE_BITMASK_BACKUP_
                if (pam_opermode == 1)
                        envflags |= FLAG_OPERATION_MODE;

                envflags != FLAG_PAM_LOGGING;
                if (sam_logging == 1)
                        envflags |= FLAG_SAM_LOGGING;
#endif //_USE_BITMASK_BACKUP_
#if 0
		pam_env = malloc(strlen(PAM_BAK_PAM_AGT_AUTHNO_FORMAT) + strlen(logItem.pamAgtAuthNo));
                if (pam_env) {
                        sprintf(pam_env, PAM_BAK_PAM_AGT_AUTHNO_FORMAT, logItem.pamAgtAuthNo);
                        pam_putenv(pamh, pam_env);

                        envflags |= FLAG_PAM_AUTHNO;
                }

                free (pam_env);
#endif
#ifdef _USE_BITMASK_BACKUP_
                char flag_str[128];
                snprintf(flag_str, sizeof(flag_str), "RECODE_FLAG=%u", envflags);
                int ret = pam_putenv(pamh, flag_str);
                if (ret != PAM_SUCCESS) {
                        //ERROR MESSAGE
			const char *error_msg = pam_strerror(pamh, ret);
			nd_log(NDLOG_TRC, "pam_putenv error: %s\n", error_msg);
                }
#endif //_USE_BITMASK_BACKUP_
		snprintf(logItem.svrConnSessKey, /*sizeof(logItem.svrConnSessKey)*/sizeof(logItem.svrConnSessKey), "%s", uuid_str ? uuid_str : "");

		if (strcmp(logItem.pamCertDtlCode, PAM_SU_LOGIN) == 0 || strcmp(logItem.pamCertDtlCode, PAM_SU_LOGOUT) == 0)
			snprintf(logItem.pamCertDtlAuthCode, sizeof(logItem.pamCertDtlAuthCode), PAM_CERT_DTL_AUTH_SU_RULE);

		const char *master_session_type = NULL;
		master_session_type = pam_getenv(pamh, HIWARE_PAM_BAK_SESSIONTYPE);
		if (master_session_type == NULL)
			master_session_type = getenv(HIWARE_PAM_BAK_SESSIONTYPE);

		if (master_session_type != NULL)
		{
			snprintf(logItem.agtConnFormTpCode, sizeof(logItem.agtConnFormTpCode), "%s", master_session_type);
		}
		
		logitem = create_archive_log(logItem.svrConnStartTime,
									 logItem.svrConnEndTime,
									 logItem.svrConnRstTpCode,
									 logItem.svrConnFailRsnCode,
									 logItem.agtNo,
									 logItem.agtConnFormTpCode,
									 logItem.agtAuthNo,
									 logItem.portNo,
									 logItem.userIp,
									 logItem.securStepNo,
									 logItem.svrConnSessKey,
									 logItem.svrConnSuSessKeyNo,
									 logItem.svrConnPreSuSessKeyNo,
									 logItem.connAcctId,
									 logItem.switchAcctId,
									 logItem.pamAgtAuthNo,
									 logItem.userNo,
									 logItem.pamCertDtlCode,
									 logItem.pamCertDtlAuthCode,
									 logItem.certTpCode,
									 logItem.certAppTpCode,
									 logItem.certSucesFailYn,
									 logItem.certStepSeqNo);

		nd_pam_archive_log(header, *logitem, (char *)sDataHomeDir);
		free_archive_log(logitem);
	}

	if (info)
		free_session_info(info);

	free((void *)agent_id);

	return retval;
};

/*
		//Function Definition of Linux PAM Module [pam_sm_setcred]
*/
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags,
							  int argc, const char **argv)
{
	(void)pamh;
	(void)flags;
	(void)argc;
	(void)argv;
	return PAM_SUCCESS;
}

/*
		//Function Definition of Linux PAM Module [pam_sm_acct_mgmt]
*/
/*
PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags,
							   int argc, const char **argv) {

	return PAM_SUCCESS;
}
*/
/*
		//Function Definition of Linux PAM Module [pam_sm_open_session]
*/
PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags,
								   int argc, const char **argv)
{
	(void)flags;
	(void)argc;
	(void)argv;

	SessionInfo *info = NULL;
	char sDataEnv_var[MAX_ENV_STR_LEN];

	bool bIsConsole = false;
	struct st_pam_conf pam_conf;
	const char *sDataHomeDir = pam_getenv(pamh, ENV_HIWARE_HOME);
	if (sDataHomeDir == NULL)
		sDataHomeDir = strdup(PRODUCT_NM);

	if (sDataHomeDir != NULL)
		g_sDataRootDir = strdup(sDataHomeDir);

	if (g_sConfFilePath == NULL)
		g_sConfFilePath = strdup(getPamConfFilePath(sDataHomeDir));

	system("clear");
	const char *tty = get_pam_item_str(pamh, PAM_TTY);
	if (tty && strstr(tty, "ssh") || tty && strstr(tty, "pts"))
	{

		bIsConsole = false;
	}
	else
		bIsConsole = true;

	parse_ssh_connection(pamh, bIsConsole);

	const char *ssh_connection = pam_getenv(pamh, "SSH_CONNECTION");
	if (bIsConsole == true)
	{
		snprintf(sDataEnv_var, sizeof(sDataEnv_var), HIWARE_SSH_CLIENT_IP, "127.0.0.1");
		pam_putenv(pamh, sDataEnv_var);
	}

	else
	{
		if (ssh_connection == NULL)
		{

			if (tty && strstr(tty, "ssh"))
			{
				info = get_ssh_session_info(pamh);
			}
			else if (tty && strstr(tty, "pts"))
			{
				info = get_su_session_info(pamh);
			}
			snprintf(sDataEnv_var, sizeof(sDataEnv_var), HIWARE_SSH_CLIENT_IP, info->remote_host);
			pam_putenv(pamh, sDataEnv_var);

			snprintf(sDataEnv_var, sizeof(sDataEnv_var), HIWARE_SSH_SERVER_PORT2, get_ssh_listening_port());
			pam_putenv(pamh, sDataEnv_var);
		}
	}

	return PAM_SUCCESS;
}

/*
		//Function Definition of Linux PAM Module [pam_sm_close_session]
*/
PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags,
									int argc, const char **argv)
{

	(void)argc;
	(void)argv;
	(void)flags;

	char bak_sess_pol_dir[1024] = {0,};
	char pamAgtAuthNo[ND_AGTAUTHNO_MAX_LEN] = {0,};
	char agtAuthNo[ND_AGTAUTHNO_MAX_LEN] = {0,};
	char agtNo[16] = {0,};
	char agt_auth_Number[4] = {0,};
	char pamCertDtlCode[4] = {0,};
	char pamCertDtlAuthCode[4] = {0,};
	char agtConnFormTpCode[4] = {0,};
	char securStepNo[ND_SECUR_STEP_NO_MAX_LEN] = {0,};
	char pamCertTpCode[4] = {0,};
	int pam_pri_no, pam_action, pam_logging, sam_pri_no, sam_action, sam_logging;
	char *agt_auth_no = NULL, *ndshell_agtAuthNo = NULL;

	bool isConsole = NULL;
	SessionInfo *info = NULL;
	struct _archive_log *logitem;
	struct st_pam_conf pam_conf;

	const char *service = get_pam_item_str(pamh, PAM_SERVICE);
	const char *tty = get_pam_item_str(pamh, PAM_TTY);
	const char *rhost = get_pam_item_str(pamh, PAM_RHOST);
	const char *user = get_pam_item_str(pamh, PAM_USER);

	nd_log(NDLOG_TRC, "pam_sm_close_session function start.");

	struct _msg_header_ header = {

		.iMsgTotalSize = 0};

	/*
		// get pam config
	*/
	const char *sDataHomeDir = pam_getenv(pamh, ENV_HIWARE_HOME);
	if (sDataHomeDir == NULL)
		sDataHomeDir = strdup(PRODUCT_NM);

	if (sDataHomeDir != NULL)
		g_sDataRootDir = strdup(sDataHomeDir);

	if (g_sConfFilePath == NULL)
		g_sConfFilePath = strdup(getPamConfFilePath(sDataHomeDir));

	getpamconf(&pam_conf);
	g_sDataHiwareUserNumber = pam_getenv(pamh, "HIWARE_USER_NUMBER");
	if (g_sDataHiwareUserNumber == NULL)
		g_sDataHiwareUserNumber = getenv("HIWARE_USER_NUMBER");

	//int pri_no, action, logging;
	const char *agent_id = get_value_as_string(getPamRuleFilePath(sDataHomeDir), "agentId");
	const char *sessionkey = pam_getenv(pamh, ENV_HIWARE_SESSIONKEY);
	const char *su_sessionkey = pam_getenv(pamh, ENV_HIWARE_SU_SESSIONKEY);
	const char *su_presessionkey = pam_getenv(pamh, ENV_HIWARE_PRE_SU_SESSIONKEY);
	const char *pam_loast_auth = pam_getenv(pamh, PAM_BAK_LAST_AUTH);
	const char *pam_env_AuthNo = pam_getenv(pamh, PAM_BAK_PAM_AGT_AUTHNO);
	const char *sam_env_AuthNo = pam_getenv(pamh, PAM_BAK_SAM_AGT_AUTHNO);
	const char *flag_str = pam_getenv(pamh, "RECODE_FLAG");

	g_nDataSshPort = get_ssh_listening_port();

	if (agent_id == NULL)
	{
		//(LOG_ERR, "pam_sm_close_session agent_id NULL");
	}

	if (sessionkey == NULL)
	{
		sessionkey = getenv(ENV_HIWARE_SESSIONKEY);
	}

	if (pam_loast_auth == NULL)
	{
		pam_loast_auth = getenv(PAM_BAK_LAST_AUTH);
	}

	snprintf(pamCertDtlCode, sizeof(pamCertDtlCode), "%s", PAM_LOGOUT);

	// Determine session type and call corresponding function
	if (tty && strstr(tty, "ssh"))
	{
		info = get_ssh_session_info(pamh);
		snprintf(pamCertTpCode, sizeof(pamCertDtlCode), "%s", PAM_LOGOUT);
	}
	else if (tty && strstr(tty, "pts"))
	{
		info = get_su_session_info(pamh);
		snprintf(pamCertTpCode, sizeof(pamCertDtlCode), "%s", PAM_SU_LOGOUT);
	}
	else
	{
		info = get_console_session_info(pamh);
		snprintf(agtConnFormTpCode, sizeof(agtConnFormTpCode), "%s", PAM_CONN_CONSOLE);
		const char *service;
		int retval = pam_get_item(pamh, PAM_SERVICE, (const void **)&service);
		if (retval != PAM_SUCCESS)
		{
			//   return retval;
		}
		snprintf(pamCertTpCode, sizeof(pamCertDtlCode), "%s", PAM_LOGOUT);

		if (service != NULL && (strcmp(service, STR_SU) == 0 || strcmp(service, STR_SUL) == 0))
		{
			snprintf(pamCertTpCode, sizeof(pamCertTpCode), "%s", PAM_SU_LOGOUT);
		}
	}

	snprintf(agtConnFormTpCode, sizeof(agtConnFormTpCode), "%s", (info->type == 1) ? PAM_CONN_CONSOLE : PAM_CONN_BYPASS);

	if (validate_json_exceptionConnection(getPamRuleFilePath(sDataHomeDir), info->remote_host) == 1)
		return PAM_SUCCESS;

	int pam_opermode = is_pam_oper_mode(sDataHomeDir);
	int sam_opermode = is_sam_oper_mode(sDataHomeDir);

#ifdef _SUPP_DATE_
	time_t current_time = time(NULL);
	struct tm *tm_info = localtime(&current_time);
	int current_wday = tm_info->tm_wday == 0 ? 7 : tm_info->tm_wday; // Adjust for Sunday being 7

	nd_log(NDLOG_TRC, "Starting the SAM-policy check.");

	snprintf(securStepNo, sizeof(securStepNo), "%s", PAM_SECUR_STEP_PAM);

	if (sam_opermode == 1 && is_pam_user_ndshell(pamh) &&
		validate_json_sampolicy(/*getPamRuleFilePath(sDataHomeDir)*/getPamSessionBakRuleFilePath(sDataHomeDir, sessionkey), 
				info->remote_host, info->current_user, current_time, current_wday, &ndshell_agtAuthNo, &sam_action, &sam_logging) == 1)
#else  //_SUPP_DATE_
	if (is_pam_user_ndshell(pamh) &&
		validate_json_sampolicy_without_date(/*getPamRuleFilePath(sDataHomeDir)*/getPamSessionBakRuleFilePath(sDataHomeDir, sessionkey), 
			info->remote_host, info->current_user, &ndshell_agtAuthNo, &sam_action, &sam_logging) == 1)
#endif //_SUPP_DATE_
	{
		snprintf(securStepNo, sizeof(securStepNo), "%s", PAM_SECUR_STEP_NDSHELL);
	}

	snprintf(agtAuthNo, sizeof(agtAuthNo), "%s", ndshell_agtAuthNo ? ndshell_agtAuthNo : "");

	if (pam_opermode == 0)
	{
		goto pam_sm_close_session_fin;
	}

	nd_log(NDLOG_TRC, "Starting the PAM-policy check.");

	if (check_pam_policy(/*getPamRuleFilePath(sDataHomeDir)*/getPamSessionBakRuleFilePath(sDataHomeDir, sessionkey)	, 
				info->remote_host, info->current_user, current_time, current_wday, &agt_auth_no, &pam_action, &pam_logging) == 1)
	{
		snprintf(securStepNo, sizeof(securStepNo), "%s", PAM_SECUR_STEP_PAM);
	}

	snprintf(pamAgtAuthNo, sizeof(pamAgtAuthNo), "%s", agt_auth_no ? agt_auth_no : "");

	nd_log(NDLOG_INF, "[NDA-PAM] User session closed | User: %s | Remote Host: %s | Terminal: %s", info->current_user, info->remote_host, tty);

pam_sm_close_session_fin:
#ifdef _USE_BITMASK_BACKUP_
	if (flag_str)
        {
                unsigned int envflags = (unsigned int)strtoul(flag_str, NULL, 10);

                if (envflags & FLAG_OPERATION_MODE)
                        pam_opermode = MODE_ON;
                if (envflags & FLAG_PAM_LOGGING)
                        pam_logging  = LOGGING_ON;
                if (envflags & FLAG_SAM_LOGGING)
                        sam_logging  = LOGGING_ON;
                if (envflags & FLAG_SAM_AUTHNO && sam_env_AuthNo != NULL)
		{
			memset (agtAuthNo,0x00, sizeof(agtAuthNo));
			snprintf(agtAuthNo, sizeof(agtAuthNo), "%s", sam_env_AuthNo);
		}
		if (envflags & FLAG_PAM_AUTHNO && pam_env_AuthNo != NULL)
		{
			memset (pamAgtAuthNo, 0x00, sizeof (pamAgtAuthNo));
			snprintf (pamAgtAuthNo, sizeof(agtAuthNo), "%s", pam_env_AuthNo);
                }
        }
#endif //_USE_BITMASK_BACKUP_

        sprintf (bak_sess_pol_dir, "/%s/rule/%s", sDataHomeDir, sessionkey);
	if (strcmp(pamCertTpCode, PAM_SU_LOGOUT) != 0)
		delete_folder_and_files(bak_sess_pol_dir);

	if (sam_logging == LOGGING_ON || pam_logging == LOGGING_ON) // 1
	{
		if (strcmp(pamCertTpCode, PAM_SU_LOGIN) == 0 || strcmp(pamCertTpCode, PAM_SU_LOGOUT) == 0)
			snprintf(pamCertDtlAuthCode, sizeof(pamCertDtlAuthCode), PAM_CERT_DTL_AUTH_SU_RULE);
		else
			snprintf(pamCertDtlAuthCode, sizeof(pamCertDtlAuthCode), pam_loast_auth);

		const char *master_session_type = pam_getenv(pamh, HIWARE_PAM_BAK_SESSIONTYPE);
		if (master_session_type == NULL)
			master_session_type = getenv(HIWARE_PAM_BAK_SESSIONTYPE);

		if (master_session_type != NULL)
		{
			snprintf(agtConnFormTpCode, sizeof(agtConnFormTpCode), "%s", master_session_type);
		}

		logitem = create_archive_log("", "", PAM_AUTH_SUCCESS, "", agent_id, agtConnFormTpCode, agtAuthNo, "", info->remote_host, securStepNo,
									 sessionkey, su_sessionkey, su_presessionkey, info->current_user, "", pamAgtAuthNo, 
									 agent_id, pamCertTpCode, pamCertDtlAuthCode, "", "", "", "");
		nd_pam_archive_log(header, *logitem, (char *)sDataHomeDir);
		free_archive_log(logitem);
	}

	return PAM_SUCCESS;
}

/*
		//Function Definition of Linux PAM Module [pam_sm_chauthtok]
*/
PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags,
								int argc, const char **argv)
{

	(void)pamh;
	(void)flags;
	(void)argc;
	(void)argv;

	return PAM_SUCCESS;
}

__attribute__((constructor)) void init()
{

	struct timeval tv;
	gettimeofday(&tv, NULL);
	srand(tv.tv_usec);
	pthread_mutex_init(&session_id_mutex, NULL); // 뮤텍스 초기화
}

__attribute__((destructor)) void cleanup()
{
	pthread_mutex_destroy(&session_id_mutex); // 뮤텍스 정리
}
