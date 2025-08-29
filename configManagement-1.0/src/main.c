/* Copyright (c) 2017, The Linux Foundation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 *       copyright notice, this list of conditions and the following
 *       disclaimer in the documentation and/or other materials provided
 *       with the distribution.
 *     * Neither the name of The Linux Foundation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <time.h>
#include <sys/time.h>
#include <errno.h>
#include <stdio.h>
#include <syslog.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>

#include <vnpt/lib_vnpt.h>

#define RECV_SOCK_TIMEOUT 10
#define SERVER_SOCK_PATH  "/var/run/comm_ctrl_socket_server"
#define ON_LED_CTRL_MSG_NAME "ledControlON"
#define OFF_LED_CTRL_MSG_NAME "ledControlOFF"
#define TURN_ON_LED_CMD "rm -rf /var/run/onLedNow"
#define TURN_OFF_LED_CMD "echo 1 > /var/run/onLedNow"

#define TIMERESTRICTIONFILE "/etc/config/homewifi"
#define ONOFFLEDFILE "/etc/config/onoffled"
#define URLFILTERFILE "/etc/config/urlFilter"
#define URLFILTERFILE_RUNNING "/var/run/urlFilterChanged"
#define RESTORECONFIG "/var/run/restoreConfig"

int onLedTime[2] = {0};
int offLedTime[2] = {0};
int onoffStatus = 0;
int preStatusOn = 0;
int preStatusOff = 0;
int preOn = 0;
int gsockFd;
struct sockaddr_un gsevrAddr;
struct sockaddr_un gclientAddr;

typedef enum
{
    LED_OFF = 0,
    LED_ON = 1
} Led_Status_e;

typedef struct
{
    char name[32];
    char rule_day[32];
    char rule_start[8];
    char rule_stop[8];
    char macEntries;
    char rule_mac[4][24];
} Time_Res_Entry_s;


static int _parseCorrectName(char* p_input, int length)
{
    int i = 0;
    char tempVal[2048] = {0};

    int j = 0;

    while (i < length)
    {
        if(*(p_input + i) != '\'' && *(p_input + i) != '\r' && *(p_input + i) != '"'){
            tempVal[j] = *(p_input + i);
            j++;
        }
        i++;
    }

    tempVal[j] = '\0';
    memcpy(p_input, tempVal, j);
    *(p_input + j) = '\0';

    return 0;
}

static int _parseCorrectLine(char* p_input, int length)
{
    int i = 0;

    while (i < length)
    {
        if(*(p_input + i) == '\n'){
            *(p_input + i) = '\0';
            break;
        }

        if(*(p_input + i) == '\0'){
            break;
        }

        i++;
    }

    return 0;
}

static int _VNPT_parseTimeResEntries(Time_Res_Entry_s *p_timeResEntries)
{
    FILE *fp = NULL;
//    int rc = -1;
    char lineBuffer[256] = {0};
    int numberOfTR = 0;
    char temp[5][64] = {{0}};
    int i = 0;
    int numberOfMac = 0;

    fp = fopen(TIMERESTRICTIONFILE, "r");
    if (fp == NULL)
    {
        return 0;
    }

    while (fgets(lineBuffer, 256, fp))
    {
        if(strstr(lineBuffer, "config group"))
        {
            memset(lineBuffer, 0, sizeof lineBuffer);

            while(fgets(lineBuffer, 256, fp))
            {
                memset(temp[0], 0, 64);
                memset(temp[1], 0, 64);
                memset(temp[2], 0, 64);
                sscanf(lineBuffer, "%s %s %s", temp[0], temp[1], temp[2]);

                if (strcmp(temp[0], "option") != 0)
                {
                    break;
                }
                if (strcmp(temp[1], "name") == 0)
                {
                	_parseCorrectName(temp[2], strlen(temp[2]));
                	snprintf(p_timeResEntries[numberOfTR].name, sizeof p_timeResEntries[numberOfTR].name, "%s", temp[2]);
                }
                else if (strcmp(temp[1], "rule_day") == 0)
                {
                    _parseCorrectName(temp[2], strlen(temp[2]));
                    snprintf(p_timeResEntries[numberOfTR].rule_day, sizeof p_timeResEntries[numberOfTR].rule_day, "%s", temp[2]);

                }
                else if (strcmp(temp[1], "rule_start") == 0)
                {
                    _parseCorrectName(temp[2], strlen(temp[2]));
                    snprintf(p_timeResEntries[numberOfTR].rule_start, sizeof p_timeResEntries[numberOfTR].rule_start, "%s", temp[2]);
                }
                else if (strcmp(temp[1], "rule_stop") == 0)
                {
                    _parseCorrectName(temp[2], strlen(temp[2]));
                    snprintf(p_timeResEntries[numberOfTR].rule_stop, sizeof p_timeResEntries[numberOfTR].rule_stop, "%s", temp[2]);

                }
                else if (strcmp(temp[1], "rule_mac") == 0)
                {
                    if (strlen(temp[2]) > 0)
                    {
                        _parseCorrectName(temp[2], strlen(temp[2]));
                        i = 0;
                        numberOfMac = 0;

                        while (i < strlen(temp[2]))
                        {
                            if(temp[2][i] == '_')
                            {
                                temp[2][i] = ' ';
                                numberOfMac++;
                            }
    
                            i++;
                        }
    
                        if (numberOfMac == 0)
                        {
                            p_timeResEntries[numberOfTR].macEntries = 1;
                            snprintf(p_timeResEntries[numberOfTR].rule_mac[0], sizeof p_timeResEntries[numberOfTR].rule_mac[0], "%s", temp[2]);
                        }
                        else if (numberOfMac == 1)
                        {
                            p_timeResEntries[numberOfTR].macEntries = 2;
                            memset(temp[0], 0, 64);
                            memset(temp[1], 0, 64);
                            sscanf(temp[2], "%s %s", temp[0], temp[1]);
                            snprintf(p_timeResEntries[numberOfTR].rule_mac[0], sizeof p_timeResEntries[numberOfTR].rule_mac[0], "%s", temp[0]);
                            snprintf(p_timeResEntries[numberOfTR].rule_mac[1], sizeof p_timeResEntries[numberOfTR].rule_mac[1], "%s", temp[1]);
                        }
                        else if (numberOfMac == 2)
                        {
                            p_timeResEntries[numberOfTR].macEntries = 3;
                            memset(temp[0], 0, 64);
                            memset(temp[1], 0, 64);
                            memset(temp[3], 0, 64);
                            sscanf(temp[2], "%s %s %s", temp[0], temp[1], temp[3]);
                            snprintf(p_timeResEntries[numberOfTR].rule_mac[0], sizeof p_timeResEntries[numberOfTR].rule_mac[0], "%s", temp[0]);
                            snprintf(p_timeResEntries[numberOfTR].rule_mac[1], sizeof p_timeResEntries[numberOfTR].rule_mac[1], "%s", temp[1]);
                            snprintf(p_timeResEntries[numberOfTR].rule_mac[2], sizeof p_timeResEntries[numberOfTR].rule_mac[2], "%s", temp[3]);
                        }
                        else if (numberOfMac == 3)
                        {
                            p_timeResEntries[numberOfTR].macEntries = 4;
                            memset(temp[0], 0, 64);
                            memset(temp[1], 0, 64);
                            memset(temp[3], 0, 64);
                            memset(temp[4], 0, 64);
                            sscanf(temp[2], "%s %s %s %s", temp[0], temp[1], temp[3], temp[4]);
                            snprintf(p_timeResEntries[numberOfTR].rule_mac[0], sizeof p_timeResEntries[numberOfTR].rule_mac[0], "%s", temp[0]);
                            snprintf(p_timeResEntries[numberOfTR].rule_mac[1], sizeof p_timeResEntries[numberOfTR].rule_mac[1], "%s", temp[1]);
                            snprintf(p_timeResEntries[numberOfTR].rule_mac[2], sizeof p_timeResEntries[numberOfTR].rule_mac[2], "%s", temp[3]);
                            snprintf(p_timeResEntries[numberOfTR].rule_mac[3], sizeof p_timeResEntries[numberOfTR].rule_mac[3], "%s", temp[4]);
                        }
                    }
                    else
                    {
                        p_timeResEntries[numberOfTR].macEntries = 0;
                    }
                }
            }

            numberOfTR++;

            if (numberOfTR >= MAX_NUMBER_GROUP)
            {
                break;
            }
        }
    } 

    fclose(fp);
    return numberOfTR;
}


static int _VNPT_runCurrentTimeRestrictionRule(void)
{
    int numberOfEntries = -1;
    Time_Res_Entry_s currRule[MAX_NUMBER_GROUP];
    int i = 0;
    int j = 0;
    char eb_options[256] = {0};

    memset(currRule, 0, sizeof(currRule));

    numberOfEntries = _VNPT_parseTimeResEntries(currRule);
    
    printf("%s: numberOfEntries = %d\n", __func__, numberOfEntries);

    while (i < numberOfEntries)
    {   
		memset(eb_options, 0, sizeof eb_options);
        sprintf(eb_options, "iptables -N %s_url", currRule[i].name);
        printf("%s: ---> run cmd: %s\n", __FUNCTION__, eb_options);
        LV_do_systemcall(eb_options, strlen(eb_options));

        printf("%s: Entries = %d: name = %s, rule_start=%s, rule_stop=%s, day=%s\n", __func__, i,
        		currRule[i].name, currRule[i].rule_start, currRule[i].rule_stop, currRule[i].rule_day);
        memset(eb_options, 0, sizeof eb_options);
        sprintf(eb_options, "iptables -N %s", currRule[i].name);
        printf("%s: ---> run cmd: %s\n", __FUNCTION__, eb_options);
        LV_do_systemcall(eb_options, strlen(eb_options));

        memset(eb_options, 0, sizeof eb_options);
        sprintf(eb_options, "iptables -A %s -m time --kerneltz --timestart %s --timestop %s --weekdays %s -j %s_url", currRule[i].name, currRule[i].rule_start, currRule[i].rule_stop, currRule[i].rule_day, currRule[i].name);
        printf("%s: ---> run cmd: %s\n", __FUNCTION__, eb_options);
        LV_do_systemcall(eb_options, strlen(eb_options));

        while (j < currRule[i].macEntries)
        {   
        	memset(eb_options, 0, sizeof eb_options);
            sprintf(eb_options, "iptables -I FORWARD -m mac --mac-source %s -j %s", currRule[i].rule_mac[j], currRule[i].name);
            printf("%s: ---> run cmd: %s\n", __FUNCTION__, eb_options);
            LV_do_systemcall(eb_options, strlen(eb_options));
            j++;
        }

		memset(eb_options, 0, sizeof eb_options);
		sprintf(eb_options, "iptables -A %s -j DROP", currRule[i].name);
		printf("%s: ---> run cmd: %s\n", __FUNCTION__, eb_options);
		LV_do_systemcall(eb_options, strlen(eb_options));

        memset(eb_options, 0, sizeof eb_options);
        sprintf(eb_options, "iptables -A %s_url -j ACCEPT", currRule[i].name);
        printf("%s: ---> run cmd: %s\n", __FUNCTION__, eb_options);
        LV_do_systemcall(eb_options, strlen(eb_options));

        memset(eb_options, 0, sizeof eb_options);
        sprintf(eb_options, "iptables -D FORWARD -j urlFilter");
        printf("%s: ---> run cmd: %s\n", __FUNCTION__, eb_options);
        LV_do_systemcall(eb_options, strlen(eb_options));

        memset(eb_options, 0, sizeof eb_options);
        sprintf(eb_options, "iptables -I FORWARD -j urlFilter");
        printf("%s: ---> run cmd: %s\n", __FUNCTION__, eb_options);
        LV_do_systemcall(eb_options, strlen(eb_options));

        i++;
        j = 0;
    }

    return 0;
}


static int _VNPT_getOnOffLedTimer(void)
{
    FILE *fp = NULL;
    int rc = -1;
    char temp[32] = {0};
    char tempData[2][5] = {{0}};
    int tempStatus = -1;
    char tempTime[4] = {0};

    fp = fopen(ONOFFLEDFILE, "r");
    if (fp == NULL)
    {
        printf("%s: No configuration for on/off LED\n", __FUNCTION__);
        return -1;
    }

    rc = fread(temp, 1, sizeof temp, fp);
    if (rc <= 0)
    {
        printf("%s: Configuration for on/off LED is error\n", __FUNCTION__);
        fclose(fp);
        return -2;
    }

    sscanf(temp, "%d %s %s", &tempStatus, tempData[0], tempData[1]);
    onoffStatus = tempStatus;

    tempTime[0] = tempData[0][2];
    tempTime[1] = tempData[0][3];
    tempTime[2] = '\0';
    offLedTime[1] = atoi(tempTime);  // start off led time

    tempTime[0] = tempData[1][2];
    tempTime[1] = tempData[1][3];
    tempTime[2] = '\0';
    onLedTime[1] = atoi(tempTime);  // stop off led time

    tempData[0][2] = '\0';
    tempData[1][2] = '\0';
    offLedTime[0] = atoi(tempData[0]);
    onLedTime[0] = atoi(tempData[1]);

    fclose(fp);

    //printf("onoffStatus: %d, onLedTime: %d:%d, offLedTime: %d:%d\n", onoffStatus, onLedTime[0], onLedTime[1], offLedTime[0], offLedTime[1]);
    return 0;
}

static int _VNPT_createSocket(void)
{
    struct timeval tv;

    // Create client socket, bind to unique pathname (based on PID)
    if ((gsockFd = socket(AF_UNIX, SOCK_DGRAM, 0)) == -1)
    {
        printf("CFG_MGR: Socket failed: %s\r\n", strerror(errno));
        return 0;
    }

    // Socket optional
    tv.tv_sec = RECV_SOCK_TIMEOUT;
    tv.tv_usec = 0;
    setsockopt(gsockFd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);

    // Construct address of client
    memset(&gclientAddr, 0, sizeof(struct sockaddr_un));
    gclientAddr.sun_family = AF_UNIX;
    snprintf(gclientAddr.sun_path, sizeof(gclientAddr.sun_path), "/tmp/config_mgr.%ld", (long) getpid());

    // Bind socket to recv msg
    if (bind(gsockFd, (struct sockaddr *) &gclientAddr, sizeof(struct sockaddr_un)) == -1)
    {
        printf("CFG_MGR: client bind failed: %s\n", strerror(errno));
        return 0;
    }

    // Construct address of server
    memset(&gsevrAddr, '0', sizeof(struct sockaddr_un));
    gsevrAddr.sun_family = AF_UNIX;
    strncpy(gsevrAddr.sun_path, SERVER_SOCK_PATH, sizeof(gsevrAddr.sun_path) - 1);

    return 1;
}

static bool _VNPT_controlMREsLeds(Led_Status_e ledSttFlag)
{
    char sendStr[STR_LEN_128] = {0};
    char recvStr[STR_LEN_512] = {0};
    int nodeNum;

    Topo_File_Node_Info_s topoNode[MAX_TOPO_NODE];
    int numNode = 0;

    memset(topoNode, 0, sizeof(topoNode));
    if (!LV_read_topology_database(topoNode, &numNode))
    {
        printf("CFG_MGR: Failed to read topology database\n");
        return 0;
    }

    // Send request to all MREs
    for (nodeNum = 0; nodeNum < numNode; nodeNum++)
    {
        // Ignore CAP node
        if (topoNode[nodeNum].deviceType == CAP)
            continue;

        memset(sendStr, 0, sizeof(sendStr));
        memset(recvStr, 0, sizeof(recvStr));
        if (ledSttFlag)
        {
            sprintf(sendStr, "{\"msgName\":\"%s\",\"mac\":\"%s\"}", ON_LED_CTRL_MSG_NAME, topoNode[nodeNum].ieee1905Mac);
        }
        else
        {
            sprintf(sendStr, "{\"msgName\":\"%s\",\"mac\":\"%s\"}", OFF_LED_CTRL_MSG_NAME, topoNode[nodeNum].ieee1905Mac);
        }

        printf("CFG_MGR: Sending to mesh_comm: %s\n", sendStr);
        if (sendto(gsockFd, sendStr, strlen(sendStr), 0, (struct sockaddr *) &gsevrAddr, sizeof(struct sockaddr_un)) == -1)
        {
            printf("CFG_MGR: Failed to send request to mesh_comm: %s\n", strerror(errno));
            continue;
        }
        else
        {
            printf("CFG_MGR: Send successful, Waiting for server response...\r\n");

            if (recvfrom(gsockFd, recvStr, sizeof(recvStr), 0, NULL, NULL) < 0)
            {
                printf("CFG_MGR: Receive on SOCK_PATH failed: %s\r\n", strerror(errno));
            }
            else
            {
                printf("CFG_MGR: Received msg: %s\r\n", recvStr);
            }
        }
    }

    return 1;
}

static int _VNPT_controlLeds(void)
{
    char timeBuffer[64] = {0};
    FILE *fp = NULL;
    int rc = -1;
    char temp[4][16] = {{0}};
    char minute[3] = {0};
    char hour[3] = {0};
    int tmpNow, tmpOff, tmpOn;

    //printf("onoffStatus = %d, preOn = %d\n", onoffStatus, preOn);

    if (onoffStatus == 0){
    	if (preOn == 0){
    	    // Turn on CAP led
            LV_do_systemcall(TURN_ON_LED_CMD, strlen(TURN_ON_LED_CMD));

            // Turn on all of MREs led
            _VNPT_controlMREsLeds(LED_ON);

            preStatusOn = 1;
            preStatusOff = 0;
    		preOn = 1;
    	}

		return 0;
    }

    // Get the current time
    fp = popen("date", "r");
    if (fp == NULL)
    {
        return -1;
    }

    rc = fread (timeBuffer, 1, sizeof timeBuffer, fp);
    if (rc <= 0)
    {
        pclose(fp);
        return -2;
    }

    sscanf(timeBuffer, "%s %s %s %s", temp[0], temp[1], temp[2], temp[3]);
    hour[0] = temp[3][0];
    hour[1] = temp[3][1];

    minute[0] = temp[3][3];
    minute[1] = temp[3][4];

    printf("%s: preStatusOn = %d, preStatusOff = %d\n", __FUNCTION__, preStatusOn, preStatusOff);
    printf("%s: time = %d:%02d, offLedTime = %d:%02d, onLedTime = %d:%02d \n", __FUNCTION__,
    		atoi(hour), atoi(minute), offLedTime[0], offLedTime[1], onLedTime[0], onLedTime[1]);

    tmpNow = atoi(hour) * 60 + atoi(minute);
    tmpOn = onLedTime[0] * 60 + onLedTime[1];
    tmpOff = offLedTime[0] * 60 + offLedTime[1];

    // Compare between the current time and on, off config time
    // 0 --- On --- Off --- 24h
    // 0 --- Off --- On --- 24h
    if (((tmpOn < tmpOff) && (tmpNow >= tmpOn && tmpNow < tmpOff)) ||
        ((tmpOn > tmpOff) && (tmpNow < tmpOff || tmpNow >= tmpOn)))
	{
        // Turn on led
        if(preStatusOn == 0){
        	printf("%s: Control ON LED \n", __FUNCTION__);
            // Turn on CAP led
            LV_do_systemcall(TURN_ON_LED_CMD, strlen(TURN_ON_LED_CMD));

            // Turn on all of MREs led
            _VNPT_controlMREsLeds(LED_ON);

            preStatusOn = 1;
            preStatusOff = 0;
        }

        preOn = 1;
    }
    else
    {
        // Turn off led
        if(preStatusOff == 0){
        	printf("%s: Control OFF LED \n", __FUNCTION__);
            // Turn off CAP led
            LV_do_systemcall(TURN_OFF_LED_CMD, strlen(TURN_OFF_LED_CMD));

            // Turn off all of MREs led
            _VNPT_controlMREsLeds(LED_OFF);

            preStatusOff = 1;
            preStatusOn = 0;
        }

        preOn = 0;
    }

    pclose(fp);
    return 0;
}

static int _VNPT_checkUrlListAvalable(void){
    FILE *fpUrl = NULL;

    fpUrl = fopen("/etc/config/urlList", "r");

    if(fpUrl == NULL){
        system("mkdir -p /etc/config/urlList");
        return 1;
    } else {
        fclose(fpUrl);
        return 0;
    }

    return 0;
}

static int _VNPT_checkDataFileAvailable(const char *domain, const char *domainIP, int ipType, int groupTimeRes){
    FILE *fp = NULL;
    char bufferLine[256] = {0};
	
	
	_VNPT_checkUrlListAvalable();

    if (groupTimeRes == 0)
    {
        if(ipType == 4)
            snprintf(bufferLine, sizeof bufferLine, "/etc/config/urlList/%s", domain);
        else
            snprintf(bufferLine, sizeof bufferLine, "/etc/config/urlList/%s_v6", domain);
    }
    else
    {
        if(ipType == 4)
            snprintf(bufferLine, sizeof bufferLine, "/etc/config/urlList/trGroup/%s", domain);
        else
            snprintf(bufferLine, sizeof bufferLine, "/etc/config/urlList/trGroup/%s_v6", domain);
    }

    fp = fopen(bufferLine, "r");
    if(fp == NULL){
        memset(bufferLine, 0, sizeof bufferLine);

        if (groupTimeRes == 0)
        {
            if(ipType == 4)
                snprintf(bufferLine, sizeof bufferLine, "echo %s > /etc/config/urlList/%s", domainIP, domain);
            else
                snprintf(bufferLine, sizeof bufferLine, "echo %s > /etc/config/urlList/%s_v6", domainIP, domain);
        }
        else
        {
            if(ipType == 4)
                snprintf(bufferLine, sizeof bufferLine, "echo %s > /etc/config/urlList/trGroup/%s", domainIP, domain);
            else
                snprintf(bufferLine, sizeof bufferLine, "echo %s > /etc/config/urlList/trGroup/%s_v6", domainIP, domain);
        }

        printf("Command: %s\n", bufferLine);
        LV_do_systemcall(bufferLine, strlen(bufferLine));

    } else {
        while(fgets(bufferLine, 256, fp)){
            sscanf(bufferLine, "%s", bufferLine);
            if(strcmp(bufferLine, domainIP) == 0){
                fclose(fp);
                return 1;
            }
        }

        fclose(fp);
        memset(bufferLine, 0, sizeof bufferLine);

        if (groupTimeRes == 0)
        {
            if(ipType == 4)
                snprintf(bufferLine, sizeof bufferLine, "echo %s >> /etc/config/urlList/%s", domainIP, domain);
            else
                snprintf(bufferLine, sizeof bufferLine, "echo %s >> /etc/config/urlList/%s_v6", domainIP, domain);
        }
        else
        {
            if(ipType == 4)
                snprintf(bufferLine, sizeof bufferLine, "echo %s >> /etc/config/urlList/trGroup/%s", domainIP, domain);
            else
                snprintf(bufferLine, sizeof bufferLine, "echo %s >> /etc/config/urlList/trGroup/%s_v6", domainIP, domain);
        }

        printf("Command: %s\n", bufferLine);
        LV_do_systemcall(bufferLine, strlen(bufferLine));
    }

    return 0;
}

static int _vnptt_ip_validate (const char *value, int family)
{
    unsigned char buf[sizeof (struct in6_addr)];
    return 1 == inet_pton (family, value, buf) ? 1 : 0;
}

static void _vnptt_lookupIP(const char *path, const char *domain, int groupTimeRes)
{
    FILE *fp = NULL;
    char bufferFp[256] = {0};
    char *ch = NULL;
    int isCheckNow = 0;
    char tempIpAddr[128] = {0};
	
	fp = fopen(path, "r");

    if(fp == NULL)
	{
        return 0;
    }

    while(fgets(bufferFp, 256, fp))
	{
        //if(strstr(bufferFp, domain) && isCheckNow == 0){
        //    isCheckNow = 1;
        //    continue;
        //}

		/*
			Address 1: x.x.x.x
			Address 2: x.x.x.x
			Address 3: x.x.x.x
		*/
        //if(isCheckNow == 1){
            ch = strstr(bufferFp, "Address");
            if(ch == NULL)
			{
				continue;
            }

			ch = strstr(bufferFp, ": ");
			if(ch == NULL) 
			{
				continue;
			}

            memset(tempIpAddr, 0, 128);
            sscanf(ch + 2, "%s", tempIpAddr);

            printf("domain: %s \t tempIpAddr: %s\t groupTimeRes = %d\n", domain,tempIpAddr, groupTimeRes);

            if(strstr(tempIpAddr, ":"))
			{
				if(1 == _vnptt_ip_validate(tempIpAddr, AF_INET6))
					_VNPT_checkDataFileAvailable(domain, tempIpAddr, 6, groupTimeRes);
            } 
			else 
			{
				if(1 == _vnptt_ip_validate(tempIpAddr, AF_INET))
					_VNPT_checkDataFileAvailable(domain, tempIpAddr, 4, groupTimeRes);
            }
        //}

        memset(bufferFp, 0, sizeof bufferFp);
    }

    fclose(fp);
}

static int _VNPT_intervalLookUpNewIP(const char *domain, int groupTimeRes){
    FILE *fp = NULL;
    char bufferFp[256] = {0};
    char *ch = NULL;
    int isCheckNow = 0;
    char tempIpAddr[128] = {0};
	char LOOKUP_PATH[] = "/tmp/iplookup";

	if(NULL == domain)
		return 0;

    memset(bufferFp, 0, sizeof bufferFp);
	
	ch = strstr(domain, "www.");

	if(NULL == strstr(domain, "www."))
	{
		//add www. to domain if it not exist
		snprintf(bufferFp, sizeof bufferFp, "nslookup www.%s > %s", domain, LOOKUP_PATH);
		printf("bufferFp: %s \n", bufferFp);
		system(bufferFp);
		_vnptt_lookupIP(LOOKUP_PATH, domain, groupTimeRes);
		
		memset(bufferFp, 0, sizeof bufferFp);
		snprintf(bufferFp, sizeof bufferFp, "nslookup %s > %s", domain, LOOKUP_PATH);
		printf("bufferFp: %s \n", bufferFp);
		system(bufferFp);
		_vnptt_lookupIP(LOOKUP_PATH, domain, groupTimeRes);
	}
	else
	{
		snprintf(bufferFp, sizeof bufferFp, "nslookup %s > %s", domain, LOOKUP_PATH);
		printf("bufferFp: %s \n", bufferFp);
		system(bufferFp);
		_vnptt_lookupIP(LOOKUP_PATH, domain, groupTimeRes);
		
		memset(bufferFp, 0, sizeof bufferFp);
		snprintf(bufferFp, sizeof bufferFp, "nslookup %s > %s", ch + 4, LOOKUP_PATH);
		printf("bufferFp: %s \n", bufferFp);
		system(bufferFp);
		_vnptt_lookupIP(LOOKUP_PATH, domain, groupTimeRes);
		
	}	

    return 0;
}

static void _vnptt_addUrlFilter(char *domain)
{
    char cmdBuffer[256] = {0};
	
	if(NULL == domain)
		return;
	
	//TODO: remove duplicate rule, don't know why???
	//system("iptables-save | uniq | iptables-restore");

	memset(cmdBuffer, 0, sizeof cmdBuffer);
	snprintf(cmdBuffer, sizeof(cmdBuffer), "iptables -w -I urlFilter -p tcp --dport 443 -m string --string \"%s\" --algo bm -j DROP", domain);
	printf("%s: ---> run cmd: %s\n", __FUNCTION__, cmdBuffer);
	LV_do_systemcall(cmdBuffer, strlen(cmdBuffer));

	memset(cmdBuffer, 0, sizeof cmdBuffer);
	snprintf(cmdBuffer, sizeof(cmdBuffer), "iptables -w -I urlFilter -p tcp --dport 80 -m string --string \"%s\" --algo bm -j DROP", domain);
	LV_do_systemcall(cmdBuffer, strlen(cmdBuffer));

	// add reject DNS
	memset(cmdBuffer, 0, sizeof cmdBuffer);
	snprintf(cmdBuffer, sizeof(cmdBuffer), "iptables -w -I urlFilter -p udp --dport 53 -m string --string \"%s\" --algo bm -j DROP", domain);
	printf("%s: ---> run cmd: %s\n", __FUNCTION__, cmdBuffer);
	LV_do_systemcall(cmdBuffer, strlen(cmdBuffer));

	memset(cmdBuffer, 0, sizeof cmdBuffer);
	snprintf(cmdBuffer, sizeof(cmdBuffer), "iptables -w -I urlFilter -p tcp --dport 53 -m string --string \"%s\" --algo bm -j DROP", domain);
	LV_do_systemcall(cmdBuffer, strlen(cmdBuffer));
}


static void _vnptt_addGroupUrlFilterTR(char *group, char *domain)
{
    char cmdBuffer[256] = {0};
	char *token = NULL;
	char buff[32] = {0};
	
	if(NULL == domain || NULL == group)
		return;
	
	////TODO: remove duplicate rule, don't know why???
	//system("iptables-save | uniq | iptables-restore");

	snprintf(buff, sizeof(buff), "%s", domain);

	token = strchr(buff, '.');
	if(NULL != token)
	{
		buff[token - buff] = '\0';
		memset(cmdBuffer, 0, sizeof cmdBuffer);
		snprintf(cmdBuffer, sizeof(cmdBuffer), "iptables -w -I %s_url -p tcp --dport 443 -m string --string \"%s\" --algo bm -j DROP", group, buff);
		printf("%s: ---> run cmd: %s\n", __FUNCTION__, cmdBuffer);
		LV_do_systemcall(cmdBuffer, strlen(cmdBuffer));
		
		memset(cmdBuffer, 0, sizeof cmdBuffer);
		snprintf(cmdBuffer, sizeof(cmdBuffer), "iptables -w -I %s_url -p tcp --dport 80 -m string --string \"%s\" --algo bm -j DROP", group, buff);
		LV_do_systemcall(cmdBuffer, strlen(cmdBuffer));
	}
	else
	{
		memset(cmdBuffer, 0, sizeof cmdBuffer);
		snprintf(cmdBuffer, sizeof(cmdBuffer), "iptables -w -I %s_url -p tcp --dport 443 -m string --string \"%s\" --algo bm -j DROP", group, domain);
		printf("%s: ---> run cmd: %s\n", __FUNCTION__, cmdBuffer);
		LV_do_systemcall(cmdBuffer, strlen(cmdBuffer));

		memset(cmdBuffer, 0, sizeof cmdBuffer);
		snprintf(cmdBuffer, sizeof(cmdBuffer), "iptables -w -I %s_url -p tcp --dport 80 -m string --string \"%s\" --algo bm -j DROP", group, domain);
		LV_do_systemcall(cmdBuffer, strlen(cmdBuffer));
	}

	memset(cmdBuffer, 0, sizeof cmdBuffer);
	snprintf(cmdBuffer, sizeof(cmdBuffer), "iptables -w -I %s_url -p udp --dport 53 -m string --string \"%s\" --algo bm -j DROP", group, domain);
	printf("%s: ---> run cmd: %s\n", __FUNCTION__, cmdBuffer);
	LV_do_systemcall(cmdBuffer, strlen(cmdBuffer));
	
	memset(cmdBuffer, 0, sizeof cmdBuffer);
	snprintf(cmdBuffer, sizeof(cmdBuffer), "iptables -w -I %s_url -p tcp --dport 53 -m string --string \"%s\" --algo bm -j DROP", group, domain);
	LV_do_systemcall(cmdBuffer, strlen(cmdBuffer));
}

static int _VNPT_runUrlFilterConfig(void)
{
    char lineBuffer[256] = {0};
    FILE *fp = NULL;
    char cmdBuffer[256] = {0};

    memset(cmdBuffer, 0, sizeof cmdBuffer);
    snprintf(cmdBuffer, sizeof cmdBuffer, "iptables -F urlFilter");
    SYS_LOG("config_management", SYSLOG_NOTICE, "%s: ---> run cmd: %s", __FUNCTION__, cmdBuffer);
    printf("%s: ---> run cmd: %s\n", __FUNCTION__, cmdBuffer);
    LV_do_systemcall(cmdBuffer, strlen(cmdBuffer));

    memset(cmdBuffer, 0, sizeof cmdBuffer);
    snprintf(cmdBuffer, sizeof cmdBuffer, "iptables -D FORWARD -j urlFilter");
    SYS_LOG("config_management", SYSLOG_NOTICE, "%s: ---> run cmd: %s", __FUNCTION__, cmdBuffer);
    printf("%s: ---> run cmd: %s\n", __FUNCTION__, cmdBuffer);
    LV_do_systemcall(cmdBuffer, strlen(cmdBuffer));

    memset(cmdBuffer, 0, sizeof cmdBuffer);
    snprintf(cmdBuffer, sizeof cmdBuffer, "iptables -X urlFilter");
    SYS_LOG("config_management", SYSLOG_NOTICE, "%s: ---> run cmd: %s", __FUNCTION__, cmdBuffer);
    printf("%s: ---> run cmd: %s\n", __FUNCTION__, cmdBuffer);
    LV_do_systemcall(cmdBuffer, strlen(cmdBuffer));

    // / re_add rule url filter /
    memset(cmdBuffer, 0, sizeof cmdBuffer);
    snprintf(cmdBuffer, sizeof cmdBuffer, "iptables -N urlFilter");
    SYS_LOG("config_management", SYSLOG_NOTICE, "%s: ---> run cmd: %s", __FUNCTION__, cmdBuffer);
    printf("%s: ---> run cmd: %s\n", __FUNCTION__, cmdBuffer);
    LV_do_systemcall(cmdBuffer, strlen(cmdBuffer));

    memset(cmdBuffer, 0, sizeof cmdBuffer);
    snprintf(cmdBuffer, sizeof cmdBuffer, "iptables -I FORWARD -j urlFilter");
    SYS_LOG("config_management", SYSLOG_NOTICE, "%s: ---> run cmd: %s", __FUNCTION__, cmdBuffer);
    printf("%s: ---> run cmd: %s\n", __FUNCTION__, cmdBuffer);
    LV_do_systemcall(cmdBuffer, strlen(cmdBuffer));

    fp = fopen("/etc/config/urlFilter", "r");
    if(fp == NULL){
         return 0;
    }

	while(fgets(lineBuffer, 256, fp)){
		_parseCorrectLine(lineBuffer, strlen(lineBuffer));
		printf("%s: lineBuffer: %s\n", __FUNCTION__, lineBuffer);
		
		_vnptt_addUrlFilter(lineBuffer);
		memset(lineBuffer, 0x0, sizeof(lineBuffer));
	}

    fclose(fp);

    return 0;
}

static int _VNPT_runUrlFilterLifeTime(void)
{
    char lineBuffer[256] = {0};
    FILE *fp = NULL;
    FILE *fpIp = NULL;
    FILE *fpFilter = NULL;
    char cmdBuffer[256] = {0};
    char fileUrlList[256] = {0};
    char lineListIp[256] = {0};

    // ipdate ip of domain
    fp = fopen("/var/run/urlLife", "r");

    if(fp == NULL)
    {
        return 1;
    }
    else
    {
		while(fgets(lineBuffer, 256, fp))
		{
			_parseCorrectLine(lineBuffer, strlen(lineBuffer));

			_VNPT_intervalLookUpNewIP(lineBuffer, 0);
			usleep(100);
		}

		fclose(fp);
    }

    /* clean all rule url filter
     * chain 'urlFilter' contains all rule block IP of required domain.
     * */
    memset(cmdBuffer, 0, sizeof cmdBuffer);
    snprintf(cmdBuffer, sizeof cmdBuffer, "iptables -F urlFilter");
    printf("%s: ---> run cmd: %s\n", __FUNCTION__, cmdBuffer);
    LV_do_systemcall(cmdBuffer, strlen(cmdBuffer));

    memset(cmdBuffer, 0, sizeof cmdBuffer);
    snprintf(cmdBuffer, sizeof cmdBuffer, "iptables -D FORWARD -j urlFilter");
    printf("%s: ---> run cmd: %s\n", __FUNCTION__, cmdBuffer);
    LV_do_systemcall(cmdBuffer, strlen(cmdBuffer));

    memset(cmdBuffer, 0, sizeof cmdBuffer);
    snprintf(cmdBuffer, sizeof cmdBuffer, "iptables -X urlFilter");
    printf("%s: ---> run cmd: %s\n", __FUNCTION__, cmdBuffer);
    LV_do_systemcall(cmdBuffer, strlen(cmdBuffer));

    /* re_add rule url filter */
    memset(cmdBuffer, 0, sizeof cmdBuffer);
    snprintf(cmdBuffer, sizeof cmdBuffer, "iptables -N urlFilter");
    printf("%s: ---> run cmd: %s\n", __FUNCTION__, cmdBuffer);
    LV_do_systemcall(cmdBuffer, strlen(cmdBuffer));

    memset(cmdBuffer, 0, sizeof cmdBuffer);
    snprintf(cmdBuffer, sizeof cmdBuffer, "iptables -I FORWARD -j urlFilter");
    printf("%s: ---> run cmd: %s\n", __FUNCTION__, cmdBuffer);
    LV_do_systemcall(cmdBuffer, strlen(cmdBuffer));

    fpFilter = fopen(URLFILTERFILE, "r");
    if (fpFilter)
    {
    	memset(lineBuffer, 0, sizeof lineBuffer);
    	while(fgets(lineBuffer, sizeof lineBuffer, fpFilter))
    	{
    		_parseCorrectLine(lineBuffer, strlen(lineBuffer));
			
			_vnptt_addUrlFilter(lineBuffer);
			memset(lineBuffer, 0, sizeof lineBuffer);
    	}

		fclose(fpFilter);
    }

//    system("iptables-save > /etc/iptables_rules");

    memset(lineBuffer, 0, sizeof lineBuffer);
    snprintf(lineBuffer, sizeof lineBuffer, "rm -rf /var/run/urlLife");
    LV_do_systemcall(lineBuffer, strlen(lineBuffer));

    memset(lineBuffer, 0, sizeof lineBuffer);
    snprintf(lineBuffer, sizeof lineBuffer, "conntrack -F");
    LV_do_systemcall(lineBuffer, strlen(lineBuffer));

    SYS_LOG("config_management", SYSLOG_NOTICE, "Delete CONTRACT");

    return 0;
}

static int _VNPT_runTrUrl2GroupConfig(void)
{
    char lineBuffer[256] = {0};
    char groupName[128] = {0};
    char domainName[128] = {0};
    FILE *fp = NULL;
    char cmdBuffer[256] = {0};
    int runNow = 1;

    /// Add rule timeres group

    fp = fopen("/etc/config/urlTimeRes", "r");
    if(fp == NULL){
        return 0;
    }

	while(fgets(lineBuffer, 256, fp)){
		memset(groupName, 0, sizeof groupName);
		memset(domainName, 0, sizeof domainName);
		sscanf(lineBuffer, "%s %s", domainName, groupName);
		printf("%s: lineBuffer: %s, domainName = %s, groupName=%s\n", __FUNCTION__, lineBuffer, domainName, groupName);

		_vnptt_addGroupUrlFilterTR(groupName, domainName);
		memset(lineBuffer, 0x0, sizeof(lineBuffer));
	}

	fclose(fp);

    return 0;
}

static int _VNPT_runTrUrl2GroupLifeTime(void)
{
    char lineBuffer[256] = {0};
    char groupName[128] = {0};
    char domainName[128] = {0};
    FILE *fp = NULL;
    char cmdBuffer[256] = {0};

    fp = fopen("/var/run/urlGroupLife", "r");
    if(fp == NULL){
        return 1;
    }

    while(fgets(lineBuffer, 256, fp)){
        memset(groupName, 0, sizeof groupName);
        memset(domainName, 0, sizeof domainName);
        sscanf(lineBuffer, "%s %s", domainName, groupName);

		_vnptt_addGroupUrlFilterTR(groupName, domainName);
		memset(lineBuffer, 0x0, sizeof(lineBuffer));
    }

    fclose(fp);

//    system("iptables-save > /etc/iptables_rules");

    memset(lineBuffer, 0, sizeof lineBuffer);
    snprintf(lineBuffer, sizeof lineBuffer, "rm -rf /var/run/urlGroupLife");
    LV_do_systemcall(lineBuffer, strlen(lineBuffer));

    return 0;
}

static int _config_check_re_run_trigger(void){
    FILE *f_re_run = NULL;

    f_re_run = fopen("/var/run/cfgReRun", "r");
    if(f_re_run == NULL){
        return 0;
    }

    fclose(f_re_run);
    system("rm /var/run/cfgReRun");
    return 1;
}

static int _VNPT_signalKillHandle(void)
{
    // Close mesh_comm communication socket
    remove(gclientAddr.sun_path);
    close(gsockFd);
    // Exit program
    exit(0);
}

int main()
{
	FILE *fp = NULL;

	printf("VNPT Config Management Application\n");

	// Register signal
	signal(SIGTERM, _VNPT_signalKillHandle);
    signal(SIGKILL, _VNPT_signalKillHandle);
    signal(SIGINT, _VNPT_signalKillHandle);

	// Create socket to communication with mesh_comm app
    _VNPT_createSocket();

    fp = fopen("/var/run/onLedNow", "r");
    if (fp == NULL)
    {
        preStatusOn = 1;
        preOn = 1;
    }
    else
    {
        preStatusOff = 1;
        fclose(fp);
    }

//    sleep(30);
    system("/etc/init.d/firewall restart");
    // run url filter
    _VNPT_runUrlFilterConfig();
    
    _VNPT_checkUrlListAvalable();
    // run time restriction
    _VNPT_runCurrentTimeRestrictionRule();

    // run time restriction urlfilter
    _VNPT_runTrUrl2GroupConfig();

    while (1)
    {
        // Read on/off led config
        if (_VNPT_getOnOffLedTimer() == 0)
        {
            // Check timer to control Led
            _VNPT_controlLeds();
        }
        
        // Check trigger URL
        _VNPT_runUrlFilterLifeTime();
        _VNPT_runTrUrl2GroupLifeTime();

        if(_config_check_re_run_trigger()){
        	printf("%s: Rerun service\n", __FUNCTION__);
            sleep(5);
            system("/etc/init.d/firewall restart");

            // run url filter
            _VNPT_runUrlFilterConfig();

            // run time restriction
            _VNPT_runCurrentTimeRestrictionRule();

            // run time restriction urlfilter
            _VNPT_runTrUrl2GroupConfig();
        }

        sleep(1);
    }

    // Close mesh_comm communication socket
    remove(gclientAddr.sun_path);
    close(gsockFd);

    return 0;
}
