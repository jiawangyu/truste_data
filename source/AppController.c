/*
* Licensee agrees that the example code provided to Licensee has been developed and released by Bosch solely as an example to be used as a potential reference for application development by Licensee. 
* Fitness and suitability of the example code for any use within application developed by Licensee need to be verified by Licensee on its own authority by taking appropriate state of the art actions and measures (e.g. by means of quality assurance measures).
* Licensee shall be responsible for conducting the development of its applications as well as integration of parts of the example code into such applications, taking into account the state of the art of technology and any statutory regulations and provisions applicable for such applications. Compliance with the functional system requirements and testing there of (including validation of information/data security aspects and functional safety) and release shall be solely incumbent upon Licensee. 
* For the avoidance of doubt, Licensee shall be responsible and fully liable for the applications and any distribution of such applications into the market.
* 
* 
* Redistribution and use in source and binary forms, with or without 
* modification, are permitted provided that the following conditions are 
* met:
* 
*     (1) Redistributions of source code must retain the above copyright
*     notice, this list of conditions and the following disclaimer. 
* 
*     (2) Redistributions in binary form must reproduce the above copyright
*     notice, this list of conditions and the following disclaimer in
*     the documentation and/or other materials provided with the
*     distribution.  
*     
*     (3)The name of the author may not be used to
*     endorse or promote products derived from this software without
*     specific prior written permission.
* 
*  THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR 
*  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED 
*  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
*  DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
*  INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
*  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
*  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
*  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
*  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
*  IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
*  POSSIBILITY OF SUCH DAMAGE.
*/
/*----------------------------------------------------------------------------*/

/**
 * @ingroup APPS_LIST
 *
 * @defgroup HTTP_EXAMPLE_CLIENT HttpExampleClient
 * @{
 *
 * @brief Demo application for communicating with the HTTP to GET and POST content on the Server and demonstrate the use of custom headers.
 *
 * @details This example shows how to use the network stack to perform an HTTP Client Request.
 *
 * The example connects to the server <a href="DEST_SERVER_HOST"></a> and establishes a connection to the server.
 *
 * To view your posts, browse to the directory name DEST_POST_PATH:
 *
 * You need to add your WLAN-Credentials in \ref AppController.h\n
 * When running the program keep the USB plugged in to the PC. You can see in the console output of the XDK-Workbench the content of the GET request.
 *
 * @file
 **/

/* module includes ********************************************************** */

/* own header files */
#include "XdkAppInfo.h"

#undef BCDS_MODULE_ID  /* Module ID define before including Basics package*/
#define BCDS_MODULE_ID XDK_APP_MODULE_ID_APP_CONTROLLER

/* own header files */
#include "AppController.h"

/* system header files */
#include <stdio.h>

/* additional interface header files */
#include "XDK_WLAN.h"
#include "XDK_ServalPAL.h"
#include "XDK_HTTPRestClient.h"
#include "XDK_SNTP.h"
#include "BCDS_BSP_Board.h"

#include "BCDS_WlanNetworkConfig.h"
#include "BCDS_WlanNetworkConnect.h"
#include "BCDS_CmdProcessor.h"
#include "BCDS_Assert.h"
#include "XDK_Utils.h"
#include "FreeRTOS.h"
#include "task.h"

/* Interface for all sensors on the XDK */
#include "XdkSensorHandle.h"

/* constant definitions ***************************************************** */

#if HTTP_SECURE_ENABLE
#define APP_RESPONSE_FROM_SNTP_SERVER_TIMEOUT           UINT32_C(10000)/**< Timeout for SNTP server time sync */
#endif /* HTTP_SECURE_ENABLE */

#define APP_RESPONSE_FROM_HTTP_SERVER_POST_TIMEOUT      UINT32_C(25000)/**< Timeout for completion of HTTP rest client POST */

#define APP_RESPONSE_FROM_HTTP_SERVER_GET_TIMEOUT       UINT32_C(25000)/**< Timeout for completion of HTTP rest client GET */

/* local variables ********************************************************** */

static WLAN_Setup_T WLANSetupInfo =
        {
                .IsEnterprise = false,
                .IsHostPgmEnabled = false,
                .SSID = WLAN_SSID,
                .Username = WLAN_PSK, /* Unused for Personal WPA2 connection */
                .Password = WLAN_PSK,
                .IsStatic = WLAN_STATIC_IP,
                .IpAddr = WLAN_IP_ADDR,
                .GwAddr = WLAN_GW_ADDR,
                .DnsAddr = WLAN_DNS_ADDR,
                .Mask = WLAN_MASK,
        };/**< WLAN setup parameters */

#if HTTP_SECURE_ENABLE
static SNTP_Setup_T SNTPSetupInfo =
        {
                .ServerUrl = SNTP_SERVER_URL,
                .ServerPort = SNTP_SERVER_PORT,
        };/**< SNTP setup parameters */
#endif /* HTTP_SECURE_ENABLE */

static HTTPRestClient_Setup_T HTTPRestClientSetupInfo =
        {
                .IsSecure = HTTP_SECURE_ENABLE,
        };/**< HTTP rest client setup parameters */

/*
 * @todo - Use only DEST_SERVER_PORT in the header for secure and non-secure.
 * And remove the below 6 lines of the macros
 */
#if HTTP_SECURE_ENABLE
#ifdef DEST_SERVER_PORT
#undef DEST_SERVER_PORT
#endif /* #ifdef DEST_SERVER_PORT */
#define DEST_SERVER_PORT        DEST_SERVER_PORT_SECURE
#endif /* if HTTP_SECURE_ENABLE */

static HTTPRestClient_Config_T HTTPRestClientConfigInfo =
        {
                .IsSecure = HTTP_SECURE_ENABLE,
                .DestinationServerUrl = DEST_SERVER_HOST,
                .DestinationServerPort = DEST_SERVER_PORT,
                .RequestMaxDownloadSize = REQUEST_MAX_DOWNLOAD_SIZE,
        }; /**< HTTP rest client configuration parameters */

static HTTPRestClient_Post_T HTTPRestClientPostInfo =
        {
                .Payload = POST_REQUEST_BODY,
        		//.Payload = getownData(),
                .PayloadLength = (sizeof(POST_REQUEST_BODY) - 1U),
                .Url = DEST_POST_PATH,
                .RequestCustomHeader0 = POST_REQUEST_CUSTOM_HEADER_0,
                .RequestCustomHeader1 = POST_REQUEST_CUSTOM_HEADER_1,
        }; /**< HTTP rest client POST parameters */



static HTTPRestClient_Config_T HTTPRestClientConfigInfoSign =
        {
                .IsSecure = HTTP_SECURE_ENABLE,
                .DestinationServerUrl = "zhengshu.elastos.org",
                .DestinationServerPort = DEST_SERVER_PORT,
                .RequestMaxDownloadSize = REQUEST_MAX_DOWNLOAD_SIZE,
        }; /**< HTTP rest client configuration parameters */

static HTTPRestClient_Post_T HTTPRestClientPostInfoSign =
        {
                .Payload = POST_REQUEST_BODY_SIGN,
                .PayloadLength = (sizeof(POST_REQUEST_BODY_SIGN) - 1U),
                .Url = "/api/1/association/certification",
                .RequestCustomHeader0 = POST_REQUEST_CUSTOM_HEADER_0,
                .RequestCustomHeader1 = POST_REQUEST_CUSTOM_HEADER_1,
        }; /**< HTTP rest client POST parameters */

/**
 * @brief   The HTTP GET request response callback.
 *
 * @param [in] responseContent
 * Pointer to the GET request response
 *
 * @param [in] responseContentLen
 * Length of the GET request response
 *
 * @param [in] isLastMessage
 * Boolean to represent if it is the last part of the ongoing message
 */
static void HTTPRestClientGetCB(const char* responseContent, uint32_t responseContentLen, bool isLastMessage);

static void HTTPRestClientGetCBSign(const char* responseContent, uint32_t responseContentLen, bool isLastMessage);


static HTTPRestClient_Get_T HTTPRestClientGetInfo =
        {
                .Url = DEST_GET_PATH,
                .GetCB = HTTPRestClientGetCB,
                .GetOffset = 0UL,
        }; /**< HTTP rest client GET parameters */


static HTTPRestClient_Get_T HTTPRestClientGetInfoSign =
        {
                .Url = DEST_GET_PATH,
                .GetCB = HTTPRestClientGetCBSign,
                .GetOffset = 0UL,
        }; /**< HTTP rest client GET parameters */

static xTaskHandle AppControllerHandle = NULL; /**< OS thread handle for Application controller */

static CmdProcessor_T * AppCmdProcessor; /**< Handle to store the main Command processor handle to be reused by ServalPAL thread */

/* global variables ********************************************************* */

/* inline functions ********************************************************* */

/* local functions ********************************************************** */

/** Refer function definition for description */
static void HTTPRestClientGetCB(const char* responseContent, uint32_t responseContentLen, bool isLastMessage)
{
    BCDS_UNUSED(isLastMessage);

    if ((NULL != responseContent) && (0UL != responseContentLen))
    {
        printf("HTTPRestClientGetCB: HTTP GET response: %.*s\r\n", (int) responseContentLen, responseContent);
    }
}

static void HTTPRestClientGetCBSign(const char* responseContent, uint32_t responseContentLen, bool isLastMessage)
{
    BCDS_UNUSED(isLastMessage);

    if ((NULL != responseContent) && (0UL != responseContentLen))
    {
    	 Retcode_T retcode = RETCODE_OK;
         printf("HTTPRestClientGetCBSign: HTTP GET response: %.*s\r\n", (int) responseContentLen, responseContent);
    }
}




/**
 * @brief This will validate the WLAN network connectivity
 *
 * If there is no connectivity then it will scan for the given network and try to reconnect
 *
 * @return  RETCODE_OK on success, or an error code otherwise.
 */
static Retcode_T AppControllerValidateWLANConnectivity(void)
{
    Retcode_T retcode = RETCODE_OK;
    WlanNetworkConnect_IpStatus_T nwStatus;
    nwStatus = WlanNetworkConnect_GetIpStatus();

    if (WLANNWCT_IPSTATUS_CT_AQRD != nwStatus)
    {
#if HTTP_SECURE_ENABLE
        static bool isSntpDisabled = false;
        if (false == isSntpDisabled)
        {
            retcode = SNTP_Disable();
        }
        if (RETCODE_OK == retcode)
        {
            isSntpDisabled = true;
            retcode = WLAN_Reconnect();
        }
        if (RETCODE_OK == retcode)
        {
            retcode = SNTP_Enable();
        }
#else
        retcode = WLAN_Reconnect();
#endif /* HTTP_SECURE_ENABLE */

    }
    return retcode;

}

/**
 * @brief Responsible for controlling the HTTP Example application control flow.
 *
 * - Synchronize the node with the SNTP server for time-stamp (if HTTPS)
 * - Check whether the WLAN network connection is available
 * - Do a HTTP rest client POST
 * - Wait for INTER_REQUEST_INTERVAL if POST was successful
 * - Do a HTTP rest client GET if POST was successful
 * - Wait for INTER_REQUEST_INTERVAL if GET was successful
 * - Redo the last 5 steps
 *
 * @param[in] pvParameters
 * Unused
 */
static void AppControllerFire(void* pvParameters)
{
    BCDS_UNUSED(pvParameters);

    Retcode_T retcode = RETCODE_OK;

#if HTTP_SECURE_ENABLE

    uint64_t sntpTimeStampFromServer = 0UL;

    /* We Synchronize the node with the SNTP server for time-stamp.
     * Since there is no point in doing a HTTPS communication without a valid time */
    do
    {
        retcode = SNTP_GetTimeFromServer(&sntpTimeStampFromServer, APP_RESPONSE_FROM_SNTP_SERVER_TIMEOUT);
        if ((RETCODE_OK != retcode) || (0UL == sntpTimeStampFromServer))
        {
            printf("AppControllerFire : SNTP server time was not synchronized. Retrying...\r\n");
        }
    } while (0UL == sntpTimeStampFromServer);

    BCDS_UNUSED(sntpTimeStampFromServer); /* Copy of sntpTimeStampFromServer will be used be HTTPS for TLS handshake */
#endif /* HTTP_SECURE_ENABLE */

    while (1)
    {
        /* Resetting / clearing the necessary buffers / variables for re-use */
        retcode = RETCODE_OK;

        /* Check whether the WLAN network connection is available */
        retcode = AppControllerValidateWLANConnectivity();

        /* initialize environmental sensor */
        Retcode_T returnValue = RETCODE_FAILURE;
        returnValue = Environmental_init(xdkEnvironmental_BME280_Handle);
        if ( RETCODE_OK != returnValue) {
         // do something
        }
        /* read and print BME280 environmental sensor data */
        Environmental_Data_T bme280 = { INT32_C(0), UINT32_C(0), UINT32_C(0) };
        returnValue = Environmental_readData(xdkEnvironmental_BME280_Handle, &bme280);

        if ( RETCODE_OK == returnValue) {
			 printf("BME280 Environmental Conversion Data :\n\r p =%ld Pa\n\rt =%ld mDeg \n\rh =%ld %%rh\n\r", (long int) bme280.pressure, (long int) bme280.temperature, (long int) bme280.humidity);
        }



        /* Do a HTTP rest client POST */
#if 0
        if (RETCODE_OK == retcode)
        {
        	char* memo = malloc(100);
        	memset(memo,0,sizeof(char)*100);
        	sprintf(memo, "{ \"name\":\"BOSCH_IoT\",\"content\":\"%ld\" }", (long int) bme280.temperature);
        	HTTPRestClientPostInfoSign.Payload = memo;
        	printf("memo:%s\r\n", memo);
        	HTTPRestClientPostInfoSign.PayloadLength = (strlen(memo)),
            retcode = HTTPRestClient_Post(&HTTPRestClientConfigInfoSign, &HTTPRestClientPostInfoSign, APP_RESPONSE_FROM_HTTP_SERVER_POST_TIMEOUT);
            free(memo);
        }
        if (RETCODE_OK == retcode)
        {
            /* Wait for INTER_REQUEST_INTERVAL */
            vTaskDelay(pdMS_TO_TICKS(INTER_REQUEST_INTERVAL));
            /* Do a HTTP rest client GET */
            retcode = HTTPRestClient_Get(&HTTPRestClientConfigInfoSign, &HTTPRestClientGetInfoSign, APP_RESPONSE_FROM_HTTP_SERVER_GET_TIMEOUT);
        }
#else

        if (RETCODE_OK == retcode)
        {
//        	char* memo = malloc(100);
//        	memset(memo,0,sizeof(char)*100);
//        	sprintf(memo, "{ \"name\":\"BOSCH_IoT\",\"content\":\"%ld\" }", (long int) bme280.temperature);

        	char * memo = upload((char*)bme280.temperature);

        	HTTPRestClientPostInfoSign.Payload = memo;
        	printf("memo:%s\r\n", memo);
        	HTTPRestClientPostInfoSign.PayloadLength = (strlen(memo)),
            retcode = HTTPRestClient_Post(&HTTPRestClientConfigInfo, &HTTPRestClientPostInfo, APP_RESPONSE_FROM_HTTP_SERVER_POST_TIMEOUT);
        	free(memo);
        }
        if (RETCODE_OK == retcode)
        {
            /* Wait for INTER_REQUEST_INTERVAL */
            vTaskDelay(pdMS_TO_TICKS(INTER_REQUEST_INTERVAL));
            /* Do a HTTP rest client GET */
            retcode = HTTPRestClient_Get(&HTTPRestClientConfigInfo, &HTTPRestClientGetInfo, APP_RESPONSE_FROM_HTTP_SERVER_GET_TIMEOUT);
        }
#endif

        if (RETCODE_OK == retcode)
        {
            /* Wait for INTER_REQUEST_INTERVAL */
            vTaskDelay(pdMS_TO_TICKS(INTER_REQUEST_INTERVAL));
        }
        if (RETCODE_OK != retcode)
        {
            printf("Error in Post/get request: Will trigger another post/get after INTER_REQUEST_INTERVAL\r\n");
            vTaskDelay(pdMS_TO_TICKS(INTER_REQUEST_INTERVAL));
            /* Report error and continue */
            Retcode_RaiseError(retcode);
        }
    }
}

/**
 * @brief To enable the necessary modules for the application
 * - WLAN
 * - ServalPAL
 * - SNTP (if HTTPS)
 * - HTTP rest client
 *
 * @param[in] param1
 * Unused
 *
 * @param[in] param2
 * Unused
 */
static void AppControllerEnable(void * param1, uint32_t param2)
{
    BCDS_UNUSED(param1);
    BCDS_UNUSED(param2);

    Retcode_T retcode = WLAN_Enable();
    if (RETCODE_OK == retcode)
    {
        retcode = ServalPAL_Enable();
    }
#if HTTP_SECURE_ENABLE
    if (RETCODE_OK == retcode)
    {
        retcode = SNTP_Enable();
    }
#endif /* HTTP_SECURE_ENABLE */
    if (RETCODE_OK == retcode)
    {
        retcode = HTTPRestClient_Enable();
    }
    if (RETCODE_OK == retcode)
    {
        if (pdPASS != xTaskCreate(AppControllerFire, (const char * const ) "AppController", TASK_STACK_SIZE_APP_CONTROLLER, NULL, TASK_PRIO_APP_CONTROLLER, &AppControllerHandle))
        {
            retcode = RETCODE(RETCODE_SEVERITY_ERROR, RETCODE_OUT_OF_RESOURCES);
        }
    }
    if (RETCODE_OK != retcode)
    {
        printf("AppControllerEnable : Failed \r\n");
        Retcode_RaiseError(retcode);
        assert(0); /* To provide LED indication for the user */
    }

    Utils_PrintResetCause();
}

/**
 * @brief To setup the necessary modules for the application
 * - WLAN
 * - ServalPAL
 * - SNTP (if HTTPS)
 * - HTTP rest client
 *
 * @param[in] param1
 * Unused
 *
 * @param[in] param2
 * Unused
 */
static void AppControllerSetup(void * param1, uint32_t param2)
{
    BCDS_UNUSED(param1);
    BCDS_UNUSED(param2);

    Retcode_T retcode = WLAN_Setup(&WLANSetupInfo);
    if (RETCODE_OK == retcode)
    {
        retcode = ServalPAL_Setup(AppCmdProcessor);
    }
#if HTTP_SECURE_ENABLE
    if (RETCODE_OK == retcode)
    {
        retcode = SNTP_Setup(&SNTPSetupInfo);
    }
#endif /* HTTP_SECURE_ENABLE */
    if (RETCODE_OK == retcode)
    {
        retcode = HTTPRestClient_Setup(&HTTPRestClientSetupInfo);
    }
    if (RETCODE_OK == retcode)
    {
        retcode = CmdProcessor_Enqueue(AppCmdProcessor, AppControllerEnable, NULL, UINT32_C(0));
    }
    if (RETCODE_OK != retcode)
    {
        printf("AppControllerSetup : Failed \r\n");
        Retcode_RaiseError(retcode);
        assert(0); /* To provide LED indication for the user */
    }
}

/* global functions ********************************************************** */

/** Refer interface header for description */
void AppController_Init(void * cmdProcessorHandle, uint32_t param2)
{
    BCDS_UNUSED(param2);
    Retcode_T retcode = RETCODE_OK;

    if (cmdProcessorHandle == NULL)
    {
        printf("AppController_Init : Command processor handle is NULL \r\n");
        retcode = RETCODE(RETCODE_SEVERITY_ERROR, RETCODE_NULL_POINTER);
    }
    else
    {
        AppCmdProcessor = (CmdProcessor_T *) cmdProcessorHandle;
        retcode = CmdProcessor_Enqueue(AppCmdProcessor, AppControllerSetup, NULL, UINT32_C(0));
    }

    if (RETCODE_OK != retcode)
    {
        Retcode_RaiseError(retcode);
        assert(0); /* To provide LED indication for the user */
    }
}

/**@} */
/** ************************************************************************* */
