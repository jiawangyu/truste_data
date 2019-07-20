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
 *  @file
 *
 *  @brief Configuration header for the AppController.c file.
 *
 */

/* header definition ******************************************************** */
#ifndef APPCONTROLLER_H_
#define APPCONTROLLER_H_

/* local interface declaration ********************************************** */
#include "XDK_Utils.h"

/* local type and macro definitions */

/* local module global variable declarations */

/* local inline function definitions */

/* WLAN configurations ****************************************************** */

#warning Please configure your WLAN below and remove this line.

/**
 * WLAN_SSID is the WIFI network name where user wants connect the XDK device.
 * Make sure to update the WLAN_PSK constant according to your required WIFI network.
 */
#define WLAN_SSID                           "jw-ap"

/**
 * WLAN_PSK is the WIFI router WPA/WPA2 password used at the Wifi network connection.
 * Make sure to update the WLAN_PSK constant according to your router password.
 */
#define WLAN_PSK                            "meiyoumima123"

/**
 * WLAN_STATIC_IP is a boolean. If "true" then static IP will be assigned and if "false" then DHCP is used.
 */
#define WLAN_STATIC_IP                      false

/**
 * WLAN_IP_ADDR is the WIFI router WPA/WPA2 static IPv4 IP address (unused if WLAN_STATIC_IP is false)
 * Make sure to update the WLAN_IP_ADDR constant according to your required WIFI network,
 * if WLAN_STATIC_IP is "true".
 */
#define WLAN_IP_ADDR                        XDK_NETWORK_IPV4(0, 0, 0, 0)

/**
 * WLAN_GW_ADDR is the WIFI router WPA/WPA2 static IPv4 gateway address (unused if WLAN_STATIC_IP is false)
 * Make sure to update the WLAN_GW_ADDR constant according to your required WIFI network,
 * if WLAN_STATIC_IP is "true".
 */
#define WLAN_GW_ADDR                        XDK_NETWORK_IPV4(0, 0, 0, 0)

/**
 * WLAN_DNS_ADDR is the WIFI router WPA/WPA2 static IPv4 DNS address (unused if WLAN_STATIC_IP is false)
 * Make sure to update the WLAN_DNS_ADDR constant according to your required WIFI network,
 * if WLAN_STATIC_IP is "true".
 */
#define WLAN_DNS_ADDR                       XDK_NETWORK_IPV4(0, 0, 0, 0)

/**
 * WLAN_MASK is the WIFI router WPA/WPA2 static IPv4 mask address (unused if WLAN_STATIC_IP is false)
 * Make sure to update the WLAN_MASK constant according to your required WIFI network,
 * if WLAN_STATIC_IP is "true".
 */
#define WLAN_MASK                           XDK_NETWORK_IPV4(0, 0, 0, 0)

/* Server configurations ***************************************************** */

/**
 * DEST_SERVER_HOST is the host name of the web server we will send HTTP requests to.
 * If you want to test this example without setting up your own server, you can use publicly available services.
 */
#define DEST_SERVER_HOST                "api-wallet-did.elastos.org"

/**
 * DEST_SERVER_PORT is the TCP port to which we will send HTTP requests to.
 * The default of 80 should be fine for most applications.
 */
#define DEST_SERVER_PORT                UINT16_C(80)

/**
 * DEST_SERVER_PORT_SECURE is the TCP port to which we will send HTTPS requests to.
 * The default of 443 should be fine for most applications.
 */
#define DEST_SERVER_PORT_SECURE         UINT16_C(443)

/**
 * DEST_GET_PATH is the path relative to the DEST_SERVER_HOST that we will send
 * the HTTP GET request to. Using / will retrieve the index page of the web server
 * which for demo purposes may be enough.
 *
 * Change this value if you use your own web server.
 */
#define DEST_GET_PATH                   "/get"

/**
 * DEST_POST_PATH is the path relative to the DEST_SERVER_HOST that we will send
 * the HTTP POST request to.
 *
 * Change this value if you use your own web server.
 */
#define DEST_POST_PATH                  "/api/1/blockagent/upchain/data"

/**
 * POST_REQUEST_CUSTOM_HEADER_0 is a custom header which is sent along with the
 * POST request. It's meant to demonstrate how to use custom header.
 */

#define POST_REQUEST_CUSTOM_HEADER_0    "X-AuthToken: Token\r\n"

/**
 * POST_REQUEST_CUSTOM_HEADER_1 is a custom header which is sent along with the
 * POST request. It's meant to demonstrate how to use custom header.
 */
// 'Accept': 'application/json',
// 'Content-Type': 'application/json'
#define POST_REQUEST_CUSTOM_HEADER_1    "Accept: application/json Content-Type: application//json\r\n "

/**
 * POST_REQUEST_BODY is sent as body with the HTTP POST request
 */
//#define POST_REQUEST_BODY               "{ \"device\": \"XDK110\", \"ping\": \"pong\" }"

#define POST_REQUEST_BODY               "{ \"msg\": \"7b22546167223a224449442050726f7065727479222c22566572223a22312e30222c22537461747573223a224e6f726d616c222c22446964223a226957674d70716f754a504b324834574d3472327a764c70385870645a774469685a53222c2250726f70657274696573223a5b7b224b6579223a2261222c2256616c7565223a2262222c22537461747573223a224e6f726d616c227d5d7d\",\"pub\": \"02ab56c5493d1b26639dcdbc53a664c5eceb4739043ce06eae358b2d8366f358b1\",\"sig\": \"2a4c27ef29b24e108a2d62a058bfab46a9ee00ed87b315832bed9b173fd259064e213ef46e9aa160e342202f8dd7201f982282c1047d74c385d1135e759374e0\" }"

//#define POST_REQUEST_BODY               "{ \"msg\": \"638313961666638616333643532613237626563653664613363643766666361326338316635303063613864356165666133222c22537461747573223a224e6f726d616c227d5d7d\",\"pub\": \"02ab56c5493d1b26639dcdbc53a664c5eceb4739043ce06eae358b2d8366f358b1\",\"sig\": \"f8df0271d08f0b3c453b1306b99d095cb6d081c9ce23a78a5b46e3d9734794a90f26bd4da27ce4f35c41377da9c0e0c453566978c29ef811c68cdc5009f5f0cb\" }"

#define POST_REQUEST_BODY_SIGN     "{ \"name\": \"XDK110\", \"content\": \"pong\" }"
/**
 * The time we wait (in milliseconds) between sending HTTP requests.
 */
#define INTER_REQUEST_INTERVAL          UINT32_C(10000)

#warning Configure HTTP_SECURE_ENABLE to 1 to enable the HTTPS based Communication otherwise Communication will happen through HTTP.

/**
 * HTTP_SECURE_ENABLE is Set to Use HTTP With Security
 */
#define HTTP_SECURE_ENABLE              UINT32_C(1)

#if HTTP_SECURE_ENABLE /* Below are SNTP related macros which are only valid for HTTPS */

/**
 * SNTP_SERVER_URL is the SNTP server URL.
 */
#define SNTP_SERVER_URL                 "0.de.pool.ntp.org"

/**
 * SNTP_SERVER_PORT is the SNTP server port number
 */
#define SNTP_SERVER_PORT                UINT16_C(123)

#endif /* #if HTTP_SECURE_ENABLE */

/**
 * The maximum amount of data we download in a single request (in bytes). This number is
 * limited by the platform abstraction layer implementation that ships with the
 * XDK. The maximum value that will work here is 512 bytes.
 */
#define REQUEST_MAX_DOWNLOAD_SIZE       UINT32_C(512)

//#define MBEDTLS_MD_SHA256       6

/**
 * @brief Gives control to the Application controller.
 *
 * @param[in] cmdProcessorHandle
 * Handle of the main command processor which shall be used based on the application needs
 *
 * @param[in] param2
 * Unused
 */
void AppController_Init(void * cmdProcessorHandle, uint32_t param2);

#endif /* APPCONTROLLER_H_ */
