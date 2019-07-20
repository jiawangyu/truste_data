#include <string.h>

#include "mbedtls/pk.h"
#include "mbedtls/config.h"
#include "mbedtls/ecp.h"
#include "mbedtls/platform.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/error.h"
#include "mbedtls/rsa.h"
#include "mbedtls/x509.h"
#include "mbedtls/md.h"


// https://kjur.github.io/jsrsasign/sample/sample-ecdsa.html verifing
const char* did = "imA3yQ4wVheaAPfdepM9SMZ5c1zc6mQRfr";
const char* pub_key = "0320ccbaebb317531cfd81137966f5e87437654fb188673c31c8aec545e6e601e8";
const char* private_key = "598629068485bf57e763dce5de7acf9fd8d1d533dede892c4b8f4a2476504b59";

int mbedtls_ecp_decompress(
    const mbedtls_ecp_group *grp,
    const unsigned char *input, size_t ilen,
    unsigned char *output, size_t *olen, size_t osize
) {
    int ret;
    size_t plen;
    mbedtls_mpi r;
    mbedtls_mpi x;
    mbedtls_mpi n;

    plen = mbedtls_mpi_size(&grp->P);

    *olen = 2 * plen + 1;

    if (osize < *olen)
        return(MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL);

    if (ilen != plen + 1)
        return(MBEDTLS_ERR_ECP_BAD_INPUT_DATA);

    if (input[0] != 0x02 && input[0] != 0x03)
        return(MBEDTLS_ERR_ECP_BAD_INPUT_DATA);

    // output will consist of 0x04|X|Y
    memcpy(output, input, ilen);
    output[0] = 0x04;

    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&x);
    mbedtls_mpi_init(&n);

    // x <= input
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&x, input + 1, plen));

    // r = x^2
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&r, &x, &x));

    // r = x^2 + a
    if (grp->A.p == NULL) {
        // Special case where a is -3
        MBEDTLS_MPI_CHK(mbedtls_mpi_sub_int(&r, &r, 3));
    } else {
        MBEDTLS_MPI_CHK(mbedtls_mpi_add_mpi(&r, &r, &grp->A));
    }

    // r = x^3 + ax
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&r, &r, &x));

    // r = x^3 + ax + b
    MBEDTLS_MPI_CHK(mbedtls_mpi_add_mpi(&r, &r, &grp->B));

    // Calculate square root of r over finite field P:
    //   r = sqrt(x^3 + ax + b) = (x^3 + ax + b) ^ ((P + 1) / 4) (mod P)

    // n = P + 1
    MBEDTLS_MPI_CHK(mbedtls_mpi_add_int(&n, &grp->P, 1));

    // n = (P + 1) / 4
    MBEDTLS_MPI_CHK(mbedtls_mpi_shift_r(&n, 2));

    // r ^ ((P + 1) / 4) (mod p)
    MBEDTLS_MPI_CHK(mbedtls_mpi_exp_mod(&r, &r, &n, &grp->P, NULL));

    // Select solution that has the correct "sign" (equals odd/even solution in finite group)
    if ((input[0] == 0x03) != mbedtls_mpi_get_bit(&r, 0)) {
        // r = p - r
        MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mpi(&r, &grp->P, &r));
    }

    // y => output
    ret = mbedtls_mpi_write_binary(&r, output + 1 + plen, plen);

cleanup:
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&x);
    mbedtls_mpi_free(&n);

    return(ret);
}

int mbedtls_ecp_compress(
    const mbedtls_ecp_group *grp,
    const unsigned char *input, size_t ilen,
    unsigned char *output, size_t *olen, size_t osize
) {
    size_t plen;

    plen = mbedtls_mpi_size(&grp->P);

    *olen = plen + 1;

    if (osize < *olen)
        return(MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL);

    if (ilen != 2 * plen + 1)
        return (MBEDTLS_ERR_ECP_BAD_INPUT_DATA);

    if (input[0] != 0x04)
        return(MBEDTLS_ERR_ECP_BAD_INPUT_DATA);

    // output will consist of 0x0?|X
    memcpy(output, input, *olen);

    // Encode even/odd of Y into first byte (either 0x02 or 0x03)
    output[0] = 0x02 + (input[2 * plen] & 1);

    return(0);
}


// Helper to convert binary to hex
static char *bytes_to_hex(const uint8_t bin[], size_t len)
{
    static const char hexchars[16] = "0123456789abcdef";
    static char hex[512];
    size_t i;

    for (i = 0; i < len; ++i)
    {
        hex[2 * i] = hexchars[bin[i] / 16];
        hex[2 * i + 1] = hexchars[bin[i] % 16];
    }
    hex[2 * len] = '\0';
    return hex;
}

// Helper to print private keys
static int dump_privatekey(const char* title, mbedtls_ecdsa_context *key)
{
    uint8_t buf[512];
    size_t len;

	size_t grp_len = ( key->grp.nbits + 7 ) / 8;
    if (mbedtls_mpi_write_binary( &key->d, buf, grp_len ) != 0) {
        printf("internal error\n");
        return 0;
    }

    len = mbedtls_mpi_size( &key->d );
    printf("%s %s:%d (%d bits)\n", title, bytes_to_hex(buf, mbedtls_mpi_size( &key->d )), len, (int) key->grp.pbits);
}

// Helper to print public keys
static void dump_pubkey(const char *title, mbedtls_ecdsa_context *key)
{
    uint8_t buf[512];
    size_t len;

    if (mbedtls_ecp_point_write_binary(&key->grp, &key->Q,
            MBEDTLS_ECP_PF_UNCOMPRESSED, &len, buf, sizeof(buf)) != 0) {
        printf("internal error\n");
        return;
    }

    printf("%s %s (%d bits)\n", title, bytes_to_hex(buf, len), (int) key->grp.pbits);
}

#if 0
// Helper to print bignums
void print_mpi(const char *title, const mbedtls_mpi *n)
{
    char buf[512];
    size_t olen = 0;
    if (mbedtls_mpi_write_string(n, 16, buf, sizeof(buf), &olen) != 0) {
        printf("print_mpi error\n");
        exit(1);
    }

    printf("%s %s\n", title, buf);
}

// Helper to check if this holds for prime P: curve->p == 3 (mod 4)
static void check_prime(mbedtls_mpi *P){
    mbedtls_mpi tmp;
    mbedtls_mpi _4;
    mbedtls_mpi_init(&tmp);
    mbedtls_mpi_init(&_4);

    mbedtls_mpi_lset(&_4, 4);
    mbedtls_mpi_copy(&tmp, P);

    mbedtls_mpi_mod_mpi(&tmp, &tmp, &_4);
    print_mpi("We can use fast sqrt mod P if the output is 3: ", &tmp);
}
#endif

int write_mpi( unsigned char * * p, unsigned char * start, const mbedtls_mpi * X )
{
    int ret;
    size_t len = 0;

    // Write the MPI
    len = mbedtls_mpi_size( X );

    if( * p < start || (size_t)( * p - start ) < len )
        return( MBEDTLS_ERR_ASN1_BUF_TOO_SMALL );

    ( * p) -= len;
    mbedtls_mpi_write_binary( X, * p, len );

    return len;
}

int readRS(const unsigned char *sig, size_t slen, unsigned char* data) {
    int ret;
    unsigned char *p = (unsigned char *) sig;
    const unsigned char *end = sig + slen;
    size_t len;
    mbedtls_mpi r, s;
    mbedtls_mpi_init( &r );
    mbedtls_mpi_init( &s );

    ret = mbedtls_asn1_get_tag( &p, end, &len,
                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE );
    if (ret != 0) {
        return ret;
    }

    ret = mbedtls_asn1_get_mpi( &p, end, &r );
    if (ret != 0) {
        return ret;
    }

    ret = mbedtls_asn1_get_mpi( &p, end, &s );
    if (ret != 0) {
        return ret;
    }

    unsigned char rs[64];
    unsigned char *rsbufend = rs + sizeof( rs );

    write_mpi(&rsbufend, rs, &s);
    write_mpi(&rsbufend, rs, &r);

    memcpy( data, rs, 64 );

    //printf("[hua] sig:%s, %d \n", bytes_to_hex(sig, slen), slen);
    //printf("[hua] data:%s \n", bytes_to_hex(data, 64));
    return 0;
}

#define _hexu(c) (((c) >= '0' && (c) <= '9') ? (c) - '0' : ((c) >= 'a' && (c) <= 'f') ? (c) - ('a' - 0x0a) :\
                  ((c) >= 'A' && (c) <= 'F') ? (c) - ('A' - 0x0a) : -1)

static inline char _toC(uint8_t u)
{
    return (u & 0x0f) + ((u & 0x0f) <= 9 ? '0' : 'A' - 0x0a);
}

char * hex2Str(const uint8_t * buff, int len)
{
    char * ret = NULL;
    int size = 0;
    if (len > 0)
    {
        size = len * 2 + 1;
        ret = malloc(size);
        if (!ret) return ret;
    }
    for (size_t i = 0; i < len; i++)
    {
        ret[2 * i] = _toC(buff[i] >> 4);
        ret[2 * i + 1] = _toC(buff[i]);
    }
    if (ret != NULL)
    {
        ret[size - 1] = '\0';
    }
    return ret;
}

static void decodeHex(uint8_t *target, size_t targetLen, const char *source, size_t sourceLen) {
    if (2 * targetLen < sourceLen || 0 != sourceLen % 2) {
        printf("[error] decodeHexCreate targetLen={%ld}, sourceLen={%ld} \n", targetLen, sourceLen);
        return;
    }

    for (unsigned i = 0; i < targetLen; i++) {
        target[i] = (uint8_t) ((_hexu(source[2 * i]) << 4) | _hexu(source[(2 * i) + 1]));
    }
}

static size_t decodeHexLength(size_t stringLen) {
    if (0 != stringLen % 2) {
        printf("[error] decodeHexCreate Invalid string length.");
	    return 0;
    }
    return stringLen / 2;
}

static uint8_t* decodeHexCreate(size_t *targetLen, char *source, size_t sourceLen) {
    size_t length = decodeHexLength(sourceLen);
    if (NULL != targetLen) {
		*targetLen = length;
    }

    uint8_t *target = (uint8_t *) malloc(length);
    if(NULL == target) {
        printf("[error] decodeHexCreate memory malloc failed! \n");
		return NULL;
	}

    decodeHex(target, length, source, sourceLen);
    return target;
}

char* createDidInfo(const char * did, const char * key, const char * value)
{
    int len = 160 + strlen(key) + strlen(value);
    printf("didinfo len: %d\n", len);
    char * buf = malloc(len);
    if (!buf) return NULL;

    sprintf(buf, "{\"Tag\":\"DID Property\",\"Ver\":\"1.0\",\"Status\":\"Normal\",\"Did\":\"%s\",\"Properties\":[{\"Key\":\"%s\",\"Value\":\"%s\",\"Status\":\"Normal\"}]}", did, key, value);
    return buf;
}

char* createMemoInfo(const char * didinfo, const char * signedInfo, const char * publicKey)
{
    char * binStr = NULL;
    char * memo = NULL;

    binStr = hex2Str(didinfo, strlen(didinfo));
    if (!binStr) goto exit;
    printf("binStr: %s\n", binStr);
    int len = 30 + strlen(binStr) + strlen(publicKey) + strlen(signedInfo);
    printf("memo len: %d\n", len);

    memo = malloc(len);
    if (!memo) goto exit;

    sprintf(memo, "{\"msg\":\"%s\",\"pub\":\"%s\",\"sig\":\"%s\"}", binStr, publicKey, signedInfo);

    exit:
    if (binStr)
    {
        free(binStr);
    }
    return memo;
}



int restore_private_key(mbedtls_pk_context* ctx_sign) {
    mbedtls_pk_init(ctx_sign);

    int ret;

    if ((ret = mbedtls_pk_setup(ctx_sign, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY))) != 0)
    {
        printf("mbedtls_pk_setup returned -0x%04x", -ret);
        return(1);
    }

    mbedtls_ecp_keypair *key = mbedtls_pk_ec(*ctx_sign);
    if( ( ret = mbedtls_ecp_group_load( &key->grp, 3) ) != 0 )
        return( ret );

    const char* privateKey = "c630ed466237a5e8666dde3173bdd1cb3f9dfe02b13767d30f69037f9b3945c5";
    size_t len;
    uint8_t* data = decodeHexCreate(&len, privateKey, strlen(privateKey));

    mbedtls_mpi_init(&key->d);
    mbedtls_mpi_read_binary(&key->d, data, len);

	dump_privatekey("Private key: ", key);
    return 0;
}

char* sign(const char* data)
{
    int           ret;
    unsigned char sig[512]     = { 0 };
    size_t        sig_len;
    unsigned char hash_data[32] = { 0 }; /* SHA-256 outputs 32 bytes */

    mbedtls_pk_context ctx_sign; 
    mbedtls_pk_init(&ctx_sign);

	//genkey(&ctx_sign);
	restore_private_key(&ctx_sign);

    // hash, 0 here means use the full SHA-256, not the SHA-224 variant
    mbedtls_sha256(data, strlen(data), hash_data, 0);

    // "Signing message
    if ((ret = mbedtls_ecdsa_write_signature(mbedtls_pk_ec(ctx_sign), 6,
            hash_data, sizeof(hash_data), sig, &sig_len, mbedtls_ctr_drbg_random, NULL)) != 0){
        printf("[error] mbedtls_ecdsa_genkey returned %d\n", ret);
        return(1);
    }

    printf("ok (signature length = %lu)\n", sig_len);
    printf(" + hash: %s\n", bytes_to_hex(hash_data, strlen((char*) hash_data)));
    printf(" + signature: %s\n", bytes_to_hex(sig, sig_len));

	char* rsdata = (char*)malloc(64);
	if(NULL == rsdata) {
        printf("[error] rsdata malloc faild! \n");
        return(1);
    }
	readRS(sig, sig_len, rsdata);

    //verify(&ctx_sign, hash_data, strlen(hash_data), sig, sig_len);

    mbedtls_pk_free(&ctx_sign);

    return rsdata;
}

char* upload(const char* value)
{
    char* didinfo = createDidInfo(did, "BOSCH_IoT", value);
	char* signedInfo = sign(didinfo);
	char* memo = createMemoInfo(didinfo, signedInfo, pub_key);
	free(didinfo);
	free(signedInfo);
	return memo;
}

//int main(int argc, char **argv)
//{
//    char* signed_data = sign("aaa");
//	printf("signed data:%s \n", bytes_to_hex(signed_data, 64));
//}
