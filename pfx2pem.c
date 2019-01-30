#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <emscripten/emscripten.h>

#ifdef __cplusplus
extern "C" {
#endif

int EMSCRIPTEN_KEEPALIVE pkcs122pem(char *src, int srclen, const char *passwd, char *cert, char *pkey) {
    BIO *in = BIO_new_mem_buf(src, srclen);
    BIO *certout = BIO_new(BIO_s_mem());
    BIO *pkeyout = BIO_new(BIO_s_mem());
  
    PKCS12 *p12 = d2i_PKCS12_bio(in, NULL);
    if (p12 == NULL) {
        return -1;
    }

    if (PKCS12_verify_mac(p12, passwd, -1) != 1) {
        printf("invalid pfx file or wrong password.\n");
        return -1;
    }

    STACK_OF(PKCS7) *asafes = NULL;
    asafes = PKCS12_unpack_authsafes(p12);
    if (asafes == NULL) {
        printf("unpack_authsafes failed.\n");
        return -1;
    }

    PKCS7 *p7;
    int bagnid;
    STACK_OF(PKCS12_SAFEBAG) *bags;
    for (int i = 0; i < sk_PKCS7_num(asafes); i++) {
        p7 = sk_PKCS7_value(asafes, i);
        bagnid = OBJ_obj2nid(p7->type);
        bags = NULL;
        if (bagnid == NID_pkcs7_data) {
            bags = PKCS12_unpack_p7data(p7);
        } else if (bagnid == NID_pkcs7_encrypted) {
            bags = PKCS12_unpack_p7encdata(p7, passwd, 6);
        } else {
            printf("unsupported bagnid.\n");
            return -1;
        }
        if (!bags) {
            continue;
        }

        for (int j = 0; j < sk_PKCS12_SAFEBAG_num(bags); j++) {
            PKCS12_SAFEBAG *bag = sk_PKCS12_SAFEBAG_value(bags, j);
            PKCS8_PRIV_KEY_INFO *p8;
            const PKCS8_PRIV_KEY_INFO *p8c;
            EVP_PKEY *pkey;

            switch(PKCS12_SAFEBAG_get_nid((const PKCS12_SAFEBAG*)bag)) {
            case NID_keyBag:
                
                p8c = PKCS12_SAFEBAG_get0_p8inf(bag);
                pkey = EVP_PKCS82PKEY(p8c);
                PEM_write_bio_PrivateKey(pkeyout, pkey, EVP_des_ede3_cbc(), NULL, 0, NULL, NULL);
                break;

            case NID_certBag:
                if (PKCS12_SAFEBAG_get_bag_nid(bag) != NID_x509Certificate)
                    break;
                X509 *x509;
                x509 = PKCS12_SAFEBAG_get1_cert(bag);
                PEM_write_bio_X509(certout, x509);
                break;

            case NID_pkcs8ShroudedKeyBag:
                p8 = PKCS12_decrypt_skey(bag, passwd, strlen(passwd));
                pkey = EVP_PKCS82PKEY(p8);
                PEM_write_bio_PrivateKey(pkeyout, pkey, NULL, NULL, 0, NULL, "");
                break;
            }
        }
    }
    
    char mbuf[20480] = {0};
    BIO_read(certout, mbuf, 20480);
    sprintf(cert, "%s", mbuf);
    BIO_read(pkeyout, mbuf, 20480);
    sprintf(pkey, "%s", mbuf);
    return 0;
}


#ifdef __cplusplus
}
#endif
