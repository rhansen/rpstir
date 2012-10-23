/*
 * $Id: sign_cert.c c 506 2008-06-03 21:20:05Z gardiner $ 
 */


#include <stdio.h>
#include <cryptlib.h>
#include <rpki-asn1/keyfile.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <rpki-asn1/certificate.h>
#include <rpki-asn1/crlv2.h>
#include <rpki-asn1/roa.h>
#include <casn/casn.h>
#include <rpki-asn1/blob.h>

char *msgs[] = {
    "Finished %s OK\n",
    "Error in %s\n",
    "Usage: TBS filename, Key filename [1 to adjust dates | 2 to keep tbs alg]\n",
    "Couldn't open %s\n",
    "Error getting memory\n",
};

static void adjust_time(
    struct casn *fromp,
    struct casn *tillp)
{
    int64_t begt,
        till;
    read_casn_time(fromp, &begt);
    read_casn_time(tillp, &till);
    till -= begt;
    begt = time(NULL);
    till += begt;
    write_casn_time(fromp, begt);
    write_casn_time(tillp, till);
}

static void fatal(
    int err,
    char *paramp)
{
    fprintf(stderr, msgs[err], paramp);
    if (err)
        exit(err);
}

int CryptInitState = 0;


static int setSignature(
    struct casn *tbhash,
    struct casn *newsignature,
    const char *keyfile)
{
    CRYPT_CONTEXT hashContext;
    CRYPT_CONTEXT sigKeyContext;
    CRYPT_KEYSET cryptKeyset;
    uchar hash[40];
    uchar *signature = NULL;
    int ansr = 0,
        signatureLength;
    char *msg;
    uchar *signstring = NULL;
    int sign_lth;

    /*
     * constants for encrypting and storing RSA private keys in p15 files 
     */
    static const char *P15_LABEL = "label";
    static const char *P15_PASSWORD = "password";

    if ((sign_lth = size_casn(tbhash)) < 0)
        fatal(1, "sizing");
    signstring = (uchar *) calloc(1, sign_lth);
    sign_lth = encode_casn(tbhash, signstring);
    memset(hash, 0, 40);
    if (!CryptInitState)
    {
        if (cryptInit() != CRYPT_OK)
            fatal(1, "CryptInit");
        CryptInitState = 1;
    }
    if ((ansr =
         cryptCreateContext(&hashContext, CRYPT_UNUSED, CRYPT_ALGO_SHA2)) != 0
        || (ansr =
            cryptCreateContext(&sigKeyContext, CRYPT_UNUSED,
                               CRYPT_ALGO_RSA)) != 0)
        msg = "creating context";
    else if ((ansr = cryptEncrypt(hashContext, signstring, sign_lth)) != 0 ||
             (ansr = cryptEncrypt(hashContext, signstring, 0)) != 0)
        msg = "hashing";
    else if ((ansr = cryptGetAttributeString(hashContext,
                                             CRYPT_CTXINFO_HASHVALUE, hash,
                                             &signatureLength)) != 0)
        msg = "getting attribute string";
    else if ((ansr = cryptKeysetOpen(&cryptKeyset, CRYPT_UNUSED,
                                     CRYPT_KEYSET_FILE, keyfile,
                                     CRYPT_KEYOPT_READONLY)) != 0)
        msg = "opening key set";
    else if ((ansr = cryptGetPrivateKey(cryptKeyset, &sigKeyContext,
                                        CRYPT_KEYID_NAME, P15_LABEL,
                                        P15_PASSWORD)) != 0)
        msg = "getting key";
    else if ((ansr = cryptCreateSignature(NULL, 0, &signatureLength,
                                          sigKeyContext, hashContext)) != 0)
        msg = "signing";
    else
    {
        signature = (uchar *) calloc(1, signatureLength + 20);
        if ((ansr = cryptCreateSignature(signature, signatureLength + 20,
                                         &signatureLength, sigKeyContext,
                                         hashContext)) != 0)
            msg = "signing";
        else if ((ansr = cryptCheckSignature(signature, signatureLength,
                                             sigKeyContext, hashContext)) != 0)
            msg = "verifying";
    }
    cryptDestroyContext(hashContext);
    cryptDestroyContext(sigKeyContext);
    if (signstring)
        free(signstring);
    signstring = NULL;
    if (ansr == 0)
    {
        struct SignerInfo siginfo;
        SignerInfo(&siginfo, (ushort) 0);
        if ((ansr = decode_casn(&siginfo.self, signature)) < 0)
            msg = "decoding signature";
        else if ((ansr = readvsize_casn(&siginfo.signature, &signstring)) < 0)
            msg = "reading signature";
        else
        {
            if ((ansr =
                 write_casn_bits(newsignature, signstring, ansr, 0)) < 0)
                msg = "writing signature";
            else
                ansr = 0;
        }
    }
    if (signstring != NULL)
        free(signstring);
    if (signature != NULL)
        free(signature);
    if (ansr)
        fatal(1, msg);
    return ansr;
}

int main(
    int argc,
    char **argv)
{
    /*
     * Args are: file TBS, keyfile, [update] 
     */
    struct Certificate cert;
    Certificate(&cert, (ushort) 0);
    struct CertificateRevocationList crl;
    CertificateRevocationList(&crl, (ushort) 0);
    struct Blob blob;
    Blob(&blob, (ushort) 0);
    struct AlgorithmIdentifier *algp,
       *tbsalgp;
    struct casn *casnp,
       *sigp,
       *selfp;
    const char *keyfile = NULL;

    if (argc < 3)
        fatal(2, (char *)0);
    char *sfx = strrchr(argv[1], (int)'.');
    keyfile = argv[2];
    if (!strcmp(sfx, ".cer"))
    {
        selfp = &cert.self;
        casnp = &cert.toBeSigned.self;
        tbsalgp = &cert.toBeSigned.signature;
        sigp = &cert.signature;
        algp = &cert.algorithm;
    }
    else if (!strcmp(sfx, ".crl"))
    {
        selfp = &crl.self;
        casnp = &crl.toBeSigned.self;
        tbsalgp = &crl.toBeSigned.signature;
        sigp = &crl.signature;
        algp = &crl.algorithm;
    }
    else if (!strcmp(sfx, ".blb"))
    {
        selfp = &blob.self;
        casnp = &blob.toBeSigned;
        tbsalgp = NULL;
        sigp = &blob.signature;
        algp = &blob.algorithm;
    }
    if (get_casn_file(selfp, argv[1], 0) < 0)
        fatal(3, argv[1]);
    if (argv[3] && (*argv[3] & 1))
    {
        if (!strcmp(sfx, ".cer"))
            adjust_time(&cert.toBeSigned.validity.notBefore.utcTime,
                        &cert.toBeSigned.validity.notAfter.utcTime);
        else if (!strcmp(sfx, ".crl"))
            adjust_time((struct casn *)&crl.toBeSigned.lastUpdate,
                        (struct casn *)&crl.toBeSigned.nextUpdate);
    }
    if (tbsalgp && (!argv[3] || !(*argv[3] & 2)))
    {
        write_objid(&tbsalgp->algorithm, id_sha_256WithRSAEncryption);
        write_casn(&tbsalgp->parameters.rsadsi_SHA256_WithRSAEncryption,
                   (uchar *) "", 0);
    }
    setSignature(casnp, sigp, keyfile);
    if (!argv[3] || !(*argv[3] & 4))
    {
        write_objid(&algp->algorithm, id_sha_256WithRSAEncryption);
        write_casn(&algp->parameters.rsadsi_SHA256_WithRSAEncryption,
                   (uchar *) "", 0);
    }
    put_casn_file(selfp, argv[1], 0);
    fatal(0, argv[1]);
    return 0;
}