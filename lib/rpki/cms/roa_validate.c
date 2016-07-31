#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <stdbool.h>
#include <inttypes.h>
#include <wchar.h>
#include <wctype.h>
#include <locale.h>

#include "roa_utils.h"
#include "rpki-object/certificate.h"
#include "util/cryptlib_compat.h"
#include "util/logging.h"
#include "util/hashutils.h"

int strict_profile_checks_cms = 0;

/*
 * This file contains the functions that semantically validate the ROA. Any
 * and all syntactic validation against existing structures is assumed to have
 * been performed at the translation step (see roa_serialize.c).
 */

#define MINMAXBUFSIZE 20

#define MANIFEST_NUMBER_MAX_SIZE 20 /* in bytes */

err_code
check_sig(
    struct CMS *rp,
    struct Certificate *certp)
{
    CRYPT_CONTEXT pubkeyContext;
    CRYPT_CONTEXT hashContext;
    CRYPT_PKCINFO_RSA rsakey;
    struct RSAPubKey rsapubkey;
    int bsize;
    int ret;
    int sidsize;
    uchar *c;
    uchar *buf;
    /** @bug magic number */
    uchar hash[40];
    /** @bug magic number */
    uchar sid[40];

    // get SID and generate the sha-1 hash
    // (needed for cryptlib; see below)
    memset(sid, 0, sizeof(sid));
    bsize = size_casn(&certp->toBeSigned.subjectPublicKeyInfo.self);
    if (bsize < 0)
        return ERR_SCM_INVALSIG;;
    /** @bug ignores error code (NULL) without explanation */
    buf = (uchar *) calloc(1, bsize);
    encode_casn(&certp->toBeSigned.subjectPublicKeyInfo.self, buf);
    sidsize = gen_hash(buf, bsize, sid, CRYPT_ALGO_SHA1);
    free(buf);

    // generate the sha256 hash of the signed attributes. We don't call
    // gen_hash because we need the hashContext for later use (below).
    struct SignerInfo *sigInfop =
        (struct SignerInfo *)member_casn(&rp->content.signedData.signerInfos.
                                         self, 0);
    memset(hash, 0, sizeof(hash));
    bsize = size_casn(&sigInfop->signedAttrs.self);
    if (bsize < 0)
        return ERR_SCM_INVALSIG;;
    /** @bug ignores error code (NULL) without explanation */
    buf = (uchar *) calloc(1, bsize);
    encode_casn(&sigInfop->signedAttrs.self, buf);
    *buf = ASN_SET;

    // (re)init the crypt library
    if (cryptInit_wrapper() != CRYPT_OK)
        return ERR_SCM_CRYPTLIB;
    if (cryptCreateContext(&hashContext, CRYPT_UNUSED, CRYPT_ALGO_SHA2))
        return ERR_SCM_CRYPTLIB;
    cryptEncrypt(hashContext, buf, bsize);
    cryptEncrypt(hashContext, buf, 0);
    if (cryptGetAttributeString(
            hashContext, CRYPT_CTXINFO_HASHVALUE, hash, &ret) != CRYPT_OK)
    {
        LOG(LOG_ERR, "cryptGetAttributeString() failed");
        free(buf);
        cryptDestroyContext(hashContext);
        return ERR_SCM_CRYPTLIB;
    }
    assert(ret == 32);          /* size of hash; should never fail */
    free(buf);

    // get the public key from the certificate and decode it into an RSAPubKey
    readvsize_casn(&certp->toBeSigned.subjectPublicKeyInfo.subjectPublicKey,
                   &c);
    RSAPubKey(&rsapubkey, 0);
    decode_casn(&rsapubkey.self, &c[1]);        // skip 1st byte (tag?) in BIT
                                                // STRING
    free(c);

    // set up the key by reading the modulus and exponent
    if (cryptCreateContext(&pubkeyContext, CRYPT_UNUSED, CRYPT_ALGO_RSA))
        return ERR_SCM_CRYPTLIB;
    cryptSetAttributeString(pubkeyContext, CRYPT_CTXINFO_LABEL, "label", 5);
    cryptInitComponents(&rsakey, CRYPT_KEYTYPE_PUBLIC);

    // read the modulus from rsapubkey
    bsize = readvsize_casn(&rsapubkey.modulus, &buf);
    c = buf;
    // if the first byte is a zero, skip it
    if (!*buf)
    {
        c++;
        bsize--;
    }
    cryptSetComponent((&rsakey)->n, c, bsize * 8);
    free(buf);

    // read the exponent from the rsapubkey
    bsize = readvsize_casn(&rsapubkey.exponent, &buf);
    cryptSetComponent((&rsakey)->e, buf, bsize * 8);
    free(buf);

    // set the modulus and exponent on the key
    cryptSetAttributeString(pubkeyContext, CRYPT_CTXINFO_KEY_COMPONENTS,
                            &rsakey, sizeof(CRYPT_PKCINFO_RSA));
    // all done with this now, free the storage
    cryptDestroyComponents(&rsakey);

    // make the structure cryptlib likes.
    // we discovered through detective work that cryptlib wants the
    // signature's SID field to be the sha-1 hash of the SID.
    struct SignerInfo sigInfo;
    SignerInfo(&sigInfo, (ushort) 0);   /* init sigInfo */
    copy_casn(&sigInfo.version.self, &sigInfop->version.self);  /* copy over */
    copy_casn(&sigInfo.sid.self, &sigInfop->sid.self);  /* copy over */
    write_casn(&sigInfo.sid.subjectKeyIdentifier, sid, sidsize);        /* sid
                                                                         * hash */

    // copy over digest algorithm, signature algorithm, signature
    copy_casn(&sigInfo.digestAlgorithm.self, &sigInfop->digestAlgorithm.self);
    copy_casn(&sigInfo.signatureAlgorithm.self,
              &sigInfop->signatureAlgorithm.self);
    copy_casn(&sigInfo.signature, &sigInfop->signature);

    // now encode as asn1, and check the signature
    bsize = size_casn(&sigInfo.self);
    buf = (uchar *) calloc(1, bsize);
    encode_casn(&sigInfo.self, buf);
    ret = cryptCheckSignature(buf, bsize, pubkeyContext, hashContext);
    free(buf);

    // all done, clean up
    cryptDestroyContext(pubkeyContext);
    cryptDestroyContext(hashContext);
    delete_casn(&rsapubkey.self);
    delete_casn(&sigInfo.self);

    // if the value returned from crypt above != 0, it's invalid
    return (ret != 0) ? ERR_SCM_INVALSIG : 0;
}

static void fill_max(
    uchar * max)
{
    max[max[1] + 1] |= ((1 << max[2]) - 1);
}

static int getTime(
    struct CertificateValidityDate *cvdp,
    int64_t * datep)
{
    int ansr;
    if (size_casn(&cvdp->utcTime) == 0)
        ansr = read_casn_time(&cvdp->generalTime, datep);
    else
        ansr = read_casn_time(&cvdp->utcTime, datep);
    return ansr;
}


static err_code
check_cert(
    struct Certificate *certp,
    int isEE)
{
    int tmp;
    int64_t lo,
        hi;
    struct CertificateToBeSigned *certtbsp = &certp->toBeSigned;

    if (read_casn_num(&certp->toBeSigned.version.self, (long *)&tmp) < 0 ||
        tmp != 2)
        return ERR_SCM_BADCERTVERS;
    if (diff_casn(&certtbsp->signature.algorithm, &certp->algorithm.algorithm))
        return ERR_SCM_BADALG;
    if (getTime(&certtbsp->validity.notBefore, &lo) < 0 ||
        getTime(&certtbsp->validity.notAfter, &hi) < 0 || lo > hi)
        return ERR_SCM_BADDATES;
    struct casn *spkeyp = &certtbsp->subjectPublicKeyInfo.subjectPublicKey;
    uchar *pubkey;
    tmp = readvsize_casn(spkeyp, &pubkey);
    uchar khash[22];
    tmp = gen_hash(&pubkey[1], tmp - 1, khash, CRYPT_ALGO_SHA1);
    free(pubkey);
    int err = 1;                // require SKI
    struct Extension *extp;
    int ski_lth = 0;
    int tmp2 = 0;
    for (extp = (struct Extension *)member_casn(&certtbsp->extensions.self, 0);
         extp; extp = (struct Extension *)next_of(&extp->self))
    {
        /** @bug error code ignored without explanation */
        if (isEE && !diff_objid(&extp->extnID, id_basicConstraints) &&
            size_casn(&extp->extnValue.basicConstraints.cA) > 0)
            return ERR_SCM_NOTEE;
        /** @bug error code ignored without explanation */
        if (!diff_objid(&extp->extnID, id_subjectKeyIdentifier))
        {
            uchar *ski;
            ski_lth =
                readvsize_casn(&extp->extnValue.subjectKeyIdentifier, &ski);
#ifndef ANYSKI
            if (ski_lth != tmp || memcmp(khash, ski, ski_lth))
                err = -1;
#endif
                    tmp2 += ski_lth;    /* dummy statement to make compiler
                                         * happy */
            free(ski);
            if (err < 0)
                return ERR_SCM_INVALSKI;
            err = 0;
        }
    }
    if (err == 1)
        return ERR_SCM_NOSKI;   // no SKI
    return 0;
}

int check_fileAndHash(
    struct FileAndHash *fahp,
    int ffd,
    uchar *inhash,
    int inhashlen,
    int inhashtotlen)
{
    uchar *contentsp;
    err_code err = 0;
    int hash_lth;
    int bit_lth;
    int name_lth = lseek(ffd, 0, SEEK_END);

    lseek(ffd, 0, SEEK_SET);
    contentsp = (uchar *) calloc(1, name_lth + 2);
    if (read(ffd, contentsp, name_lth + 2) != name_lth)
    {
        free(contentsp);
        return (ERR_SCM_BADFILE);
    }
    if (inhash != NULL && inhashlen > 0 && inhashlen <= (name_lth + 2))
    {
        memcpy(contentsp, inhash, inhashlen);
        hash_lth = inhashlen;
    }
    else
    {
        hash_lth = gen_hash(contentsp, name_lth, contentsp, CRYPT_ALGO_SHA2);
        if (hash_lth < 0)
        {
            free(contentsp);
            return (ERR_SCM_BADMKHASH);
        }
    }
    bit_lth = vsize_casn(&fahp->hash);
    uchar *hashp = (uchar *) calloc(1, bit_lth);
    read_casn(&fahp->hash, hashp);
    if (hash_lth != (bit_lth - 1) ||
        memcmp(&hashp[1], contentsp, hash_lth) != 0)
        err = ERR_SCM_BADMFTHASH;
    free(hashp);
    if (inhash != NULL && inhashtotlen >= hash_lth && inhashlen == 0
        && err == 0)
        memcpy(inhash, contentsp, hash_lth);
    free(contentsp);
    return err == 0 ? hash_lth : err;
}

/*
 * Find unique attribute, according to
 * http://tools.ietf.org/html/rfc6488#section-2.1.6.4
 *
 *       SignedAttributes ::= SET SIZE (1..MAX) OF Attribute
 *
 *       Attribute ::= SEQUENCE {
 *         attrType OBJECT IDENTIFIER,
 *         attrValues SET OF AttributeValue }
 *
 *       AttributeValue ::= ANY
 *
 * The signedAttrs element MUST include only a single instance of any
 * particular attribute.  Additionally, even though the syntax allows
 * for a SET OF AttributeValue, in an RPKI signed object, the attrValues
 * MUST consist of only a single AttributeValue.
 *
 * @param[in] attrsp
 *     Attributes to search for the OID in.
 * @param[in] oidp
 *     Attribute OID to search for.
 * @param[out] found_any
 *     True indicates any attributes with the OID were found.  False
 *     indicates no attributes with the OID were found.
 * @return
 *     Non-NULL unique attribute, or NULL if the attribute was not
 *     found or was not unique.
 */
static struct Attribute *find_unique_attr(
    struct SignedAttributes *attrsp,
    char *oidp,
    bool *found_any)
{
    struct Attribute *attrp,
       *ch_attrp = NULL;
    *found_any = false;
    for (attrp = (struct Attribute *)member_casn(&attrsp->self, 0);
         attrp != NULL; attrp = (struct Attribute *)next_of(&attrp->self))
    {
        /** @bug error code ignored without explanation */
        if (!diff_objid(&attrp->attrType, oidp))
        {
            if (*found_any)
            {
                return NULL;
            }
            *found_any = true;
            ch_attrp = attrp;
        }
    }
    // within the attribute, ensure there is exactly one attrValue
    if (ch_attrp && num_items(&ch_attrp->attrValues.self) != 1)
        return NULL;
    return ch_attrp;
}

static err_code
setup_cert_minmax(
    struct IPAddressOrRangeA *rpAddrRangep,
    uchar *cmin,
    uchar *cmax,
    int fam)
{
    memset(cmin, 0, MINMAXBUFSIZE);
    /** @bug magic number */
    memset(cmax, -1, MINMAXBUFSIZE);
    /** @bug magic number */
    if (fam == 1)
        /** @bug magic number */
        fam = 7;
    /** @bug magic number */
    else if (fam == 2)
        /** @bug magic number */
        fam = 19;
    else
        /** @bug error message not logged */
        return ERR_SCM_INVALFAM;
    /** @bug error code ignored without explanation */
    if (tag_casn(&rpAddrRangep->self) == ASN_SEQUENCE)
    {
        /** @bug error code ignored without explanation */
        if (size_casn(&rpAddrRangep->addressRange.min) > fam ||
            /** @bug error code ignored without explanation */
            size_casn(&rpAddrRangep->addressRange.max) > fam)
            /** @bug error message not logged */
            return ERR_SCM_INVALFAM;
        /** @bug error code ignored without explanation */
        encode_casn(&rpAddrRangep->addressRange.min, cmin);
        /** @bug error code ignored without explanation */
        encode_casn(&rpAddrRangep->addressRange.max, cmax);
    }
    else
    {
        /** @bug error code ignored without explanation */
        if (size_casn(&rpAddrRangep->addressPrefix) > fam)
            /** @bug error message not logged */
            return ERR_SCM_INVALFAM;
        /** @bug error code ignored without explanation */
        encode_casn(&rpAddrRangep->addressPrefix, cmin);
        /** @bug error code ignored without explanation */
        encode_casn(&rpAddrRangep->addressPrefix, cmax);
    }
    fill_max(cmax);
    cmin[2] = 0;
    cmax[2] = 0;
    return 0;
}

static err_code
setup_roa_minmax(
    struct IPAddress *ripAddrp,
    uchar *rmin,
    uchar *rmax,
    int fam)
{
    memset(rmin, 0, MINMAXBUFSIZE);
    /** @bug magic number */
    memset(rmax, -1, MINMAXBUFSIZE);
    /** @bug magic number */
    if (fam == 1)
        /** @bug magic number */
        fam = 7;
    /** @bug magic number */
    else if (fam == 2)
        /** @bug magic number */
        fam = 19;
    else
        /** @bug error message not logged */
        return ERR_SCM_INVALFAM;
    /** @bug error code ignored without explanation */
    if (size_casn(ripAddrp) > fam)
        /** @bug error message not logged */
        return ERR_SCM_INVALIPL;
    /** @bug error code ignored without explanation */
    encode_casn(ripAddrp, rmin);
    /** @bug error code ignored without explanation */
    encode_casn(ripAddrp, rmax);
    fill_max(rmax);
    rmin[2] = 0;
    rmax[2] = 0;
    return 0;
}

static err_code
test_maxLength(
    struct ROAIPAddress *roaAddrp,
    int familyMaxLength)
{
    if (size_casn(&roaAddrp->maxLength) == 0)
        return 0;
    long maxLength = 0;
    int lth = vsize_casn(&roaAddrp->address);
    uchar *addr = (uchar *) calloc(1, lth);
    read_casn(&roaAddrp->address, addr);
    /*
     * Compute the length of the IP prefix, noting that the ASN.1 encoding of
     * a bit string uses the first byte to specify the number of unused bits
     * at the end.
     */
    int addrLength = ((lth - 1) * 8) - addr[0];
    free(addr);
    read_casn_num(&roaAddrp->maxLength, &maxLength);
    if (addrLength > maxLength)
        return ERR_SCM_INVALIPL;
    if (maxLength > familyMaxLength)
        return ERR_SCM_INVALIPL;
    return 0;
}

static err_code
validateIPContents(
    struct ROAIPAddrBlocks *ipAddrBlockp)
{
    // check that addressFamily is IPv4 OR IPv6
    // check that the addressPrefixes are valid IP addresses OR valid ranges
    uchar rmin[MINMAXBUFSIZE],
        rmax[MINMAXBUFSIZE],
        rfam[8];
    struct ROAIPAddress *roaAddrp;
    struct ROAIPAddressFamily *roaipfamp;
    int i;
    err_code err = 0;
    int num = 0;

    if ((i = num_items(&ipAddrBlockp->self)) == 0 || i > 2)
        return ERR_SCM_INVALFAM;
    int family = 0;
    for (roaipfamp =
         (struct ROAIPAddressFamily *)member_casn(&ipAddrBlockp->self, 0);
         roaipfamp;
         roaipfamp =
         (struct ROAIPAddressFamily *)next_of(&roaipfamp->self), num++)
    {
        if ((i = read_casn(&roaipfamp->addressFamily, rfam)) < 0 || i > 2 ||
            rfam[0] != 0 || (rfam[1] != 1 && rfam[1] != 2))
            return ERR_SCM_INVALFAM;
        family = rfam[1];
        if (num == 1 && family == 1)
            return ERR_SCM_INVALFAM;
        for (roaAddrp = &roaipfamp->addresses.rOAIPAddress; roaAddrp;
             roaAddrp = (struct ROAIPAddress *)next_of(&roaAddrp->self))
        {
            int siz = vsize_casn(&roaAddrp->address);
            if ((family == 1 && siz > 5) || (family == 2 && siz > 17))
                return ERR_SCM_INVALIPL;
            int familyMaxLength = 0;
            if (family == 1)
                familyMaxLength = 32;
            if (family == 2)
                familyMaxLength = 128;
            if ((err = test_maxLength(roaAddrp, familyMaxLength)) < 0 ||
                (err =
                 setup_roa_minmax(&roaAddrp->address, rmin, rmax, i)) < 0)
                return err;
            if (memcmp(&rmax[3], &rmin[3], sizeof(rmin) - 3) < 0)
                return ERR_SCM_INVALIPB;
        }
    }
    return 0;
}

static err_code
cmsValidate(
    struct CMS *rp)
{
    // validates general CMS things common to ROAs and manifests

    int num_certs;
    err_code ret = 0;
    int tbs_lth;
    struct SignerInfo *sigInfop;
    uchar digestbuf[40];
    uchar hashbuf[40];
    uchar *tbsp;

    // check that roa->content->version == 3
    if (diff_casn_num(&rp->content.signedData.version.self, 3) != 0)
        /** @bug error message not logged */
        return ERR_SCM_BADCMSVER;

    // check that roa->content->digestAlgorithms == SHA-256 and NOTHING ELSE
    // (= OID 2.16.840.1.101.3.4.2.1)
    if (num_items(&rp->content.signedData.digestAlgorithms.self) != 1)
        /** @bug error message not logged */
        return ERR_SCM_BADNUMDALG;
    /** @bug error code ignored without explanation */
    if (diff_objid
        (&rp->content.signedData.digestAlgorithms.cMSAlgorithmIdentifier.
         algorithm, id_sha256))
        /** @bug error message not logged */
        return ERR_SCM_BADDA;

    if ((num_certs = num_items(&rp->content.signedData.certificates.self)) != 1)
        /** @bug error message not logged */
        return ERR_SCM_BADNUMCERTS;

    if (num_items(&rp->content.signedData.signerInfos.self) != 1)
        /** @bug error message not logged */
        return ERR_SCM_NUMSIGINFO;

    sigInfop =
        (struct SignerInfo *)member_casn(&rp->content.signedData.signerInfos.
                                         self, 0);
    memset(digestbuf, 0, 40);

    if (diff_casn_num(&sigInfop->version.self, 3))
        /** @bug error message not logged */
        return ERR_SCM_SIGINFOVER;
    if (!size_casn(&sigInfop->sid.subjectKeyIdentifier))
        /** @bug error message not logged */
        return ERR_SCM_SIGINFOSID;
    /** @bug error code ignored without explanation */
    if (diff_objid(&sigInfop->digestAlgorithm.algorithm, id_sha256))
        /** @bug error message not logged */
        return ERR_SCM_BADHASHALG;

    if (!num_items(&sigInfop->signedAttrs.self))
        /** @bug error message not logged */
        return ERR_SCM_BADSIGATTRS;
    struct Attribute *attrp;
    bool found_any;
    // make sure there is one and only one content
    if (!(attrp = find_unique_attr(&sigInfop->signedAttrs, id_contentTypeAttr,
                                   &found_any)) ||
        // make sure it is the same as in EncapsulatedContentInfo
        diff_casn(&attrp->attrValues.array.contentType,
                  &rp->content.signedData.encapContentInfo.eContentType))
        /** @bug error message not logged */
        return ERR_SCM_BADCONTTYPE;
    // make sure there is one and only one message digest
    if (!(attrp = find_unique_attr(&sigInfop->signedAttrs,
                                   id_messageDigestAttr, &found_any)) ||
        // make sure the message digest is 32 bytes long and we can get it
        vsize_casn(&attrp->attrValues.array.messageDigest) != 32 ||
        read_casn(&attrp->attrValues.array.messageDigest, digestbuf) != 32)
        /** @bug error message not logged */
        return ERR_SCM_BADMSGDIGEST;

    // if there is a signing time, make sure it is the right format
    attrp =
        find_unique_attr(&sigInfop->signedAttrs, id_signingTimeAttr,
                         &found_any);
    if (attrp)
    {
        uchar loctime[30];
        int usize,
            gsize;
        if ((usize =
             vsize_casn(&attrp->attrValues.array.signingTime.utcTime)) > 15
            || (gsize =
                vsize_casn(&attrp->attrValues.array.
                           signingTime.generalizedTime)) > 17)
            /** @bug error message not logged */
            return ERR_SCM_SIGINFOTIM;
        if (usize > 0)
        {
            read_casn(&attrp->attrValues.array.signingTime.utcTime, loctime);
            if (loctime[0] <= '7' && loctime[0] >= '5')
                /** @bug error message not logged */
                return ERR_SCM_SIGINFOTIM;
        }
        else
        {
            read_casn(&attrp->attrValues.array.signingTime.generalizedTime,
                      loctime);
            if (strncmp((char *)loctime, "2050", 4) < 0)
                /** @bug error message not logged */
                return ERR_SCM_SIGINFOTIM;
        }
    }
    else if (found_any)
        /** @bug error message not logged */
        return ERR_SCM_SIGINFOTIM;
    // check that there is no more than one binSigning time attribute
    attrp =
        find_unique_attr(&sigInfop->signedAttrs, id_binSigningTimeAttr,
                         &found_any);
    if (attrp == NULL && found_any)
        /** @bug error message not logged */
        return ERR_SCM_BINSIGTIME;
    // check the hash
    memset(hashbuf, 0, 40);
    // read the content
    tbs_lth =
        readvsize_casn(&rp->content.signedData.encapContentInfo.eContent.self,
                       &tbsp);

    // hash it, make sure it's the right length and it matches the digest
    if (gen_hash(tbsp, tbs_lth, hashbuf, CRYPT_ALGO_SHA2) != 32 ||
        memcmp(digestbuf, hashbuf, 32) != 0)
        /** @bug error message not logged */
        ret = ERR_SCM_BADDIGEST;
    free(tbsp);                 // done with the content now

    // if the hash didn't match, bail now
    if (ret != 0)
        return ret;

    // make sure there are no disallowed signed attributes
    for (attrp = (struct Attribute *)member_casn(&sigInfop->signedAttrs.self, 0);
        attrp != NULL;
        attrp = (struct Attribute *)next_of(&attrp->self))
    {
        /** @bug error code ignored without explanation */
        if (diff_objid(&attrp->attrType, id_contentTypeAttr) &&
            /** @bug error code ignored without explanation */
            diff_objid(&attrp->attrType, id_messageDigestAttr) &&
            /** @bug error code ignored without explanation */
            diff_objid(&attrp->attrType, id_signingTimeAttr) &&
            /** @bug error code ignored without explanation */
            diff_objid(&attrp->attrType, id_binSigningTimeAttr))
        {
            /** @bug error message not logged */
            return ERR_SCM_INVALSATTR;
        }
    }

    // check the cert
    struct Certificate *certp =
        (struct Certificate *)member_casn(&rp->content.signedData.
                                          certificates.self, 0);
    if ((ret = check_cert(certp, 1)) < 0)
        return ret;
    if ((ret = check_sig(rp, certp)) != 0)
        return ret;
    // check that the cert's SKI matches that in SignerInfo
    struct Extension *extp;
    /** @bug error code ignored without explanation */
    for (extp =
         (struct Extension *)member_casn(&certp->toBeSigned.extensions.
                                         self, 0);
         /** @bug error code ignored without explanation */
         extp && diff_objid(&extp->extnID, id_subjectKeyIdentifier);
         /** @bug error code ignored without explanation */
         extp = (struct Extension *)next_of(&extp->self));
    if (!extp
        /** @bug error code ignored without explanation */
        || diff_casn(&extp->extnValue.subjectKeyIdentifier,
                     &sigInfop->sid.subjectKeyIdentifier))
        /** @bug error message not logged */
        return ERR_SCM_SIGINFOSID;

    // check that roa->content->crls == NULL
    if (size_casn(&rp->content.signedData.crls.self) > 0)
        /** @bug error message not logged */
        return ERR_SCM_HASCRL;

    // check that roa->content->signerInfo.digestAlgorithm == SHA-256
    // (= OID 2.16.840.1.101.3.4.2.1)
    /** @bug error code ignored without explanation */
    if (diff_objid
        (&rp->content.signedData.signerInfos.signerInfo.digestAlgorithm.
         algorithm, id_sha256))
        /** @bug error message not logged */
        return ERR_SCM_BADDA;

    if (size_casn
        (&rp->content.signedData.signerInfos.signerInfo.unsignedAttrs.self) !=
        0)
        /** @bug error message not logged */
        return ERR_SCM_UNSIGATTR;

    // See http://www.ietf.org/mail-archive/web/sidr/current/msg04813.html for
    // why we deviate from the RFC here.
    struct casn *oidp =
        &rp->content.signedData.signerInfos.signerInfo.signatureAlgorithm.
        algorithm;
    /** @bug error code ignored without explanation */
    if (!diff_objid(oidp, id_rsadsi_rsaEncryption))
    {
        LOG(LOG_DEBUG, "signatureAlgorithm is id_rsadsi_rsaEncryption");
    }
    /** @bug error code ignored without explanation */
    else if (!diff_objid(oidp, id_sha_256WithRSAEncryption))
    {
        LOG(LOG_DEBUG, "signatureAlgorithm is id_sha_256WithRSAEncryption");
    }
    else
    {
        LOG(LOG_ERR, "invalid signature algorithm in CMS");
        return ERR_SCM_BADSIGALG;
    }

    // check that the subject key identifier has proper length
    if (vsize_casn
        (&rp->content.signedData.signerInfos.signerInfo.
         sid.subjectKeyIdentifier) != 20)
        /** @bug error message not logged */
        return ERR_SCM_INVALSKI;

    // everything checked out
    return 0;
}

static err_code
check_mft_version(
    struct casn *casnp)
{
    long val = 0;
    int lth = read_casn_num(casnp, &val);

    if (lth < 0)
        return ERR_SCM_BADMANVER;       // invalid read

    if (val != 0)
        return ERR_SCM_BADMANVER;       // incorrect version number

    if (lth != 0)
        return ERR_SCM_BADMANVER;       // explicit zero (should be implicit
                                        // default)

    return 0;
}

static err_code
check_mft_number(
    struct casn *casnp)
{
    int lth = vsize_casn(casnp);
    uint8_t val[MANIFEST_NUMBER_MAX_SIZE];

    if (lth <= 0)
    {
        LOG(LOG_ERR, "Error reading manifest number");
        return ERR_SCM_BADMFTNUM;
    }
    else if (lth > MANIFEST_NUMBER_MAX_SIZE)
    {
        LOG(LOG_ERR, "Manifest number is too long (%d bytes)", lth);
        return ERR_SCM_BADMFTNUM;
    }

    read_casn(casnp, val);

    if (val[0] & 0x80)
    {
        LOG(LOG_ERR, "Manifest number is negative");
        return ERR_SCM_BADMFTNUM;
    }

    return 0;
}

static err_code
check_mft_dates(
    struct Manifest *manp,
    struct Certificate *certp,
    int *stalep)
{
    time_t now;
    time(&now);

    int64_t thisUpdate;
    int64_t nextUpdate;
    int64_t notBefore;
    int64_t notAfter;

    if (read_casn_time(&manp->thisUpdate, &thisUpdate) < 0)
    {
        LOG(LOG_ERR, "Manifest's thisUpdate is invalid");
        return ERR_SCM_INVALDT;
    }

    if (thisUpdate > now)
    {
        LOG(LOG_ERR, "Manifest's thisUpdate is in the future");
        return ERR_SCM_INVALDT;
    }

    if (read_casn_time(&manp->nextUpdate, &nextUpdate) < 0)
    {
        LOG(LOG_ERR, "Manifest's nextUpdate is invalid");
        return ERR_SCM_INVALDT;
    }

    if (nextUpdate < thisUpdate)
    {
        LOG(LOG_ERR, "Manifest's nextUpdate is earlier than thisUpdate");
        return ERR_SCM_INVALDT;
    }

    if (read_casn_time(&certp->toBeSigned.validity.notBefore.self, &notBefore) < 0)
    {
        LOG(LOG_ERR, "Manifest's EE's notBefore is invalid");
        return ERR_SCM_INVALDT;
    }

    if (thisUpdate < notBefore)
    {
        LOG(LOG_ERR,
            "Manifest's thisUpdate is before its EE certificate's validity");
        return ERR_SCM_INVALDT;
    }

    if (read_casn_time(&certp->toBeSigned.validity.notAfter.self, &notAfter) < 0)
    {
        LOG(LOG_ERR, "Manifest's EE's notAfter is invalid");
        return ERR_SCM_INVALDT;
    }

    if (nextUpdate > notAfter)
    {
        LOG(LOG_ERR,
            "Manifest's nextUpdate is after its EE certificate's validity");
        return ERR_SCM_INVALDT;
    }

    if (now > nextUpdate)
    {
        *stalep = 1;
    }
    else
    {
        *stalep = 0;
    }

    return 0;
}

static err_code
check_mft_filenames(
    struct FileListInManifest *fileListp)
{
    struct FileAndHash *fahp;
    char file[NAME_MAX];
    int file_length;
    int i;
    int filenum = 0;
    for (fahp = (struct FileAndHash *)member_casn(&fileListp->self, 0);
         fahp != NULL;
         fahp = (struct FileAndHash *)next_of(&fahp->self), filenum++)
    {
        if (vsize_casn(&fahp->file) > NAME_MAX)
            return ERR_SCM_BADMFTFILENAME;
        file_length = read_casn(&fahp->file, (unsigned char *)file);
        if (file_length <= 0)
            return ERR_SCM_BADMFTFILENAME;
        for (i = 0; i < file_length; ++i)
        {
            if (file[i] == '\0' || file[i] == '/')
                return ERR_SCM_BADMFTFILENAME;
        }
        if (file_length == 1 && file[0] == '.')
            return ERR_SCM_BADMFTFILENAME;
        if (file_length == 2 && file[0] == '.' && file[1] == '.')
            return ERR_SCM_BADMFTFILENAME;
        int hash_lth = vsize_casn(&fahp->hash);
        if (hash_lth != 33)
            return ERR_SCM_BADMFTHASH;
    }
    return 0;
}

static int strcmp_ptr(
    const void *s1,
    const void *s2)
{
    return strcmp(*(char const *const *)s1, *(char const *const *)s2);
}

static err_code
check_mft_duplicate_filenames(
    struct Manifest *manp)
{
    struct FileAndHash *fahp;
    char **filenames;
    err_code ret = 0;
    int file_length;
    int total;
    int i;
    int j;
    total = num_items(&manp->fileList.self);
    if (total == 0)
        return 0;
    filenames = malloc(total * sizeof(char *));
    if (filenames == NULL)
    {
        return ERR_SCM_NOMEM;
    }
    for (i = 0; i < total; ++i)
    {
        fahp = (struct FileAndHash *)member_casn(&manp->fileList.self, i);
        file_length = vsize_casn(&fahp->file);
        filenames[i] = malloc(file_length + 1);
        if (filenames[i] == NULL)
        {
            for (j = 0; j < i; ++j)
                free(filenames[j]);
            free(filenames);
            return ERR_SCM_NOMEM;
        }
        read_casn(&fahp->file, (unsigned char *)filenames[i]);
        filenames[i][file_length] = '\0';
    }
    qsort(filenames, total, sizeof(char *), strcmp_ptr);
    for (i = 0; i < total; ++i)
    {
        if (ret == 0 && i + 1 < total)
        {
            if (strcmp(filenames[i], filenames[i + 1]) == 0)
            {
                ret = ERR_SCM_MFTDUPFILE;
            }
        }
        free(filenames[i]);
    }
    free(filenames);
    return ret;
}

err_code
manifestValidate(
    struct CMS *cmsp,
    int *stalep)
{
    LOG(LOG_DEBUG, "manifestValidate(cmsp=%p, stalep=%p)", cmsp, stalep);

    err_code iRes;

    // Check that content type is id-ct-rpkiManifest
    /** @bug error code ignored without explanation */
    if (diff_objid(&cmsp->content.signedData.encapContentInfo.eContentType,
                   id_roa_pki_manifest))
    {
        LOG(LOG_ERR, "manifest has invalid content type");
        iRes = ERR_SCM_BADCT;
        goto done;
    }

    // Check version
    struct Manifest *manp =
        &cmsp->content.signedData.encapContentInfo.eContent.manifest;
    if (size_casn(&manp->self) <= 0)
    {
        LOG(LOG_ERR, "manifest content too small");
        iRes = ERR_SCM_BADCT;
        goto done;
    }
    if ((iRes = check_mft_version(&manp->version.self)) < 0)
    {
        goto done;
    }

    // Check manifest number
    if ((iRes = check_mft_number(&manp->manifestNumber)) < 0)
    {
        goto done;
    }

    // Check the hash algorithm
    /** @bug error code ignored without explanation */
    if (diff_objid(&manp->fileHashAlg, id_sha256))
    {
        LOG(LOG_ERR, "Incorrect hash algorithm");
        iRes = ERR_SCM_BADHASHALG;
        goto done;
    }

    // Check the list of files and hashes
    if ((iRes = check_mft_filenames(&manp->fileList)) < 0)
    {
        goto done;
    }
    iRes = check_mft_duplicate_filenames(manp);
    if (iRes < 0)
    {
        goto done;
    }

    // Check general CMS structure
    iRes = cmsValidate(cmsp);
    if (iRes < 0)
    {
        goto done;
    }

    struct Certificate *certp =
        &cmsp->content.signedData.certificates.certificate;

    // Check dates
    if ((iRes = check_mft_dates(manp, certp, stalep)) < 0)
    {
        goto done;
    }

    if (has_non_inherit_resources(certp))
    {
        LOG(LOG_ERR, "Manifest's EE certificate has RFC3779 resources "
            "that are not marked inherit");
        iRes = ERR_SCM_NOTINHERIT;
        goto done;
    }
done:
    LOG(LOG_DEBUG, "manifestValidate() returning %s: %s",
        err2name(iRes), err2string(iRes));
    return iRes;
}

struct certrange {
    uchar lo[18],
        hi[18];
};

static int setuprange(
    struct certrange *certrangep,
    struct casn *lorangep,
    struct casn *hirangep)
{
    uchar locbuf[18];
    memset(locbuf, 0, 18);
    memset(certrangep->lo, 0, sizeof(certrangep->lo));
    memset(certrangep->hi, -1, sizeof(certrangep->hi));
    int lth = read_casn(lorangep, locbuf);
    int unused = locbuf[0];
    memcpy(certrangep->lo, &locbuf[1], --lth);
    certrangep->lo[lth - 1] &= (0xFF << unused);
    lth = read_casn(hirangep, locbuf);
    unused = locbuf[0];
    memcpy(certrangep->hi, &locbuf[1], --lth);
    certrangep->hi[lth - 1] |= (0xFF >> (8 - unused));
    return 0;
}

static int certrangecmp(
    const void *range1_voidp,
    const void *range2_voidp)
{
    const struct certrange *range1 = (const struct certrange *)range1_voidp;
    const struct certrange *range2 = (const struct certrange *)range2_voidp;

    int ret = memcmp(range1->lo, range2->lo, sizeof(range1->lo));
    if (ret != 0)
        return ret;
    else
        return memcmp(range1->hi, range2->hi, sizeof(range1->hi));
}

/** @return non-zero iff range1 fully contains range2 */
static int certrangeContains(
    const struct certrange *range1,
    const struct certrange *range2)
{
    return memcmp(range2->lo, range1->lo, sizeof(range1->lo)) >= 0 &&
        memcmp(range2->hi, range1->hi, sizeof(range1->hi)) <= 0;
}

/** @return non-zero iff range1 does not intersect range2
  and range1 is before range2 */
static int certrangeBefore(
    const struct certrange *range1,
    const struct certrange *range2)
{
    return memcmp(range1->hi, range2->lo, sizeof(range1->hi)) < 0;
}

static err_code
checkIPAddrs(
    struct Certificate *certp,
    struct ROAIPAddrBlocks *roaIPAddrBlocksp)
{
    // determine if all the address blocks in the ROA are within the EE cert
    struct Extension *extp;
    /** @bug error code ignored without explanation */
    for (extp =
         (struct Extension *)member_casn(&certp->toBeSigned.extensions.self,
                                         0);
         /** @bug error code ignored without explanation */
         extp && diff_objid(&extp->extnID, id_pe_ipAddrBlock);
         /** @bug error code ignored without explanation */
         extp = (struct Extension *)next_of(&extp->self));
    if (!extp)
        return ERR_SCM_NOIPEXT;
    struct IpAddrBlock *certIpAddrBlockp = &extp->extnValue.ipAddressBlock;

    struct ROAIPAddressFamily *roaFamilyp;
    struct IPAddressFamilyA *certFamilyp;

    // make sure none of the cert families are marked inherit
    for (certFamilyp =
        (struct IPAddressFamilyA *)member_casn(&certIpAddrBlockp->self, 0);
        certFamilyp;
        certFamilyp = (struct IPAddressFamilyA *)next_of(&certFamilyp->self))
    {
        if (size_casn(&certFamilyp->ipAddressChoice.inherit))
        {
            LOG(LOG_ERR,
                "ROA's EE certificate has IP resources marked inherit");
            return ERR_SCM_ROAIPMISMATCH;
        }
    }

    // for each ROA family, see if it is in cert
    for (roaFamilyp =
         (struct ROAIPAddressFamily *)member_casn(&roaIPAddrBlocksp->self, 0);
         roaFamilyp;
         roaFamilyp = (struct ROAIPAddressFamily *)next_of(&roaFamilyp->self))
    {
        int matchedCertFamily = 0;
        for (certFamilyp =
             (struct IPAddressFamilyA *)member_casn(&certIpAddrBlockp->self,
                                                    0); certFamilyp;
             certFamilyp =
             (struct IPAddressFamilyA *)next_of(&certFamilyp->self))
        {
            if (diff_casn
                (&certFamilyp->addressFamily, &roaFamilyp->addressFamily))
                continue;
            matchedCertFamily = 1;
            // for each ROA entry, see if it is in cert
            const int roaNumPrefixes = num_items(&roaFamilyp->addresses.self);
            struct certrange *roaRanges =
                malloc(roaNumPrefixes * sizeof(struct certrange));
            if (!roaRanges)
                return ERR_SCM_NOMEM;
            struct ROAIPAddress *roaIPAddrp;
            int roaPrefixNum;
            for (roaIPAddrp =
                 (struct ROAIPAddress *)member_casn(&roaFamilyp->addresses.
                                                    self, 0), roaPrefixNum = 0;
                 roaIPAddrp;
                 roaIPAddrp =
                 (struct ROAIPAddress *)next_of(&roaIPAddrp->self),
                 ++roaPrefixNum)
            {
                // roaIPAddrp->address is a prefix (BIT string)
                setuprange(&roaRanges[roaPrefixNum], &roaIPAddrp->address,
                           &roaIPAddrp->address);
            }
            qsort(roaRanges, roaNumPrefixes, sizeof(roaRanges[0]),
                  certrangecmp);
            struct IPAddressOrRangeA *certIPAddressOrRangeAp =
                (struct IPAddressOrRangeA *)member_casn(&certFamilyp->
                                                        ipAddressChoice.
                                                        addressesOrRanges.self,
                                                        0);
            struct certrange certrange;
            roaPrefixNum = 0;
            while (roaPrefixNum < roaNumPrefixes)
            {
                do
                {
                    if (certIPAddressOrRangeAp == NULL)
                    {
                        // reached end of certranges when there are still
                        // roaranges to match
                        free(roaRanges);
                        return ERR_SCM_ROAIPMISMATCH;
                    }
                    // certIPAddressOrRangep is either a prefix (BIT string)
                    // or a range
                    if (size_casn(&certIPAddressOrRangeAp->addressRange.self))
                        setuprange(&certrange,
                                   &certIPAddressOrRangeAp->addressRange.min,
                                   &certIPAddressOrRangeAp->addressRange.max);
                    else
                        setuprange(&certrange,
                                   &certIPAddressOrRangeAp->addressPrefix,
                                   &certIPAddressOrRangeAp->addressPrefix);
                    certIPAddressOrRangeAp =
                        (struct IPAddressOrRangeA
                         *)next_of(&certIPAddressOrRangeAp->self);
                } while (!certrangeContains
                         (&certrange, &roaRanges[roaPrefixNum])
                         && !certrangeBefore(&roaRanges[roaPrefixNum],
                                             &certrange));
                if (!certrangeContains(&certrange, &roaRanges[roaPrefixNum]))
                {
                    // roarange is unmatched and all remaining certrange are
                    // greater than roarange
                    free(roaRanges);
                    return ERR_SCM_ROAIPMISMATCH;
                }
                while (roaPrefixNum < roaNumPrefixes &&
                       certrangeContains(&certrange, &roaRanges[roaPrefixNum]))
                {
                    // skip all roaranges contained by this certrange
                    ++roaPrefixNum;
                }
            }
            free(roaRanges);
        }
        if (!matchedCertFamily)
            return ERR_SCM_ROAIPMISMATCH;
    }
    return 0;
}

err_code
roaValidate(
    struct CMS *rp)
{
    LOG(LOG_DEBUG, "roaValidate(rp=%p)", rp);

    err_code sta = 0;
    intmax_t iAS_ID = 0;

    // ///////////////////////////////////////////////////////////
    // Validate ROA constants
    // ///////////////////////////////////////////////////////////
    if ((sta = cmsValidate(rp)) < 0)
    {
        goto done;
    }

    // check that eContentType is routeOriginAttestation (=
    // OID 1.2.240.113549.1.9.16.1.24)
    /** @bug error code ignored without explanation */
    if (diff_objid(&rp->content.signedData.encapContentInfo.eContentType,
                   id_routeOriginAttestation))
    {
        LOG(LOG_ERR, "ROA's eContentType is not routeOriginaAttestation");
        sta = ERR_SCM_BADCT;
        goto done;
    }

    struct RouteOriginAttestation *roap =
        &rp->content.signedData.encapContentInfo.eContent.roa;

    // check that the ROA version is right
    long val;
    if (read_casn_num(&roap->version.self, &val) != 0)
    {
        LOG(LOG_ERR, "unable to read ROA version number");
        sta = ERR_SCM_BADROAVER;
        goto done;
    }
    if (val != 0)
    {
        LOG(LOG_ERR, "ROA's version number is not 0");
        sta = ERR_SCM_BADROAVER;
        goto done;
    }
    // check that the asID is a non-negative integer in the range
    // specified by RFC4893
    if (read_casn_num_max(&roap->asID, &iAS_ID) < 0)
    {
        LOG(LOG_ERR, "error reading ROA's AS number");
        sta = ERR_SCM_INVALASID;
        goto done;
    }
    else if (iAS_ID < 0)
    {
        LOG(LOG_ERR, "ROA has negative AS number (%" PRIdMAX ")", iAS_ID);
        sta = ERR_SCM_INVALASID;
        goto done;
    }
    else if (iAS_ID > 0xffffffffLL)
    {
        LOG(LOG_ERR, "ROA's AS number is too large (%" PRIdMAX ")", iAS_ID);
        sta = ERR_SCM_INVALASID;
        goto done;
    }
    struct Certificate *certp =
        &rp->content.signedData.certificates.certificate;

    // NOTE: ROA asID need not be within EE cert's AS allocation!

    // check that the contents are valid
    struct ROAIPAddrBlocks *roaIPAddrBlocksp =
        &rp->content.signedData.encapContentInfo.eContent.roa.ipAddrBlocks;
    if ((sta = validateIPContents(roaIPAddrBlocksp)) < 0)
    {
        goto done;
    }
    // and that they are within the cert's resources
    if ((sta = checkIPAddrs(certp, roaIPAddrBlocksp)) < 0)
    {
        goto done;
    }

done:
    LOG(LOG_DEBUG, "roaValidate() returning %s: %s",
        err2name(sta), err2string(sta));
    return sta;
}

#define HAS_EXTN_SKI 0x01
#define HAS_EXTN_ASN 0x02
#define HAS_EXTN_IPADDR 0x04

err_code
roaValidate2(
    struct CMS *rp)
{
    LOG(LOG_DEBUG, "roaValidate2(rp=%p)", rp);

    err_code sta = 0;
    long ii;
    long ij;
    struct Extension *extp;
    char *oidp = NULL;
    uchar cmin[MINMAXBUFSIZE];
    uchar cmax[MINMAXBUFSIZE];
    uchar rmin[MINMAXBUFSIZE];
    uchar rmax[MINMAXBUFSIZE];
    /** @bug magic number */
    uchar rfam[8];
    /** @bug magic number */
    uchar cfam[8];
    int all_extns = 0;
    struct SignedData *rd = &rp->content.signedData;

    /** @bug error code ignored without explanation */
    struct Certificate *cert =
        (struct Certificate *)member_casn(&rd->certificates.self, 0);

    //
    // if (certificate exists in roa)
    // - ignore it
    // - Or check the certificate against x (optional)

    /** @bug this next comment is simply wrong */
    // ///////////////////////////////////////////////////////////////
    // We get to assume cert validity up the chain, because by virtue
    // of having been extracted, it is reputable
    // ///////////////////////////////////////////////////////////////
    for (extp = (struct Extension *)&cert->toBeSigned.extensions.extension;
         extp;
         /** @bug error code ignored without explanation */
         extp = (struct Extension *)next_of(&extp->self))
    {
        // free oidp from prev iteration (or no-op if first
        // iteration).  oidp malloc()ed during last iteration will be
        // free()d just before returning.
        free(oidp);
        /** @bug error code ignored without explanation */
        readvsize_objid(&extp->extnID, &oidp);
        // if it's the SKID extension
        /** @bug invalid read if oidp longer than id_subjectKeyIdentifier */
        if (!memcmp(oidp, id_subjectKeyIdentifier, strlen(oidp)))
        {
            all_extns |= HAS_EXTN_SKI;
            // Check that roa->envelope->SKI = cert->SKI
            /** @bug error code ignored without explanation */
            if (diff_casn(
                    &rd->signerInfos.signerInfo.sid.subjectKeyIdentifier,
                    (struct casn *)&extp->extnValue.subjectKeyIdentifier) != 0)
            {
                /** @bug error message not logged */
                sta = ERR_SCM_INVALSKI;
                goto done;
            }
        }
        // or if it's the IP addr extension
        /** @bug invalid read if oidp longer than id_pe_ipAddrBlock */
        else if (!memcmp(oidp, id_pe_ipAddrBlock, strlen(oidp)))
        {
            all_extns |= HAS_EXTN_IPADDR;
            // start at first family in cert. NOTE order must be v4
            // then v6, per RFC3779
            struct IPAddressFamilyA *rpAddrFamp =
                &extp->extnValue.ipAddressBlock.iPAddressFamilyA;
            /** @bug error code ignored without explanation */
            read_casn(&rpAddrFamp->addressFamily, cfam);
            // for ieach of the ROA's families
            struct ROAIPAddressFamily *ripAddrFamp;
            struct RouteOriginAttestation *roa =
                &rd->encapContentInfo.eContent.roa;
            for (ripAddrFamp = &roa->ipAddrBlocks.rOAIPAddressFamily;
                 ripAddrFamp;
                 /** @bug error code ignored without explanation */
                 ripAddrFamp = (struct ROAIPAddressFamily *)next_of(
                     &ripAddrFamp->self))
            {
                // find that family in cert
                /** @bug error code ignored without explanation */
                read_casn(&ripAddrFamp->addressFamily, rfam);
                /** @bug magic number */
                /** @bug are cfam and rfam guaranteed to have len 2? */
                while (rpAddrFamp && memcmp(cfam, rfam, 2) != 0)
                {
                    /** @bug error code ignored without explanation */
                    if (!(rpAddrFamp = (struct IPAddressFamilyA *)next_of(
                              &rpAddrFamp->self)))
                    {
                        sta = ERR_SCM_INVALIPB;
                        goto done;
                    }
                    /** @bug error code ignored without explanation */
                    read_casn(&rpAddrFamp->addressFamily, cfam);
                }
                // OK, got the cert family, too f it's not inheriting
                /** @bug error code ignored without explanation */
                if (tag_casn(&rpAddrFamp->ipAddressChoice.self) == ASN_SEQUENCE)
                {
                    // go through all ip addresses in that ROA family
                    struct ROAIPAddress *roaAddrp;
                    for (roaAddrp = &ripAddrFamp->addresses.rOAIPAddress;
                         roaAddrp;
                         /** @bug error code ignored without explanation */
                         roaAddrp = (struct ROAIPAddress *)next_of(
                             &roaAddrp->self))
                    {
                        // set up the limits
                        /** @bug error code possibly ignored without
                         * explanation */
                        /** @bug why rfam[1]? */
                        if ((sta = setup_roa_minmax(
                                 &roaAddrp->address, rmin, rmax, rfam[1])) < 0)
                        {
                            goto done;
                        }
                        // first set up initial entry in cert
                        struct IPAddressOrRangeA *rpAddrRangep =
                            &rpAddrFamp->ipAddressChoice.addressesOrRanges.
                            iPAddressOrRangeA;
                        /** @bug error code possibly ignored without
                         * explanation */
                        /** @bug why cfam[1]? */
                        if ((sta = setup_cert_minmax(
                                 rpAddrRangep, cmin, cmax, cfam[1])) < 0)
                        {
                            goto done;
                        }
                        // go through cert addresses until a high
                        // enough one is found i.e. skip cert
                        // addresses whose max is below roa's min
                        while (rpAddrRangep && memcmp(
                                   &cmax[2], &rmin[2], sizeof(rmin) - 2) <= 0)
                        {
                            /** @bug brace nesting too deep */

                            /** @bug error code ignored without explanation */
                            if (!(rpAddrRangep =
                                  (struct IPAddressOrRangeA *)next_of(
                                      &rpAddrRangep->self))
                                || setup_cert_minmax(
                                    rpAddrRangep, cmin, cmax, cfam[1]) < 0)
                            {
                                /** @bug error message not logged */
                                sta = ERR_SCM_INVALIPB;
                                goto done;
                            }
                        }
                        if (rpAddrRangep)
                        {
                            // now at cert values at or beyond roa.
                            // if roa min is below cert min OR roa max
                            // beyond cert max, bail out
                            if ((ii = memcmp(
                                     &rmin[2], &cmin[2], sizeof(cmin) - 2)) < 0
                                || (ij = memcmp(
                                        &rmax[2], &cmax[2],
                                        sizeof(cmin) - 2)) > 0)
                            {
                                /** @bug error message not logged */
                                sta = ERR_SCM_INVALIPB;
                                goto done;
                            }
                        }
                    }
                }
            }
        }
    }
    if (all_extns != (HAS_EXTN_IPADDR | HAS_EXTN_SKI))
    {
        /** @bug error message not logged */
        sta = ERR_SCM_INVALIPB;
        goto done;
    }
    // check the signature
    if ((sta = check_sig(rp, cert)))
    {
        goto done;
    }

done:
    free(oidp);
    LOG(LOG_DEBUG, "roaValidate2() returning %s: %s",
        err2name(sta), err2string(sta));
    return sta;
}

static err_code
check_ghostbusters_cms(
    struct CMS *cms)
{
    /** @bug error code ignored without explanation */
    if (diff_objid(&cms->content.signedData.encapContentInfo.eContentType,
                   id_ct_rpkiGhostbusters))
    {
        LOG(LOG_ERR, "Ghostbusters record has incorrect content type");
        return ERR_SCM_BADCT;
    }

    return 0;
}

static err_code
check_ghostbusters_cert(
    struct CMS *cms)
{
    struct Certificate *cert =
        &cms->content.signedData.certificates.certificate;

    if (has_non_inherit_resources(cert))
    {
        LOG(LOG_ERR, "Ghostbusters record's EE certificate has RFC3779 "
            "resources that are not marked inherit");
        return ERR_SCM_NOTINHERIT;
    }

    return 0;
}

static err_code
check_ghostbusters_content(
    struct CMS *cms)
{
    unsigned char *content = NULL;
    int content_len = 0;
    err_code sta = 0;

    content_len = readvsize_casn(
        &cms->content.signedData.encapContentInfo.eContent.ghostbusters,
        &content);
    if (content_len < 0)
    {
        LOG(LOG_ERR, "Error reading ghostbusters record's content");
        return ERR_SCM_INTERNAL;
    }

    // TODO: Verify that it's actually a valid vCard conforming to RFC6493.
    // For now, we just verify the the content is valid UTF-8
    // (http://tools.ietf.org/html/rfc6350#section-3.1) and has no control
    // characters (which could mess up a user's terminal).

    // backup the old locale and make sure we're using UTF-8
    const char *old_locale = setlocale(LC_CTYPE, NULL);
    if (setlocale(LC_CTYPE, "C.UTF-8") == NULL)
    {
        LOG(LOG_WARNING, "System does not support C.UTF-8 locale. Ghostbusters "
            "records with invalid contents may be accepted.");
        goto done;
    }

    size_t content_idx = 0;
    wchar_t pwc;
    size_t pwc_mb_len;
    mbstate_t ps;
    memset(&ps, 0, sizeof(ps));
    while (content_idx < (size_t)content_len)
    {
        pwc_mb_len = mbrtowc(&pwc, (char *)content + content_idx,
                             (size_t)content_len - content_idx, &ps);
        if (pwc_mb_len <= 0 || pwc_mb_len > (size_t)content_len - content_idx)
        {
            LOG(LOG_ERR, "Invalid byte sequence in ghostbusters content");
            sta = ERR_SCM_BADCHAR;
            goto done;
        }

        content_idx += pwc_mb_len;

        if (iswcntrl(pwc) && !iswspace(pwc))
        {
            LOG(LOG_ERR, "Ghostbusters content contains a control character "
                "<U+%04" PRIXMAX ">", (uintmax_t)pwc);
            sta = ERR_SCM_BADCHAR;
            goto done;
        }
    }


done:
    setlocale(LC_CTYPE, old_locale);

    free(content);

    return sta;
}

err_code
ghostbustersValidate(
    struct CMS *cms)
{
    err_code sta;

    sta = cmsValidate(cms);
    if (sta < 0)
    {
        return sta;
    }

    // ghostbusters profile checks

    sta = check_ghostbusters_cms(cms);
    if (sta < 0)
    {
        return sta;
    }

    sta = check_ghostbusters_cert(cms);
    if (sta < 0)
    {
        return sta;
    }

    sta = check_ghostbusters_content(cms);
    if (sta < 0)
    {
        return sta;
    }

    return 0;
}
