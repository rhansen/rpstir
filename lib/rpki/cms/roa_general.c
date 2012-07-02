/*
 * $Id: roa_general.c 475 2008-04-11 13:17:55Z dmontana $ 
 */


#include <assert.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "roa_utils.h"

#define SKI_SIZE 20

// ROA_utils.h contains the headers for including these functions

// NOTE: it is assumed, when calling the address translation functions,
// that the ROA has
// been validated at entry and that ipaddrmax exceeds ipaddrmin

// A quick itoa implementation that works only for radix <= 10
static int itoa(
    int n,
    char *cN,
    int radix)
{
    int i = 0;
    int j = 0;
    char *s;

    if ((radix > 10) || (NULL == cN))
        return ERR_SCM_INVALARG;

    s = (char *)calloc(33, sizeof(char));
    if (s == NULL)
        return ERR_SCM_NOMEM;

    do
    {
        s[i++] = (char)(n % radix + '0');
        n -= n % radix;
    }
    while ((n /= radix) > 0);

    for (j = 0; j < i; j++)
        cN[i - 1 - j] = s[j];

    cN[j] = '\0';
    free(s);
    return 0;
}

static int cvalhtoc2(
    unsigned char cVal,
    unsigned char *c2Array)
{
    char cHigh = 0;
    char cLow = 0;

    if (NULL == c2Array)
        return ERR_SCM_INVALARG;

    cLow = cVal & 0x0f;
    cHigh = ((cVal & 0xf0) >> 4);

    if (cLow > 0x09)
        cLow += 'A' - 10;
    else
        cLow += '0';

    if (cHigh > 0x09)
        cHigh += 'A' - 10;
    else
        cHigh += '0';

    c2Array[0] = cHigh;
    c2Array[1] = cLow;

    return 0;
}

static int cvaldtoc3(
    unsigned char cVal,
    unsigned char *c2Array,
    int *iLength)
{
    char cHigh = 0;
    char cMid = 0;
    char cLow = 0;

    if (NULL == c2Array)
        return ERR_SCM_INVALARG;

    cLow = cVal % 10;
    cHigh = cVal / 10;

    cMid = cHigh % 10;
    cHigh = cHigh / 10;

    cLow += '0';
    cMid += '0';
    cHigh += '0';

    if ('0' != cHigh)
    {
        c2Array[0] = cHigh;
        c2Array[1] = cMid;
        c2Array[2] = cLow;
        *iLength = 3;
    }
    else if ('0' != cMid)
    {
        c2Array[0] = cMid;
        c2Array[1] = cLow;
        *iLength = 2;
    }
    else
    {
        c2Array[0] = cLow;
        *iLength = 1;
    }

    return 0;
}

unsigned char *roaSKI(
    struct ROA *r)
{
    int i = 0;
    unsigned char *cSID = NULL;
    unsigned char *cReturn = NULL;
    unsigned char c2Ans[2];

    // parameter check
    if (NULL == r)
        return NULL;

    if (SKI_SIZE !=
        vsize_casn(&
                   (r->content.signedData.signerInfos.signerInfo.sid.
                    subjectKeyIdentifier)))
        return NULL;
    if (0 >
        readvsize_casn(&
                       (r->content.signedData.signerInfos.signerInfo.sid.
                        subjectKeyIdentifier), &cSID))
        return NULL;
    else
    {
        cReturn = calloc(1 + (SKI_SIZE * 3), sizeof(char));
        if (NULL == cReturn)
        {
            // free(cSID);
            return NULL;
        }
        for (i = 0; i < SKI_SIZE; i++)
        {
            cvalhtoc2(cSID[i], c2Ans);
            cReturn[(3 * i)] = c2Ans[0];
            cReturn[(3 * i) + 1] = c2Ans[1];
            cReturn[(3 * i) + 2] = ':';
        }
        // Clear the incorrectly allocated : in the last loop
        cReturn[(3 * (i - 1)) + 2] = 0x00;
        free(cSID);
        return cReturn;
    }

    return NULL;
}

unsigned char *roaSignature(
    struct ROA *r,
    int *lenp)
{
    if (r == NULL || lenp == NULL)
        return (NULL);
    *lenp = r->content.signedData.signerInfos.signerInfo.signature.lth;
    return (r->content.signedData.signerInfos.signerInfo.signature.startp);
}

static unsigned char *printIPv4String(
    unsigned char *array,
    int iArraySize,
    int iFill,
    int iPrintPrefix,
    int maxLen)
{
    int i = 0;
    unsigned char j = 0;
    int iSecLen = 0;
    int iReturnLen = 0;
    unsigned char cPrefix = 0;
    unsigned int prefix;
    unsigned char *cReturnString = NULL;
    int cReturnStringSize = 0;
    unsigned char cDecimalSection[3];

    if (NULL == array)
        return NULL;

    prefix = (8 * (iArraySize - 1)) - array[0];
    assert(prefix < 33);
    cPrefix = (uchar) prefix;
    cReturnStringSize = 30 + (3 * iArraySize);
    cReturnString = calloc(sizeof(char), cReturnStringSize);
    if (NULL == cReturnString)
        return NULL;

    for (i = 1; i < iArraySize; i++)
    {
        // If this is the last char in the array, and we're obeying DER rules
        // for the maximum in a prefix (i.e. Fill is 1), then we need to add
        // back the removed '1' bits (aka array[0])
        if ((1 == iFill) && (i == iArraySize - 1))
        {
            for (j = 0; j < array[0]; j++)
                array[i] |= (0x01 << j);
        }
        cvaldtoc3(array[i], cDecimalSection, &iSecLen);
        memcpy(cReturnString + iReturnLen, cDecimalSection, iSecLen);
        iReturnLen += iSecLen;
        // Interleaved periods (up to array maximum)
        if (4 > i)
        {
            memcpy(cReturnString + iReturnLen, ".", 1);
            iReturnLen++;
        }
    }

    if (iArraySize < 5)
    {
        for (; i < 5; i++)
        {
            if (1 == iFill)
            {
                memcpy(cReturnString + iReturnLen, "255", 3);
                iReturnLen += 3;
            }
            else if (0 == iFill)
            {
                memcpy(cReturnString + iReturnLen, "0", 1);
                iReturnLen++;
            }
            // Interleaved periods (continued)
            if (4 > i)
            {
                memcpy(cReturnString + iReturnLen, ".", 1);
                iReturnLen++;
            }
        }
    }

    // If we're printing prefixes, we need the array to either not be
    // full length or to have unused bits mentioned in array[0]
    if ((cTRUE == iPrintPrefix) && (32 != cPrefix))
    {
        memcpy(cReturnString + iReturnLen, "/", 1);
        iReturnLen++;
        cvaldtoc3(cPrefix, cDecimalSection, &iSecLen);
        memcpy(cReturnString + iReturnLen, cDecimalSection, iSecLen);
        iReturnLen += iSecLen;
        if (maxLen)
        {
            char maxlenbuf[10];
            memset(maxlenbuf, 0, sizeof(maxlenbuf));
            sprintf(maxlenbuf, "^%d-%d", prefix, maxLen);
            assert(iReturnLen + strlen(maxlenbuf) < cReturnStringSize);
            strcpy((char *)&cReturnString[iReturnLen], maxlenbuf);
            iReturnLen += strlen(maxlenbuf);
        }
    }

    return cReturnString;
}

static unsigned char *printIPv6String(
    unsigned char *array,
    int iArraySize,
    int iFill,
    int iPrintPrefix,
    int maxLen)
{
    int i = 0;
    unsigned char j = 0;
    int iSecLen = 0;
    int iReturnLen = 0;
    unsigned int prefix;
    unsigned char cPrefix = 0;
    unsigned char *cReturnString = NULL;
    unsigned char cHexSection[2];
    int cReturnStringSize = 0;
    unsigned char cDecimalPrefix[3];

    if (NULL == array)
        return NULL;

    prefix = 8 * (iArraySize - 1) - array[0];
    assert(prefix < 129);
    cPrefix = (uchar) prefix;
    cReturnStringSize = 60 + (3 * iArraySize);
    cReturnString = calloc(sizeof(char), cReturnStringSize);
    if (NULL == cReturnString)
        return NULL;

    for (i = 1; i < iArraySize; i++)
    {
        // If this is the last char in the array, and we're obeying DER rules
        // for the maximum in a prefix (i.e. Fill is 1), then we need to add
        // back the removed '1' bits in the prefix (array[0])
        if ((1 == iFill) && (i == iArraySize - 1))
        {
            for (j = 0; j < array[0]; j++)
                array[i] |= (0x01 << j);
        }
        cvalhtoc2(array[i], cHexSection);
        memcpy(cReturnString + iReturnLen, cHexSection, 2);
        iReturnLen += 2;
        // Interleaved colons
        if ((16 > i) && (0 == i % 2))
        {
            memcpy(cReturnString + iReturnLen, ":", 1);
            iReturnLen++;
        }
    }
    if (iArraySize < 17)
    {
        for (; i < 17; i++)
        {
            if (1 == iFill)
            {
                memcpy(cReturnString + iReturnLen, "FF", 2);
                iReturnLen += 2;
            }
            else if (0 == iFill)
            {
                memcpy(cReturnString + iReturnLen, "00", 2);
                iReturnLen += 2;
            }
            // Every other translated byte needs a colon
            if ((16 > i) && (0 == i % 2))
            {
                memcpy(cReturnString + iReturnLen, ":", 1);
                iReturnLen++;
            }
        }
    }

    // If we're printing prefixes, we need the array to either not be
    // full length or to have unused bits mentioned in array[0]
    if ((cTRUE == iPrintPrefix) && (128 != cPrefix))
    {
        memcpy(cReturnString + iReturnLen, "/", 1);
        iReturnLen++;
        cvaldtoc3(cPrefix, cDecimalPrefix, &iSecLen);
        memcpy(cReturnString + iReturnLen, cDecimalPrefix, iSecLen);
        iReturnLen += iSecLen;
        if (maxLen)
        {
            char maxlenbuf[10];
            memset(maxlenbuf, 0, sizeof(maxlenbuf));
            sprintf(maxlenbuf, "^%d-%d", prefix, maxLen);
            assert(iReturnLen + strlen(maxlenbuf) < cReturnStringSize);
            strcpy((char *)&cReturnString[iReturnLen], maxlenbuf);
            iReturnLen += strlen(maxlenbuf);
        }
    }

    return cReturnString;
}

static unsigned char *roaIPAddr(
    struct ROAIPAddress *raddr,
    int iFamily)
{
    int iSize = 0,
        maxLen;
    unsigned char *cASCIIString = NULL,
        ipaddr[200];

    // parameter check
    if ((NULL == raddr) || (0 == iFamily))
        return NULL;

    memset(ipaddr, 0, sizeof(ipaddr));
    iSize = vsize_casn(&raddr->address);

    if ((0 >= iSize) || (sizeof(ipaddr) < iSize))
        return NULL;
    if (0 > read_casn(&raddr->address, ipaddr))
        return NULL;
    if (read_casn_num(&raddr->maxLength, (long *)(&maxLen)) == 0)
        maxLen = 0;
    if (IPV4 == iFamily)
    {
        cASCIIString = printIPv4String(ipaddr, iSize, 0, cTRUE, maxLen);
    }
    else if (IPV6 == iFamily)
    {
        cASCIIString = printIPv6String(ipaddr, iSize, 0, cTRUE, maxLen);
    }

    return cASCIIString;
}

static unsigned char **roaIPAddresses(
    struct ROAIPAddressFamily *roapAddrFam,
    int *numOfAddresses)
{
    int i,
        j = 0;
    int iRes = 0;
    int iFamily = 0;
    int iAddrs = 0;
    unsigned char **pcAddresses = NULL;
    unsigned char family[3];

    struct ROAIPAddress *rIPAddr = NULL;

    // parameter check
    if ((NULL == roapAddrFam) || (NULL == numOfAddresses))
        return NULL;

    iRes = read_casn(&(roapAddrFam->addressFamily), family);
    if (0 > iRes)
        return NULL;

    if (0x01 == family[1])
        iFamily = IPV4;
    else if (0x02 == family[1])
        iFamily = IPV6;
    else
        return NULL;

    iAddrs = num_items(&(roapAddrFam->addresses.self));

    if (0 >= iAddrs)
        return NULL;

    pcAddresses = (unsigned char **)calloc(iAddrs, sizeof(char **));
    if (NULL == pcAddresses)
        return NULL;

    for (i = 0; i < iAddrs; i++)
    {
        rIPAddr =
            (struct ROAIPAddress *)member_casn(&(roapAddrFam->addresses.self),
                                               i);
        pcAddresses[i] = roaIPAddr(rIPAddr, iFamily);
        if (NULL == pcAddresses[i])
        {
            for (j = i - 1; j >= 0; j--)
                free(pcAddresses[j]);
            free(pcAddresses);
            return NULL;
        }
    }

    *numOfAddresses = iAddrs;
    return pcAddresses;
}

int roaAS_ID(
    struct ROA *r)
{
    long iAS_ID = 0;

    // parameter check
    if (NULL == r)
        return 0;

    if (0 >=
        read_casn_num(&
                      (r->content.signedData.encapContentInfo.eContent.roa.
                       asID), &iAS_ID))
        return -1;

    return iAS_ID;
}

/*
 * void roaFree(struct ROA *r) { if (NULL != r) { delete_casn(&(r->self));
 * free((void *)r); } } 
 */
static int convertAddr(
    int family,
    struct ROAIPAddress *ipaddressp,
    char *outbuf,
    int outbufLth)
{
    memset(outbuf, 0, outbufLth);
    uchar abuf[36];
    int addrLth = read_casn(&ipaddressp->address, abuf);
    if (family == AF_INET)
    {
        uint32_t addrVal = 0;
        uint32_t xx;
        int ii;
        if (outbufLth < INET_ADDRSTRLEN + 6)
            return ERR_SCM_INVALSZ;
        for (ii = 1; ii < addrLth; ii++)
            addrVal = (addrVal << 8) + abuf[ii];
        while (ii++ <= sizeof(uint))
            addrVal <<= 8;
        xx = htonl(addrVal);
        if (!inet_ntop(family, &xx, outbuf, outbufLth))
            return ERR_SCM_INVALIPL;
        // prefix length is ((addrLth - 1) * 8) - unused bits
        sprintf(&outbuf[strlen(outbuf)], "/%d", ((addrLth - 1) * 8) - abuf[0]);
    }
    else if (family == AF_INET6)
    {
        if (outbufLth < INET6_ADDRSTRLEN + 6)
            return ERR_SCM_INVALSZ;
        uchar addrVal[16];
        memset(addrVal, 0, 16);
        memcpy(addrVal, &abuf[1], addrLth - 1);
        if (!inet_ntop(family, &addrVal, outbuf, outbufLth))
            return ERR_SCM_INVALIPL;
        sprintf(&outbuf[strlen(outbuf)], "/%d", ((addrLth - 1) * 8) - abuf[0]);
    }
    else
        return ERR_SCM_INVALIPB;

    int lth = strlen(outbuf);
    if (vsize_casn(&ipaddressp->maxLength))
    {
        long j;
        read_casn_num(&ipaddressp->maxLength, &j);
        sprintf(&outbuf[lth], "(%d)", (int)j);
        lth = strlen(outbuf);
    }
    return lth;
}

int roaGetIPAddresses(
    struct ROA *rp,
    char **str)
{
    struct ROAIPAddrBlocks *addrBlocksp =
        &rp->content.signedData.encapContentInfo.eContent.roa.ipAddrBlocks;
    struct ROAIPAddressFamily *famp;
    int replysiz = 0,
        lth;
    char *replyp = NULL;
    char tmpbuf[INET6_ADDRSTRLEN + 8];  // to be on safe side
    *str = NULL;                // in case of failure
    for (famp =
         (struct ROAIPAddressFamily *)member_casn(&addrBlocksp->self, 0); famp;
         famp = (struct ROAIPAddressFamily *)next_of(&famp->self))
    {
        uchar famtyp[4];
        if (read_casn(&famp->addressFamily, famtyp) < 0)
            return -1;
        int family;
        if (famtyp[1] == 1)
            family = AF_INET;
        else if (famtyp[1] == 2)
            family = AF_INET6;
        struct ROAIPAddress *ipaddressp;
        for (ipaddressp =
             (struct ROAIPAddress *)member_casn(&famp->addresses.self, 0);
             ipaddressp;
             ipaddressp = (struct ROAIPAddress *)next_of(&ipaddressp->self))
        {
            lth =
                convertAddr(family, ipaddressp, tmpbuf, INET6_ADDRSTRLEN + 8);
            if (lth < 0)
            {
                if (replyp)
                    free(replyp);
                return lth;
            }
            if (!replysiz)
            {                   // lth + 1 allows for null
                if (!(replyp = (char *)calloc(1, lth + 1)))
                    return ERR_SCM_NOMEM;
                strcpy(replyp, tmpbuf);
                replysiz = lth; // size without null
            }
            else
            {
                char *tmpp = (char *)realloc(replyp, replysiz + lth + 3);
                if (!tmpp)
                {
                    free(replyp);
                    return ERR_SCM_NOMEM;;
                }
                replyp = tmpp;
                char *b = &replyp[replysiz];
                *b++ = ',';
                *b++ = ' ';
                strcpy(b, tmpbuf);
                replysiz += lth + 2;    // without null
            }
        }
    }
    *str = replyp;
    return 0;
}

int roaGenerateFilter(
    struct ROA *r,
    uchar * cert,
    FILE * fp,
    char *str,
    int strLen)
{
    int i,
        j = 0;
    int iRes = 0;
    int iFamilies = 0;
    int iAddrNum = 0;
    int iAS_ID = 0;
    int sta;
    char cAS_ID[17];
    unsigned char *cSID = NULL;
    unsigned char **pcAddresses = NULL;
    struct ROAIPAddressFamily *roaFamily = NULL;

    // for local use, for brevity
    struct casn *ipblocks =
        &r->content.signedData.encapContentInfo.eContent.roa.ipAddrBlocks.self;

    UNREFERENCED_PARAMETER(cert);
    // parameter check
    if (NULL == fp && NULL == str)
        return ERR_SCM_INVALARG;

    memset(cAS_ID, 0, 17);
    iAS_ID = roaAS_ID(r);
    if (iAS_ID == 0)
        return ERR_SCM_INVALASID;
    sta = itoa(iAS_ID, cAS_ID, 10);
    if (sta < 0)
        return sta;

    cSID = roaSKI(r);
    if (NULL == cSID)
        return ERR_SCM_INVALSKI;

    // For each family, print out all triplets beginning with SKI and AS#
    // and ending with each IP address listed in the ROA
    iFamilies = num_items(ipblocks);
    for (i = 0; i < iFamilies; i++)
    {
        roaFamily = (struct ROAIPAddressFamily *)member_casn(ipblocks, i);
        if (NULL == roaFamily)
        {
            free(cSID);
            return ERR_SCM_INVALIPB;
        }
        pcAddresses = roaIPAddresses(roaFamily, &iAddrNum);
        if (NULL == pcAddresses)
        {
            free(cSID);
            return ERR_SCM_INVALIPB;
        }

        for (j = 0; j < iAddrNum; j++)
        {
            if (str != NULL)
            {
                iRes = snprintf(str, strLen, "%s %s %s\n",
                                cSID, cAS_ID, pcAddresses[j]);
                strLen -= strlen(str);
                str += strlen(str);
            }
            if (fp != NULL)
            {
                iRes = fprintf(fp, "%s %s %s\n", cSID, cAS_ID, pcAddresses[j]);
                if (0 > iRes)
                    return ERR_SCM_BADFILE;
            }
        }
        for (j = iAddrNum - 1; j >= 0; j--)
            free(pcAddresses[j]);
        free(pcAddresses);
        pcAddresses = NULL;
    }

    free(cSID);
    return 0;
}

int roaGenerateFilter2(
    struct ROA *r,
    char **strpp)
{
    int i,
        j = 0;
    int iRes = 0;
    int iFamilies = 0;
    int iAddrNum = 0;
    int iAS_ID = 0;
    int sta;
    char cAS_ID[20];
    unsigned char *cSID = NULL;
    unsigned char **pcAddresses = NULL;
    struct ROAIPAddressFamily *roaFamily = NULL;

    // for local use, for brevity
    struct casn *ipblocks =
        &r->content.signedData.encapContentInfo.eContent.roa.ipAddrBlocks.self;

    // parameter check
    if (*strpp != NULL)
        free(*strpp);

    memset(cAS_ID, 0, sizeof(cAS_ID));
    if ((iAS_ID = roaAS_ID(r)) == 0)
        return ERR_SCM_INVALASID;
    if ((sta = itoa(iAS_ID, cAS_ID, 10)) < 0)
        return sta;

    if ((cSID = roaSKI(r)) == NULL)
        return ERR_SCM_INVALSKI;

#define FILTER_INCR 1024
    int strLen,
        remLen;
    char *rstrp,
       *strp;
    rstrp = strp = (char *)calloc(1, FILTER_INCR);
    strLen = remLen = FILTER_INCR;
    // For each family, print out all triplets beginning with SKI and AS#
    // and ending with each IP address listed in the ROA
    iFamilies = num_items(ipblocks);
    for (i = 0; i < iFamilies; i++)
    {
        if ((roaFamily = (struct ROAIPAddressFamily *)member_casn(ipblocks, i))
            == NULL)
        {
            free(cSID);
            return ERR_SCM_INVALIPB;
        }
        if ((pcAddresses = roaIPAddresses(roaFamily, &iAddrNum)) == NULL)
        {
            free(cSID);
            return ERR_SCM_INVALIPB;
        }
        for (j = 0; j < iAddrNum; j++)
        {
            while ((iRes = snprintf(rstrp, remLen, "%s %s %s\n", cSID, cAS_ID,
                                    pcAddresses[j])) > remLen)
            {
                int used = rstrp - strp;
                strp = (char *)realloc(strp, strLen += FILTER_INCR);
                rstrp = &strp[used];
                remLen += FILTER_INCR;
            }

            remLen -= strlen(rstrp);
            rstrp += strlen(rstrp);
        }
        for (j = iAddrNum - 1; j >= 0; j--)
            free(pcAddresses[j]);
        free(pcAddresses);
        pcAddresses = NULL;
    }

    free(cSID);
    *strpp = strp;
    return 0;
}