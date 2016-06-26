/*****************************************************************************
File:     casn_objid.c
Contents: Basic functions for ASN.1 objects.
System:   Compact ASN development.
Created:
Author:   Charles W. Gardiner <gardiner@bbn.com>

Remarks:

COPYRIGHT 2004 BBN Systems and Technologies
10 Moulton St.
Cambridge, Ma. 02138
617-873-3000
*****************************************************************************/

#include "casn.h"
#include "casn_private.h"
#include "util/stringutils.h"

int diff_objid(
    struct casn *casnp,
    const char *objid)
{
    int ret;
    char *c = NULL;

    if ((ret = readvsize_objid(casnp, &c)) < 0)
    {
        goto done;
    }
    // the !! converts all non-0 values to 1
    ret = !!strcmp(c, objid);
done:
    free(c);
    return ret;
}

int read_objid(
    struct casn *casnp,
    char *to,
    size_t tolen)
{
    if (_clear_error(casnp) < 0)
        return -1;
    if (casnp->type != ASN_OBJ_ID && casnp->type != ASN_RELATIVE_OID)
        return _casn_obj_err(casnp, ASN_TYPE_ERR);
    return _readsize_objid(casnp, to, tolen, 1);
}

int vsize_objid(
    struct casn *casnp)
{
    /** @bug magic number */
    char buf[16];

    if (_clear_error(casnp) < 0)
        return -1;
    if (casnp->type != ASN_OBJ_ID && casnp->type != ASN_RELATIVE_OID)
        return _casn_obj_err(casnp, ASN_TYPE_ERR);
    return _readsize_objid(casnp, buf, sizeof(buf), 0);
}

int write_objid(
    struct casn *casnp,
    const char *from)
{

    if (_clear_error(casnp) < 0)
        return -1;
    if (casnp->type != ASN_OBJ_ID && casnp->type != ASN_RELATIVE_OID)
        return -1;
    if (casnp->tag == ASN_NOTYPE)
        return _write_enum(casnp);
    return _write_objid(casnp, from);
}

// If there's no OID and no error, return 0. If there's an error, return
// negative. If there is an OID, it includes a trailing NULL byte in the
// length and optionally the buffer.
int _readsize_objid(
    struct casn *casnp,
    char *to,
    size_t tolen,
    int mode)
{
    int lth = 0;
    uchar *c = casnp->startp;
    uchar *e = &c[casnp->lth];
    char *b = to;
    ulong val;

    if (tolen)
    {
        // make sure the string is null terminated if we return 0
        *to = '\0';
    }

    if (casnp->tag == ASN_NOTYPE && (lth = _check_enum(&casnp)) <= 0)
        return lth;
    if (!casnp->lth)
        return 0;
    // elements 1 & 2
    if (casnp->type == ASN_OBJ_ID ||
        // have to allow tag for a mixed definer
        (casnp->type == ASN_ANY && casnp->tag == ASN_OBJ_ID))
    {
        /**
         * @bug
         *     This logic does not properly handle OID components that
         *     are too big to fit in an unsigned long
         */
        /**
         * @bug
         *     BER and DER require the minimal number of octets.  This
         *     logic ignores excess octets.  Should it error out
         *     instead?
         */
        for (val = 0; c < e && (*c & 0x80); c++)
        {
            val = (val << 7) + (*c & 0x7F);
        }
        /** @bug invalid read if c == e */
        val = (val << 7) + *c++;
        /** @bug magic numbers */
        /** @bug _putd() takes a long, not an unsigned long */
        b = _putd(b, tolen - (b - to), (val < 120) ? (val / 40) : 2);
        b += xstrlcpy(b, ".", tolen - (b - to));
        /** @bug magic numbers */
        /** @bug _putd() takes a long, not an unsigned long */
        b = _putd(b, tolen - (b - to), (val < 120) ? (val % 40) : val - 80);
        /** @bug callers seem to assume that mode is a boolean */
        if (!(mode & ASN_READ))
        {
            lth = b - to;
            b = to;
        }
        if (c < e)
        {
            b += xstrlcpy(b, ".", tolen - (b - to));
        }
    }
    while (c < e)
    {
        /**
         * @bug
         *     This logic does not properly handle OID components that
         *     are too big to fit in an unsigned long
         */
        /**
         * @bug
         *     BER and DER require the minimal number of octets.  This
         *     logic ignores excess octets.  Should it error out
         *     instead?
         */
        /** @bug invalid read if c >= e */
        for (val = 0; (*c & 0x80); c++)
        {
            val = (val << 7) + (*c & 0x7F);
        }
        /** @bug invalid read if c >= e */
        val = (val << 7) + *c++;
        /** @bug _putd() takes a long, not an unsigned long */
        b = _putd(b, tolen - (b - to), val);
        if (c < e)
        {
            b += xstrlcpy(b, ".", tolen - (b - to));
        }
        /** @bug callers seem to assume that mode is a boolean */
        if (!(mode & ASN_READ))
        {
            lth += b - to;
            b = to;
        }
    }
    /** @bug callers seem to assume that mode is a boolean */
    return (mode & ASN_READ) ? (b - to) : lth;
}
