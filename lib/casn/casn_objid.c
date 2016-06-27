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
    int ret = 0;
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

    if (casnp->tag == ASN_NOTYPE && (ret = _check_enum(&casnp)) <= 0)
    {
        return ret;
    }

    while (c < e)
    {
        /**
         * @bug
         *     BER and DER require the minimal number of octets.  This
         *     logic ignores excess octets.  Should it error out
         *     instead?
         */
        for (val = 0; c < e && (*c & 0x80); c++)
        {
            static const ulong MSB_MASK = (ulong)(-1) - ((ulong)(-1) >> 7);
            if (val & MSB_MASK)
            {
                // ulong isn't big enough to hold the value
                return _casn_obj_err(casnp, ASN_OVERFLOW_ERR);
            }
            val = (val << 7) + (*c & 0x7F);
        }
        if (c == e)
        {
            // the last byte had its most significant bit set
            return _casn_obj_err(casnp, ASN_CODING_ERR);
        }
        val = (val << 7) + *c++;

        _Bool first_iter = (b == to && !lth);
        if (!first_iter)
        {
            b += xstrlcpy(b, ".", tolen - (b - to));
        }
        if ((casnp->type == ASN_OBJ_ID ||
             // have to allow tag for a mixed definer
             (casnp->type == ASN_ANY && casnp->tag == ASN_OBJ_ID))
            && first_iter)
        {
            // The encoding of the first two elements is special:
            // According to X.690, the only valid values for the first
            // element are 0, 1, and 2.  If the first element has
            // value 0 or 1, the second element must have a value
            // between 0 and 39 (inclusive).  The first two elements
            // are encoded together by encoding the value:
            //     40*element1 + element2
            // Thus:
            //   - If val is < 40, then the first element is 0 and the
            //     second element is val.
            //   - If val is >= 40 and < 80, then the first element is
            //     1 and the second element is val - 40.
            //   - If val is >= 80, then the first element is 2 and
            //     the second element is val - 80.
            b = _putd(b, tolen - (b - to), (val < 80) ? (val / 40) : 2);
            b += xstrlcpy(b, ".", tolen - (b - to));
            b = _putd(b, tolen - (b - to), (val < 80) ? (val % 40) : val - 80);
        }
        else
        {
            b = _putd(b, tolen - (b - to), val);
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
