/*****************************************************************************
File:     casn.c
Contents: Basic functions for ASN.1 objects.
System:   Compact ASN development.
Created:
Author:   Charles W. Gardiner <gardiner@bbn.com>

Remarks:

*****************************************************************************/

#include "casn.h"

int encodesize_casn(
    struct casn *casnp,
    uchar ** pp)
{
    int lth;

    *pp = NULL;
    if ((lth = size_casn(casnp)) < 0)
        return lth;
    *pp = calloc(1, lth);
    return encode_casn(casnp, *pp);
}

int readvsize_casn(
    struct casn *casnp,
    uchar ** pp)
{
    int lth;

    *pp = NULL;
    if ((lth = vsize_casn(casnp)) < 0)
        return lth;
    *pp = calloc(1, lth + 1);
    return read_casn(casnp, *pp);
}

int readvsize_objid(
    struct casn *casnp,
    char **pp)
{
    int lth;

    *pp = NULL;
    if ((lth = vsize_objid(casnp)) < 0)
        return lth;
    *pp = calloc(1, lth + 1);
    return read_objid(casnp, *pp, lth + 1);
}
