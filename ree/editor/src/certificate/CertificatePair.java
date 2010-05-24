/* ***** BEGIN LICENSE BLOCK *****
 * 
 * BBN Rule Editor/Engine for Address and AS Number PKI
 * Verison 1.0
 * 
 * COMMERCIAL COMPUTER SOFTWARE�RESTRICTED RIGHTS (JUNE 1987)
 * US government users are permitted restricted rights as
 * defined in the FAR.  
 *
 * This software is distributed on an "AS IS" basis, WITHOUT
 * WARRANTY OF ANY KIND, either express or implied.
 *
 * Copyright (C) Raytheon BBN Technologies Corp. 2007.  All Rights Reserved.
 *
 * Contributor(s):  Charlie Gardiner
 *
 * ***** END LICENSE BLOCK ***** */
package certificate;
import orname.*;
import name.*;
import Algorithms.*;
// import serial_number.*;
import extensions.*;
import asn.*;
public class CertificatePair extends AsnArray
    {
    public Certificate forward = new Certificate();
    public Certificate reverse = new Certificate();
    public CertificatePair()
        {
        _tag = AsnStatic.ASN_SEQUENCE;
        _type = (short)AsnStatic.ASN_SEQUENCE;
        _setup((AsnObj)null, forward, (short)(AsnStatic.ASN_OPTIONAL_FLAG | AsnStatic.ASN_EXPLICIT_FLAG), (int)0xA0);
        _setup(forward, reverse, (short)(AsnStatic.ASN_OPTIONAL_FLAG | AsnStatic.ASN_EXPLICIT_FLAG), (int)0xA1);
        }
    public AsnObj _dup()
        {
        CertificatePair objp = new CertificatePair();
        _set_pointers(objp);
        return objp;
        }

    public CertificatePair index(int index)
        {
        return (CertificatePair)_index_op(index);
        }

    public CertificatePair set(CertificatePair frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
