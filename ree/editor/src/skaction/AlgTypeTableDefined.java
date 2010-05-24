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
package skaction;
import name.*;
import Algorithms.*;
import certificate.*;
import crlv2.*;
import asn.*;
public class AlgTypeTableDefined extends AsnChoice
    {
    public AsnInteger rsa = new AsnInteger();
    public DsaInAlgTypeTable dsa = new DsaInAlgTypeTable();
    public AlgTypeTableDefined()
        {
        _flags |= AsnStatic.ASN_DEFINED_FLAG;
        _setup((AsnObj)null, rsa, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0x0);
        _setup(rsa, dsa, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0x0);
        }
    public AlgTypeTableDefined set(AlgTypeTableDefined frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
