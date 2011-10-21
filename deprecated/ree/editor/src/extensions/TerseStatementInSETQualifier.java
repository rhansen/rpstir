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
package extensions;
import orname.*;
import name.*;
import Algorithms.*;
// import serial_number.*;
import asn.*;
public class TerseStatementInSETQualifier extends AsnChoice
    {
    public AsnVisibleString visibleString = new AsnVisibleString();
    public AsnBMPString bmpString = new AsnBMPString();
    public TerseStatementInSETQualifier()
        {
        _tag = AsnStatic.ASN_CHOICE;
        _type = (short)AsnStatic.ASN_CHOICE;
        _setup((AsnObj)null, visibleString, (short)0, (int)0x0);
        visibleString._boundset(1, 2048);
        _setup(visibleString, bmpString, (short)0, (int)0x0);
        bmpString._boundset(1, 2048);
        }
    public TerseStatementInSETQualifier set(TerseStatementInSETQualifier frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }