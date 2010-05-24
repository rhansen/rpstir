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
package orname;
import name.*;
import asn.*;
public class ORName extends AsnArray
    {
    public StandardAttributes standard_attributes = new StandardAttributes();
    public DomainDefinedAttributes domain_defined_attributes = new DomainDefinedAttributes();
    public ExtensionAttributes extension_attributes = new ExtensionAttributes();
    public ORName()
        {
        _tag = AsnStatic.ASN_CHOICE;
        _type = (short)AsnStatic.ASN_CHOICE;
        _tag = 0x60;
        _type = (short)AsnStatic.ASN_SEQUENCE;
        _setup((AsnObj)null, standard_attributes, (short)0, (int)0x0);
        _setup(standard_attributes, domain_defined_attributes, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0x0);
        _setup(domain_defined_attributes, extension_attributes, (short)(AsnStatic.ASN_OPTIONAL_FLAG), (int)0x0);
        }
    public AsnObj _dup()
        {
        ORName objp = new ORName();
        _set_pointers(objp);
        return objp;
        }

    public ORName index(int index)
        {
        return (ORName)_index_op(index);
        }

    public ORName set(ORName frobj)
        {
        ((AsnObj)this).set(frobj);
	return this;
	}
    }
