#!/bin/sh
# ***** BEGIN LICENSE BLOCK *****
#  
#  BBN Address and AS Number PKI Database/repository software
#  Version 3.0-beta
#  
#  US government users are permitted unrestricted rights as
#  defined in the FAR.  
# 
#  This software is distributed on an "AS IS" basis, WITHOUT
#  WARRANTY OF ANY KIND, either express or implied.
# 
#  Copyright (C) Raytheon BBN Technologies Corp. 2007-2010.  All Rights Reserved.
# 
#  Contributor(s):  David Montana
# 
# ***** END LICENSE BLOCK *****
# listen for feeder connections and load the data fed into the database

# set environment variables if not set
THIS_SCRIPT_DIR=$(dirname $0)
. $THIS_SCRIPT_DIR/../envir.setup

$RPKI_ROOT/proto/rcli -w $RPKI_PORT -p
