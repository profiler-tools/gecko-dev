/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 *
 * The contents of this file are subject to the Netscape Public License
 * Version 1.0 (the "NPL"); you may not use this file except in
 * compliance with the NPL.  You may obtain a copy of the NPL at
 * http://www.mozilla.org/NPL/
 *
 * Software distributed under the NPL is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the NPL
 * for the specific language governing rights and limitations under the
 * NPL.
 *
 * The Initial Developer of this code under the NPL is Netscape
 * Communications Corporation.  Portions created by Netscape are
 * Copyright (C) 1998 Netscape Communications Corporation.  All Rights
 * Reserved.
 */

#ifndef _nsHTTPResponseListener_h_
#define _nsHTTPResponseListener_h_

#include "nsIStreamListener.h"
#include "nsString.h"
#include "nsCOMPtr.h"

class nsIBuffer;
class nsIChannel;
class nsHTTPResponse;
class nsIHTTPChannel;

/* 
    The nsHTTPResponseListener class is the response reader listener that 
    receives notifications of OnStartRequest, OnDataAvailable and 
    OnStopRequest as the data is received from the server. Each instance 
    of this class is tied to the corresponding transport that it reads the
    response data stream from. 

  
    The essential purpose of this class is to create the actual response 
    based on the data that is coming off the net. 

    This class is internal to the protocol handler implementation and 
    should theroetically not be used by the app or the core netlib.

    -Gagan Saksena 04/29/99
*/
class nsHTTPResponseListener : public nsIStreamListener
{

public:

    nsHTTPResponseListener();
    virtual ~nsHTTPResponseListener();

    // nsISupports functions
    NS_DECL_ISUPPORTS

    // nsIStreamListener functions
    NS_IMETHOD OnDataAvailable(nsIChannel* channel, nsISupports* context,
                               nsIInputStream *aIStream, 
                               PRUint32 aSourceOffset,
                               PRUint32 aLength);


    NS_IMETHOD OnStartRequest(nsIChannel* channel, nsISupports* context);

    NS_IMETHOD OnStopRequest(nsIChannel* channel, nsISupports* context,
                            nsresult aStatus,
                            const PRUnichar* aMsg);

protected:
    // nsHTTPResponseListener methods...
    nsresult FireOnHeadersAvailable();

    nsresult ParseStatusLine(nsIBuffer* aBuffer, PRUint32 aLength,
                             PRUint32 *aBytesRead);

    nsresult ParseHTTPHeader(nsIBuffer* aBuffer, PRUint32 aLength, 
                             PRUint32* aBytesRead);


protected:
    PRBool              m_bHeadersDone;
    PRBool              m_bFirstLineParsed;
    nsHTTPResponse*     m_pResponse;
    nsIHTTPChannel*     m_pConnection;
    nsIStreamListener*  m_pConsumer;
    PRUint32            m_ReadLength; // Already read

    nsString            m_HeaderBuffer;

    nsCOMPtr<nsISupports> m_ResponseContext;
    nsCOMPtr<nsIChannel>  m_Channel;
};

#endif /* _nsHTTPResponseListener_h_ */
