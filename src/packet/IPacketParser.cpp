//
// Created by pchand on 24/4/17.
//

#include "IPacketParser.h"
#include "base/Error.h"
#include "base/Log.h"
#include "processor/RequestProcessor.h"

/*!
 * Constructor
 */
IPacketParser::IPacketParser()
{
    //Empty Constructor
}

/*!
 * Destructor
 */
IPacketParser::~IPacketParser()
{
    //Empty Destructor
}

/*!
 * Parse credentials
 * @param packet
 * @return
 */
int IPacketParser::parse_credentials(Packet *packet)
{
    assert(packet != NULL);
    assert(packet->_pb_msg != NULL);

    RequestProcessor::GetInstance()->SetWorkGroup(packet->_pb_msg->requestpacket().smbdetails().workgroup());
    RequestProcessor::GetInstance()->SetUserName(packet->_pb_msg->requestpacket().smbdetails().username());
    RequestProcessor::GetInstance()->SetPassword(packet->_pb_msg->requestpacket().smbdetails().password());
    RequestProcessor::GetInstance()->SetUrl(packet->_pb_msg->requestpacket().smbdetails().url());
    if (packet->_pb_msg->requestpacket().smbdetails().has_kerberos())
    {
        RequestProcessor::GetInstance()->SetKerberos(packet->_pb_msg->requestpacket().smbdetails().kerberos());
    }

    return SMB_SUCCESS;
}

/*!
 * Parse status/error packet
 * @param status
 * @return
 */
int IPacketParser::parse_status(const Status &status)
{
    INFO_LOG("Status-code %d, Status-msg %s", status.code(), status.msg().c_str());
    return SMB_SUCCESS;
}

/*!
 * Verify request-id
 * @param packet - request packet
 * @return
 */
int IPacketParser::verify_request_id(Packet *packet)
{
    /*first packet, lets store it */
    if (RequestProcessor::GetInstance()->RequestId().length() == 0)
    {
        RequestProcessor::GetInstance()->SetRequestId(packet->GetID());
        return SMB_SUCCESS;
    }
    else
    {
        if (packet->GetID().compare(RequestProcessor::GetInstance()->RequestId()))
        {
            WARNING_LOG("IPacketParser::ParsePacket Request-id mismatch %s vs %s, received wrong packet",
                        packet->GetID().c_str(),
                        RequestProcessor::GetInstance()->RequestId().c_str());
            return SMB_ERROR;
        }
    }

    return SMB_SUCCESS;
}
