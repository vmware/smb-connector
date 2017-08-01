/*
 * Copyright (C) 2017 VMware, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-3.0
 *
 */

#ifdef _DEBUG_

#include <gtest/gtest.h>

#include "core/Server.h"
#include "base/Error.h"
#include "base/Protocol.h"
#include "processor/DownloadProcessor.h"
#include "processor/UploadProcessor.h"
#include "processor/OpenDirReqProcessor.h"
#include "processor/AddFolderProcessor.h"
#include "processor/DeleteProcessor.h"
#include "processor/TestConnection.h"

static Server *server = NULL;
static SessionManager *sessionManager = NULL;
static char sock_path[] = "sample";
static UnixDomainSocket client_socket;
static std::string request_id="1234";
static DownloadProcessor *processor;
static std::thread *th = NULL;
extern int should_exit;

TEST(SessionManager, Setup)
{
    server = ALLOCATE(Server);
    should_exit = 0;
    processor = ALLOCATE(DownloadProcessor);
    processor->SetUrl("test");
    processor->SetUserName("test");
    processor->SetPassword("test");
    processor->SetWorkGroup("test");
    th = ALLOCATE(std::thread, &Server::Runloop,server);
    sessionManager = server->GetSessionManager();
    EXPECT_EQ(server->Init(sock_path), SMB_SUCCESS);
    EXPECT_EQ(client_socket.Create(), SMB_SUCCESS);
    client_socket.SetNonBlocking(true);
    EXPECT_EQ(client_socket.Connect(sock_path), SMB_SUCCESS);
    while(server->GetSocket() == NULL)
        sleep(1);
    EXPECT_EQ(sessionManager->Init(server), SMB_SUCCESS);
    EXPECT_EQ(sessionManager->IsReady(), true);
    EXPECT_EQ(SMB_SUCCESS, processor->Init(request_id));
    RequestProcessor::SetInstance(processor);
}

TEST(SessionManager, ProcessWrite_ValidSocket)
{
    Packet *packet = ALLOCATE(Packet);
    EXPECT_EQ(SMB_SUCCESS, processor->PacketCreator()->CreatePacket(packet, DOWNLOAD_INIT_REQ, NULL));
    sessionManager->PushResponseAgain(packet);
    EXPECT_EQ(sessionManager->ProcessWriteEvent(), SMB_SUCCESS);
}

TEST(SessionManager, ProcessRead_ValidSocket)
{
    sessionManager->FreeAllRequest();
    Packet *packet = ALLOCATE(Packet);
    EXPECT_EQ(SMB_SUCCESS, processor->PacketCreator()->CreatePacket(packet, DOWNLOAD_INIT_REQ, NULL));
    packet->_complete = false;
    sessionManager->PushRequest(packet);
    EXPECT_EQ(sessionManager->ProcessReadEvent(), SMB_SUCCESS);
    sessionManager->FreeAllRequest();
    packet = ALLOCATE(Packet);
    EXPECT_EQ(SMB_SUCCESS, processor->PacketCreator()->CreatePacket(packet, DOWNLOAD_INIT_REQ, NULL));
    client_socket.Send(packet->_data, packet->GetLength());
    packet->_complete = true;
    sessionManager->PushRequest(packet);
    EXPECT_EQ(sessionManager->ProcessReadEvent(), SMB_SUCCESS);
    sessionManager->FreeAllRequest();
}

TEST(SessionManager, ProcessWrite_InvalidSocket)
{
    client_socket.Close();
    while(RequestProcessor::GetInstance() != NULL)
        sleep(1);
    processor = ALLOCATE(DownloadProcessor);
    RequestProcessor::SetInstance(processor);
    EXPECT_EQ(processor->Init(request_id), SMB_SUCCESS);
    Packet *packet = ALLOCATE(Packet);
    EXPECT_EQ(SMB_SUCCESS, processor->PacketCreator()->CreatePacket(packet, DOWNLOAD_INIT_REQ, NULL));
    sessionManager->PushResponseAgain(packet);
    EXPECT_EQ(sessionManager->ProcessWriteEvent(), SMB_ERROR);
}

TEST(SessionManager, ProcessRead_InvalidSocket)
{
    sessionManager->FreeAllRequest();
    Packet *packet = ALLOCATE(Packet);
    EXPECT_EQ(SMB_SUCCESS, processor->PacketCreator()->CreatePacket(packet, DOWNLOAD_INIT_REQ, NULL));
    packet->_complete = true;
    sessionManager->PushRequest(packet);
    EXPECT_EQ(sessionManager->ProcessReadEvent(), SMB_ERROR);
}

TEST(SessionManager, InitProcessor)
{
    Packet *packet = ALLOCATE(Packet);
    UploadProcessor u_processor;
    RequestProcessor::SetInstance(&u_processor);
    EXPECT_EQ(u_processor.Init(request_id), SMB_SUCCESS);
    EXPECT_EQ(SMB_SUCCESS, u_processor.PacketCreator()->CreatePacket(packet, UPLOAD_INIT_REQ, NULL));
    EXPECT_EQ(SMB_SUCCESS, sessionManager->InitProcessor(packet));
    EXPECT_TRUE(typeid(*RequestProcessor::GetInstance()) == typeid(UploadProcessor));

    OpenDirReqProcessor o_processor;
    RequestProcessor::SetInstance(&o_processor);
    EXPECT_EQ(o_processor.Init(request_id), SMB_SUCCESS);
    EXPECT_EQ(SMB_SUCCESS, o_processor.PacketCreator()->CreatePacket(packet, GET_STRUCTURE_INIT_REQ, NULL));
    EXPECT_EQ(SMB_SUCCESS, sessionManager->InitProcessor(packet));
    EXPECT_TRUE(typeid(*RequestProcessor::GetInstance()) == typeid(OpenDirReqProcessor));

    AddFolderProcessor a_processor;
    RequestProcessor::SetInstance(&a_processor);
    EXPECT_EQ(a_processor.Init(request_id), SMB_SUCCESS);
    EXPECT_EQ(SMB_SUCCESS, a_processor.PacketCreator()->CreatePacket(packet, ADD_FOLDER_INIT_REQ, NULL));
    EXPECT_EQ(SMB_SUCCESS, sessionManager->InitProcessor(packet));
    EXPECT_TRUE(typeid(*RequestProcessor::GetInstance()) == typeid(AddFolderProcessor));

    DeleteProcessor d_processor;
    RequestProcessor::SetInstance(&d_processor);
    EXPECT_EQ(d_processor.Init(request_id), SMB_SUCCESS);
    EXPECT_EQ(SMB_SUCCESS, d_processor.PacketCreator()->CreatePacket(packet, DELETE_INIT_REQ, NULL));
    EXPECT_EQ(SMB_SUCCESS, sessionManager->InitProcessor(packet));
    EXPECT_TRUE(typeid(*RequestProcessor::GetInstance()) == typeid(DeleteProcessor));

    TestConnection t_processor;
    RequestProcessor::SetInstance(&t_processor);
    EXPECT_EQ(t_processor.Init(request_id), SMB_SUCCESS);
    EXPECT_EQ(SMB_SUCCESS, t_processor.PacketCreator()->CreatePacket(packet, TEST_CONNECTION_INIT_REQ, NULL));
    EXPECT_EQ(SMB_SUCCESS, sessionManager->InitProcessor(packet));
    EXPECT_TRUE(typeid(*RequestProcessor::GetInstance()) == typeid(TestConnection));

    processor = ALLOCATE(DownloadProcessor);
    RequestProcessor::SetInstance(processor);
    EXPECT_EQ(processor->Init(request_id), SMB_SUCCESS);
    EXPECT_EQ(SMB_SUCCESS, processor->PacketCreator()->CreatePacket(packet, DOWNLOAD_INIT_REQ, NULL));
    EXPECT_EQ(SMB_SUCCESS, sessionManager->InitProcessor(packet));
    EXPECT_TRUE(typeid(*RequestProcessor::GetInstance()) == typeid(DownloadProcessor));

    EXPECT_EQ(SMB_SUCCESS, processor->PacketCreator()->CreatePacket(packet, DOWNLOAD_END_RESP, NULL));
    EXPECT_EQ(SMB_ERROR, sessionManager->InitProcessor(packet));
}

TEST(SessionManager, ResponseQueue)
{
    sessionManager->FreeAllResponse();
    EXPECT_EQ(true, sessionManager->IsResponseSpaceAvailable());

    for(int i = 0; i < 999; ++i)
    {
        Packet *packet = ALLOCATE(Packet);
        EXPECT_EQ(SMB_SUCCESS, processor->PacketCreator()->CreatePacket(packet, DOWNLOAD_INIT_REQ, NULL));
        sessionManager->PushResponseAgain(packet);
        EXPECT_EQ(true, sessionManager->IsResponseSpaceAvailable());
    }

    Packet *packet = ALLOCATE(Packet);
    EXPECT_EQ(SMB_SUCCESS, processor->PacketCreator()->CreatePacket(packet, DOWNLOAD_INIT_REQ, NULL));
    sessionManager->PushResponseAgain(packet);
    EXPECT_EQ(false, sessionManager->IsResponseSpaceAvailable());
    packet = ALLOCATE(Packet);
    EXPECT_EQ(SMB_SUCCESS, processor->PacketCreator()->CreatePacket(packet, DOWNLOAD_INIT_REQ, NULL));
    sessionManager->PushResponse(packet);
    sessionManager->ProcessWriteEvent();
    EXPECT_EQ(false, sessionManager->IsResponseSpaceAvailable());
    EXPECT_TRUE(sessionManager->PopResponse() != NULL);
    EXPECT_EQ(true, sessionManager->IsResponseSpaceAvailable());
    sessionManager->FreeAllResponse();
}

TEST(SessionManager, RequestQueue)
{
    sessionManager->FreeAllRequest();
    EXPECT_EQ(true, sessionManager->IsRequestSpaceAvailable());

    for(int i = 0; i < 999; ++i)
    {
        Packet *packet = ALLOCATE(Packet);
        EXPECT_EQ(SMB_SUCCESS, processor->PacketCreator()->CreatePacket(packet, DOWNLOAD_INIT_REQ, NULL));
        sessionManager->PushRequest(packet);
        EXPECT_EQ(true, sessionManager->IsRequestSpaceAvailable());
    }

    Packet *packet = ALLOCATE(Packet);
    EXPECT_EQ(SMB_SUCCESS, processor->PacketCreator()->CreatePacket(packet, DOWNLOAD_INIT_REQ, NULL));
    sessionManager->PushRequestAgain(packet);
    EXPECT_EQ(false, sessionManager->IsRequestSpaceAvailable());
    EXPECT_TRUE(sessionManager->GetLastRequest() != NULL);
    for(int i = 0; i < 1000; ++i)
        EXPECT_TRUE(sessionManager->PopRequest() != NULL);
    EXPECT_TRUE(sessionManager->PopRequest() == NULL);
    EXPECT_TRUE(sessionManager->GetLastRequest() == NULL);
    EXPECT_EQ(true, sessionManager->IsRequestSpaceAvailable());
    sessionManager->FreeAllRequest();
}

TEST(SessionManager, TearDown)
{
    should_exit = 1;
    EXPECT_EQ(server->Quit(), SMB_SUCCESS);
    FREE(server);
}

#endif //_DEBUG_