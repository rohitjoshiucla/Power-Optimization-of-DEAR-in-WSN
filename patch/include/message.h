// Copyright (c) 2001-2008, Scalable Network Technologies, Inc.  All Rights Reserved.
//                          6701 Center Drive West
//                          Suite 520
//                          Los Angeles, CA 90045
//                          sales@scalable-networks.com
//
// This source code is licensed, not sold, and is subject to a written
// license agreement.  Among other things, no portion of this source
// code may be copied, transmitted, disclosed, displayed, distributed,
// translated, used as the basis for a derivative work, or used, in
// whole or in part, for any program or purpose other than its intended
// use in compliance with the license agreement as part of the QualNet
// software.  This source code and certain of the algorithms contained
// within it are confidential trade secrets of Scalable Network
// Technologies, Inc. and may not be used as the basis for any other
// software, hardware, product or service.


// /**
// PACKAGE      :: MESSAGE
// DESCRIPTION  :: This file describes the message structure used to implement events
//                 and functions for message operations.
// **/


#ifndef MESSAGE_H
#define MESSAGE_H


#include "main.h"
#include "trace.h"


// Size constants should be multiples of 8/sizeof(double).

// /**
// CONSTANT    :: MSG_MAX_HDR_SIZE             :   512
// DESCRIPTION :: Maximum Header Size
// **/
#define MSG_MAX_HDR_SIZE                           512

// /**
// CONSTANT    :: SMALL_INFO_SPACE_SIZE        :   112
// DESCRIPTION :: Size of small Info field.  Should be larger
//                than all commonly used info field data structures,
//                especially PropTxInfo and PropRxInfo.
// **/
#define SMALL_INFO_SPACE_SIZE                      112

// /**
// CONSTANT    :: MSG_PAYLOAD_LIST_MAX         :   1000
// DESCRIPTION :: Maximum message payload list
// **/
#define MSG_PAYLOAD_LIST_MAX                       1000

// /**
// CONSTANT    :: MAX_CACHED_PAYLOAD_SIZE      :   1024
// DESCRIPTION :: Maximum cached payload size
// **/
#define MAX_CACHED_PAYLOAD_SIZE                    1024

// /**
// CONSTANT    :: MSG_INFO_LIST_MAX            :   1000
// DESCRIPTION :: Maximum message info list
// **/
#define MSG_INFO_LIST_MAX                          1000

#ifndef ADDON_BOEINGFCS
// /**
// CONSTANT    :: MAX_INFO_FIELDS              :   10
// DESCRIPTION :: Maximum number of info fields
// **/
#define MAX_INFO_FIELDS                            10

#else
// /**
// CONSTANT    :: MAX_INFO_FIELDS              :   12
// DESCRIPTION :: Maximum number of info fields
// **/
#define MAX_INFO_FIELDS                            12
#endif

// Arbitrary constant to support packet trace facility

// /**
// CONSTANT    :: MAX_HEADERS                  :   10
// DESCRIPTION :: Maximum number of headers
// **/
#define MAX_HEADERS                                10


// /**
// MACRO       :: MESSAGE_AddVirtualPayload
// DESCRIPTION :: Defines the MESSAGE_AddVirtualPayload macro
//                to add virual payload to a message
// **/
#define MESSAGE_AddVirtualPayload(node, msg, payLoadSize) \
        (msg->virtualPayLoadSize += payLoadSize)



// /**
// MACRO       :: MESSAGE_RemoveVirtualPayload
// DESCRIPTION :: Defines the MESSAGE_RemoveVirtualPayload macro
//                to remove virual payload from a message
// **/
#define MESSAGE_RemoveVirtualPayload(node, msg, payLoadSize) \
        (msg->virtualPayLoadSize -= payLoadSize)

// /**
// MACRO       :: MESSAGE_ReturnPacket
// DESCRIPTION :: Returns a pointer to the packet of the message
// **/
#define MESSAGE_ReturnPacket(msg) (msg->packet)

// /**
// MACRO       :: MESSAGE_ReturnPacketSize
// DESCRIPTION :: Returns the packet size of the message which
//                includes the actula packet size and the virtual
//                payload size.
// **/
#define MESSAGE_ReturnPacketSize(msg) \
        (msg->packetSize + msg->virtualPayLoadSize)

// /**
// MACRO       :: MESSAGE_ReturnActualPacketSize
// DESCRIPTION :: Returns the actual packet size of the message
// **/
#define MESSAGE_ReturnActualPacketSize(msg) (msg->packetSize)

// /**
// MACRO       :: MESSAGE_ReturnVirtualPacketSize
// DESCRIPTION :: Returns the virtual payload size
// **/
#define MESSAGE_ReturnVirtualPacketSize(msg) (msg->virtualPayLoadSize)


// Given the layer and protocol fields,  this macro will
// form the a layerType field of the Message structure.

// /**
// MACRO       :: MESSAGE_SetLayer
// DESCRIPTION :: Sets the layer of a message
// **/
#define MESSAGE_SetLayer(msg, layer, protocol) \
        (msg)->layerType = (layer); \
        (msg)->protocolType = (protocol);


// The following two functions will retrieve the actual layer and
// protocol type fileds from the layerType variable

// /**
// MACRO       :: MESSAGE_GetLayer
// DESCRIPTION :: Returns the layer associated with a message
// **/
#define MESSAGE_GetLayer(msg) ((msg)->layerType)

// /**
// MACRO       :: MESSAGE_GetProtocol
// DESCRIPTION :: Returns the protocol associated with a message
// **/
#define MESSAGE_GetProtocol(msg) ((msg)->protocolType)

// /**
// MACRO       :: MESSAGE_SetEvent
// DESCRIPTION :: Set the event associated with a message
// **/
#define MESSAGE_SetEvent(msg, event) (msg->eventType = (event))

// /**
// MACRO       :: MESSAGE_GetEvent
// DESCRIPTION :: Returns the event type of a message
// **/
#define MESSAGE_GetEvent(msg) (msg->eventType)

// /**
// MACRO       :: MESSAGE_SetInstanceId
// DESCRIPTION :: Sets the instanceId of a message
// **/
#define MESSAGE_SetInstanceId(msg, instance) \
   (msg)->instanceId = (instance);

// /**
// MACRO       :: MESSAGE_GetInstanceId
// DESCRIPTION :: Returns the instanceId of a message
// **/
#define MESSAGE_GetInstanceId(msg) ((msg)->instanceId)

// /**
// MACRO       :: MESSAGE_GetPacketCreationTime
// DESCRIPTION :: Returns the packet creation time
// **/
#define MESSAGE_GetPacketCreationTime(msg) ((msg)->packetCreationTime)


// /**
// STRUCT      :: MessageInfoHeader
// DESCRIPTION :: This is a structure which contains information
//                about a info field.
// **/
typedef struct message_info_header_str
{
    unsigned short infoType; // type of the info field
    unsigned int infoSize; // size of buffer pointed to by "info" variable
    char* info;              // pointer to buffer for holding info
} MessageInfoHeader;
typedef struct message_info_bookkeeping_str
{
    int msgSeqNum; // Sequence number of the message
    int fragSize;  // Fragment size.
    int infoLowerLimit; // starting index for the info field.
    int infoUpperLimit; // ending index for the info field + 1
} MessageInfoBookKeeping;

// /**
// ENUM        :: MessageInfoType
// DESCRIPTION :: Type of information in the info field. One message can only
//                have up to one info field with a specific info type.
// **/
typedef enum message_info_type_str
{
    INFO_TYPE_UNDEFINED = 0,  // an empty info field.
    INFO_TYPE_DEFAULT = 1,    // default info type used in situations where
                              // specific type is given to the info field.
    INFO_TYPE_AbstractCFPropagation, // type for abstract contention free
                                     // propagation info field.
    INFO_TYPE_AppName,      // Pass the App name down to IP layer
    INFO_TYPE_StatCategoryName,
    INFO_TYPE_DscpName,
    INFO_TYPE_SourceAddr,
    INFO_TYPE_SourcePort,
    INFO_TYPE_DestAddr,
    INFO_TYPE_DestPort,
    INFO_TYPE_DeliveredPacketTtlTotal, // Pass from IP to APP for session-based hop counts
    INFO_TYPE_IpTimeStamp,
    INFO_TYPE_DataSize,
#ifdef ADDON_NGCNMS
    INFO_TYPE_SendTime,
    INFO_TYPE_SubnetId,
#endif
#ifdef ADDON_BOEINGFCS
    INFO_TYPE_VoiceData,
    INFO_TYPE_QNHeaderInfo,
    INFO_TYPE_MacCesUsapHeaderInfo,
    INFO_TYPE_MacCesSincgarsPrecedence,
    INFO_TYPE_RoutingCesSdrDuplicate,
    INFO_TYPE_MacCesEplrsCTU,
#endif
    INFO_TYPE_TransportOverhead,
    INFO_TYPE_NetworkOverhead,
    INFO_TYPE_MacOverhead,
    INFO_TYPE_PhyOverhead,
    INFO_TYPE_ALE_ChannelIndex,
    INFO_TYPE_PhyIndex,
    INFO_TYPE_SuperAppUDPData,
    INFO_TYPE_OriginalInsertTime,
    INFO_TYPE_ExternalData,
    INFO_TYPE_UdpFragData,
    INFO_TYPE_AppStatsDbContent,
    INFO_TYPE_TransStatsDbContent,
    INFO_TYPE_NetStatsDbContent,
    INFO_TYPE_QueueStatsDbContent,
    INFO_TYPE_ForwardTcpHeader,
    INFO_TYPE_DearNextHop
} MessageInfoType;


// Generic Message received/sent by any layer in QualNet
// typedef to Message in main.h

// /**
// STRUCT      :: message_str
// DESCRIPTION :: This is the main data strucure that represents a
//                discrete event in qualnet. Typedefed to Message in
//                main.h, this is used to represent timer as well as
//                to simulate actual sending of packets across the network.
// **/
struct message_str
{
    Message*  next; // For kernel use only.

    // The following fields are simulation related information.

    short layerType;    // Layer which will receive the message
    short protocolType; // Protocol which will receive the message
                        // in the layer.
    short instanceId;   // Which instance to give message to (for multiple
                        // copies of a protocol or application).
    short eventType;    // Message's Event type.

    unsigned int naturalOrder;  // used to maintain natural ordering
                                // for events at same time & node

    char error;         // Does the packet contain errors?

    char    mtPendingFree;      // (boolean) When message is sent to remote
                                // paritions the allocation/recyling/free
                                // lice cycle has to perform different steps.
    unsigned char    mtPendingSend;      // (count) While message is pending send
                                // via worker thread.
                                // NOTE, that a count of
                                // MESSAGE_MT_PENDING_SEND_INFINITE
                                // prevents wrap around (but leaks mem)
                                // This coutner must _ONLY_ be incremented by
                                // partition thread
    unsigned char    mtPendingSent;      // (count) As worker thread sends this
                                // message out this coutner will count up.
                                // The message can be freed once the Pending
                                // coutners are equal.
                                // This coutner must _ONLY_ be incremented by
                                // the worker thread.
                                // NOTE, that a count of
                                // MESSAGE_MT_PENDING_SEND_INFINITE
                                // prevents wrap around (but leaks mem)
    char    mtWasMT;            // Messages handed to the worker thread
                                // can't participate in the message recycling.
                                // As the partitionData->msgFreeList isn't
                                // locked.



    NodeId    nodeId;       // used only by the parallel code, otherwise ignored.
    clocktype eventTime;    // used only by the parallel code, otherwise ignored.
    clocktype eot;          // used only by the parallel code, otherwise ignored.
    int sourcePartitionId;  // used only by the parallel code, otherwise ignored.


    // An array of fields carries any information that needs to be
    // transported between layers.
    // It can be used for carrying data for messages which are not packets.
    // It can also be used to carry additional information for messages
    // which are packets.

    //MessageInfoHeader infoArray[MAX_INFO_FIELDS];

    double smallInfoSpace[SMALL_INFO_SPACE_SIZE / sizeof(double)];


    // The following two fields are only used when the message is being
    // used to simulate an actual packt.

    // PacketSize field will indicate the simulated packet size. As a
    // packet moves up or down between the various layers, this field
    // will be updated to reflect the addition or deletion of the various
    // layer headers. For most purposes this does not have to be modified
    // by the users as it will be controlled through the following
    // functions: MESSAGE_AllocPacket, MESSAGE_AddHeader,
    // MESSAGE_RemoveHeader

    int packetSize;

    // The "packet" as seen by a particular layer for messages
    // which are used to simulate packets.

    char *packet;



    // This field is used for messages used to send packets. It is
    // used for internal error checking and should not be used by users.

    char *payLoad;

    // Size of the buffer pointed to by payLoad.
    // This field should never be changed by the user.

    int payLoadSize;


    // Size of additional payload which should affect the
    // transmission delay of the packet, but need not be stored
    // in the actual char *payLoad

    int virtualPayLoadSize;

    // If this is a packet, its the creation time.
    clocktype packetCreationTime;

    clocktype pktNetworkSendTime;
    BOOL cancelled;

    // Extra fields to support packet trace facility.
    // Will slow things down.
    NodeAddress originatingNodeId;
    int sequenceNumber;
    int originatingProtocol;
    int numberOfHeaders;
    int headerProtocols[MAX_HEADERS];
    int headerSizes[MAX_HEADERS];
    // Added field for SatCom parallel mode
    // holds the hw address of relay ground
    // node to prevent message repeat
    NodeAddress relayNodeAddr;

    std::vector<MessageInfoHeader> infoArray;
    std::vector<MessageInfoBookKeeping> infoBookKeeping;
// MILITARY_RADIOS_LIB
    int subChannelIndex;  // for multiple frequencies per interface
// MILITARY_RADIOS_LIB
    // Users should not modify anything above this line.
};

// mtPendingSend count that prevents wrap around - will leak, but won't crash.
#define MESSAGE_MT_PENDING_SEND_INFINITE 255

// /**
// API       :: MESSAGE_PrintMessage
// LAYER     :: ANY LAYER
// PURPOSE      Print out the contents of the message for debugging purposes.
// PARAMETERS ::
// + node    :  Node*     : node which is sending message
// + msg     :  Message*  : message to be printed
// RETURN    :: void : NULL
// **/
void MESSAGE_PrintMessage(Message* msg);

// /**
// API       :: MESSAGE_Send
// LAYER     :: ANY LAYER
// PURPOSE   :: Function call used to send a message within QualNet. When
//              a message is sent using this mechanism, only the pointer
//              to the message is actually sent through the system. So the
//              user has to be careful not to do anything with the content
//              of the pointer once MESSAGE_Send has been called.
// PARAMETERS ::
// + node    :  Node*     : node which is sending message
// + msg     :  Message*  : message to be delivered
// + delay   :  clocktype : delay suffered by this message.
// RETURN    :: void : NULL
// **/
void MESSAGE_Send(Node *node, Message *msg, clocktype delay);

// /**
// API       :: MESSAGE_RemoteSend
// LAYER     :: ANY_LAYER
// PURPOSE   :: Function used to send a message to a node that might be
//              on a remote partition.  The system will make a shallow copy
//              of the message, meaning it can't contain any pointers in
//              the info field or the packet itself.  This function is very
//              unsafe.  If you use it, your program will probably crash.
//              Only I can use it.
//
// PARAMETERS ::
// + node       :  Node*     : node which is sending message
// + destNodeId :  NodeId    : nodeId of receiving node
// + msg        :  Message*  : message to be delivered
// + delay      :  clocktype : delay suffered by this message.
// RETURN    :: void : NULL
// **/
void MESSAGE_RemoteSend(Node*     node,
                        NodeId    destNodeId,
                        Message*  msg,
                        clocktype delay);

// /**
// API       :: MESSAGE_RouteReceivedRemoteEvent
// LAYER     :: ANY_LAYER
// PURPOSE   :: Counterpart to MESSAGE_RemoteSend, this function allows
//              models that send remote messages to provide special handling
//              for them on the receiving partition.  This function is
//              called in real time as the messages are received, so must
//              be used carefully.
//
// PARAMETERS ::
// + node       :  Node*     : node which is sending message
// + msg        :  Message*  : message to be delivered
// RETURN    :: void : NULL
// **/
void MESSAGE_RouteReceivedRemoteEvent(Node*    node,
                                      Message* msg);

// /**
// API       :: MESSAGE_CancelSelfMsg
// LAYER     :: ANY LAYER
// PURPOSE   :: Function call used to cancel a event message in the
//              QualNet scheduler.  The Message must be a self message
//              (timer) .i.e. a message a node sent to itself.  The
//              msgToCancelPtr must a pointer to the original message
//              that needs to be canceled.
// PARAMETERS ::
// + node    :  Node*   : node which is sending message
// + msgToCancelPtr     :  Message* : message to be cancelled
// RETURN    :: void : NULL
// **/
static void MESSAGE_CancelSelfMsg(Node *node, Message *msgToCancelPtr){
   msgToCancelPtr->cancelled = TRUE;
}

static void MESSAGE_SetLooseScheduling (Message *msg){
    msg->eventTime = -msg->eventTime;
#ifdef ADDON_BOEINGFCS
    if (msg->eventTime == 0) // j.o - difference in MERGE
    {
        msg->eventTime = -1;
    }
#endif
}

static bool MESSAGE_AllowLooseScheduling (Message *msg){
    return (msg->eventTime < 0);
}

// /**
// API        :: MESSAGE_Alloc
// LAYER      :: ANY LAYER
// PURPOSE    :: Allocate a new Message structure. This is called when a
//               new message has to be sent through the system. The last
//               three parameters indicate the layerType, protocol and the
//               eventType that will be set for this message.
// PARAMETERS ::
// + node     :  Node* : node which is allocating message
// + layerType:  int : Layer type to be set for this message
// + protocol :  int : Protocol to be set for this message
// + eventType:  int : event type to be set for this message
// RETURN     :: Message* : Pointer to allocated message structure
// **/
Message* MESSAGE_Alloc(
    Node *node, int layerType, int protocol, int eventType);

// /**
// API        :: MESSAGE_Alloc
// LAYER      :: ANY LAYER
// PURPOSE    :: Allocate a new Message structure. This is called when a
//               new message has to be sent through the system. The last
//               three parameters indicate the layerType, protocol and the
//               eventType that will be set for this message.
// PARAMETERS ::
// + partition:  PartitionData* : partition that is allocating message
// + layerType:  int : Layer type to be set for this message
// + protocol :  int : Protocol to be set for this message
// + eventType:  int : event type to be set for this message
// RETURN     :: Message* : Pointer to allocated message structure
// **/
Message* MESSAGE_Alloc(
    PartitionData *partition, int layerType, int protocol, int eventType,
    bool isMT = false);

// /**
// API        :: MESSAGE_AllocMT
// LAYER      :: ANY LAYER
// PURPOSE    :: Mutli-thread safe version of MESSAGE_Alloc for use
//               by worker threads.
// PARAMETERS ::
// + partition:  PartitionData* : partition that is allocating message
// + layerType:  int : Layer type to be set for this message
// + protocol :  int : Protocol to be set for this message
// + eventType:  int : event type to be set for this message
// RETURN     :: Message* : Pointer to allocated message structure
// **/
Message* MESSAGE_AllocMT(PartitionData *partition,
                       int layerType,
                       int protocol,
                       int eventType);

// /**
// API       :: MESSAGE_InfoFieldAlloc
// LAYER     :: ANY LAYER
// PURPOSE   :: Allocate space for one "info" field
// PARAMETERS ::
// + node    :  Node* : node which is allocating the space.
// + infoSize:  int : size of the space to be allocated
// RETURN    :: char* : pointer to the allocated space.
// **/
char* MESSAGE_InfoFieldAlloc(Node *node, int infoSize, bool isMT = false);

// /**
// API       :: MESSAGE_InfoFieldAlloc
// LAYER     :: ANY LAYER
// PURPOSE   :: Allocate space for one "info" field
// PARAMETERS ::
// + partition: PartitionData* : partition which is allocating the space.
// + infoSize:  int : size of the space to be allocated
// RETURN    :: char* : pointer to the allocated space.
// **/
char* MESSAGE_InfoFieldAlloc(PartitionData *partition, int infoSize,
                             bool isMT = false);

// /**
// API       :: MESSAGE_InfoFieldFree
// LAYER     :: ANY LAYER
// PURPOSE   :: Free space for one "info" field
// PARAMETERS ::
// + node    :  Node* : node which is allocating the space.
// + hdrPtr  :  MessageInfoHeader* : pointer to the "info" field
// RETURN    :: void : NULL
// **/
void MESSAGE_InfoFieldFree(Node *node, MessageInfoHeader* hdrPtr,
                           bool isMT = false);

// API       :: MESSAGE_InfoFieldFreeMT
// LAYER     :: ANY LAYER
// PURPOSE   :: Multithread safe version of MESSAGE_InfoFieldFree ()
// PARAMETERS ::
// + partition:  PartitionData* : partition which is allocating the space.
// + hdrPtr  :  MessageInfoHeader* : pointer to the "info" field
// RETURN    :: void : NULL
// **/
void MESSAGE_InfoFieldFreeMT(PartitionData *partition, MessageInfoHeader* hdrPtr);

// API       :: MESSAGE_InfoFieldFree
// LAYER     :: ANY LAYER
// PURPOSE   :: Free space for one "info" field
// PARAMETERS ::
// + partition:  PartitionData* : partition which is allocating the space.
// + hdrPtr  :  MessageInfoHeader* : pointer to the "info" field
// RETURN    :: void : NULL
// **/
void MESSAGE_InfoFieldFree(PartitionData *partition,
                           MessageInfoHeader* hdrPtr, bool isMT);

// /**
// API       :: MESSAGE_AddInfo
// LAYER     :: ANY LAYER
// PURPOSE   :: Allocate one "info" field with given info type for the
//              message. This function is used for the delivery of data
//              for messages which are NOT packets as well as the delivery
//              of extra information for messages which are packets. If a
//              "info" field with the same info type has previously been
//              allocated for the message, it will be replaced by a new
//              "info" field with the specified size. Once this function
//              has been called, MESSAGE_ReturnInfo function can be used
//              to get a pointer to the allocated space for the info field
//              in the message structure.
// PARAMETERS ::
// + node    :  Node* : node which is allocating the info field.
// + msg     :  Message* : message for which "info" field
//                         has to be allocated
// + infoSize:  int : size of the "info" field to be allocated
// + infoType:  unsigned short : type of the "info" field to be allocated.
// RETURN    :: char* : Pointer to the added info field
// **/
char* MESSAGE_AddInfo(Node *node,
                      Message *msg,
                      int infoSize,
                      unsigned short infoType);

// /**
// API       :: MESSAGE_AddInfo
// LAYER     :: ANY LAYER
// PURPOSE   :: Allocate one "info" field with given info type for the
//              message. This function is used for the delivery of data
//              for messages which are NOT packets as well as the delivery
//              of extra information for messages which are packets. If a
//              "info" field with the same info type has previously been
//              allocated for the message, it will be replaced by a new
//              "info" field with the specified size. Once this function
//              has been called, MESSAGE_ReturnInfo function can be used
//              to get a pointer to the allocated space for the info field
//              in the message structure.
// PARAMETERS ::
// + partition:  PartitionData* : partition which is allocating the info field.
// + msg     :  Message* : message for which "info" field
//                         has to be allocated
// + infoSize:  int : size of the "info" field to be allocated
// + infoType:  unsigned short : type of the "info" field to be allocated.
// RETURN    :: char* : Pointer to the added info field
// **/
char* MESSAGE_AddInfo(PartitionData *partition,
                      Message *msg,
                      int infoSize,
                      unsigned short infoType);

// /**
// API       :: MESSAGE_RemoveInfo
// LAYER     :: ANY LAYER
// PURPOSE   :: Remove one "info" field with given info type from the
//              info array of the message.
// PARAMETERS ::
// + node    :  Node* : node which is removing info field.
// + msg     :  Message* : message for which "info" field
//                         has to be removed
// + infoType:  unsigned short : type of the "info" field to be removed.
// RETURN    :: void : NULL
// **/
void MESSAGE_RemoveInfo(Node *node, Message *msg, unsigned short infoType);

// /**
// API       :: MESSAGE_InfoAlloc
// LAYER     :: ANY LAYER
// PURPOSE   :: Allocate the default "info" field for the message. This
//              function is similar to MESSAGE_AddInfo. The difference
//              is that it assumes the type of the info field to be
//              allocated is INFO_TYPE_DEFAULT.
// PARAMETERS ::
// + node    :  Node* : node which is allocating the info field.
// + msg     :  Message* : message for which "info" field
//                         has to be allocated
// + infoSize:  int : size of the "info" field to be allocated
// RETURN    :: char * :
// **/
static char * MESSAGE_InfoAlloc(Node *node, Message *msg, int infoSize)
{
    return (MESSAGE_AddInfo(node, msg, infoSize, (unsigned short) INFO_TYPE_DEFAULT));
}

// /**
// API       :: MESSAGE_InfoAlloc
// LAYER     :: ANY LAYER
// PURPOSE   :: Allocate the default "info" field for the message. This
//              function is similar to MESSAGE_AddInfo. The difference
//              is that it assumes the type of the info field to be
//              allocated is INFO_TYPE_DEFAULT.
// PARAMETERS ::
// + partition:  PartitionData* : partition which is allocating the info field.
// + msg     :  Message* : message for which "info" field
//                         has to be allocated
// + infoSize:  int : size of the "info" field to be allocated
// RETURN    :: char * :
// **/
static char * MESSAGE_InfoAlloc(PartitionData *partition, Message *msg, int infoSize)
{
    return (MESSAGE_AddInfo(partition, msg, infoSize, (unsigned short) INFO_TYPE_DEFAULT));
}

// /**
// API       :: MESSAGE_ReturnInfoSize
// LAYER     :: ANY LAYER
// PURPOSE   :: Returns the size of a "info" field with given info type
//              in the info array of the message.
// PARAMETERS ::
// + msg     :  Message* : message for which "info" field
//                         has to be returned
// + infoType:  unsigned short : type of the "info" field.
// + fragmentNumber: int: Location of the fragment in the TCP packet
// RETURN    :: int : size of the info field.
// **/
static int MESSAGE_ReturnInfoSize(Message *msg,
                                  unsigned short infoType,
                                  int fragmentNumber)
{
    int i;
    int infoLowerLimit =
        msg->infoBookKeeping.at(fragmentNumber).infoLowerLimit;
    int infoUpperLimit =
        msg->infoBookKeeping.at(fragmentNumber).infoUpperLimit;

    for (i = infoLowerLimit; i < infoUpperLimit; i ++)
    {
        if (msg->infoArray[i].infoType == infoType)
        {
            return msg->infoArray[i].infoSize;
        }
    }

    return 0;
}
// /**
// API       :: MESSAGE_ReturnInfoSize
// LAYER     :: ANY LAYER
// PURPOSE   :: Returns the size of a "info" field with given info type
//              in the info array of the message.
// PARAMETERS ::
// + msg     :  Message* : message for which "info" field
//                         has to be returned
// + infoType:  unsigned short : type of the "info" field.
// RETURN    :: int : size of the info field.
// **/
static int MESSAGE_ReturnInfoSize(const Message* msg,
                                  unsigned short infoType = INFO_TYPE_DEFAULT)
{
    unsigned int i;

    if (msg->infoArray.size() > 0)
    {
        /*if (infoType == INFO_TYPE_DEFAULT)
        {
            return msg->infoArray[0].infoSize;
        }*/


        for (i = 0; i < msg->infoArray.size(); i ++)
        {
            MessageInfoHeader* hdrPtr = (MessageInfoHeader*)&(msg->infoArray[i]);
            if (hdrPtr->infoType == infoType)
            {
                return hdrPtr->infoSize;
            }
        }
    }

    return 0;
}

// /**
// API       :: MESSAGE_ReturnInfo
// LAYER     :: ANY LAYER
// PURPOSE   :: Returns a pointer to the "info" field with given info type
//              in the info array of the message.
// PARAMETERS ::
// + msg     :  Message* : message for which "info" field
//                         has to be returned
// + infoType:  unsigned short : type of the "info" field to be returned.
// RETURN    :: char* : Pointer to the "info" field with given type.
//                      NULL if not found.
// **/
static char* MESSAGE_ReturnInfo(const Message *msg,
                                unsigned short infoType = INFO_TYPE_DEFAULT)
{
    unsigned int i;

    if (msg->infoArray.size() > 0)
    {
        /*if (infoType == INFO_TYPE_DEFAULT)
        {
            return msg->infoArray[0].info;
        }*/

        for (i = 0; i < msg->infoArray.size(); i ++)
        {
            MessageInfoHeader* hdrPtr = (MessageInfoHeader*)&(msg->infoArray[i]);
            if (hdrPtr->infoType == infoType)
            {
                return hdrPtr->info;
            }
        }
    }
    return NULL;
}

// /**
// API       :: MESSAGE_CopyInfo
// LAYER     :: ANY LAYER
// PURPOSE   :: Copy the "info" fields of the source message to
//              the destination message.
// PARAMETERS ::
// + node    :  Node*    : Node which is copying the info fields
// + dsgMsg  :  Message* : Destination message
// + srcMsg  :  Message* : Source message
// RETURN    :: void : NULL
// **/
void MESSAGE_CopyInfo(Node *node, Message *dstMsg, Message *srcMsg);

// /**
// API       :: MESSAGE_CopyInfo
// LAYER     :: ANY LAYER
// PURPOSE   :: Copy the "info" fields of the source info header to
//              the destination message.
// PARAMETERS ::
// + node    :  Node*    : Node which is copying the info fields
// + dsgMsg  :  Message* : Destination message
// + srcInfo  :  MessageInfoHeader* : Info Header structure
// RETURN    :: void : NULL
// **/
void MESSAGE_CopyInfo(Node *node, Message *dstMsg, std::vector<MessageInfoHeader*> srcInfo);

// /**
// /**
// API       :: MESSAGE_ReturnInfo
// LAYER     :: ANY LAYER
// PURPOSE   :: Returns a pointer to the "info" field with given info type
//              in the info array of the message.
// PARAMETERS ::
// + msg     :  Message* : message for which "info" field
//                         has to be returned
// + infoType:  unsigned short : type of the "info" field to be returned.
// + fragmentNumber: int: Location of the fragment in the TCP packet.
// RETURN    :: char* : Pointer to the "info" field with given type.
//                      NULL if not found.
// **/
static char* MESSAGE_ReturnInfo(const Message *msg,
                                unsigned short infoType,
                                int fragmentNumber)
{
    int i;
    int infoLowerLimit =
        msg->infoBookKeeping.at(fragmentNumber).infoLowerLimit;
    int infoUpperLimit =
        msg->infoBookKeeping.at(fragmentNumber).infoUpperLimit;

    for (i = infoLowerLimit ; i < infoUpperLimit; i ++)
    {
        if (msg->infoArray[i].infoType == infoType)
        {
            return msg->infoArray[i].info;
        }
    }

    return NULL;
}


// /**
// API       :: MESSAGE_FragmentPacket
// LAYER     :: ANY LAYER
// PURPOSE   :: Fragment one packet into multiple fragments
//              Note: The original packet will be freed in this function.
//                    The array for storing pointers to fragments will be
//                    dynamically allocated. The caller of this function
//                    will need to free the memory.
// PARAMETERS ::
// + node    :  Node* : node which is fragmenting the packet
// + msg     :  Message* : The packet to be fragmented
// + fragUnit:  int : The unit size for fragmenting the packet
// + fragList:  Message*** : A list of fragments created.
// + numFrags:  int* : Number of fragments in the fragment list.
// + protocolType : TraceProtocolType : Protocol type for packet tracing.
// RETURN    :: void : NULL
// **/
void MESSAGE_FragmentPacket(
         Node* node,
         Message* msg,
         int fragUnit,
         Message*** fragList,
         int* numFrags,
         TraceProtocolType protocolType);

// /**
// API       :: MESSAGE_ReassemblePacket
// LAYER     :: ANY LAYER
// PURPOSE   :: Reassemble multiple fragments into one packet
//              Note: All the fragments will be freed in this function.
// PARAMETERS ::
// + node    :  Node* : node which is assembling the packet
// + fragList:  Message** : A list of fragments.
// + numFrags:  int : Number of fragments in the fragment list.
// + protocolType : TraceProtocolType : Protocol type for packet tracing.
// RETURN    :: Message* : The reassembled packet.
// **/
Message* MESSAGE_ReassemblePacket(
             Node* node,
             Message** fragList,
             int numFrags,
             TraceProtocolType protocolType);

// /**
// FUNCTION   :: MESSAGE_PackMessage
// LAYER      :: MAC
// PURPOSE    :: Pack a list of messages to be one message structure
//               Whole contents of the list messages will be put as
//               payload of the new message. So the packet size of
//               the new message cannot be directly used now.
//               The original lis of msgs will be freed.
// PARAMETERS ::
// + node      : Node*    : Pointer to node.
// + msgList   : Message* : Pointer to a list of messages
// + origProtocol: TraceProtocolType : Protocol allocating this packet
// + actualPktSize : int* : For return sum of packet size of msgs in list
// RETURN     :: Message* : The super msg contains a list of msgs as payload
// **/
Message* MESSAGE_PackMessage(Node* node,
                             Message* msgList,
                             TraceProtocolType origProtocol,
                             int* actualPktSize);

// /**
// FUNCTION   :: MESSAGE_UnpackMessage
// LAYER      :: MAC
// PURPOSE    :: Unpack a super message to the original list of messages
//               The list of messages were stored as payload of this super
//               message.
// PARAMETERS ::
// + node      : Node*    : Pointer to node.
// + msg       : Message* : Pointer to the supper msg contains list of msgs
// + copyInfo  : BOOL     : Whether copy info from old msg to first msg
// + freeOld   : BOOL     : Whether the original message should be freed
// RETURN     :: Message* : A list of messages unpacked from original msg
// **/
Message* MESSAGE_UnpackMessage(Node* node,
                               Message* msg,
                               BOOL copyInfo,
                               BOOL freeOld);

// /**
// API       :: MESSAGE_PacketAlloc
// LAYER     :: ANY LAYER
// PURPOSE   :: Allocate the "payLoad" field for the packet to be delivered.
//              Add additional free space in front of the packet for
//              headers that might be added to the packet. This function
//              can be called from the application layer or anywhere else
//              (e.g TCP, IP) that a packet may originiate from. The
//              "packetSize" variable will be set to the "packetSize"
//              parameter specified in the function call. Once this function
//              has been called the "packet" variable in the message
//              structure can be used to access this space.
// PARAMETERS ::
// + node    :  Node* : node which is allocating the packet
// + msg     :  Message* : message for which packet has to be allocated
// + packetSize: int : size of the packet to be allocated
// + originalProtocol: TraceProtocolType : Protocol allocating this packet
// RETURN    :: void : NULL
// **/
void MESSAGE_PacketAlloc(Node *node,
                         Message *msg,
                         int packetSize,
                         TraceProtocolType originalProtocol);


// /**
// API       :: MESSAGE_PacketAlloc
// LAYER     :: ANY LAYER
// PURPOSE   :: Allocate the "payLoad" field for the packet to be delivered.
//              Add additional free space in front of the packet for
//              headers that might be added to the packet. This function
//              can be called from the application layer or anywhere else
//              (e.g TCP, IP) that a packet may originiate from. The
//              "packetSize" variable will be set to the "packetSize"
//              parameter specified in the function call. Once this function
//              has been called the "packet" variable in the message
//              structure can be used to access this space.
// PARAMETERS ::
// + partition:  PartitionData* : artition which is allocating the packet
// + msg     :  Message* : message for which packet has to be allocated
// + packetSize: int : size of the packet to be allocated
// + originalProtocol: TraceProtocolType : Protocol allocating this packet
// + isMT    : bool   : Is this packet being created from a worker thread
// RETURN    :: void : NULL
// **/
void MESSAGE_PacketAlloc(PartitionData *partition,
                         Message *msg,
                         int packetSize,
                         TraceProtocolType originalProtocol,
                         bool isMT);

// /**
// API       :: MESSAGE_AddHeader
// LAYER     :: ANY LAYER
// PURPOSE   :: This function is called to reserve additional space for a
//              header of size "hdrSize" for the packet enclosed in the
//              message. The "packetSize" variable in the message structure
//              will be increased by "hdrSize".
//              Since the header has to be prepended to the current packet,
//              after this function is called the "packet" variable in the
//              message structure will point the space occupied by this new
//              header.
// PARAMETERS ::
// + node    : Node*    : node which is adding header
// + msg     : Message* : message for which header has to be added
// + hdrSize : int      : size of the header to be added
// + traceProtocol: TraceProtocolType : protocol name, from trace.h
// RETURN    :: void : NULL
// **/
void MESSAGE_AddHeader(Node *node,
                       Message *msg,
                       int hdrSize,
                       TraceProtocolType traceProtocol);

// /**
// API       :: MESSAGE_RemoveHeader
// LAYER     :: ANY LAYER
// PURPOSE   :: This function is called to remove a header from the packet.
//              The "packetSize" variable in the message will be decreased
//              by "hdrSize".
// PARAMETERS ::
// + node    :  Node*       : node which is removing the packet header
// + msg     :  Message*    : message for which header is being removed
// + hdrSize :  int         : size of the header being removed
// + traceProtocol: TraceProtocolType : protocol removing this header.
// RETURN    :: void : NULL
// **/
void MESSAGE_RemoveHeader(Node *node,
                          Message *msg,
                          int hdrSize,
                          TraceProtocolType traceProtocol);

// /**
// API       :: MESSAGE_ExpandPacket
// LAYER     :: ANY LAYER
// PURPOSE   :: Expand packet by a specified size
// PARAMETERS ::
// + node    :  Node* : node which is expanding the packet
// + msg     :  Message* : message which is to be expanded
// + size    :  int : size to expand
// RETURN    :: void : NULL
// **/
void MESSAGE_ExpandPacket(Node *node,
                          Message *msg,
                          int size);

// /**
// API       :: MESSAGE_ShrinkPacket
// LAYER     :: ANY LAYER
// PURPOSE   :: This function is called to shrink
//              packet by a specified size.
// PARAMETERS ::
// + node    :  Node* : node which is shrinking packet
// + msg     :  Message* : message whose packet is be shrinked
// + size    :  int : size to shrink
// RETURN    :: void : NULL
// **/
void MESSAGE_ShrinkPacket(Node *node,
                          Message *msg,
                          int size);

// /**
// API       :: MESSAGE_Free
// LAYER     :: ANY LAYER
// PURPOSE   :: When the message is no longer needed it
//              can be freed. Firstly the "payLoad" and "info" fields
//              of the message are freed. Then the message itself is freed.
//              It is important to remember to free the message. Otherwise
//              there will nasty memory leaks in the program.
// PARAMETERS ::
// + partition:  PartitionData*    : partition which is freeing the message
// + msg     :  Message* : message which has to be freed
// RETURN    :: void : NULL
// **/
void MESSAGE_Free(PartitionData *partition, Message *msg);

/*
 * FUNCTION     MESSAGE_FreeMT
 * PURPOSE      Multithread safe version of MESSAGE_Free
 *
 * Parameters:
 *    partition:  partition which is freeing the message
 *    msg:        message which has to be freed
 */
void MESSAGE_FreeMT(PartitionData *partition, Message *msg);

// /**
// API       :: MESSAGE_Free
// LAYER     :: ANY LAYER
// PURPOSE   :: When the message is no longer needed it
//              can be freed. Firstly the "payLoad" and "info" fields
//              of the message are freed. Then the message itself is freed.
//              It is important to remember to free the message. Otherwise
//              there will nasty memory leaks in the program.
// PARAMETERS ::
// + node    :  Node*    : node which is freeing the message
// + msg     :  Message* : message which has to be freed
// RETURN    :: void : NULL
// **/
void MESSAGE_Free (Node *node, Message *msg);

// /**
// API       :: MESSAGE_FreeList
// LAYER     :: ANY LAYER
// PURPOSE   :: Free a list of message until the next pointer of the
//              message is NULL.
// PARAMETERS ::
// + node    :  Node*    : node which is freeing the message
// + msg     :  Message* : message which has to be freed
// RETURN    :: void : NULL
// **/
void MESSAGE_FreeList(Node *node, Message *msg);

// /**
// API       :: MESSAGE_Duplicate
// LAYER     :: ANY LAYER
// PURPOSE   :: Create a new message which is an exact duplicate
//              of the message supplied as the parameter to the function and
//              return the new message.
// PARAMETERS ::
// + node    :  Node*    : node is calling message copy
// + msg     :  Message* : message for which duplicate has to be made
// RETURN    :: Message* : Pointer to the new message
// **/
Message *MESSAGE_Duplicate (Node *node, const Message *msg);

// /**
// API       :: MESSAGE_Duplicate
// LAYER     :: ANY LAYER
// PURPOSE   :: Create a new message which is an exact duplicate
//              of the message supplied as the parameter to the function and
//              return the new message.
// PARAMETERS ::
// + partition:  PartitionData*    : partition is calling message copy
// + msg     :  Message* : message for which duplicate has to be made
// + isMT   : bool : Is this function being called from the context
//                    of multiple threads
// RETURN    :: Message* : Pointer to the new message
// **/
Message* MESSAGE_Duplicate (PartitionData *partition, const Message *msg,
    bool isMT);

// /**
// API       :: MESSAGE_PayloadAlloc
// LAYER     :: ANY LAYER
// PURPOSE   :: Allocate a character payload out of the free list,
//              if possible otherwise via malloc.
// PARAMETERS ::
// + node    :  Node* : node which is allocating payload
// + payloadSize: int : size of the field to be allocated
// RETURN    :: char* : pointer to the allocated memory
// **/
char* MESSAGE_PayloadAlloc(Node *node, int payloadSize, bool isMT = false);

// /**
// API       :: MESSAGE_PayloadAlloc
// LAYER     :: ANY LAYER
// PURPOSE   :: Allocate a character payload out of the free list,
//              if possible otherwise via malloc.
// PARAMETERS ::
// + partition  :  PartitionData* : partition which is allocating payload
// + payloadSize: int : size of the field to be allocated
// + isMT    : bool   : Is this packet being created from a worker thread
// RETURN    :: char* : pointer to the allocated memory
// **/
char* MESSAGE_PayloadAlloc(PartitionData *partition, int payloadSize, bool isMT);

// /*
// * FUNCTION     MESSAGE_PayloadFreeMT
// * PURPOSE      Multithread safe version of MESSAGE_PayloadFree ()
// *
// * Parameters:
// *    partition:    partition which is allocating payload
// *    payloadSize:  size of the "info" field to be allocated
// */
void MESSAGE_PayloadFreeMT(PartitionData *partition, char *payload, int payloadSize);

// /**
// API       :: MESSAGE_PayloadFree
// LAYER     :: ANY LAYER
// PURPOSE   :: Return a character payload to the free list,
//              if possible otherwise free it.
// PARAMETERS ::
// + partition:  PartitionData* : partition which is freeing payload
// + payload :  Char* : Pointer to the payload field
// + payloadSize: int : size of the payload field
// RETURN    :: void : NULL
// **/
void MESSAGE_PayloadFree(PartitionData *partition, char *payload, int payloadSize,
    bool wasMT);

// /**
// API       :: MESSAGE_PayloadFree
// LAYER     :: ANY LAYER
// PURPOSE   :: Return a character payload to the free list,
//              if possible otherwise free it.
// PARAMETERS ::
// + node    :  Node* : node which is freeing payload
// + payload :  Char* : Pointer to the payload field
// + payloadSize: int : size of the payload field
// RETURN    :: void : NULL
// **/
void MESSAGE_PayloadFree(Node *node, char *payload, int payloadSize);

// /**
// API       :: MESSAGE_FreeList
// LAYER     :: ANY LAYER
// PURPOSE   :: Free a list of messages until the next pointer of the
//              message is NULL.
// PARAMETERS ::
// + node    :  Node*     : node which is freeing the message
// + msg     :  Message*  : message which has to be freed
// RETURN    :: void : NULL
// **/
void MESSAGE_FreeList(Node *node, Message *msg);

// /**
// API       :: MESSAGE_ReturnNumFrags
// LAYER     :: ANY LAYER
// PURPOSE   :: Returns the number of fragments used to create a TCP packet.
// PARAMETERS ::
// + msg     :  Message* : message for which "info" field
//                         has to be returned
// RETURN    :: int : Number of Fragments.
//                      0 if none.
// **/
static int MESSAGE_ReturnNumFrags(const Message* msg)
{
    return (int)msg->infoBookKeeping.size();
}

// /**
// API       :: MESSAGE_ReturnFragSeqNum
// LAYER     :: ANY LAYER
// PURPOSE   :: Returns the sequence number of a particular fragments
//              in the TCP packet.
// PARAMETERS ::
// + msg     :  Message* : message for which "info" field
//                         has to be returned
// + fragmentNumber: int : fragment location in the TCP message.
// RETURN    :: int : Sequence number of the fragment.
//                      -1 if none.
// **/
static int MESSAGE_ReturnFragSeqNum (const Message* msg,
                                     unsigned int fragmentNumber)
{
    if (fragmentNumber >= 0 &&
        fragmentNumber < msg->infoBookKeeping.size())
    {
        return msg->infoBookKeeping.at(fragmentNumber).msgSeqNum;
    }
    return -1;
}

// /**
// API       :: MESSAGE_ReturnFragSize
// LAYER     :: ANY LAYER
// PURPOSE   :: Returns the size of a particular fragment
//              in the TCP packet.
// PARAMETERS ::
// + msg     :  Message* : message for which "info" field
//                         has to be returned
// + fragmentNumber: int : fragment location in the TCP message.
// RETURN    :: int : Sequence number of the fragment.
//                      0 if none.
// **/
static int MESSAGE_ReturnFragSize (const Message* msg,
                                   unsigned int fragmentNumber)
{
    if (fragmentNumber >= 0 &&
        fragmentNumber < msg->infoBookKeeping.size())
    {
        return msg->infoBookKeeping.at(fragmentNumber).fragSize;
    }
    return 0;
}

// /**
// API       :: MESSAGE_ReturnFragNumInfos
// LAYER     :: ANY LAYER
// PURPOSE   :: Returns the number of info fields associated with
//              a particular fragment in the TCP packet.
// PARAMETERS ::
// + msg     :  Message* : message for which "info" field
//                         has to be returned
// + fragmentNumber: int : fragment location in the TCP message.
// RETURN    :: int : Sequence number of the fragment.
//                      0 if none.
// **/
static int MESSAGE_ReturnFragNumInfos (const Message* msg,
                                       unsigned int fragmentNumber)
{
    if (fragmentNumber >= 0 &&
        fragmentNumber < msg->infoBookKeeping.size())
    {
        int numInfos = 0;
        numInfos = msg->infoBookKeeping.at(fragmentNumber).infoUpperLimit -
                   msg->infoBookKeeping.at(fragmentNumber).infoLowerLimit;
        return numInfos;
    }
    return 0;
}

// /**
// API       :: MESSAGE_AppendInfo
// LAYER     :: ANY LAYER
// PURPOSE   :: Appends the "info" fields of the source message to
//              the destination message.
// PARAMETERS::
// + node    :  Node*    : Node which is copying the info fields
// + msg  :  Message* : Destination message
// + infosize: int : size of the info field
// + infoType: short : type of info field.
// RETURN    :: void : NULL
// **/
char* MESSAGE_AppendInfo(Node* node,
                        Message *msg,
                        int infoSize,
                        unsigned short infoType);
// /**
// API       :: MESSAGE_AppendInfo
// LAYER     :: ANY LAYER
// PURPOSE   :: Appends the "info" fields of the source message to
//              the destination message.
// PARAMETERS::
// + node    :  Node*    : Node which is copying the info fields
// + dsgMsg  :  Message* : Destination message
// + srcInfo  :  MessageInfoHeader* : Source message info vector
// RETURN    :: void : NULL
// **/
void MESSAGE_AppendInfo(Node *node, Message *dstMsg, std::vector<MessageInfoHeader> srcInfo);

// /**
// API       :: MESSAGE_AppendInfo
// LAYER     :: ANY LAYER
// PURPOSE   :: Appends the "info" fields of the source message to
//              the destination message.
// PARAMETERS::
// + node    :  Node*    : Node which is copying the info fields
// + dsgMsg  :  Message* : Destination message
// + srcMsg  :  Message* : Source message
// RETURN    :: void : NULL
// **/
void MESSAGE_AppendInfo(Node *node, Message *dstMsg, Message* srcMsg);

#endif /* _MESSAGE_H_ */

