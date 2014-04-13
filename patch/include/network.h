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
// PACKAGE     :: NETWORK LAYER
// DESCRIPTION :: This file describes the data structures and functions used by the Network Layer.
// **/

#ifndef _NETWORK_H_
#define _NETWORK_H_

#include "mapping.h"

//---------------------------------------------------------------------------
// DEFINES
//---------------------------------------------------------------------------

//---------------------------------------------------------------------------
// Queues
//---------------------------------------------------------------------------

// /**
// CONSTANT    :: DEFAULT_IP_QUEUE_COUNT : 3
// DESCRIPTION :: Default number of output queue per interface
// **/
#define DEFAULT_IP_QUEUE_COUNT  3

// /**
// CONSTANT    :: DEFAULT_CPU_QUEUE_SIZE : 640000
// DESCRIPTION :: Default size of CPU queue (in byte)
// **/
#define DEFAULT_CPU_QUEUE_SIZE                  640000

// /**
// CONSTANT    :: DEFAULT_NETWORK_INPUT_QUEUE_SIZE : 150000
// DESCRIPTION :: Default size in bytes of an input queue, if it's not
//                specified in the input file with the
//                IP-QUEUE-PRIORITY-INPUT-QUEUE-SIZE parameter.
// **/
#define DEFAULT_NETWORK_INPUT_QUEUE_SIZE        150000

// /**
// CONSTANT    :: DEFAULT_NETWORK_OUTPUT_QUEUE_SIZE : 150000
// DESCRIPTION :: Default size in bytes of an output queue, if it's not
//                specified in the input file with the
//                IP-QUEUE-PRIORITY-QUEUE-SIZE parameter.
// **/
#define DEFAULT_NETWORK_OUTPUT_QUEUE_SIZE       150000

// /**
// CONSTANT    :: DEFAULT_ETHERNET_MTU : 1500
// DESCRIPTION :: Default Ethernet MTU(Maximum transmission unit) in bytes.
//                QualNet does not model Ethernet yet, but this value is
//                used (in the init functions in network/fifoqueue.c and
//                network/redqueue.c) to compute the initial number of
//                Message * instances that are used to store packets in
//                queues.Regardless, the buffer capacity of a queue is not
//                the number of Message * instances, but a certain number
//                of bytes, as expected.
// **/
#define DEFAULT_ETHERNET_MTU                      1500

// /**
// CONSTANT    :: IP_MAXPACKET : 65535
// DESCRIPTION :: Maximum IP packet size
// **/
#ifndef IP_MAXPACKET
#define IP_MAXPACKET    65535
#endif

// /**
// CONSTANT    :: NETWORK_IP_UNLIMITED_BACKPLANE_THROUGHPUT : 0
// DESCRIPTION :: Maximum throughput of backplane of network.
// **/
#define NETWORK_IP_UNLIMITED_BACKPLANE_THROUGHPUT (0)

// /**
// ENUM        :: NetworkIpBackplaneStatusType
// DESCRIPTION :: Status of backplane (either busy or idle)
// **/
typedef enum
{
    NETWORK_IP_BACKPLANE_IDLE,
    NETWORK_IP_BACKPLANE_BUSY
} NetworkIpBackplaneStatusType;


//-----------------------------------------------------------------------------
// STRUCTS, ENUMS, AND TYPEDEFS
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// Queues
//-----------------------------------------------------------------------------

//
// The priority value of queues and packets is type unsigned.
// The priority value is used in the application layer to specify
// priority values for packets; in the network layer to create and
// access queues of different priorities; and in the MAC layer also
// to access the network-layer queues.
//

typedef int TosType;
typedef TosType QueuePriorityType;

//
// Enumeration values assigned to different routing protocols of both
// the network and application layers.  These values are used by layer
// functions and when sending messages.
//

//-----------------------------------------------------------------------------
// Routing
//-----------------------------------------------------------------------------

//
// Administrative distances.  [These values don't match the
// recommended Cisco values, yet. -Jeff]
//

// /**
// ENUM        :: NetworkRoutingAdminDistanceType
// DESCRIPTION :: Administrative distance of different routing protocol
// **/
typedef enum
{
    ROUTING_ADMIN_DISTANCE_STATIC = 1,
#ifdef ADDON_BOEINGFCS
    ROUTING_ADMIN_DISTANCE_EBGPv4_HANDOFF = 111,
#endif
    ROUTING_ADMIN_DISTANCE_EBGPv4 = 20,
    ROUTING_ADMIN_DISTANCE_IBGPv4 = 200,
    ROUTING_ADMIN_DISTANCE_BGPv4_LOCAL = 200,
    ROUTING_ADMIN_DISTANCE_OSPFv2 = 110,
    ROUTING_ADMIN_DISTANCE_IGRP = 100,
    ROUTING_ADMIN_DISTANCE_STAR,
    ROUTING_ADMIN_DISTANCE_RIPv3,
    ROUTING_ADMIN_DISTANCE_BELLMANFORD,
    ROUTING_ADMIN_DISTANCE_FISHEYE,
#ifdef ADDON_BOEINGFCS
    ROUTING_ADMIN_DISTANCE_CES_SRW,
    ROUTING_ADMIN_DISTANCE_BOEING_ODR,
    ROUTING_ADMIN_DISTANCE_ROUTING_CES_SDR,
    ROUTING_ADMIN_DISTANCE_HSLS,
    ROUTING_ADMIN_DISTANCE_OSPFv2_EXTERNAL = 120,
#endif
    ROUTING_ADMIN_DISTANCE_OLSR,
    ROUTING_ADMIN_DISTANCE_EIGRP,
//StartRIP
    ROUTING_ADMIN_DISTANCE_RIP,
//EndRIP
//StartRIPng
    ROUTING_ADMIN_DISTANCE_RIPNG,
//EndRIPng
    ROUTING_ADMIN_DISTANCE_SDR,


    ROUTING_ADMIN_DISTANCE_OSPFv3 = 115,

    ROUTING_ADMIN_DISTANCE_OLSRv2_NIIGATA,

    ROUTING_ADMIN_DISTANCE_FSRL = 210,
//InsertPatch ROUTING_DISTANCE_TYPE

    // Should always have the highest adminstrative distance
    // (ie, least important).
    ROUTING_ADMIN_DISTANCE_DEFAULT = 255
} NetworkRoutingAdminDistanceType;

// /**
// ENUM        :: NetworkRoutingProtocolType
// DESCRIPTION :: Enlisted different network/routing protocol
// **/
typedef enum
{
    NETWORK_PROTOCOL_IP = 0,
    NETWORK_PROTOCOL_IPV6,
    NETWORK_PROTOCOL_MOBILE_IP,
    NETWORK_PROTOCOL_NDP,
    NETWORK_PROTOCOL_SPAWAR_LINK16,
    NETWORK_PROTOCOL_ICMP,
    ROUTING_PROTOCOL_AODV,
    ROUTING_PROTOCOL_DSR,
    ROUTING_PROTOCOL_FSRL,
#ifdef ADDON_BOEINGFCS
    ROUTING_PROTOCOL_CES_MALSR,
    ROUTING_PROTOCOL_CES_SRW,
    ROUTING_PROTOCOL_CES_ROSPF,
    ROUTING_CLUSTER,
    NETWORK_CES_REGION,
    ROUTING_PROTOCOL_CES_MPR,
    ROUTING_PROTOCOL_CES_HSLS,
    NETWORK_PROTOCOL_MAC_CES_SINCGARS,
    ROUTING_PROTOCOL_CES_SDR,
    ROUTING_PROTOCOL_BOEING_ODR,
    NETWORK_PROTOCOL_CES_EPLRS,
    ROUTING_PROTOCOL_CES_EPLRS,
    MULTICAST_PROTOCOL_RPIM,
#endif // ADDON_BOEINGFCS
    ROUTING_PROTOCOL_STAR,
    ROUTING_PROTOCOL_LAR1,
    ROUTING_PROTOCOL_ODMRP,
    ROUTING_PROTOCOL_OSPF,
    ROUTING_PROTOCOL_OSPFv2,
#ifdef ADDON_BOEINGFCS
    ROUTING_PROTOCOL_OSPFv2_EXTERNAL,
#endif
    ROUTING_PROTOCOL_SDR,
    ROUTING_PROTOCOL_BELLMANFORD,
    ROUTING_PROTOCOL_STATIC,
    ROUTING_PROTOCOL_DEFAULT,
    ROUTING_PROTOCOL_FISHEYE,
    ROUTING_PROTOCOL_OLSR_INRIA,
    ROUTING_PROTOCOL_IGRP,
    ROUTING_PROTOCOL_EIGRP,
    ROUTING_PROTOCOL_BRP,
//StartRIP
    ROUTING_PROTOCOL_RIP,
//EndRIP
//StartRIPng
    ROUTING_PROTOCOL_RIPNG,
//EndRIPng
//StartIARP
    ROUTING_PROTOCOL_IARP,
//EndIARP
//StartZRP
    ROUTING_PROTOCOL_ZRP,
//EndZRP
//StartIERP
    ROUTING_PROTOCOL_IERP,
//EndIERP
//InsertPatch ROUTING_PROTOCOL_TYPE

    EXTERIOR_GATEWAY_PROTOCOL_EBGPv4,
    EXTERIOR_GATEWAY_PROTOCOL_IBGPv4,
    EXTERIOR_GATEWAY_PROTOCOL_BGPv4_LOCAL,

    GROUP_MANAGEMENT_PROTOCOL_IGMP,
    LINK_MANAGEMENT_PROTOCOL_CBQ,

    MULTICAST_PROTOCOL_STATIC,
    MULTICAST_PROTOCOL_DVMRP,
    MULTICAST_PROTOCOL_MOSPF,
    MULTICAST_PROTOCOL_ODMRP,

    MULTICAST_PROTOCOL_PIM,

    // ADDON_MAODV
    MULTICAST_PROTOCOL_MAODV,

    NETWORK_PROTOCOL_GSM,
    NETWORK_PROTOCOL_ARP,

    ROUTING_PROTOCOL_OSPFv3,
    ROUTING_PROTOCOL_OLSRv2_NIIGATA,

    ROUTING_PROTOCOL_ALL,

    NETWORK_PROTOCOL_CELLULAR,


    ROUTING_PROTOCOL_AODV6,
    ROUTING_PROTOCOL_DYMO,
    ROUTING_PROTOCOL_DYMO6,

#ifdef IA_LIB
    ROUTING_PROTOCOL_ANODR,
    NETWORK_PROTOCOL_SECURENEIGHBOR,
    NETWORK_PROTOCOL_SECURECOMMUNITY,
    NETWORK_PROTOCOL_IPSEC_AH,
    NETWORK_PROTOCOL_IPSEC_ESP = 5199,
    NETWORK_PROTOCOL_ISAKMP,
#endif // IA_LIB

#ifdef  ADDON_NGCNMS
        NETWORK_PROTOCOL_NGC_HAIPE,
#endif
    NETWORK_ROUTE_REDISTRIBUTION,

    ROUTING_PROTOCOL_DEAR,
    ROUTING_PROTOCOL_DEAR2,
    ROUTING_PROTOCOL_DEAR3,
    ROUTING_PROTOCOL_SRIP,
    ROUTING_PROTOCOL_NONE // this must be the last one
} NetworkRoutingProtocolType;

//-----------------------------------------------------------------------------
// Network layer
//-----------------------------------------------------------------------------

//
// typedef to NetworkDataIp in network/ip.h.
//

struct struct_network_ip_str;

#ifdef CELLULAR_LIB
// defined in gsm_layer3.h
struct struct_layer3_gsm_str;
#endif // CELLULAR_LIB
#ifdef ADDON_NGCNMS
//Function ptrs for Reseting Network Layer
typedef void (*NetworkSetFunctionPtr)(Node*, int);

struct
struct_network_reset_function
{
    // Corresponding set function
    NetworkSetFunctionPtr funcPtr;

    // the next match command
    struct struct_network_reset_function* next;
};

typedef struct
struct_network_reset_function_linkedList
{
    struct struct_network_reset_function* first;
    struct struct_network_reset_function* last;
} NetworkResetFunctionList;
#endif

// /**
// STRUCT      :: struct_network_str
// DESCRIPTION :: Main data structure of network layer
//                typedef to NetworkData in include/main.h.
// **/
struct struct_network_str
{
    struct struct_network_ip_str *networkVar;  // IP state

    NetworkProtocolType networkProtocol;

#ifdef CELLULAR_LIB
    struct struct_layer3_gsm_str *gsmLayer3Var;
    struct struct_cellular_layer3_str *cellularLayer3Var;
#endif // CELLULAR_LIB

    BOOL networkStats;  // TRUE if network statistics are collected

    //It is true if ARP is enabled
    BOOL isArpEnable;
    //It is true if RARP is enabled
    BOOL isRarpEnable;
    struct address_resolution_module *arModule;
#ifdef ADDON_BOEINGFCS
    BOOL useNetworkCesQosDiffServ;
#endif
#ifdef ADDON_NGCNMS
    NetworkResetFunctionList* resetFunctionList;
#endif
};


//-----------------------------------------------------------------------------
// INLINED FUNCTIONS (none)
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// PROTOTYPES FOR FUNCTIONS WITH EXTERNAL LINKAGE
//-----------------------------------------------------------------------------

// /**
// FUNCTION   :: NetworkGetInterfaceInfo()
// LAYER      :: Network
// PURPOSE    :: Returns interface information for a interface. Information
//               means its address and type
//
// PARAMETERS ::
// + node      : Node* : Pointer to node.
// + interfaceIndex : int : interface index for which info required.
// + address        : Address* : interface info returned
// RETURN     :: void : NULL
// **/
void NetworkGetInterfaceInfo(
    Node* node,
    int interfaceIndex,
    Address *address,
    NetworkType networkType = NETWORK_IPV4);

// /**
// FUNCTION   :: NetworkIpGetInterfaceAddressString
// LAYER      :: Network
// PURPOSE    :: ipAddrString is filled in by interface's ipv6 address
//               in character format.
// PARAMETERS ::
// + node      : Node* : Pointer to node.
// + interfaceIndex : int : Interface index.
// + ipAddrString   : const char* : Pointer to string ipv6 address.
// RETURN     :: void :
// **/
void
NetworkIpGetInterfaceAddressString(
    Node *node,
    const int interfaceIndex,
    char ipAddrString[]);

// /**
// FUNCTION   :: NetworkIpGetInterfaceType
// LAYER      :: Network
// PURPOSE    :: Returns type of network (ipv4 or ipv6) the interface.
//
// PARAMETERS ::
// + node      : Node* : Pointer to node.
// + interfaceIndex : int : Interface index.
// RETURN     :: NetworkType :
// **/
NetworkType NetworkIpGetInterfaceType(
    Node* node,
    int interfaceIndex);


// /**
// FUNCTION   :: NETWORK_ReceivePacketFromMacLayer
// LAYER      :: Network
// PURPOSE    :: Network-layer receives packets from MAC layer, now check
//              Overloaded Function to support Mac Address
//              type of IP and call proper function
// PARAMETERS  ::
// + node : Node* : Pointer to node
// + message : Message* : Message received
// + lastHopAddress : NodeAddress : last hop address
// + interfaceIndex : int : incoimg interface
// RETURN     :: void :
// **/
void NETWORK_ReceivePacketFromMacLayer(Node* node,
    Message* msg,
                                       MacHWAddress* macAddr,
    int interfaceIndex);

#ifdef ADDON_NGCNMS
// /**
// FUNCTION   :: NETWORK_Reset
// LAYER      :: Network
// PURPOSE    :: Reset Network protocols and/or layer.
// PARAMETERS ::
// + node      : Node* : Pointer to node.
// + interfaceIndex : int: Interface index.
// RETURN     :: void :
// **/
void
NETWORK_Reset(Node *node,
              int interfaceIndex);

// /**
// FUNCTION   :: NETWORK_AddResetFunctionList
// LAYER      :: Network
// PURPOSE    :: Add which protocols to be reset to a
//               fuction list pointer.
// PARAMETERS ::
// + node      : Node* : Pointer to node.
// + interfaceIndex : int: Interface index.
// RETURN     :: void :
// **/
void
NETWORK_AddResetFunctionList(Node* node,
                             void *param);

clocktype NETWORK_CalculateRestartDelay(Node* node,
                                        int interfaceIndex);

void NETWORK_SetRebootDelay(Node* node,
                            int interfaceIndex,
                            clocktype resetDelay);

#endif
//
//
// The other network.c functions are prototyped in include/api.h.
//
#endif // _NETWORK_H_
