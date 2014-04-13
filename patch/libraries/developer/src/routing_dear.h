#ifndef _DEAR_H_
#define _DEAR_H_

typedef struct dear_table_entry {
 BOOL				valid;			// Whether the entry is valid.
 double				power;			// Power, in dBm, to base from this neighbour.
 double				battery_max;	// Maximum battery of this neighbour.
} DearTableEntry;

typedef struct dear_str
{
 NodeAddress		destination;	// The base station.
 double				defaultPower;	// Default transmission power, in dBm
 double				defaultRange;	// Default range, in meters.
 DearTableEntry*	neighbours;	// List of neighbours of this node.

 int numIndirectTransmissions;	// Number of indirect transmissions. 
 int numDirectTransmissions;		// Number of direct transmissions.
} DearData;

void DearInit(Node* node, DearData** dearPtr, const NodeInput* nodeInput, int interfaceIndex);
void DearHandleProtocolEvent(Node* node, Message* msg);
void DearHandleProtocolPacket(Node* node, Message* msg, NodeAddress sourceAddress);
void DearFinalize(Node *node);
void DearRouterFunction(Node* node, Message* msg, NodeAddress destAddr, NodeAddress previousHopAddress, BOOL* packetWasRouted);

#endif
