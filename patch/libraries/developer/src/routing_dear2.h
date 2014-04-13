#ifndef _DEAR2_H_
#define _DEAR2_H_

typedef struct dear2_table_entry {
 BOOL				valid;					// Whether the entry is valid.
 double				power;					// Power to this neighbour, in dBm.
 double				powerToBase;			// Power to base, in dBm, from this neighbour.
 double				battery_max;			// Maximum battery of this neighbour.
} Dear2TableEntry;

typedef struct dear2_str
{
 NodeAddress			destination;		// The base station.
 double					powerBoost;		// Power boost on calculated power (in dB).
 double					neighbourRange;	// Neighbourhood radius, in meters.
 Dear2TableEntry*	neighbours;		// List of neighbours of this node.
 
 int numIndirectTransmissions;			// Number of indirect transmissions. 
 int numDirectTransmissions;				// Number of direct transmissions.
} Dear2Data;

void Dear2Init(Node* node, Dear2Data** dearPtr, const NodeInput* nodeInput, int interfaceIndex);
void Dear2HandleProtocolEvent(Node* node, Message* msg);
void Dear2HandleProtocolPacket(Node* node, Message* msg, NodeAddress sourceAddress);
void Dear2Finalize(Node *node);
void Dear2RouterFunction(Node* node, Message* msg, NodeAddress destAddr, NodeAddress previousHopAddress, BOOL* packetWasRouted);

#endif
