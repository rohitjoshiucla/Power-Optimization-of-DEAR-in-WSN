#ifndef _SRIP_H_
#define _SRIP_H_

typedef struct srip_str {
	double			powerBoost;				// Power boost on calculated power (in dB).
	double			neighbourRange;			// Neighbourhood radius, in meters.

	int numIndirectTransmissions;			// Number of indirect transmissions. 
	int numDirectTransmissions;				// Number of direct transmissions.
} SripData;

typedef struct srip_node {
	float				battery_max;				// Maximum battery of the node.
} SripNode;

typedef struct srip_entry {
	float				distance;					// Distance between nodes.
	float				power;						// Transmission power between nodes.
} SripEntry;

typedef struct srip_global {
	std::vector<SripNode>						nodes;	// Node details.
	std::vector<std::vector<SripEntry> >	entries;	// Path details.
} SripGlobalData;

void SripInit(Node* node, SripData** sripPtr, const NodeInput* nodeInput, int interfaceIndex);
void SripHandleProtocolEvent(Node* node, Message* msg);
void SripHandleProtocolPacket(Node* node, Message* msg, NodeAddress sourceAddress);
void SripFinalize(Node *node);
void SripRouterFunction(Node* node, Message* msg, NodeAddress destAddr, NodeAddress previousHopAddress, BOOL* packetWasRouted);

#endif
