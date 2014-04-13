#ifndef _DEAR3_H_
#define _DEAR3_H_

typedef struct dear3_node {
    unsigned int	seq;							// Sequence number from the node.
	float				battery;						// Battery of the node.
	float				battery_max;				// Maximum battery of the node.
} Dear3Node;

typedef struct dear3_entry {
	float				distance;					// Distance between nodes.
	float				power;						// Transmission power between nodes.
} Dear3Entry;

typedef struct dear3_str {
	int				maxUpdateLoss;			// Maximum number of updates that can be lost before node is assumed dead.
	double			neighbourRange;			// Neighbourhood radius, in meters.
    double			defaultPower;				// Default transmission power, for update broadcasts.
	double			powerBoost;				// Power boost on calculated power (in dB).
	clocktype		updateInterval;			// Battery update interval.
	
	std::vector<Dear3Node>						nodes;	// Node details.
	std::vector<std::vector<Dear3Entry> >	entries;	// Path details.
	
	// Statistics //
	int numIndirectTransmissions;			// Number of indirect transmissions. 
	int numDirectTransmissions;				// Number of direct transmissions.
	int numUpdateBroadcasts;				// Number of update broadcasts.
} Dear3Data;

void Dear3Init(Node* node, Dear3Data** dearPtr, const NodeInput* nodeInput, int interfaceIndex);
void Dear3HandleProtocolEvent(Node* node, Message* msg);
void Dear3HandleProtocolPacket(Node* node, Message* msg, NodeAddress sourceAddress);
void Dear3Finalize(Node *node);
void Dear3RouterFunction(Node* node, Message* msg, NodeAddress destAddr, NodeAddress previousHopAddress, BOOL* packetWasRouted);

#endif
