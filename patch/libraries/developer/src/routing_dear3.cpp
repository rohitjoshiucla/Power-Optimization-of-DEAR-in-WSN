#include <stdlib.h>
#include <stdio.h>
#include <vector>
#include <algorithm>

#include "api.h"
#include "message.h"
#include "network_ip.h"
#include "routing_dear3.h"
#include "routing_dear_common.h"

////////////////////////
// Data structures //
///////////////////////
// Node structure for the algorithm.
struct dnode {
 double cost;
 bool processed;
 int previousNode;
};

struct dedge {
 double weight;
};

/*
 * Returns the best next hop for the given route.
 */
int Dear3GetNextHopByDijkstra(Node *node, int source, int dest) {
 ///////////////////////
 // Algorithm data //
 //////////////////////
 static int numNodes = 0;
 static std::vector<dnode> nodes;
 static std::vector<std::vector<dedge> > edges;
 
 // Obtain a pointer to the local variable space.
 Dear3Data *dear = (Dear3Data*)NetworkIpGetRoutingProtocol(node, ROUTING_PROTOCOL_DEAR3);
 assert(dear != NULL);
 
 // Allocate memory for algorithm if necessary. This is done with 
 // static variables to avoid memory allocation every time the
 // function is called.
 if (numNodes != node->numNodes) {
  numNodes = node->numNodes;
  nodes.resize(1 + numNodes);
  edges.resize(1 + numNodes);
  for (int i = 0; i <= numNodes; i++)
   edges[i].resize(1 + numNodes);
 }
 
 /////////////////////////
 // Degenerate case //
 ////////////////////////
 if (source == dest)
  return dest;
 
 ///////////////////////
 // Update metrics //
 //////////////////////
 for (int i = 1; i <= numNodes; i++) {
  nodes[i].cost = (i == source ? 0.0f : 1e+29f);
  nodes[i].processed = false;
  nodes[i].previousNode = 0;
  
  // Get the node's battery.  
  double battery = 100.0 * dear->nodes[i].battery / dear->nodes[i].battery_max;

  // Check staleness of battery update.
  if (dear->nodes[source].seq - dear->nodes[i].seq > dear->maxUpdateLoss)
   battery = 0; // Assume the node is dead.
  
  // Update metrics.
  for (int j = 1; j <= numNodes; j++) {  
   // Get the transmit power in mW.
   double power_mW = pow(10.0, dear->entries[i][j].power / 10.0);
   
   // Calculate metric (the edge weight).
   if (battery > 1e-4)
    edges[i][j].weight = power_mW / battery;
   else
    edges[i][j].weight = 1e+30f;
  }
 }
 
 /////////////////////////////////
 // Shortest path algorithm //
 ////////////////////////////////
 // This algorithm is similiar to (but not) APSP, and can be improved
 // if Dijkstra is used instead. Question is whether Dijkstra will improve
 // search time, because the graph is complete.
 for (int j = 1; j <= numNodes; j++)
  // Process all nodes.
  for (int current = 1; current <= numNodes; current++)
   // Process all neighbours.
   for (int i = 1; i <= numNodes; i++)
    // Check cost.
    if (nodes[current].cost + edges[current][i].weight < nodes[i].cost) {
     // Update cheapter route.
     nodes[i].cost = nodes[current].cost + edges[current][i].weight;
     nodes[i].previousNode = current;
    }
 
 ////////////////////
 // Final answer //
 ///////////////////
 int i;

 // We're done with all the nodes. Get the previous hop, starting from destination.
 for (i = dest; nodes[i].previousNode != source; i = nodes[i].previousNode)
  if (!nodes[i].previousNode)
   return 0; // No nodes (!)
 
 return i;
}

/*
 * Protocol initialization function. Check parameters, allocate storage space, read parameters, etc.
 */
void Dear3Init(Node* node, Dear3Data** dearPtr, const NodeInput* nodeInput, int interfaceIndex) {
 BOOL retVal;
 
 if (MAC_IsWiredNetwork(node, interfaceIndex))
  ERROR_ReportError("DEAR3 supports only wireless interfaces");
  
 if (node->numberInterfaces > 1)
  ERROR_ReportError("DEAR3 supports only one interface of node");
 
 // Allocate memory for variables.
 Dear3Data *dear = (Dear3Data*)MEM_malloc(sizeof(Dear3Data));
 (*dearPtr) = dear;
 
 // Reset transmission power.
 DearSetTxPower(node, DearGetTxPower(node));
 
 // Initalize parameters.
 dear->maxUpdateLoss = 5;
 dear->powerBoost = 2.0;
 dear->updateInterval = 10 * SECOND;
 dear->defaultPower = DearGetTxPower(node);
 dear->neighbourRange = DearGetPropagationDistance(node);
  
 // Read parameter(s).
 // Max update loss.
 IO_ReadInt(node->nodeId, ANY_ADDRESS, nodeInput, "DEAR3-MAX-UPDATE-LOSS", &retVal, &dear->maxUpdateLoss);
 if (!retVal) {
  ERROR_ReportWarning("DEAR3-MAX-UPDATE-LOSS not specified! Assuming 5...");
  dear->maxUpdateLoss = 5;
 }
 
 // Update interval.
 IO_ReadTime(node->nodeId, ANY_ADDRESS, nodeInput, "DEAR3-UPDATE-INTERVAL", &retVal, &dear->updateInterval);
 if (!retVal) {
  ERROR_ReportWarning("DEAR3-UPDATE-INTERVAL not specified! Assuming 10s...");
  dear->updateInterval = 10 * SECOND;
 }
 
 // Initialize statistics.
 dear->numIndirectTransmissions =
 dear->numDirectTransmissions = 
 dear->numUpdateBroadcasts = 0;
 
 // Initialize vectors.
 new (&dear->nodes) std::vector<Dear3Node>;
 new (&dear->entries) std::vector<std::vector<Dear3Entry> >;
 
 // Allocate entries.
 dear->nodes.resize(1 + node->numNodes);
 dear->entries.resize(1 + node->numNodes);
 for (int i = 0; i <= node->numNodes; i++)
  dear->entries[i].resize(1 + node->numNodes); 
 
 // Obtain the neighbours.
 for (int i = 1; i <= node->numNodes; i++) {
  // Update table entry.
  dear->nodes[i].seq = 0;
  dear->nodes[i].battery = 0.0;
  
  // Get the node and it's maximum battery.
  Node *node1 = DearGetNodeById(node, i);
  dear->nodes[i].battery_max = DearGetRemainingBattery(node1);
  assert(dear->nodes[i].battery_max);
  
  // Calculate powers to all other neighbours.
  for (int j = 1; j <= node->numNodes; j++) {
   // Get the node.
   Node *node2 = DearGetNodeById(node, j);
   
   // Get the positions.
   double x1, y1, z1, x2, y2, z2;
   DearGetNodePosition(node1, x1, y1, z1);
   DearGetNodePosition(node2, x2, y2, z2);
   
   // Calculate distance between destination and neighbour.
   // Then calculate the TX power.
   x2 -= x1; y2 -= y1; z2 -= z1;
   double distance = sqrt(x2 * x2 + y2 * y2 + z2 * z2);
   double power = DearGetPowerForDistance(node1, distance, dear->defaultPower, dear->neighbourRange) + dear->powerBoost;
   
   // Set the entries.
   dear->entries[i][j].distance = distance;
   dear->entries[i][j].power = power;
  }
 }
 
 // Tell IP to use our function to route packets, and update the table.
 NetworkIpSetRouterFunction(node, &Dear3RouterFunction, interfaceIndex);
 
 // Schedule the next update broadcast after a random delay.
 RandomSeed startupSeed;
 RANDOM_SetSeed(startupSeed, node->globalSeed, node->nodeId, ROUTING_PROTOCOL_DEAR3, DEFAULT_INTERFACE);
 clocktype delay = RANDOM_nrand(startupSeed) % dear->updateInterval;
 Message *newMsg = MESSAGE_Alloc(node, NETWORK_LAYER, ROUTING_PROTOCOL_DEAR3, MSG_NETWORK_RTBroadcastAlarm);
 MESSAGE_Send(node, newMsg, delay);
}

/*
 * Protocol event handler (nothing to do).
 */
void Dear3HandleProtocolEvent(Node* node, Message* msg) { 
 // Only one message type is used.
 assert(msg->eventType == MSG_NETWORK_RTBroadcastAlarm);
 
 // Obtain a pointer to the local variable space.
 Dear3Data* dear = (Dear3Data*)NetworkIpGetRoutingProtocol(node, ROUTING_PROTOCOL_DEAR3);
 assert(dear != NULL);
 
 // Prepare a route update packet with (seq, bat).
 Message *newMsg = MESSAGE_Alloc(node, 0, 0, 0);
 size_t pktSize = (sizeof(unsigned int) + sizeof(float)) * node->numNodes;
 MESSAGE_PacketAlloc(node, newMsg, pktSize, TRACE_ANY_PROTOCOL);
 char *pktPtr = newMsg->packet;
 
 // Update self state and statistic.
 dear->nodes[node->nodeId].battery = DearGetRemainingBattery(node);
 dear->nodes[node->nodeId].seq++;
 dear->numUpdateBroadcasts++;
 
 // Fill the packet with the table entries.
 for (int i = 1; i <= node->numNodes; i++) {
  // Sequence number.
  memcpy(pktPtr, &(dear->nodes[i].seq), sizeof(unsigned int));
  pktPtr += sizeof(unsigned int);
  
  // Battery.
  float battery = dear->nodes[i].battery;
  memcpy(pktPtr, &battery, sizeof(float));
  pktPtr += sizeof(float);
 }
 
 // Reset the power and send the route update packet to MAC layer.
 DearSetTxPower(node, dear->defaultPower);
 NetworkIpSendRawMessageToMacLayer(node, newMsg, node->nodeId, ANY_DEST, 0, IPPROTO_DEAR3, 1, DEFAULT_INTERFACE, ANY_DEST);
 
 // Schedule the next route update broadcast after a fixed delay.
 newMsg = MESSAGE_Alloc(node, NETWORK_LAYER, ROUTING_PROTOCOL_DEAR3, MSG_NETWORK_RTBroadcastAlarm);
 MESSAGE_Send(node, newMsg, dear->updateInterval);
 
 // Free old message after being processed.
 MESSAGE_Free(node, msg);
}

/*
 * Protocol packet handler (nothing to do).
 */
void Dear3HandleProtocolPacket(Node* node, Message* msg, NodeAddress sourceAddress) {
 // Obtain a pointer to the local variable space.
 Dear3Data* dear = (Dear3Data*)NetworkIpGetRoutingProtocol(node, ROUTING_PROTOCOL_DEAR3);
 assert(dear != NULL);
 
 // Read the packet.
 char *pktPtr = msg->packet;
 
 // Apply the entry updates.
 for (int i = 1; i <= node->numNodes; i++) {
  unsigned int seq;
  float battery;
  
  // Read sequence number.
  memcpy(&seq, pktPtr, sizeof(seq));
  pktPtr += sizeof(seq);
  
  // Read battery.
  memcpy(&battery, pktPtr, sizeof(battery));
  pktPtr += sizeof(battery);
  
  // Skip for self (although not skipping will do no harm; since only we
  // have the largest sequence number).
  if (i == node->nodeId)
   continue;
  
  // Check if it's newer.
  if (seq > dear->nodes[i].seq) {
   // Sanity check: Giving a 1% margin to floating-point error round-off
   // the reported battery must be less than the maximum.
   assert(battery / dear->nodes[i].battery_max < 1.01);
   
   // Apply the update.
   dear->nodes[i].seq = seq;
   dear->nodes[i].battery = battery;
  }
 }
 
 // This is the packet's final destination.
 MESSAGE_Free(node, msg);
}

/*
 * Protocol finalization function.
 */
void Dear3Finalize(Node *node) {
 char buf[MAX_STRING_LENGTH];
 
 // Obtain a pointer to the local variable space.
 Dear3Data *dear = (Dear3Data*)NetworkIpGetRoutingProtocol(node, ROUTING_PROTOCOL_DEAR3);
 assert(dear != NULL);
 
 // Report statistics in stat file.
 // Direct transmissions.
 sprintf(buf, "Number of direct transmissions = %u", dear->numDirectTransmissions);
 IO_PrintStat(node, "Network", "DEAR3", ANY_DEST, -1, buf);
 
 // Indirect transmissions.
 sprintf(buf, "Number of indirect transmissions = %u", dear->numIndirectTransmissions);
 IO_PrintStat(node, "Network", "DEAR3", ANY_DEST, -1, buf);

 // Updates broadcast.
 sprintf(buf, "Number of updates broadcast = %u", dear->numUpdateBroadcasts);
 IO_PrintStat(node, "Network", "DEAR3", ANY_DEST, -1, buf);
 
 // Destroy the vectors.
 dear->nodes.~vector();
 dear->entries.~vector();
}

/*
 * Protocol routing function.
 */
void Dear3RouterFunction(Node* node, Message* msg, NodeAddress destAddr, NodeAddress previousHopAddress, BOOL* packetWasRouted) {
 double ratio = 1.0e+299;
 NodeAddress nextHop = 0, destination = MAPPING_GetNodeIdFromInterfaceAddress(node, destAddr);
 NodeAddress *nextHopInfoPtr = (NodeAddress *)MESSAGE_ReturnInfo(msg, INFO_TYPE_DearNextHop);
 IpHeaderType* ipHeader = (IpHeaderType*)msg->packet;
 
 // Obtain a pointer to the local variable space.
 Dear3Data *dear = (Dear3Data*)NetworkIpGetRoutingProtocol(node, ROUTING_PROTOCOL_DEAR3);
 assert(dear != NULL);
  
 // Do not route any packets destined to self.
 if (destination == node->nodeId) {
  // Remove the next hop info field if present.
  if (nextHopInfoPtr != NULL)
   MESSAGE_RemoveInfo(node, msg, INFO_TYPE_DearNextHop);
  return;
 }
 
 // Do not route the packet if we are not the next hop for this packet.
 if (nextHopInfoPtr != NULL && *nextHopInfoPtr != node->nodeId)
  return;
 
 // Get the best next hop.
 nextHop = (NodeAddress)Dear3GetNextHopByDijkstra(node, node->nodeId, destination);
 
 // Transmit directly if no route found.
 if (!nextHop)
  nextHop = destination;
 
 // Update metrics.
 if (dear->entries[node->nodeId][nextHop].distance < dear->neighbourRange)
  dear->numIndirectTransmissions++;
 else
  dear->numDirectTransmissions++;
  
 // Allocate the next hop information header if needed.
 if (nextHopInfoPtr == NULL) {
  MESSAGE_AddInfo(node, msg, sizeof(nextHop), INFO_TYPE_DearNextHop);
  nextHopInfoPtr = (NodeAddress *)MESSAGE_ReturnInfo(msg, INFO_TYPE_DearNextHop);
  assert(nextHopInfoPtr);
 }
  
 // Write the next hop, set the power, and route the packet.
 *nextHopInfoPtr = nextHop;
 *packetWasRouted = TRUE;
 DearSetTxPower(node, dear->entries[node->nodeId][nextHop].power);
 NetworkIpSendPacketToMacLayer(node, msg, DEFAULT_INTERFACE, nextHop);
}
