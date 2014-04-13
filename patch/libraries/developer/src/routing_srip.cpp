#include <stdlib.h>
#include <stdio.h>
#include <vector>
#include <algorithm>

#include "api.h"
#include "message.h"
#include "network_ip.h"
#include "routing_srip.h"
#include "routing_dear_common.h"

////////////////////////////
// Global protocol data //
///////////////////////////
SripGlobalData *g_Srip = NULL;

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
int SripGetNextHopByDijkstra(Node *node, int source, int dest) {
 ///////////////////////
 // Algorithm data //
 //////////////////////
 static int numNodes = 0;
 static std::vector<dnode> nodes;
 static std::vector<std::vector<dedge> > edges;
 
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
  
  // Get the node and it's battery.
  Node *node1 = DearGetNodeById(node, i);
  double battery = DearGetRemainingBatteryPercent(node1, g_Srip->nodes[i].battery_max);
  
  // Update metrics.
  for (int j = 1; j <= numNodes; j++) {  
   // Get the transmit power in mW.
   double power_mW = pow(10.0, g_Srip->entries[i][j].power / 10.0);
   
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
void SripInit(Node* node, SripData** sripPtr, const NodeInput* nodeInput, int interfaceIndex) {
 BOOL retVal;
 
 if (MAC_IsWiredNetwork(node, interfaceIndex))
  ERROR_ReportError("SRIP supports only wireless interfaces");
  
 if (node->numberInterfaces > 1)
  ERROR_ReportError("SRIP supports only one interface of node");
 
 // Allocate memory for variables.
 SripData *srip = (SripData*)MEM_malloc(sizeof(SripData));
 (*sripPtr) = srip;
 
 // Reset transmission power.
 DearSetTxPower(node, DearGetTxPower(node));
 
 // Initalize parameters.
 srip->powerBoost = 2.0;
 srip->neighbourRange = DearGetPropagationDistance(node);
 
 // Read parameter(s).
 // Power boost.
 IO_ReadDouble(node->nodeId, ANY_ADDRESS, nodeInput, "SRIP-POWER-BOOST", &retVal, &srip->powerBoost);
 if (!retVal) {
  ERROR_ReportWarning("SRIP-POWER-BOOST not specified! Assuming 2dB...");
  srip->powerBoost = 2.0;
 }
 
 // Initialize statistics.
 srip->numIndirectTransmissions =
 srip->numDirectTransmissions = 0;
 
 // Initialize globals.
 if (node->nodeId == 1) {
  g_Srip = (SripGlobalData*)MEM_malloc(sizeof(SripGlobalData));
  
  // Initialize vectors.
  new (&g_Srip->nodes) std::vector<SripNode>;
  new (&g_Srip->entries) std::vector<std::vector<SripEntry> >;
  
  // Allocate entries.
  g_Srip->nodes.resize(1 + node->numNodes);
  g_Srip->entries.resize(1 + node->numNodes);
  for (int i = 0; i <= node->numNodes; i++)
   g_Srip->entries[i].resize(1 + node->numNodes);
  
  // Obtain the neighbours.
  for (int i = 1; i <= node->numNodes; i++) {
   // Get the node and it's battery.
   Node *node1 = DearGetNodeById(node, i);
   g_Srip->nodes[i].battery_max = DearGetRemainingBattery(node1);
   
   // Calculate powers to all other neighbours.
   for (int j = 1; j <= node->numNodes; j++) {
    double defaultPower = DearGetTxPower(node);
    
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
    double power = DearGetPowerForDistance(node1, distance, defaultPower, srip->neighbourRange) + srip->powerBoost;
    
    // Set the entries.
    g_Srip->entries[i][j].distance = distance;
    g_Srip->entries[i][j].power = power;
   }
  }
 }
 
 // Tell IP to use our function to route packets, and update the table.
 NetworkIpSetRouterFunction(node, &SripRouterFunction, interfaceIndex);
}

/*
 * Protocol event handler (nothing to do).
 */
void SripHandleProtocolEvent(Node* node, Message* msg) {
 // No messages used.
 assert(false);
}

/*
 * Protocol packet handler (nothing to do).
 */
void SripHandleProtocolPacket(Node* node, Message* msg, NodeAddress sourceAddress) {
 // No messages used.
 assert(false);
}

/*
 * Protocol finalization function.
 */
void SripFinalize(Node *node) {
 char buf[MAX_STRING_LENGTH];

 // Finalize globals data.
 if (node->nodeId == 1) {
  if (g_Srip) {
   // Destroy the vectors.
   g_Srip->nodes.~vector();
   g_Srip->entries.~vector();

   // Free the memory.
   MEM_free(g_Srip);
  }
  
  g_Srip = NULL;
 }
 
 // Obtain a pointer to the local variable space.
 SripData *srip = (SripData*)NetworkIpGetRoutingProtocol(node, ROUTING_PROTOCOL_SRIP);
 assert(srip != NULL);
 
 // Report statistics in stat file.
 // Direct transmissions.
 sprintf(buf, "Number of direct transmissions = %u", srip->numDirectTransmissions);
 IO_PrintStat(node, "Network", "SRIP", ANY_DEST, -1, buf);
 
 // Indirect transmissions.
 sprintf(buf, "Number of indirect transmissions = %u", srip->numIndirectTransmissions);
 IO_PrintStat(node, "Network", "SRIP", ANY_DEST, -1, buf);
}

/*
 * Protocol routing function.
 */
void SripRouterFunction(Node* node, Message* msg, NodeAddress destAddr, NodeAddress previousHopAddress, BOOL* packetWasRouted) {
 double ratio = 1.0e+299;
 NodeAddress nextHop = 0, destination = MAPPING_GetNodeIdFromInterfaceAddress(node, destAddr);
 NodeAddress *nextHopInfoPtr = (NodeAddress *)MESSAGE_ReturnInfo(msg, INFO_TYPE_DearNextHop);
 IpHeaderType* ipHeader = (IpHeaderType*)msg->packet;
 
 // Obtain a pointer to the local variable space.
 SripData *srip = (SripData*)NetworkIpGetRoutingProtocol(node, ROUTING_PROTOCOL_SRIP);
 assert(srip != NULL);
  
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
 nextHop = (NodeAddress)SripGetNextHopByDijkstra(node, node->nodeId, destination);
 
 if (nextHop) {
  // Update metrics.
  if (g_Srip->entries[node->nodeId][nextHop].distance < srip->neighbourRange)
   srip->numIndirectTransmissions++;
  else
   srip->numDirectTransmissions++;
  
  // Allocate the next hop information header if needed.
  if (nextHopInfoPtr == NULL) {
   MESSAGE_AddInfo(node, msg, sizeof(nextHop), INFO_TYPE_DearNextHop);
   nextHopInfoPtr = (NodeAddress *)MESSAGE_ReturnInfo(msg, INFO_TYPE_DearNextHop);
   assert(nextHopInfoPtr);
  }
  
  // Write the next hop, set the power, and route the packet.
  *nextHopInfoPtr = nextHop;
  *packetWasRouted = TRUE;
  DearSetTxPower(node, g_Srip->entries[node->nodeId][nextHop].power);
  NetworkIpSendPacketToMacLayer(node, msg, DEFAULT_INTERFACE, nextHop);
 }
}
