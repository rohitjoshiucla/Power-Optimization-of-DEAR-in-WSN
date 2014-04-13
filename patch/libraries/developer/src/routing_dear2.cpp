#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <math.h>

#include "api.h"
#include "message.h"
#include "network_ip.h"
#include "routing_dear2.h"
#include "routing_dear_common.h"

/*
 * Protocol initialization function. Check parameters, allocate storage space, read parameters, etc.
 */
void Dear2Init(Node* node, Dear2Data** dearPtr, const NodeInput* nodeInput, int interfaceIndex) {
 BOOL retVal;
 
 if (MAC_IsWiredNetwork(node, interfaceIndex))
  ERROR_ReportError("DEAR2 supports only wireless interfaces");
  
 if (node->numberInterfaces > 1)
  ERROR_ReportError("DEAR2 supports only one interface of node");
  
 // Allocate memory for variables of this node.
 Dear2Data* dear = (Dear2Data*)MEM_malloc(sizeof(Dear2Data));
 (*dearPtr) = dear;
 
 // Reset transmission power.
 DearSetTxPower(node, DearGetTxPower(node));
 
 // Initalize parameters.
 dear->destination = 1;
 dear->powerBoost = 2.0;
 dear->neighbourRange = DearGetPropagationDistance(node);
 dear->neighbours = (Dear2TableEntry*)MEM_malloc((1 + node->numNodes) * sizeof(Dear2TableEntry));
 
 // Read parameters.
 // Destination.
 IO_ReadInt(node->nodeId, ANY_ADDRESS, nodeInput, "DEAR2-DESTINATION", &retVal, (int*)(&dear->destination));
 if (!retVal)
  ERROR_ReportError("DEAR2-DESTINATION not specified!");
 
 // Power boost.
 IO_ReadDouble(node->nodeId, ANY_ADDRESS, nodeInput, "DEAR2-POWER-BOOST", &retVal, &dear->powerBoost);
 if (!retVal) {
  ERROR_ReportWarning("DEAR2-POWER-BOOST not specified! Assuming 2dB...");
  dear->powerBoost = 2.0;
 }
 
 // Initialize statistics.
 dear->numIndirectTransmissions =
 dear->numDirectTransmissions = 0;
 
 // Obtain the neighbours.
 for (int i = 1; i <= node->numNodes; i++) {
  double defaultPower = DearGetTxPower(node);
  
  // Get the neighbour node.
  Node *neighbour = DearGetNodeById(node, i);
  Node *destination = DearGetNodeById(node, dear->destination);

  // Store the neighbour's maximum battery.
  dear->neighbours[i].battery_max = DearGetRemainingBattery(neighbour);
  
  // Get the positions.
  double x0, y0, z0, x1, y1, z1, x2, y2, z2;
  DearGetNodePosition(node, x0, y0, z0);
  DearGetNodePosition(neighbour, x1, y1, z1);
  DearGetNodePosition(destination, x2, y2, z2);
  
  // Calculate distance between destination and neighbour.
  // Then set the valid neighbour property and the TX power.
  x0 -= x1; y0 -= y1; z0 -= z1;
  double distance0 = sqrt(x0 * x0 + y0 * y0 + z0 * z0);
  dear->neighbours[i].valid = (distance0 < dear->neighbourRange);
  dear->neighbours[i].power = DearGetPowerForDistance(node, distance0, defaultPower, dear->neighbourRange) + dear->powerBoost;
  
  // Calculate distance between destination and neighbour.
  // Then estimate transmission power in dBm. Assume the default transmission power
  // is used for the given neighbour size (this is expected to preserve the error rate).
  x2 -= x1; y2 -= y1; z2 -= z1;
  double distance2 = sqrt(x2 * x2 + y2 * y2 + z2 * z2);
  dear->neighbours[i].powerToBase = DearGetPowerForDistance(neighbour, distance2, defaultPower, dear->neighbourRange) + dear->powerBoost;
 }
 
 // Tell IP to use our function to route packets, and update the table.
 NetworkIpSetRouterFunction(node, &Dear2RouterFunction, interfaceIndex);
}

/*
 * Protocol event handler (nothing to do).
 */
void Dear2HandleProtocolEvent(Node* node, Message* msg) {
 // No messages used.
 assert(false);
}

/*
 * Protocol packet handler (nothing to do).
 */
void Dear2HandleProtocolPacket(Node* node, Message* msg, NodeAddress sourceAddress) {
 // No messages used.
 assert(false);
}

/*
 * Protocol finalization function.
 */
void Dear2Finalize(Node *node) {
 char buf[MAX_STRING_LENGTH];
 
 // Obtain a pointer to the local variable space.
 Dear2Data* dear = (Dear2Data*)NetworkIpGetRoutingProtocol(node, ROUTING_PROTOCOL_DEAR2);
 assert(dear != NULL);
 
 // Report statistics in stat file.
 // Direct transmissions.
 sprintf(buf, "Number of direct transmissions = %u", dear->numDirectTransmissions);
 IO_PrintStat(node, "Network", "DEAR2", ANY_DEST, -1, buf);
 
 // Indirect transmissions.
 sprintf(buf, "Number of indirect transmissions = %u", dear->numIndirectTransmissions);
 IO_PrintStat(node, "Network", "DEAR2", ANY_DEST, -1, buf);
}

/*
 * Protocol routing function.
 */
void Dear2RouterFunction(Node* node, Message* msg, NodeAddress destAddr, NodeAddress previousHopAddress, BOOL* packetWasRouted) {
 double ratio = 1.0e+299;
 NodeAddress nextHop = 0;
 NodeAddress *nextHopInfoPtr = (NodeAddress *)MESSAGE_ReturnInfo(msg, INFO_TYPE_DearNextHop);
 IpHeaderType* ipHeader = (IpHeaderType*)msg->packet;
 
 // Obtain a pointer to the local variable space.
 Dear2Data* dear = (Dear2Data*)NetworkIpGetRoutingProtocol(node, ROUTING_PROTOCOL_DEAR2);
 assert(dear != NULL);
  
 // Do not route any packets destined to self.
 if (MAPPING_GetNodeIdFromInterfaceAddress(node, destAddr) == node->nodeId) {
  // Remove the next hop info field if present.
  if (nextHopInfoPtr != NULL)
   MESSAGE_RemoveInfo(node, msg, INFO_TYPE_DearNextHop);
  return;
 }
 
 // Do not route the packet if we are not the next hop for this packet.
 if (nextHopInfoPtr != NULL && *nextHopInfoPtr != node->nodeId)
  return;
 
 // Find the best neighbour to route packet to.
 for (int i = 1; i <= node->numNodes; i++) {
  // Skip non-neighbours.
  if (!dear->neighbours[i].valid)
   continue;
  
  // Skip the degenerate case where destination sends to destination.
  if (i == dear->destination)
   continue;
  
  // Get the candidate node.
  Node *candidate = DearGetNodeById(node, i);
  
  // Read the battery level of the candidate.
  double battery = DearGetRemainingBatteryPercent(candidate, dear->neighbours[i].battery_max);
  
  // Make sure the node isn't dead.
  if (battery <= 0.0)
   continue;
  
  // Calculate the power in mW.
  double power_mW = pow(10.0, dear->neighbours[i].powerToBase / 10.0);
  
  // Calculate the metric.
  double metric = power_mW / battery;
  
  if (candidate->nodeId != node->nodeId) {
   // INDIRECT TRANSMISSION: Add the default transmission power to neighbour.
   battery = DearGetRemainingBatteryPercent(node, dear->neighbours[node->nodeId].battery_max);
   
   if (battery <= 0.0)
    continue; // This can only happen if the originating node is dead.
   
   // Calculate the power in mW.
   power_mW = pow(10.0, dear->neighbours[i].power / 10.0);
   
   // Adjust the metric. 
   metric += power_mW / battery;
  }
  
  // Check if calculated metric is lower than the lowest metric so far.
  if (metric < ratio) {
   nextHop = i;
   ratio = metric;
  }
 }
 
 // Set the real destination if needed (when next hop is current node,
 // the real next hop is the final destination).
 if (nextHop == node->nodeId)
  nextHop = dear->destination;
 
 // Route the packet only when the destination is considered reachable.
 if (nextHop) {
  if (dear->neighbours[nextHop].valid) {
   dear->numIndirectTransmissions++;
   DearSetTxPower(node, dear->neighbours[nextHop].power);
  } else {
   dear->numDirectTransmissions++;
   DearSetTxPower(node, dear->neighbours[node->nodeId].powerToBase);
  }
  
  // Allocate the next hop information header if needed.
  if (nextHopInfoPtr == NULL) {
   MESSAGE_AddInfo(node, msg, sizeof(nextHop), INFO_TYPE_DearNextHop);
   nextHopInfoPtr = (NodeAddress *)MESSAGE_ReturnInfo(msg, INFO_TYPE_DearNextHop);
   assert(nextHopInfoPtr);
  }
  
  // Write the next hop, and route the packet.
  *nextHopInfoPtr = nextHop;
  *packetWasRouted = TRUE;  
  NetworkIpSendPacketToMacLayer(node, msg, DEFAULT_INTERFACE, nextHop);
 }
}
