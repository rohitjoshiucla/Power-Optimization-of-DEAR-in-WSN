#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <math.h>

#include "api.h"
#include "message.h"
#include "network_ip.h"
#include "routing_dear.h"
#include "routing_dear_common.h"

static const double DearPowerBoost = 2.0; // in dBm

/*
 * Protocol initialization function. Check parameters, allocate storage space, read parameters, etc.
 */
void DearInit(Node* node, DearData** dearPtr, const NodeInput* nodeInput, int interfaceIndex) {
 BOOL retVal;
 
 if (MAC_IsWiredNetwork(node, interfaceIndex))
  ERROR_ReportError("DEAR supports only wireless interfaces");
  
 if (node->numberInterfaces > 1)
  ERROR_ReportError("DEAR supports only one interface of node");
  
 // Allocate memory for variables of this node.
 DearData* dear = (DearData*)MEM_malloc(sizeof(DearData));
 (*dearPtr) = dear;
 
 // Reset transmission power.
 DearSetTxPower(node, DearGetTxPower(node));
 
 // Initalize parameters.
 dear->destination = 1;
 dear->defaultPower = DearGetTxPower(node);
 dear->defaultRange = DearGetPropagationDistance(node);
 dear->neighbours = (DearTableEntry*)MEM_malloc((1 + node->numNodes) * sizeof(DearTableEntry));

 // Read parameter(s).
 IO_ReadInt(node->nodeId, ANY_ADDRESS, nodeInput, "DEAR-DESTINATION", &retVal, (int*)(&dear->destination));
 if (!retVal)
  ERROR_ReportError("DEAR-DESTINATION not specified!");
 
 // Initialize statistics.
 dear->numIndirectTransmissions =
 dear->numDirectTransmissions = 0;
 
 // Obtain the neighbours.
 for (int i = 1; i <= node->numNodes; i++) {
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
  // Then set the valid neighbour property.
  x0 -= x1; y0 -= y1; z0 -= z1;
  double distance0 = sqrt(x0 * x0 + y0 * y0 + z0 * z0);
  dear->neighbours[i].valid = (distance0 < dear->defaultRange);
  
  // Calculate distance between destination and neighbour.
  // Then estimate transmission power in dBm. Assume the default transmission power
  // is used for the given neighbour size (this is expected to preserve the error rate).
  x2 -= x1; y2 -= y1; z2 -= z1;
  double distance2 = sqrt(x2 * x2 + y2 * y2 + z2 * z2);
  dear->neighbours[i].power = DearGetPowerForDistance(neighbour, distance2, dear->defaultPower, dear->defaultRange) + DearPowerBoost;
  
  // NOTE the power does NOT fall below the default power (this violates "correctness").
  if (dear->neighbours[i].power < dear->defaultPower)
   dear->neighbours[i].power = dear->defaultPower;
 }
 
 // Tell IP to use our function to route packets.
 NetworkIpSetRouterFunction(node, &DearRouterFunction, interfaceIndex);
}

/*
 * Protocol event handler (nothing to do).
 */
void DearHandleProtocolEvent(Node* node, Message* msg) {
 // No messages used.
 assert(false);
}

/*
 * Protocol packet handler (nothing to do).
 */
void DearHandleProtocolPacket(Node* node, Message* msg, NodeAddress sourceAddress) {
 // No messages used.
 assert(false); 
}

/*
 * Protocol finalization function.
 */
void DearFinalize(Node *node) {
 char buf[MAX_STRING_LENGTH];
 
 // Obtain a pointer to the local variable space.
 DearData* dear = (DearData*)NetworkIpGetRoutingProtocol(node, ROUTING_PROTOCOL_DEAR);
 assert(dear != NULL);
 
 // Report statistics in stat file.
 // Direct transmissions.
 sprintf(buf, "Number of direct transmissions = %u", dear->numDirectTransmissions);
 IO_PrintStat(node, "Network", "DEAR", ANY_DEST, -1, buf);
 
 // Indirect transmissions.
 sprintf(buf, "Number of indirect transmissions = %u", dear->numIndirectTransmissions);
 IO_PrintStat(node, "Network", "DEAR", ANY_DEST, -1, buf);
}

/*
 * Protocol routing function.
 */
void DearRouterFunction(Node* node, Message* msg, NodeAddress destAddr, NodeAddress previousHopAddress, BOOL* packetWasRouted) {
 double ratio = 1.0e+299;
 NodeAddress nextHop = 0;
 NodeAddress *nextHopInfoPtr = (NodeAddress *)MESSAGE_ReturnInfo(msg, INFO_TYPE_DearNextHop);
 IpHeaderType* ipHeader = (IpHeaderType*)msg->packet;
   
 // Obtain a pointer to the local variable space.
 DearData* dear = (DearData*)NetworkIpGetRoutingProtocol(node, ROUTING_PROTOCOL_DEAR);
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
  double power_mW = pow(10.0, dear->neighbours[i].power / 10.0);
  
  // Calculate the metric.
  double metric = power_mW / battery;
  
  if (candidate->nodeId != node->nodeId) {
   // INDIRECT TRANSMISSION: Add the default transmission power to neighbour.
   battery = DearGetRemainingBatteryPercent(node, dear->neighbours[node->nodeId].battery_max);
   
   if (battery <= 0.0)
    continue; // This can only happen if the originating node is dead.
   
   // Calculate the power in mW.
   power_mW = pow(10.0, dear->defaultPower / 10.0);
   
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
   DearSetTxPower(node, dear->defaultPower);   
  } else {
   dear->numDirectTransmissions++;
   DearSetTxPower(node, dear->neighbours[node->nodeId].power);
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
