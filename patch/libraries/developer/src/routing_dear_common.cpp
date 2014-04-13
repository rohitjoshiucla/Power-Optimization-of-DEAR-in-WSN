#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <math.h>

#include "api.h"
#include "message.h"
#include "network_ip.h"
#include "routing_dear_common.h"

//////////////////////////////////////// UTILITY FUNCTIONS ////////////////////////////////////////
#include "partition.h"
#include "battery_model.h"
#include "phy_802_11.h"

/*
 * Returns the Node with the specified node ID.
 */
Node *DearGetNodeById(Node *nodeRef, NodeAddress nodeId) {
 // NOTE indexes are [0, count).
 if (nodeId == 0)
  return NULL;
 else
  return nodeRef->partitionData->nodeData[nodeId - 1];
}

/*
 * Gets the node's location in (x, y, z) co-ordinates.
 */
void DearGetNodePosition(Node *node, double &x, double &y, double &z) {
 x = node->mobilityData->current->position.cartesian.x;
 y = node->mobilityData->current->position.cartesian.y;
 z = node->mobilityData->current->position.cartesian.z;
}

/*
 * Returns the remaining battery charge of the selected node.
 */
double DearGetRemainingBattery(Node *node) {
 // Use the API.
 return BatteryGetRemainingCharge(node);
}

/*
 * Returns the remaining battery charge of the selected node.
 */
double DearGetRemainingBatteryPercent(Node *node, double battery_max) {
 // Use the API.
 return 100.0 * BatteryGetRemainingCharge(node) / battery_max;
}

/*
 * Returns the propagation distance for the selected node.
 */
double DearGetPropagationDistance(Node *node) {
 const int interfaceIndex = DEFAULT_INTERFACE;
 
 // Use the API.
 return PHY_PropagationRange(node, interfaceIndex, FALSE);
}

/*
 * Estimates the power required in dBm for the given range, assuming
 * the given input range, power and accuracy.
 */
double DearGetPowerForDistance(Node *node, const double range, const double defaultPower, const double defaultRange) {
 const int interfaceIndex = DEFAULT_INTERFACE;
 const double defaultAccuracy = 1.0; // meter
 const double defaultIncrement = 32.0; // dBm
 
 if (range < 1.0e-3)
  return -100.0; // Prevent an infinite loop.
 
 // This algorithm increments the power in fixed increments till the power
 // is more than sufficient. Then it follows a "binary search"-like method
 // dividing the increment in half till the power is accurate upto one meter.
 double oldPower = DearGetTxPower(node);
 double currPower = defaultPower, incrPower = defaultIncrement;
 double currRange = -1.0;

 for (;;) {
  // Calculate range.
  DearSetTxPower(node, currPower);
  currRange = PHY_PropagationRange(node, interfaceIndex, FALSE);
  
  if (currRange < range) {
   // Increment as long as it's not sufficient.
   currPower += incrPower;
  } else {
   // If we've reached the accuracy limit, then stop.
   if (currRange - range < defaultAccuracy)
    break;
   
   // Remove the increment, halve it, and add back.
   currPower -= incrPower;
   incrPower /= 2;
   currPower += incrPower;
  }
 }
  
 // Set original power.
 DearSetTxPower(node, oldPower);
 return currPower;
}

/*
 * Returns the default transmit power (i.e. the transmit power for the currently selected
 * data rate).
 */
double DearGetTxPower(Node *node) {
 const int interfaceIndex = DEFAULT_INTERFACE;
 
 if (node->phyData[interfaceIndex]->phyModel == PHY802_11a) {
  // We assume the lowest and highest data rate powers are same (and return the highest).
  int dataRate;
  PhyData802_11* phy802_11a = (PhyData802_11*)(node->phyData[interfaceIndex]->phyVar);
  assert(phy802_11a->highestDataRateType == phy802_11a->lowestDataRateType);
  return phy802_11a->txDefaultPower_dBm[phy802_11a->highestDataRateType];
 } else if (node->phyData[interfaceIndex]->phyModel == PHY802_11b) {
  // We assume the lowest and highest data rate powers are same (and return the highest).
  int dataRate;
  PhyData802_11* phy802_11b = (PhyData802_11*)(node->phyData[interfaceIndex]->phyVar); 
  assert(phy802_11b->highestDataRateType == phy802_11b->lowestDataRateType);
  return phy802_11b->txDefaultPower_dBm[phy802_11b->highestDataRateType];
 } else {
  // Use the API. Convert mW to dBm.
  double power = -1.0;
  PHY_GetTransmitPower(node, interfaceIndex, &power);
  return 10.0 * log10(power);
 }
}

/*
 * Sets the transmit power for *ALL* data rates.
 */
void DearSetTxPower(Node *node, const double power) {
 const int interfaceIndex = DEFAULT_INTERFACE;

 if (node->phyData[interfaceIndex]->phyModel == PHY802_11a) {
  // Change the power for all data rates. This is probably not what we should be doing.
  PhyData802_11* phy802_11a = (PhyData802_11*)(node->phyData[interfaceIndex]->phyVar); 
  phy802_11a->txDefaultPower_dBm[PHY802_11a__6M] =
  phy802_11a->txDefaultPower_dBm[PHY802_11a__9M] =
  phy802_11a->txDefaultPower_dBm[PHY802_11a_12M] =
  phy802_11a->txDefaultPower_dBm[PHY802_11a_18M] =
  phy802_11a->txDefaultPower_dBm[PHY802_11a_24M] =
  phy802_11a->txDefaultPower_dBm[PHY802_11a_36M] =
  phy802_11a->txDefaultPower_dBm[PHY802_11a_48M] =
  phy802_11a->txDefaultPower_dBm[PHY802_11a_54M] = power; 
 } else if (node->phyData[interfaceIndex]->phyModel == PHY802_11b) {
  // Change the power for all data rates. This is probably not what we should be doing.
  PhyData802_11* phy802_11b = (PhyData802_11*)(node->phyData[interfaceIndex]->phyVar); 
  phy802_11b->txDefaultPower_dBm[PHY802_11b__1M] =
  phy802_11b->txDefaultPower_dBm[PHY802_11b__2M] =
  phy802_11b->txDefaultPower_dBm[PHY802_11b__6M] =
  phy802_11b->txDefaultPower_dBm[PHY802_11b_11M] = power;
 } else {
  // Use the API. Convert dBm to mW.
  double power_dBm = pow(10.0, power / 10.0);
  PHY_SetTransmitPower(node, interfaceIndex, power_dBm);
 }
}
