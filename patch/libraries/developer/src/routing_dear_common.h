#ifndef _DEAR_COMMON_H_
#define _DEAR_COMMON_H_

// Utility function prototypes.
Node *DearGetNodeById(Node *nodeRef, NodeAddress nodeId);
void DearGetNodePosition(Node *node, double &x, double &y, double &z);
double DearGetRemainingBattery(Node *node);
double DearGetRemainingBatteryPercent(Node *node, double battery_max);
double DearGetPropagationDistance(Node *node);
double DearGetPowerForDistance(Node *node, const double range, const double defaultPower, const double defaultRange);
double DearGetTxPower(Node *node);
void DearSetTxPower(Node *node, const double power);

#endif
