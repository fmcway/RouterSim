namespace eval OSPF_intf_fsm {
proc intf_state_Down {intf} {init_intf $intf; disable_intf_timer $intf;clear_adjacency $intf}
proc intf_state_Loopback {intf} {}
proc intf_state_Waiting {intf} {}
proc intf_state_P2P {intf} {form_adjacency neighbor $intf; send_hello}
proc intf_state_DRother {intf} {form_adjacency $dr($intf) } 
proc intf_state_BDR {intf} {form_adjacency neighbor $intf; flooding $intf}
proc intf_state_DR {intf} {form_adjacency neighbor $intf; flooding $intf}
proc intf_event_InterfaceUp {intf} {if {$intfStatus{$intf}=="Up"} {return 1}; return 0}
proc intf_event_WaitTimer {intf} {if {$WaitTimer($intf)==1} {set WaitTimer($intf) 0; return 1}; return 0}
proc intf_event_BackupSeen {intf} {return [expr [neighbor_is_bdr $intf] || [neighbor_is_dr $intf] ]}
proc intf_event_NeighborChange {intf} {
if {[neighbor_state $intf]>=$neighbor_fsm_state(2-Way)} {return 1}
if {[neighbor_state $intf]<=$neighbor_state(Init)} {return 1}
if {$dr_change($intf)==1} {set dr_change($intf) 0;return 1}   ;#seen from Hello 
if {$bdr_change($intf)==1} {set bdr_change($intf) 0;return 1} ;#seen from Hello 
if {$pri_change($intf)==1} {set pri_change($intf) 0;return 1} ;#seen from Hello 
return 0}
proc intf_event_LoopInd {intf} {if {$intfStatus{$intf}=="Loopback"} {return 1}; return 0}
proc intf_event_UnloopInd {intf} {if {$intfStatus{$intf}!="Loopback"} {return 1}; return 0}
proc intf_event_InterfaceDown {intf} {if {$intfStatus{$intf}=="Down"} {return 1}; return 0}
array set intf_fsm_state {
Down	0
Loopback 1
Waiting	2
P2P	3
DRother	4
BDR 5
DR	6
Error 100
}
array set intf_fsm_event {
None 0
InterfaceUp 1
WaitTimer 2
BackupSeen 3
NeighborChange 4
LoopInd 5
UnloopInd 6
InterfaceDown 7
F0/0 None
F1/0 None
}

array set intf_fsm {
Down)(InterfaceUp "intf_fsm_dp(Down)(InterfaceUp) start_hello_timer"

Waiting)(BackupSeen "dr_bdr_election"
Waiting)(WaitTimer "dr_bdr_election"

DRother)(NeighborChange "dr_bdr_election"
BDR)(NeighborChange "dr_bdr_election"
DR)(NeighborChange "dr_bdr_election"

Down)(InterfaceDown "Set_State_Loopback reset_intf"
Loopback)(InterfaceDown "Set_State_Loopback reset_intf"
Waiting)(InterfaceDown "Set_State_Loopback reset_intf"
P2P)(InterfaceDown "Set_State_Loopback reset_intf"
DRother)(InterfaceDown "Set_State_Loopback reset_intf"
BDR)(InterfaceDown "Set_State_Loopback reset_intf"
DR)(InterfaceDown "Set_State_Loopback reset_intf"

Down)(LoopInd "Set_State_Loopback reset_intf"
Loopback)(LoopInd "Set_State_Loopback reset_intf"
Waiting)(LoopInd "Set_State_Loopback reset_intf"
P2P)(LoopInd "Set_State_Loopback reset_intf"
DRother)(LoopInd "Set_State_Loopback reset_intf"
BDR)(LoopInd "Set_State_Loopback reset_intf"
DR)(LoopInd "Set_State_Loopback reset_intf"

Loopbacak)(UnloopInd "Set_State_Down"
}
proc Set_State_Down {} {return "Down"}
proc Set_State_Loopback {} {return "Loopback"} 
proc reset_intf {intf} {
#reset para
#clear timer
#foreach neighbors send event KillNbr 
}
proc intf_fsm_dp(Down)(InterfaceUp) {intf} {
set index "$intf)(Type"
set intf_Type $Interface_Data($index)
if {$intf_Type=="P2P"||"P2MP"||"Virtual_Link"} {return "P2P"}
if {$intf_Type=="Broadcast"||"NBMA"} {
if {[DR_Eligible $intf]!=1} {return "DRother"} 
start_wait_timer; 
if {$intf_Type=="NBMA"} {start_nbma_neighbor $intf}
return "Waiting"
}
puts "intf_fsm_dp(Down)(InterfaceUp) Error"; exit
}


proc start_hello_timer {intf} {}
proc DR_Eligible {intf} {
set index "$intf)(RouterPri"
set pri $OSPF_util::Interface_Data($index)
if {$pri>0} {return 1}
return 0
}
proc start_wait_timer {intf} {}
proc start_nbma_neighbor {intf} {}
proc dr_bdr_election {intf} {
set DR 0.0.0.0
set BDR 0.0.0.0
#get all eligible neighbors (state>=2-way && pri>0 ) +self if eligible
#from declared_dr, elect [pri, rid] highest to be dr
#from left router, from bdr_declared, elect [pri, rid] highest to be bdr
#from [none declare] elect [pri, rid] highest to be bdr
return 
}
}