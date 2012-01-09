source "routerlib.tcl"

source "sfp_area.tcl" ;# include intf, lsa_db; intf include nbr, intf_fsm; nbr include nbr_fsm;
source "OSPF_util.tcl" ;#parser

variable server "OSPF_server"
package require comm
::comm::comm configure -port $cfg::port($server)

;#intf, msg [hello dd LSR LSU LSAck] 
# if correct msg, generate event [intf, OSPF_msg] 
# if wrong msg, puts msg  

array set msg_proc {
router_server)(ospf  "OSPF_util::parse_ospf body [expr [lindex \$::Ether_Header_parser 0]+[lindex \$::IPv4_Header_parser 0]] OSPF_Header_parser" 
router_server)(up    "set event InterfaceUp"
router_server)(down  "set event InterfaceDown"
timer_server)(hello  "set event HelloTimer"
timer_server)(wait   "set event WaitTimer"
nms_client)(rsh      "eval [set cmd $body]"
}
eval [list puts $::OSPF_Header_parser]
proc msg_comm args {
set event ""
#msg: from id reply_to_id to subject body
set from [lindex $args 0]; set id      [lindex $args 1]; set reply_to_id [lindex $args 2]; 
set to   [lindex $args 3]; set subject [lindex $args 4]; set body        [lindex $args 5]
puts "\n\npktLen=[string length $body]"
puts "From:$from\tID:$id\tReply to:$reply_to_id\tTo:$to\tSubject:$subject"
if {$subject=="rsh"} {puts "Body=$body"} else {puts "Body=[Hex2Char $body]"}
set index "$from)($subject" ;#------------------Lookup
if {0!=[catch {set handle $::msg_proc($index)}]} {puts "Invalid msg"; return}

set time [clock format [clock seconds] -format "%Y-%m-%d %H:%M:%S"]
::log_msg $time $from $id $reply_to_id $to $subject $body ;#save to log DB
puts "Handle=$handle"
return [eval $handle]
}
#---------------------------------------------------------------send ospf test-------------------------------------------------------
set intf "F0/0"
set OSPF_header1 [OSPF_util::build_OSPF_header \
$OSPF_cfg::Version \
$OSPF_cfg::Pkt_Type(Hello) \
[lindex $::OSPF_Header_parser 0]  \
$OSPF_cfg::RID \
$OSPF_cfg::Interface_Data([set t $intf)(AID]) \
"\x00\x00" \
"\x00\x00" \
"\x00\x00\x00\x00\x00\x00\x00\x00" ]

set OSPF_hello1 [OSPF_util::build_OSPF_hello \
[::Len2Mask $OSPF_cfg::Interface_Data([set t $intf)(Mask])]\
$OSPF_cfg::Interface_Data([set t $intf)(HelloInterval]) \
$OSPF_cfg::Hello_Options($intf) \
$OSPF_cfg::Interface_Data([set t $intf)(RouterPri]) \
$OSPF_cfg::Interface_Data([set t $intf)(RouterDeadInterval]) \
$OSPF_cfg::Interface_Data([set t $intf)(DR]) \
$OSPF_cfg::Interface_Data([set t $intf)(BDR]) \
$OSPF_cfg::Interface_Data([set t $intf)(Neighbor*]) ]
set OSPF_pkt1 $OSPF_header1$OSPF_hello1
set OSPF_pkt1 [OSPF_util::update_OSPF_len_chksum OSPF_pkt1]
set ip_header1 [build_ipv4_header 4  5 110000 00 20 0 000 0 1 89 \x00\x00 $OSPF_cfg::Interface_Data([set t $intf)(IP]) $::AllSPFRouters]
set ip_header1 [update_ip_header_len_chksum ip_header1 [string length $ip_header1$OSPF_pkt1]]
set ip1 $ip_header1$OSPF_pkt1
set ether1 [::build_ether_header $::AllSPFRouters_MAC $cfg::myMac $cfg::PID_IP]
set pkt1 $ether1$ip1
puts [Hex2Char $pkt1]
::comm::comm send -async $cfg::port(router_server) send [list "F0/0" $pkt1]

vwait forever