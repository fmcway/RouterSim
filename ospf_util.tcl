namespace eval parser {
variable state  0
variable code   0
}
namespace eval OSPF_util {
namespace export parse_ospf Fletcher_Checksum
proc Fletcher_Checksum {in} {} ;#LSA except for the Age
variable OSPF_lls \xff\xf6\x00\x03\x00\x01\x00\x04\x00\x00\x00\x01
#header=Version Type Len RID AID Checksum Auth_Type Auth_Data
#hello=header hello lls
#DD=header dd lsa_header* lls
#lsa_header=Age Options LSA_Type Link_State_ID Advertising_Router Sequence Checksum Len
#lsr=header lsr
#lsu=header lsa_num lsa*
#lsa=lsa_header (router_lsa|net_lsa|netsum_lsa|asbr_lsa|external_lsa|nssa_lsa)
#router_lsa=Reserved1 Virtual_Link_Endpoint_bit External_bit Border_bit Reserved2 Number_of_Links Link*
#link=Link_ID Link_Data Link_Type TOS_Num=0 Metric TOS*=0
#net_lsa=Network_Mask Attached_Router*= in net lsa DB 
#netsum_lsa=Network_Mask Reserved1 Metric
#asbr_lsa=Network_Mask Reserved1 Metric
#nssa_lsa=Network_Mask External_Metric_bit TOS Metric Forwarding_Address External_Route_Tag

array set parser_fsm {
OSPF_Header_parser "OSPF_util::dp_field ospf header type [Bin2Dec \$::OSPF_Header_Type]"
OSPF_Hello_parser  "OSPF_util::get_hello_nbr_parser [expr [lindex \$::Ether_Header_parser 0] + [lindex \$::IPv4_Header_parser 0] + [Bin2Dec \$::OSPF_Header_Len] - \$offset]"
OSPF_Nbr_parser    "OSPF_util::dp_field ospf hello_option [expr 1+[string first 1 \$::OSPF_Hello_Options]]"
OSPF_DD_parser     ""
OSPF_LLS_parser    "OSPF_LLS_TLV_parser"
OSPF_LLS_parser    ""
}

proc extension {options} {}

array set parser_lookup {
ospf)(header)(type)(1 "OSPF_Hello_parser"
ospf)(header)(type)(2 "OSPF_DD_parser"
ospf)(header)(type)(3 "OSPF_LSR_parser"
ospf)(header)(type)(4 "OSPF_LSU_parser"
ospf)(header)(type)(5 "OSPF_LSAck_parser"
ospf)(hello_option)(4 "OSPF_LLS_parser"
}
proc dp_field args {
set index ""
foreach arg $args {append index "($arg)"}; set index [string range $index 1 end-1]
set parser $OSPF_util::parser_lookup($index); return $parser
}
#dp_field ospf header type 1
variable OSPF_Nbr_parser

proc get_hello_nbr_parser {nbr_len} {
set parser ""
set fields ""
if {$nbr_len%4 != 0} { set parser::state "Error"; set parser::code "Hello Nbr: $nbr_len%4 != 0"} else {
set ::OSPF_nbr_num [expr $nbr_len / 4]
for {set i 1} {$i <= $::OSPF_nbr_num} {incr i} {append parser "B32"; append fields "::OSPF_Hello_Neighbor_$i"}
}
set ::OSPF_Nbr_parser "$nbr_len $parser $fields"
return "OSPF_Nbr_parser"
}

proc parse_ospf {pktIn offset parserName} {
upvar $pktIn pkt
set parser::state  $parserName
set parser::code   ""
eval "set parser \$::$parserName"
set pktLen [string length $pkt]
set parserLen [lindex $parser 0]

while {$parser::state!="Error"} {
puts "$offset@$pktLen parser=$parser"
if {$parserLen==0} {set parser::state "Complete"; puts $parser::state:$parser::code;break}
if {[expr $pktLen - $offset] < $parserLen} {
puts "[expr $pktLen - $offset] < $parserLen"
puts -------------------------------
set parser::state "Error"; set parser::code "$pktLen-$offset<$parser";puts $parser::state:$parser::code;break}

eval  "binary scan \$pkt @$offset[lrange $parser 1 end]";#get field of parser
set offset [expr $offset+$parserLen];#Move offset

if {$offset==$pktLen} {set parser::state "Complete";puts $parser::state:$parser::code;break}
set index $parserName; set parserName [eval $OSPF_util::parser_fsm($index)] ;#Use current parser to get next parser from fsm
eval "set parser \$::$parserName";set parserLen [lindex $parser 0];
}
puts "::OSPF_Hello_Network_Mask= [Bin2IPv4 $::OSPF_Hello_Network_Mask]"
puts "::OSPF_Hello_Interval=[Bin2Dec $::OSPF_Hello_Interval]"
puts "::OSPF_Hello_Options=[Bin2Dec $::OSPF_Hello_Options]"  
puts "::OSPF_Hello_Pri=[Bin2Dec $::OSPF_Hello_Pri ]" 
puts "::OSPF_Hello_Dead_Interval =[Bin2Dec  $::OSPF_Hello_Dead_Interval]"
puts "::OSPF_Hello_DR=[Bin2IPv4 $::OSPF_Hello_DR ]" 
puts "::OSPF_Hello_BDR=[Bin2IPv4 $::OSPF_Hello_BDR ]"
puts "OSPF_nbr_num=$::OSPF_nbr_num"
for {set i 1} {$i<=$::OSPF_nbr_num} {incr i} {puts [eval "set t \$::OSPF_Hello_Neighbor_$i"];}
}

proc build_OSPF_header {ver type len rid aid chksum atype adata} {
set OutPkt([set t OSPF)(Header)(1)(Version])  [Dec2Bin8 $ver]
set OutPkt([set t OSPF)(Header)(2)(Type])     [Dec2Bin8 $type]
set OutPkt([set t OSPF)(Header)(3)(Len])      [Dec2Bin16 $len]
set OutPkt([set t OSPF)(Header)(4)(RID])      [IPv42Bin $rid]
set OutPkt([set t OSPF)(Header)(5)(AID])      [Dec2Bin32 $aid]
set OutPkt([set t OSPF)(Header)(6)(Checksum]) [Hex2Bin $chksum]
set OutPkt([set t OSPF)(Header)(7)(AuthType]) [Hex2Bin $atype]
set OutPkt([set t OSPF)(Header)(8)(AuthData]) [Hex2Bin $adata]
set pattern [lindex $::OSPF_Header_parser 1] 
set varList ""
set expr "(?i)ospf\\)\\(header"
set indexes [lsort [lsearch -inline -all -regexp [array name OutPkt] $expr]]
foreach index $indexes {append varList "$OutPkt($index) "}
set pkt [eval "binary format $pattern $varList"]; # B3B6... 0010 000 00110 ...
}

proc build_OSPF_hello {mask interval options pri deadinterval dr bdr nbrs} {
set OutPkt([set t OSPF)(Hello)(1)(Network_Mask]) [IPv42Bin $mask]
set OutPkt([set t OSPF)(Hello)(2)(Interval])     [Dec2Bin16 $interval]
set OutPkt([set t OSPF)(Hello)(3)(Options])      $options
set OutPkt([set t OSPF)(Hello)(4)(Pri])          [Dec2Bin8 $pri]
set OutPkt([set t OSPF)(Hello)(5)(Dead_Interval]) [Dec2Bin32 $deadinterval]
set OutPkt([set t OSPF)(Hello)(6)(DR])           [IPv42Bin $dr]
set OutPkt([set t OSPF)(Hello)(7)(BDR])          [IPv42Bin $bdr]
set OutPkt([set t OSPF)(Hello)(8)(Neighbor*])    [IPv4List2Bin $nbrs]

set pattern "[lindex $::OSPF_Hello_parser 1][string repeat "B4" [llength $nbrs]]"
set varList ""
set expr "(?i)ospf\\)\\(hello"
set indexes [lsort [lsearch -inline -all -regexp [array name OutPkt] $expr]]
foreach index $indexes {append varList "$OutPkt($index) "}
set pkt [eval "binary format $pattern $varList"]; 
}

proc update_OSPF_len_chksum {pktIn} {
upvar $pktIn pkt
set offset [parser_field_pos "(?i)len" $::OSPF_Header_parser ]
set pkt [string replace $pkt $offset [expr $offset+1] [16bitDec2Hex [string length $pkt]]]
set offset [parser_field_pos "(?i)ch(ec)?ksum" $::OSPF_Header_parser ]
set pkt [string replace $pkt $offset [expr $offset+1] [16bitDec2Hex [inet_cksum32 $pkt]]]
}


proc link_init {intf } {
variable ifLink "" ;#$OSPF_util::intf_Type($intf)
if {$ifLink == $OSPF_cfg::Link_Type(stub) } {
set OSPF_util::Link_ID($intf)     [::IPv4Prefix $OSPF_util::intf_IP($intf) $OSPF_util::intfMask($intf)] 
# Network/subnet 1.0.0.0
set OSPF_util::Link_Data($intf)   [::Len2Mask $OSPF_util::intfMask($intf)] 
# Network Mask 255.0.0.0
}
if {$ifLink == $OSPF_cfg::Link_Type(transit)} {
set OSPF_util::Link_ID($intf)     $OSPF_util::DR_intf_IP($intf)  ;# DR_intf_IP 1.0.0.2
set OSPF_util::Link_Data($intf)   $OSPF_util::intf_IP($intf)     ;# intf_IP 1.0.0.1
}
if {$ifLink == $OSPF_cfg::Link_Type(p2p)} {
set OSPF_util::Link_ID($intf)     $OSPF_util::Neighbor_Rid($intf) ;# Neighbor_Rid 1.0.0.2
set OSPF_util::Link_Data($intf)   $OSPF_util::intf_IP($intf)        ;# Network Mask 1.0.0.1
}
if {$ifLink == $OSPF_cfg::Link_Type(vl)} {
set OSPF_util::Link_ID($intf)     $OSPF_util::Neighbor_Rid($intf)       ;# Neighbor_Rid 1.0.0.2
set OSPF_util::Link_Data($intf)   $OSPF_util::Mib_II($intf) 			  ;# Mib_II 1
}
}

link_init F0/0
link_init F1/0
}
#--------------------------------------------test----------------------------------
#set body "sdasd"
#OSPF_util::parse_ospf $body