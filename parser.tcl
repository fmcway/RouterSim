source routerlib.tcl
#--------------------------------------------------------------------------------------------------------------------------------
proc parser_byte {parser} {lindex $parser 0}
#------------------------------------------------------------------------------------------------------------------------------
proc get_formator {parser_name} {set formator_name [string map {parser formator} $parser_name ]; eval return \$::$formator_name}
#get_formator Ether_Header_parser;return;# [Bin2Dec $::Ether_Header_DMAC]=Ether_Header_formator
#------------------------------------------------------------------------------------------------------------------------------
proc build_parser {db table protocol message} {
set pattern "";set fields "";set bits 0;
$db eval "SELECT * FROM $table where protocol='$protocol' AND message='$message'" values {
if {[string is integer -strict $values(Length)] && $values(Length)>0} {
append pattern    "B$values(Length)"; 
append fields     "::$protocol" "_$message" "_$values(Field) ";
set bits [expr $bits+$values(Length)]}
}
return "[expr $bits/8] $pattern $fields"
}
#-----------------------------------------------------------------------------------------------------------------------------
proc build_all_parser {db table} {
$db eval "SELECT DISTINCT protocol,message FROM $table" values {
set protocol $values(Protocol); set message $values(Message)
set cmd  [join [list "set ::$protocol" "_$message" "_parser \[build_parser $db $table $protocol $message" "\]"] ""]
eval $cmd
set cmd  [join [list "set ::$protocol" "_$message" "__Len \[parser_byte \$::$protocol" "_$message" "_parser\]"] ""]
eval $cmd
}
}
#-----------------------------------------------------------------------------------------------------------------------------
proc build_formator {db table protocol message} {
set pattern ""
$db eval "SELECT * FROM $table where protocol='$protocol' AND message='$message'" values {
if {[string is integer -strict $values(Length)] && $values(Length)>0} {
set var ""; append var "$" "::" "$protocol" "_" "$message" "_" "$values(Field)";
if {![string is space $values(Format)]}  {
append pattern "\[$values(Format) " "$var" "\] "
} else {
append pattern "$var "}
}
}
return "$pattern"
}
#-----------------------------------------------------------------------------------------------------------------------------
proc build_all_formator {db table} {
$db eval "SELECT DISTINCT protocol,message FROM $table" values {
set protocol $values(Protocol); set message $values(Message)
set name ""; append name "::" "$protocol" "_" "$message" "_formator"
set $name [build_formator $db $table $protocol $message]
}
}
#-----------------------------------------------------------------------------------------------------------------------------
proc parser_field_pos {exp in} {
if {[regexp $exp $in]==0} {return -1};
set bitLens [lrange [split [lindex $in 1] "B"] 1 end]; set vars [lrange $in 2 end];#
set pos [lsearch -regexp $vars $exp]
for {set i 0;set offset 0} {$i < $pos} {incr i} {set offset [expr $offset + [lindex $bitLens $i]]};
return [expr $offset/8]
}
#puts [parser_field_pos "(?i)ch(ec)?ksum" "24 B8B16B16 Ver Len Checksum"]
#------------------------------------------------------------------------------------------------------------------------------
proc fixed_parsing {pktIn offsetIn lenIn parserIn} {
upvar $pktIn pkt $offsetIn offset $lenIn len;set parser_len [lindex $parserIn 0];set pkt_len [string length $pkt];
puts "fixed_parsing:begin...pkt_len:$pkt_len,offset:$offset,len=$len\n"
if {$len < $parser_len || $pkt_len<($offset+$len)} {
puts "fixed_parsing:exit...len($len)<parser_len($parser_len) || pkt_len($pkt_len)<offset($offset)+len($len)\n"
return "";}
set offset_old $offset;set len_old $len
if {[set list_out [binary_scan $pkt $offset $parserIn]]!=""} {
incr offset $parser_len
set len [expr $len - $parser_len]
}
puts "fixed_parsing:end...offset:$offset=$offset_old+$parser_len,len:$len=$len_old-$parser_len\n"
#list_out=$list_out\n"
return $list_out
}
#set pkt \
01005e000005c20126880000080045c0005004e200000159d2ac01000002e0000005020100306400000200000000bf9400000000000000000000ff000000000a1201000000280100000200000000c8000001fff600030001000400000001 ;set pkt [Char2Hex $pkt];\
set offset 14;set len 20;set listOut [fixed_parsing pkt offset len $::IPv4_Header_parser];puts "offset=$offset\n$listOut";return
#------------------------------------------------------------------------------------------------------------------------------
array set parser_fsm {
Ether_Header_parser    {
set offset [set ::Ether_Payload__Offset [expr $::Ether_Header__Offset + $::Ether_Header__Len]];
set len    [set ::Ether_Payload__Len    [expr $::Ether__Len           - $::Ether_Header__Len]];
set parser [get_ether_type_len_parser $::Ether_Header_Type_Len]
}

ether_header_type_0800 {
set ::IPv4_Header__Offset $::Ether_Payload__Offset
set parser "IPv4_Header_parser"
}

ether_header_type_8100 {
set parser "802.1Q_parser"
}

Ether_Header_Len       {
set parser "Ether_LLC_parser"
}
}
proc get_ether_type_len_parser {len} {
if {[Bin2Dec $len] > 1500} {set parser "ether_header_type_[Bin2Hex2Char $len]"} else {set parser "Ether_Header_Len"}
}
#puts [get_ether_type_len_parser [Hex2Bin [Char2Hex 0800]]];\
puts [get_ether_type_len_parser [Dec2Bin 1500 16]];return
#------------------------------------------------------------------------------------------------------------------------------
array set parser_fsm {
IPv4_Header_parser  {
set ::IPv4__Len  [Bin2Dec $::IPv4_Header_Len]
set offset [set ::IPv4_Payload__Offset [expr $::IPv4_Header__Offset + $::IPv4_Header__Len]];
set len    [set ::IPv4_Payload__Len    [expr $::IPv4__Len           - $::IPv4_Header__Len]];
set parser ipv4_header_pid_[Bin2Dec $::IPv4_Header_PID]
}

ipv4_header_pid_89  {
set ::OSPF_Header__Offset $::IPv4_Payload__Offset
set parser "OSPF_Header_parser"
}
}
#---------------------------------------------------------------------------------------------------------------------------------
array set parser_fsm {
OSPF_Header_parser  {
set ::OSPF__Len [Bin2Dec $::OSPF_Header_Len]
#set offset [set ::OSPF_Payload__Offset [expr $::OSPF_Header__Offset + $::OSPF_Header__Len]];
set len    [set ::OSPF_Payload__Len    [expr $::OSPF__Len           - $::OSPF_Header__Len]];
set parser ospf_header_type_[Bin2Dec $::OSPF_Header_Type]
}

ospf_header_type_1  {
set ::OSPF_Hello__Len     $::OSPF_Payload__Len
#set ::OSPF_Hello__Offset  $::OSPF_Payload__Offset
set parser "OSPF_Hello_parser"
}

ospf_header_type_2  {
set parser "OSPF_DD_parser"
}

ospf_header_type_3  {
set parser "OSPF_LSR"
}

ospf_header_type_4  {
set parser "OSPF_LSU_parser"
}

ospf_header_type_5  {
set parser "OSPF_LSAck"
}
}
#------------------------------------------------------------------------------------------------------------------------------
array set parser_fsm {
OSPF_LSR          {
set lsr_list [list_parsing pkt offset len OSPF_LSR_Item]
set ::OSPF_LSR_Num [llength $lsr_list]
lappend parsing_list $lsr_list
set parser ""
}

OSPF_LSR_Item {
set parser "OSPF_LSR_Item_parser"
}
}
#------------------------------------------------------------------------------------------------------------------------------
array set parser_fsm {
OSPF_LSAck          {
set lsa_hdr_list [list_parsing pkt offset len OSPF_LSA_Header]
set ::OSPF_LSAck_LSA_Header_Num [llength $lsa_hdr_list]
lappend parsing_list $lsa_hdr_list
set parser ""
}
}
#------------------------------------------------------------------------------------------------------------------------------
array set parser_fsm {
OSPF_Hello_parser   {
set nbr_list [list_parsing pkt offset len OSPF_Hello_Nbr]
set parsing_list [lappend_lindex $parsing_list end $nbr_list]

# parsing ospf_hello
# get ospf_hello parser_list:
# ospf_hello_fixed_parser_1 -> set ospf_hello_fixed_parsing_1 [fixed_parsing pkt offset len ospf_hello_part1_parser]
# ospf_hello_list_parser_1* -> set ospf_hello_fixed_parsing_1 [list_parsing pkt offset len ospf_hello_v1
# ospf_hello_tlv_parser_1* -> tlv_parsing pkt offset len ospf_hello_v1
# ospf_hello_fixed_parser_2  parsing pkt offset len ospf_hello_part2_parser
# ospf_hello_v2* -> list_parsing pkt offset len ospf_hello_v2
# osfp_hello_last 

if {$offset<[string length $pkt]} { 
set option_bits $::OSPF_Hello_Options;set parser "OSPF_Options"
} else { set parser ""
}
}

OSPF_Hello_Nbr {
set parser "OSPF_Nbr_parser"
}
}
#------------------------------------------------------------------------------------------------------------------------------
array set parser_fsm {
OSPF_Options	{
puts "len=$len,offset=$offset,pkt_len=[string length $pkt]"
set len [expr [Bin2Dec $::IPv4_Header_Len] - 4*[Bin2Dec $::IPv4_Header_HLen]- [Bin2Dec $::OSPF_Header_Len]]
puts "len=$len,offset=$offset,pkt_len=[string length $pkt]";

if {[set option_list [option_list_parsing pkt offset len ospf_option $option_bits]]!=""} {
lappend parsing_list $option_list}
set parser ""
}

ospf_option_4 {
set parser OSPF_LLS
}

OSPF_LLS      {
if {[set ospf_lls [parsing pkt offset len "OSPF_LLS_parser"]]!=""} {
lassign [lindex $ospf_lls 0] checksum len_in_4byte;# ospf_lls={{checksum len_in_4_byte}} 
set len [expr $len_in_4byte * 4 - [parser_byte $::OSPF_LLS_parser]]  ;# len=4 byte*len-tlv_header_len
if {[set tlvs [list_parsing pkt offset len OSPF_LLS_TLV]]!=""} {
set ospf_lls [lappend_lindex $ospf_lls end $tlvs]
}
}
set parsing_list $ospf_lls
set parser ""
}

OSPF_LLS_TLV  {
if {[set tlv [tlv_parsing pkt offset len "OSPF_LLS_TLV_parser" 1 0]]!=""} {
set parsing_list $tlv ;#TLV parsing is called separately, do not need to lappend parsing_list
}
set parser ""
}
}
#------------------------------------------------------------------------------------------------------------------------------
array set parser_fsm {
OSPF_DD_parser      {
set len [expr [Bin2Dec $::OSPF_Header_Len] - [parser_byte $::OSPF_Header_parser]-[parser_byte $::OSPF_DD_parser]]
set lsa_hdr_list [list_parsing pkt offset len OSPF_LSA_Header]
set ::OSPF_DD_LSA_Header_Num [llength $lsa_hdr_list]
set parsing_list [lappend_lindex $parsing_list end $lsa_hdr_list]
if {$offset<[string length $pkt]} {
set option_bits $::OSPF_DD_Options; set parser "OSPF_Options"
} else {
set parser ""
}
}
}
#------------------------------------------------------------------------------------------------------------------------------
array set parser_fsm {
OSPF_LSA_Header {
set parser "OSPF_LSA_Header_parser"
}
}
#------------------------------------------------------------------------------------------------------------------------------
array set parser_fsm {
OSPF_LSU_parser     {
set len [expr [Bin2Dec $::OSPF_Header_Len] - [parser_byte $::OSPF_Header_parser]-[parser_byte $::OSPF_LSU_parser]]
set lsa_list [list_parsing pkt offset len OSPF_LSA [Bin2Dec $::OSPF_LSU_LSA_Num]]
set parsing_list [lappend_lindex $parsing_list end $lsa_list]
set parser ""
}
}
#------------------------------------------------------------------------------------------------------------------------------
array set parser_fsm {
OSPF_LSA     {
if {[set lsa_header [parsing pkt offset len "OSPF_LSA_Header_parser"]]!=""} {
     set len [expr [Bin2Dec $::OSPF_LSA_Header_Len] -[parser_byte $::OSPF_LSA_Header_parser]]
     if {[set lsa_body [parsing pkt offset len "OSPF_LSA_Header_Type_[Bin2Dec $::OSPF_LSA_Header_Type]"]]!=""} {
     set parsing_list "\{ $lsa_header $lsa_body \}"
     }
} 
set parser ""
}

OSPF_LSA_Header_Type_1 {
set parser "OSPF_Router_LSA_parser"
}

OSPF_LSA_Header_Type_2 {
set parser "OSPF_Network_LSA_parser"
}

OSPF_LSA_Header_Type_3 {
set parser "OSPF_Network_Sumary_LSA_parser"
}

OSPF_LSA_Header_Type_4 {
set parser "OSPF_ASBR_Sumary_LSA_parser"
}

OSPF_LSA_Header_Type_5 {
set parser "OSPF_AS_External_LSA"
}

OSPF_LSA_Header_Type_6 {
set parser "OSPF_Group_LSA_parser"
}

OSPF_LSA_Header_Type_7 {
set parser "OSPF_NSSA_External_LSA_parser"
}
}
#------------------------------------------------------------------------------------------------------------------------------
array set parser_fsm {
OSPF_Router_LSA_parser         {
set len [expr [Bin2Dec $::OSPF_LSA_Header_Len]-[parser_byte $::OSPF_LSA_Header_parser]-[parser_byte $::OSPF_Router_LSA_parser]]
set links [list_parsing pkt offset len OSPF_Link [Bin2Dec $::OSPF_Router_LSA_LinkNum]]
set parsing_list [lappend_lindex $parsing_list end $links]
set parser ""
}

OSPF_Link			{
if {[set link [parsing pkt offset len "OSPF_Link_parser"]]==""} { 
set parser ""
} elseif {[set tos_list [list_parsing pkt offset len OSPF_TOS [Bin2Dec $::OSPF_Link_TOS_Num]]]!=""} {
lappend link $tos_list
} else {
set  parsing_list $link
}
set parser ""
}

OSPF_TOS {
set parser "OSPF_TOS_parser"
}
}
#------------------------------------------------------------------------------------------------------------------------------
array set parser_fsm {
OSPF_Network_LSA_parser        {
set len [expr [Bin2Dec $::OSPF_LSA_Header_Len]-[parser_byte $::OSPF_LSA_Header_parser]-[parser_byte $::OSPF_Network_LSA_parser]]
set attach_router_list [list_parsing pkt offset len OSPF_Attach_Router]; 
set ::OSPF_Network_LSA_Attach_Router_Num [llength $attach_router_list]
set parsing_list [lappend_lindex $parsing_list end $attach_router_list]
set parser ""
}
OSPF_Attach_Router {
set parser "OSPF_Router_parser"
}
}
#------------------------------------------------------------------------------------------------------------------------------
array set parser_fsm {
OSPF_Network_Sumary_LSA_parser {
set len [expr [Bin2Dec $::OSPF_LSA_Header_Len]-[parser_byte $::OSPF_LSA_Header_parser]-[parser_byte $::OSPF_Network_Sumary_LSA_parser]]
set metric_list [list_parsing pkt offset len OSPF_Metric]; 
set ::OSPF_Network_Summary_LSA_Metric_Num [llength $metric_list]
set parsing_list [lappend_lindex $parsing_list end $metric_list]
set parser ""
}

OSPF_Metric {
set parser "OSPF_Metric_parser"
}
}
#------------------------------------------------------------------------------------------------------------------------------
array set parser_fsm {
OSPF_ASBR_Sumary_LSA_parser    {
set len [expr [Bin2Dec $::OSPF_LSA_Header_Len]-[parser_byte $::OSPF_LSA_Header_parser]-[parser_byte $::OSPF_ASBR_Sumary_LSA_parser]]
set metric_list [list_parsing pkt offset len OSPF_Metric]; 
set ::OSPF_ASBR_Summary_LSA_Metric_Num [llength $metric_list]
set parsing_list [lappend_lindex $parsing_list end $metric_list]
set parser ""
}
}
#------------------------------------------------------------------------------------------------------------------------------
array set parser_fsm {
OSPF_AS_External_LSA    {
set metric_list [list_parsing pkt offset len OSPF_External_Metric]; 
set ::OSPF_AS_External_LSA_Metric_Num [llength $metric_list]
set parsing_list [lappend_lindex $parsing_list end $metric_list]
set parser ""
}

OSPF_External_Metric {
set parser "OSPF_External_Metric_parser"
}
}
#------------------------------------------------------------------------------------------------------------------------------
array set parser_fsm {
OSPF_Group_LSA_parser		   ""
}
#------------------------------------------------------------------------------------------------------------------------------
array set parser_fsm {
OSPF_NSSA_External_LSA  {
set metric_list [list_parsing pkt offset len OSPF_External_Metric]; 
set ::OSPF_NSSA_External_LSA_Metric_Num [llength $metric_list]
set parsing_list [lappend_lindex $parsing_list end $metric_list]
set parser ""
}
}
#------------------------------------------------------------------------------------------------------------------------------
proc parsing {pktIn offsetIn lenIn parserNameIn} {
upvar $pktIn pkt $offsetIn offset $lenIn len;set parser_name $parserNameIn;
set parsing_list "";
while {1} {
set offset_old $offset
if {[info exists ::$parser_name]} { eval "set parser \$::$parser_name";
puts "-------------------------------parsing: $parser_name begin...offset=$offset,len=$len
$parser_name=$parser\n"
if {[set var [fixed_parsing pkt offset len $parser]]==""} {
puts "-------------------------------parsing: $parser_name null...offset=$offset,len=$len\n"
break
}
eval set var \"[get_formator $parser_name]\"
lappend parsing_list $var
if {$len<=0} {break}
puts "var=$var
parsing_list=$parsing_list
-------------------------------parsing: $parser_name end...offset=$offset,len=$len\n"
}
set old_parser_name $parser_name
if {[info exists ::parser_fsm($parser_name)]} {
  puts "-------------------------------parsing:$old_parser_name action begin...offset=$offset,len=$len
  parser_fsm($parser_name):$::parser_fsm($parser_name)" 
  if {[set parser_name [eval $::parser_fsm($parser_name)]]==""}  {
  puts "-------------------------------parsing:$old_parser_name no next parser...offset=$offset,len=$len\n"
  break
  }
  puts "-------------------------------parsing: $old_parser_name action end...offset=$offset,len=$len\n" 
} else {
  puts "-------------------------------parsing: $old_parser_name no more action...offset=$offset,len=$len\n"
  break
}
}
return $parsing_list
}
#------------------------------------------------------------------------------------------------------------------------------
proc tlv_parsing {pktIn offsetIn lenIn tl_parserName lenByte inclusive} {
upvar $offsetIn offset  $pktIn pkt $lenIn len;set parser_name $tl_parserName;
if {![info exists ::$parser_name]} { return ""}
eval "set parser \$::$parser_name";
set pkt_len  [string length $pkt];set pkt_left [expr $pkt_len - $offset]
puts "--------------------------------------tlv_parsing:tl begin...pkt_len=$pkt_len,offset=$offset,len=$len
$parser_name=$parser,LenByte=$lenByte,inclusive=$inclusive\n"
set offset_old $offset;
if {[set tl [fixed_parsing pkt offset len $parser] ]==""} {
puts "--------------------------------------tlv_parsing:tl parsing null\n"
return ""
}
eval set tl \"[get_formator $parser_name]\"
puts "tl=$tl
--------------------------------------tlv_parsing:tl parsing end...offset=$offset,len=$len\n"
set t [lindex $tl 0]; set l [lindex $tl 1]; set v_len [expr $l*$lenByte]
if {$inclusive==1} {set v_len [expr $v_len-($offset-$offset_old)]};
set v_parser "$v_len B[expr $v_len*8] temp";
set offset_old $offset;
if {[set v [fixed_parsing pkt offset len $v_parser]]==""} {return $tl}
set tlv "$tl [Bin2Hex $v]"
puts "tlv=$tlv
--------------------------------------tlv_parsing:end ...pkt_len=$pkt_len,offset=$offset,len=$len\n"
return $tlv
}
#Hello;
#set pkt \
01005e000005c20126880000080045c0005004e200000159d2ac01000002e0000005020100306400000200000000bf9400000000000000000000ff000000000a1201000000280100000200000000c8000001fff600030001000400000001 ;set pkt [Char2Hex $pkt];\
set offset 82;set len 12;set tlv [tlv_parsing pkt offset len OSPF_LLS_parser 4 1];puts "offset=$offset,tlv=$tlv\n";\
lassign $tlv t l v;set offset [expr $offset - [string length $v]/8];set len 8;\
set tlv [tlv_parsing pkt offset len OSPF_LLS_TLV_parser 1 0];puts "$offset tlv=$tlv\n";return
#------------------------------------------------------------------------------------------------------------------------------
proc list_parsing {pktIn offsetIn lenIn list_name {numIn -1}} {
set proc list_parsing
if {$numIn<=0 && $numIn!=-1} {return ""}
upvar $pktIn pkt $offsetIn offset $lenIn len ;set var_list ""
for {set num 1} {[expr ($numIn==-1)?1:$num<=$numIn]} {incr num} {
puts "-------------------------------$proc:$list_name,loop=$num begin...,offset=$offset,len=$len,num=$numIn\n"
set offset_old $offset;
if {[set var [parsing pkt offset len $list_name]]!=""} {
set var_list [append var_list $var " "]
} else {break}

if {$len <= 0} {break}
puts "var_list=$var_list
-------------------------------$proc:$list_name,loop=$num end...,offset=$offset,len=$len,num=$numIn\n"
}
puts "var_list=$var_list
-------------------------------$proc:$list_name end...\n"
set global_name ""; append global_name "$list_name" "_List";
#if {[info exists "::$global_name"]} {puts "::$global_name=[eval set temp \$::$global_name] exists!!!!";break} 
set ::$global_name $var_list
return $var_list
}
#set pkt \
01005e000005c20126880000080045c0005004e200000159d2ac01000002e0000005020100306400000200000000bf9400000000000000000000ff000000000a1201000000280100000200000000c8000001fff600030001000400000001 ;set pkt [Char2Hex $pkt];\
set offset 86;set tlv "";set tlv [list_parsing pkt offset 8 OSPF_LLS_TLV];puts "offset=$offset,tlv=$tlv\n";return
#set pkt \
01005e000005c20126880000080045c0005004e200000159d2ac01000002e0000005020100306400000200000000bf9400000000000000000000ff000000000a1201000000280100000200000000c8000001fff600030001000400000001 ;set pkt [Char2Hex $pkt];set offset 78;\
set nbr_list [list_parsing pkt offset 4 OSPF_Hello_Nbr];\
puts "Test3:offset=$offset,nbr_list=$nbr_list";return; 
#------------------------------------------------------------------------------------------------------------------------------
proc option_list_parsing {pktIn offsetIn lenIn optionName option_bits } {
set proc option_list_parsing
upvar $pktIn pkt $offsetIn offset $lenIn len; set options "";
if {[Bin2Dec $option_bits]==0} {return ""}
set index [string first 1 $option_bits]
set new_option_bits [string replace $option_bits $index $index 0]
incr index
set var "";append var $optionName _ $index;
set offset_old $offset;
puts "-------------------------------$proc:$optionName,$option_bits=$index begin...,offset=$offset,len=$len\n"
if {[set option [parsing pkt offset len $var]]!=""} {append options $option " "}
puts "options=$option
-------------------------------$proc:$optionName,$option_bits=$index end...,offset=$offset,len=$len\n"
if {[set left_options [option_list_parsing pkt offset len $optionName $new_option_bits]]!=""} {append options $left_options " "}
return $options 
}
#set pkt \
01005e000005c20126880000080045c0005004e200000159d2ac01000002e0000005020100306400000200000000bf9400000000000000000000ff000000000a1201000000280100000200000000c8000001fff600030001000400000001 ;set pkt [Char2Hex $pkt];\
set offset 82; set options [option_list_parsing pkt offset 12 "ospf_option" "00010010"];puts $options;return
#set pkt \
ca0104540008ca0004540008080045c000627a060000ff063ccb01010101010101020286a0b815b95835d0323798501010204f940000000100360101010100000400002c00000018010000148080050c0000000000000064010405dc0c0407020200000400000010896a000400000000 ;#label mapping
#set pkt [Char2Hex $pkt];set pkt_len [string length $pkt]; set offset 88; set len 4;\
tlv_parsing2 pkt offset len LDP MTU_TLV 1;return
#------------------------------------------------------------------------------------------------------------------------------
set pkt \
01005e000005c20126880000080045c0005004e200000159d2ac01000002e0000005020100306400000200000000bf9400000000000000000000ff000000000a1201000000280100000200000000c8000001fff600030001000400000001 ;#Hello;
#01005e000005c20156940001080045c000681fd900000159549d64000002e0000005020500546400000200000000b37a0000000000000000000000372201c8000002c8000002800000017ecd003000012201c8000002c800000280000002d51000300001220264000001c8000002800000015f790020;#LSAck
#006008817a7000e018b10cad080045c000802be800000159b721c0a8aa08c0a8aa020203006cc0a8aa080000000175950000000000000000000000000001c0a8aa03c0a8aa030000000550d41000c0a8aa02000000059479ab00c0a8aa0200000005c0827800c0a8aa0200000005c0a80000c0a8aa0200000005c0a80100c0a8aa0200000005c0a8ac00c0a8aa02 ;#LSR no option 7 LSRs
#01005e00000500e018b10cad080045c00130081c0000015964e3c0a8aa08e00000050205011cc0a8aa0800000001e95e0000000000000000000000020201c0a8aa03c0a8aa03800000013a9c00300003020550d41000c0a8aa02800000012a490024000302059479ab00c0a8aa028000000134a5002400030205c0827800c0a8aa0280000001d319002400030205c0a80000c0a8aa02800000013708002400030205c0a80100c0a8aa02800000012c12002400030205c0a8ac00c0a8aa028000000133410024000102059479ab00c0a8aa03800000012eaa002400010205c0827800c0a8aa0380000001cd1e002400010205c0a80000c0a8aa0380000001310d002400010205c0a80100c0a8aa03800000012617002400010205c0a8ac00c0a8aa03800000012d4600240001020550d41000c0a8aa0380000001244e0024 ;#LSAck no option 13 LSA Header
#c20156940001c20056940001080045c00038260000000159caaa640000016400000202030024c8000002000000006dd000000000000000000000000000016400000264000002 ;#LSR
#00e018b10cad006008817a70080045c000c088c3000001595a06c0a8aa02c0a8aa08020200acc0a8aa0300000001f0670000000000000000000005dc02024177a97e00010201c0a8aa03c0a8aa03800000013a9c00300002020550d41000c0a8aa02800000012a490024000202059479ab00c0a8aa028000000134a5002400020205c0827800c0a8aa0280000001d319002400020205c0a80000c0a8aa02800000013708002400020205c0a80100c0a8aa02800000012c12002400020205c0a8ac00c0a8aa028000000133410024 ;#DD no option 7 LSA Header
#006008817a7000e018b10cad080045c000342be500000159b770c0a8aa08c0a8aa0202020020c0a8aa0800000001a0520000000000000000000005dc02074177a97e ;#DD no option
#01005e000005006008817a70080045c00044b37e00000159ba72c0a8aa02e000000502010030c0a8aa0300000001273c00000000000000000000ffffff00000a0201000000280000000000000000c0a8aa08 ;# Hello no option 1 nbr
#01005e00000500e018b10cad080045c0004008120000015965ddc0a8aa08e00000050201002cc0a8aa0800000001273b00000000000000000000ffffff00000a020100000028c0a8aa0800000000 ;#Hello no option no nbr
#c20156940001c20056940001080045c00060260100000159ca8164000001640000020204004cc8000002000000005357000000000000000000000000000100372201c8000002c8000002800000017ecd00300000000264000000ff0000000300000ac8000000ffff00000300000a;#LSU;
#01005e000006006008817a70080045c001383025000001593cd7c0a8aa02e000000602040124c0a8aa0300000001366b000000000000000000000000000700020201c0a8aa03c0a8aa03800000013a9c003002000002c0a8aa00ffffff000300000ac0a8aa00ffffff000300000a0003020550d41000c0a8aa02800000012a490024ffffffff800000140000000000000000000302059479ab00c0a8aa028000000134a50024ffffff0080000014c0a8aa010000000000030205c0827800c0a8aa0280000001d3190024ffffff0080000014000000000000000000030205c0a80000c0a8aa028000000137080024ffffff0080000014000000000000000000030205c0a80100c0a8aa02800000012c120024ffffff0080000014000000000000000000030205c0a8ac00c0a8aa028000000133410024ffffff0080000014c0a8aa0a00000000 ;#LSU
#c20056940001c20156940001080045c000541fd300000159d0bb64000002640000010202003464000002000000003e290000000000000000000005dc520200000008002b220164000002640000028000000199550030fff600030001000400000001 ;#DD
#01005e000005c201139c0001080045c0004c04b2000001596fe064000002e00000050201002c6400000200000000249a00000000000000000000ff000000000a1201000000286400000200000000fff600030001000400000001 ;#Hello
#c20156940001c20056940001080045c0004025f700000159caab640000016400000202020020c800000200000000ddef0000000000000000000005dc520700000008fff600030001000400000001 ;#DD
set pkt [Char2Hex $pkt]
set len [set Ether__Len [string length $pkt]]
set offset [set Ether_Header__Offset 0]
build_all_formator router_db parser_new
build_all_parser router_db parser_new
#set parsing_list [parsing pkt offset len "Ether_Header_parser"] \
puts $parsing_list