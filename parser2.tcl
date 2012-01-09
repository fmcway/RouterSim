#common error :table parser_new: duplicate discontinuous Part, FieldIndex
source routerlib.tcl
#source parser.tcl
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

#-----------------------------------------------------------------------------------------------------------------------------
#called by build_parser_record to build format_cmd
set ::protocol_message_name_len 64

proc fill_string {in lenIn} {
upvar $lenIn len;if {$len<[set in_len [string length $in]]} {set len $in_len;return $in}
append in [string repeat " " [expr $len-$in_len]]
}

proc build_1_formator2 {db table protocol message part} {
set pattern ""
$db eval "SELECT * FROM $table where protocol='$protocol' AND message='$message' AND part=$part"  values {
switch $values(Parser_Type) {
"Fixed" - "Variable" - "TLV" {
set var ""; append var "$" "::" "$protocol" "_$message" "_$values(Field)";
set var_name ""; append var_name "$protocol" "_$message" "_$values(Field)";
set var_name [fill_string $var_name ::protocol_message_name_len]
if {![string is space $values(Format)]}  {
append pattern "\n$var_name \[$values(Format) " "$var" "\]"
} else {
append pattern "\n$var_name $var"}
}}}
return "$pattern"
}
#puts [build_1_formator2 router_db parser_new LDP MTU_TLV 1];return
#[Bin2Hex2Char $::LDP_MTU_TLV_ID] [Bin2Dec $::LDP_MTU_TLV_Len] [Bin2Dec $::LDP_MTU_TLV_MTU]
#--------------------------------------------------------------------------------------------------------------------------------
proc get_ospf_options {} {
set ospf_type [Bin2Dec $::OSPF_Header_Type];set options ""
switch $ospf_type {
1 {set options $::OSPF_Hello_Options}
2 {set options $::OSPF_DD_Options}
}
return $options
}
#puts get_ospf_options;#Hello->Hello.Options; DD->DD.Options
#--------------------------------------------------------------------------------------------------------------------------------
proc build_parser_lookup_table {db table array_name} {
$db eval "SELECT DISTINCT * FROM $table" values {
set cmd [join [list "set $array_name" "($values(Protocol))($values(Message))($values(Field))($values(Value)) \{" "$values(Next_Protocol) $values(Next_Message) $values(Next_Part) $values(Next_Field)\}"] ""]
eval $cmd
}
$db eval "SELECT Distinct protocol,message,field,format from $table" values {
set cmd [join [list "set $array_name" "($values(Protocol))($values(Message))($values(Field))(Format) " "$values(Format)"] ""]
eval $cmd
}
}
#type_parser_table(Ether)(Header)(Type_Len)(<=1500) = LLC Pkt 1 \
type_parser_table(Ether)(Header)(Type_Len)(0800) = IPv4 Header 1 \
type_parser_table(Ether)(Header)(Type_Len)(Format)=Hex
build_parser_lookup_table router_db type_new ::type_parser_table;
#parray type_parser_table;return; 
#--------------------------------------------------------------------------------------------------------------------------------
#called by type_parser_lookup to convert key
proc type_lookup_convert {protocol message field key} {
set var $key; set table_name ::type_parser_table
set index $protocol)($message)($field)(Format
eval [join [list "set type_format \$$table_name" "(\$index)"] ""]
switch $type_format {
"Dec" {set var [Bin2Dec $key]}
"Hex" {set var [Bin2Hex2Char $key]}
}}
#type_parser_table(OSPF)(LSA_Header)(Type)(Format)  = Dec 
#puts [type_lookup_convert OSPF LSA_Header Type 0001<-Key in binary format];return
#--------------------------------------------------------------------------------------------------------------------------------
#called by parsing_part to lookup key and get next protocol message part
proc type_parser_lookup {protocol message field key } {
set table_name "::type_parser_table"
set item ""; set proc type_parser_lookup
set var [type_lookup_convert $protocol $message $field $key]
set index "$protocol)($message)($field)($var"
puts "$proc: Begin...$protocol $message $field $key->$var"
if {$field=="Type_Len" && [Char2Hex2Dec $var]<=1500} {
set index "$protocol)($message)(Type_Len)(<=1500"}
catch {eval [join [list "set item \$$table_name" "(\$index)"] ""]}
puts "$proc:End...$item"
return $item
}
#\
Protocol	Message		Part	Field		Format	Value		Next_Protocol	Next_Message	Next_Part	Next_Field	Description\
"Ether"		"Header"	"1"		"Type_Len"	"Hex"	"0800"		"IPv4"			"Pkt"\
"Ether"		"Header"	"1"		"Type_Len"	"Dec"	"<=1500"	"LLC"			"Pkt"\
type_parser_table(Ether)(Header)(Type_Len)(<=1500) = LLC Pkt 1
#puts [type_parser_lookup Ether Header Type_Len 00010];return
#--------------------------------------------------------------------------------------------------------------------------------
proc get_parsed_value {msg protocol message field} {
set var_name [join [list "$protocol" "_$message" "_$field"] ""];
set val [regexp -nocase -all -inline -- "$var_name\\s+\[^\\s\{\}\]+" $msg ];
string map {"\} \{" "\}\n\{"} $val
}
#set msg [lindex $::LDP_TLV__List 0]\
puts [get_parsed_value $msg Ether Pkt DMAC]
#--------------------------------------------------------------------------------------------------------------------------------
#used in parser table list_cmd, len_cmd
proc field_value {formator protocol message part field } { 
set cmd [join [list "$formator $" "::" "$protocol" "_$message" "_$field"] ""];
eval $cmd
}
#set ::OSPF_LLS_Len [Dec2Bin 4 16]; puts [field_value Bin2Dec OSPF LLS 1 Len];return;#->16
#--------------------------------------------------------------------------------------------------------------------------------
# called by build_parser_array to build 1 parser record = type,list_num,parser,len_cmd,format_cmd
proc build_parser_record {db table protocol message part parser_type} {
set new_fields ""; set parser ""; set list_num ""; set len_cmd ""; 
set format_cmd [build_1_formator2 $db $table $protocol $message $part];
switch $parser_type {
"Fixed" - "TLV"   {
set pattern "";set new_fields "";set bits 0;
$db eval "SELECT * FROM $table \
where protocol='$protocol' AND message='$message' AND part=$part AND parser_type='$parser_type' AND length!=''" values {
if {$values(FieldIndex)==2 } {set list_num "$values(List_Num)";}
append pattern    "B$values(Length)"; append new_fields "::$protocol" "_$message" "_$values(Field) ";
set bits [expr $bits+$values(Length)]
}; set parser "[expr $bits/8] $pattern $new_fields"}

"List"  {
$db eval "SELECT * FROM $table \
where protocol='$protocol' AND message='$message' AND part=$part AND parser_type='$parser_type'" values {
set parser [string range $values(Field) 1 end-2]; set list_num "$values(List_Num)"; set len_cmd "$values(Length)"
}}

default {
$db eval "SELECT * FROM $table \
where protocol='$protocol' AND message='$message' AND part=$part AND parser_type='$parser_type'" values {
set parser "$values(Field)"; set list_num "$values(List_Num)"; set len_cmd "$values(Length)"}}
}
return "$parser_type \{$list_num\} \{$parser\} \{$len_cmd\} \{$format_cmd\}"
}
#puts [build_parser_record router_db parser_new Ether Header 1 Fixed];\
puts [build_parser_record router_db parser_new OSPF LLS 2 List];\
puts [build_parser_record router_db parser_new OSPF LSA 1 Message];\
return
#--------------------------------------------------------------------------------------------------------------------------------
proc build_parser_array {db table} {
set array_name ::parser_array
$db eval "SELECT Distinct protocol,message from parser_new" values {
set protocol $values(Protocol); set message $values(Message);
$db eval "SELECT count(distinct part) from parser_new where protocol='$protocol' AND message='$message'" values {
set index "count(distinct part)"
eval [join [list "set $array_name" "($protocol)($message)(Part_Num)  \[set part_num \$values(\$index)\]"] ""]
}

for {set i 1} {$i<=$part_num} {incr i} {
$db eval "SELECT Distinct * from parser_new where protocol='$protocol' AND message='$message' AND part=$i" values {
eval [join [list "set $array_name" "($protocol)($message)($i) \[build_parser_record $db $table $protocol $message $i \$values(Parser_Type)\]"] ""]
}}}}
build_parser_array router_db parser_new;
#parray ::parser_array;return
#parser_array(OSPF)(LLS)(Part_Num)=2 \
::parser_array(OSPF)(LLS)(1) = Fixed {} {4 B16B16 ::OSPF_LLS_Checksum ::OSPF_LLS_Len } {} {[Bin2Hex2Char $::OSPF_LLS_Checksum] [Bin2Dec $::OSPF_LLS_Len] }\
::parser_array(OSPF)(LLS)(2) = List {} {OSPF LLS_TLV} {[field_value Bin2Dec OSPF LLS 1 Len]*4-[message_byte OSPF LLS 1]} {$::OSPF_LLS_(OSPF LLS_TLV)* }
#--------------------------------------------------------------------------------------------------------------------------------
#called by parsing2 and get_parsed_value to get part_num of protocol,message
proc get_part_num {protocol message} {
set array_name ::parser_array;set index "$protocol)($message)(Part_Num";set part_num 0
set cmd  [join [list "set part_num $" "$array_name" "(\$index)"] ""];catch {eval $cmd}; return $part_num
}
#--------------------------------------------------------------------------------------------------------------------------------
#called by get_parsed_value,message_byte,tlv_parsing2,parsing2,parsing_part to get record
proc get_parser_record {protocol message part} {
set array_name ::parser_array; set index "$protocol)($message)($part";
set cmd  [join [list "set record $" "$array_name" "(\$index)"] ""];
eval $cmd; return $record
}
#--------------------------------------------------------------------------------------------------------------------------------
#used in parser table len_cmd
proc message_byte {protocol message part} {
set msg_byte 0
catch {
set record [get_parser_record $protocol $message $part]
switch [parser_record_type $record] {
"Fixed" {set msg_byte [lindex [parser_record_parser $record] 0]}
}}
return $msg_byte}
#parser_array(Ether)(Header)(1) = type list_cmd parser len_cmd format_cmd
#--------------------------------------------------------------------------------------------------------------------------------
proc parser_record_type {in} {lindex $in 0} ;# called by message_byte,parsing_part,parsing2
proc parser_record_list_cmd {in} {lindex $in 1} ;#called by tlv_parsing2,parsing_part
proc parser_record_parser {in} {lindex $in 2} ;#called by get_parsed_value,message_byte,tlv_parsing2,parsing_part
proc parser_record_len_cmd {in} {lindex $in 3} ;#called by parsing_part
proc parser_record_format_cmd {in} {lindex $in 4} ;#called by get_tlv_vname,get_tlv_tl_formator,tlv_parsing2,parsing_part
#puts [message_byte OSPF LLS 1];return;#->4
#------------------------------------------------------------------------------------------------------------------------------
#called by parsing_part
proc list_parsing2 {pktIn offsetIn lenIn protocol message {numIn ""}} {
set proc list_parsing2
if {$numIn==""} {set loop_control "\$len>0"} elseif {![string is integer $numIn] || $numIn<=0} {return ""} else {set loop_control "\$num<=\$numIn && \$len>0"}
upvar $pktIn pkt $offsetIn offset $lenIn len ;set var_list ""
for {set num 1} {[expr $loop_control]} {incr num} {
puts "-------------------------------$proc:$protocol $message loop=$num begin...,offset=$offset,len=$len,num=$numIn\n"
set len_old $len; set offset_old $offset
if {[set var [parsing2 pkt offset len $protocol $message]]!=""} {
set var_list [append var_list "\{" $var "\} "]
} else {break}
set item_len [expr $offset - $offset_old]; set len [expr $len_old -$item_len]
#if {$len <= 0} {break}
}
set var_list "\{$var_list\}"
puts "List=$var_list
-------------------------------$proc:$protocol $message loop=$num end...,offset=$offset,len=$len,num=$numIn\n"
set global_name ""; append global_name "$protocol" "_$message" "__List";set ::$global_name $var_list;
return $var_list
}
#------------------------------------------------------------------------------------------------------------------------------
#called by parsing_part
proc option_list_parsing2 {pktIn offsetIn lenIn protocol options_prefix option_bits } {
set proc option_list_parsing
upvar $pktIn pkt $offsetIn offset $lenIn len; set options "";set options_index "$options_prefix"
if {[Bin2Dec $option_bits]==0} {return ""}
set index [string first 1 $option_bits]; set new_option_bits [string replace $option_bits $index $index 0]
incr index
append options_index "_$index";# Options_4
puts "-------------------------------$proc:$protocol,$options_prefix,$option_bits=$index begin...,offset=$offset,len=$len\n"
if {[set option [parsing2 pkt offset len $protocol $options_index]]!=""} {append options "\{$option\} " }
puts "options=$option
-------------------------------$proc:$protocol,$options_prefix,$option_bits=$index end...,offset=$offset,len=$len\n"
if {[set left_options [option_list_parsing2 pkt offset len $protocol $options_prefix $new_option_bits]]!=""} {
append options "$left_options "}
return $options 
}
#--------------------------------------------------------------------------------------------------------------------------------
#called by parsing2
proc parsing_part {pktIn offsetIn lenIn protocol message part} {
upvar $pktIn pkt $offsetIn offset $lenIn len;
set proc parsing_part; set var ""
set record [get_parser_record $protocol $message $part]
set type [parser_record_type $record]
set list_cmd [parser_record_list_cmd $record]
set parser [parser_record_parser $record]
set len_cmd [parser_record_len_cmd $record]
set format_cmd [parser_record_format_cmd $record]
set offset_old $offset;set len_old $len;
if {$len_cmd!=""} {catch {set len [eval expr $len_cmd];}}
set list_num "";if {$list_cmd!=""} {catch {set list_num [eval expr $list_cmd]};}

set cmd [join [list "set ::$protocol" "_$message" "_$part" "__Offset \$offset"] ""]
eval $cmd
puts "-------------------------------$proc: $protocol $message $part $type begin...offset=$offset,len=$len\n"
switch $type {

"Fixed" {
#Ether)(Header)(1 {\
type=Fixed \
list_cmd={} \
parser= {14 B48B48B16 ::Ether_Header_DMAC ::Ether_Header_SMAC ::Ether_Header_Type_Len } \
len_cmd={} \
format_cmd= {Ether_Header_DMAC [Bin2mac $::Ether_Header_DMAC] Ether_Header_SMAC [Bin2mac $::Ether_Header_SMAC] Ether_Header_Type_Len [Bin2Hex2Char $::Ether_Header_Type_Len] }} 
if {[fixed_parsing pkt offset len $parser]!=""} {
eval set var \"$format_cmd\"
}
}

#"TLV" {\
set var [tlv_parsing2 pkt offset len $protocol $message $part]\
}

"List" {
#OSPF)(LSU)(2 {\
type=List \
list_cmd={[field_value Bin2Dec OSPF LSU 1 LSA_Num]}\
parser= {OSPF LSA} \
len_cmd={} \
format_cmd={}}
set new_protocol [lindex $parser 0];set new_message [lindex $parser 1];
set var [list_parsing2 pkt offset len $new_protocol $new_message $list_num] 
}

"Message" {
#OSPF)(LSA)(1 {\
type=Message\
list_cmd={} \
parser={OSPF LSA_Header} \
len_cmd={[field_value Bin2Dec OSPF Header Len]-[message_byte OSPF Header 1]} \
format_cmd={}}
#puts "Message:$parser"
set new_protocol [lindex $parser 0];set new_message [lindex $parser 1]
set var [parsing2 pkt offset len $new_protocol $new_message]
}

"Lookup" {
#OSPF)(LSA)(2 {\
type=Lookup \
list_cmd={} \
parser={OSPF LSA_Header Type} \
len_cmd={[field_value Bin2Dec OSPF LSA_Header 1 Len]-[message_byte OSPF LSA_Header 1]} \
format_cmd={}}
eval set key \$::[join $parser "_"];#set key $::OSPF_LSA_Header_Type
set item [type_parser_lookup [lindex $parser 0] [lindex $parser 1] [lindex $parser 2] $key];
if {$item!=""} {
set new_protocol [lindex $item 0];set new_message [lindex $item 1];
set var [parsing2 pkt offset len $new_protocol $new_message]}
}

"OSPF_Option_List" {
#OSPF)(Pkt)(3 {\
type=OSPF_Option_List \
list_cmd={} \
parser={get_ospf_options} \
len_cmd={[field_value Bin2Dec IPv4 Header 1 Len] - [message_byte IPv4 Header 1] - [ field_value Bin2Dec OSPF Header 1 Len]} \
format_cmd={}}
set option_bits [eval $parser]
set var [option_list_parsing2 pkt offset len OSPF Options $option_bits]
}

"Variable" {
#ARP)(Pkt)(2 {\
type=Variable \
list_cmd={} \
parser={Sender_Hardware} \
len_cmd={[field_value Bin2Dec ARP Pkt 1 Hardware_Byte]} \
format_cmd={ARP_Pkt_Sender_Hardware [Bin2mac $::ARP_Pkt_Sender_Hardware]}}
set parser "$len B[expr $len*8] [join [list "::$protocol" "_$message" "_$parser"] ""]"
if {[fixed_parsing pkt offset len $parser]!=""} {
eval set var \"$format_cmd\"
}
} ;# Variable
} ;# switch
set len [expr $len_old - ($offset-$offset_old)]
puts "$var\"
-------------------------------$proc: $protocol $message $part $type End...offset=$offset,len=$len\n"
return $var
}
#--------------------------------------------------------------------------------------------------------------------------------
proc parsing2 {pktIn offsetIn lenIn protocol message} {
upvar $pktIn pkt $offsetIn offset $lenIn len;set proc parsing2
set array_name ::parser_array;set part_num 0;set parsing_list ""
#::parser_array(Ether)(Header)(Part_Num) = 1
set part_num [get_part_num $protocol $message]
if {$part_num==0} { return ""}
puts "-------------------------------$proc: $protocol $message $part_num begin...offset=$offset,len=$len\n"
for {set i 1} {$i<=$part_num} {incr i} {
set part_item [parsing_part pkt offset len $protocol $message $i]
if {$part_item != ""} {
set record [get_parser_record  $protocol $message $i]
switch [parser_record_type $record] {
"Fixed" - "Variable" {append parsing_list "\{$part_item\} "}
default {append parsing_list $part_item}
}
} 
}
puts "$parsing_list
-------------------------------$proc: $protocol $message $part_num End...offset=$offset,len=$len\n"
return $parsing_list
}
set pkt \
ca0104540008ca0004540008080046c000d004240000ff2e1d13010101010101010294040000100194feff0000b800100107010101020000000001010101000c0301c0a80001020004040008050100007530001414010108c0a800022000010801010102200000081301000008000010cf070101040552315f7430000000000c0b07010101010000005700240c0200000007010000067f00000546fa0000447a000046fa0000000000007fffffff00300d020000000a010000080400000100000001060000014b3ebc2008000001000000000a000001000005dc05000000 ;#RSVP Path
#{Ether_Pkt_DMAC ca.01.04.54.00.08 \
Ether_Pkt_SMAC ca.00.04.54.00.08 \
Ether_Pkt_Type_Len 0800} \
{IPv4_Header_Version 4 IPv4_Header_HLen 6 \
IPv4_Header_DSCP 110000 IPv4_Header_ECN 00 IPv4_Header_Len 208 IPv4_Header_ID 0424 IPv4_Header_Flags 000 IPv4_Header_Offset 0 IPv4_Header_TTL 255 IPv4_Header_PID 46 IPv4_Header_Checksum 1d13 IPv4_Header_SIP 1.1.1.1 IPv4_Header_DIP 1.1.1.2 } {IPv4_Header_Options 94040000 } \
{RSVP_Header_Version 1 RSVP_Header_Flags 0000 RSVP_Header_Type 1 RSVP_Header_Checksum 94fe RSVP_Header_TTL 255 RSVP_Header_Reserve 00000000 RSVP_Header_Len 184 } \
{\
{{RSVP_Object_Len 16 RSVP_Object_Class_Type 0107 } {RSVP_Obj_Session_IPv4_LSP_RID 1.1.1.2 RSVP_Obj_Session_IPv4_LSP_Reserve 0 RSVP_Obj_Session_IPv4_LSP_ID 0 RSVP_Obj_Session_IPv4_LSP_Extend_ID 1.1.1.1 } } \
{{RSVP_Object_Len 12 RSVP_Object_Class_Type 0301 } {RSVP_Obj_Hop_IPv4_IP 192.168.0.1 RSVP_Obj_Hop_IPv4_Intf 33555460 } } {{RSVP_Object_Len 8 RSVP_Object_Class_Type 0501 } {RSVP_Obj_Time_Values_Refresh_Period 30000 } } \
{{RSVP_Object_Len 20 RSVP_Object_Class_Type 1401 } {\
{{RSVP_Subobject_L 0 RSVP_Subobject_Type 1 RSVP_Subobject_Len 8 } {RSVP_Subobj_IPv4_Prefix_IP 192.168.0.2RSVP_Subobj_IPv4_Prefix_Prefix 32 RSVP_Subobj_IPv4_Prefix_Reserve 0 } } \
{{RSVP_Subobject_L 0 RSVP_Subobject_Type 1 RSVP_Subobject_Len 8 } {RSVP_Subobj_IPv4_Prefix_IP 1.1.1.2 RSVP_Subobj_IPv4_Prefix_Prefix 32 RSVP_Subobj_IPv4_Prefix_Reserve 0 } } \
}} \
{{RSVP_Object_Len 8 RSVP_Object_Class_Type 1301 } {RSVP_Obj_Label_Req_Reserve 0 RSVP_Obj_Label_Req_L3PID 2048 } }\
{{RSVP_Object_Len 16 RSVP_Object_Class_Type cf07 } \
{RSVP_Obj_Session_Attribute_LSP_Setup_Pri 1 RSVP_Obj_Session_Attribute_LSP_Hold_Pri 1 RSVP_Obj_Session_Attribute_LSP_Flags 4 RSVP_Obj_Session_Attribute_LSP_Name_Len 5 } \
{RSVP_Obj_Session_Attribute_LSP_Name R1_t0  } } \
{{RSVP_Object_Len 12 RSVP_Object_Class_Type 0b07 } {RSVP_IPv4_LSP_IP 1.1.1.1 RSVP_IPv4_LSP_Reserve 0 RSVP_IPv4_LSP_ID 87 } } \
{{RSVP_Object_Len 36 RSVP_Object_Class_Type 0c02 } {RSVP_Msg_Version 0 RSVP_Msg_Reserve1 0 RSVP_Msg_Len 7 } {{{RSVP_Svc_Header 1 SVP_Svc_Reserve 0 RSVP_Svc_Len 6 } {\
{{RSVP_Para_ID 127 RSVP_Para_Flags 0 RSVP_Para_Len 5 } \
{RSVP_Para_Token_Bucket_TSpec_Token_Bucket_Rate 32000.0 RSVP_Para_Token_Bucket_TSpec_Token_Bucket_Size 1000.0 RSVP_Para_Token_Bucket_TSpec_Peak_Data_Rate 32000.0 RSVP_Para_Token_Bucket_TSpec_Minimum_Policed_Unit 0 RSVP_Para_Token_Bucket_TSpec_Maximum_Packet_Size 2147483647 } } \
}} }} \
{{RSVP_Object_Len 48 RSVP_Object_Class_Type 0d02 } {RSVP_Msg_Version 0 RSVP_Msg_Reserve1 0 RSVP_Msg_Len 10 } \
{\
{{RSVP_Svc_Header 1 RSVP_Svc_Reserve 0 RSVP_Svc_Len 8 } {\
{{RSVP_Para_ID 4 RSVP_Para_Flags 0 RSVP_Para_Len 1 } {RSVP_Para_IS_Hops_Value 1 } }\
{{RSVP_Para_ID 6 RSVP_Para_Flags 0 RSVP_Para_Len 1 } {RSVP_Para_Path_BW_Value 12500000.0 } } \
{{RSVP_Para_ID 8 RSVP_Para_Flags 0 RSVP_Para_Len 1 } {RSVP_Para_Min_Path_Latency_Value 0 } } \
{{RSVP_Para_ID 10 RSVP_Para_Flags 0 RSVP_Para_Len 1 } {RSVP_Para_MTU_Value 1500 } } }} \
{{RSVP_Svc_Header 5 RSVP_Svc_Reserve 0 RSVP_Svc_Len 0 } {}} }} }

#{ca.01.04.54.00.08 ca.00.04.54.00.08 0800 } \
{4 6 110000 00 208 0424 000 0 255 46 1d13 1.1.1.1 1.1.1.2 } {94040000} \
RSVP Header {1 0000 1 94fe 255 00000000 184 } \
{RSVP obj*\
Session {{16 0107 } {1.1.1.2 0 0 1.1.1.1 } }\
Hop {{12 0301 } {192.168.0.1 33555460 } }\
Time {{8 0501 } {30000 } } \
Explicit Route {{20 1401 } {IPv4{{0 1 8 } {192.168.0.2 32 0 } } IPv4{{0 1 8 } {1.1.1.2 32 0 } } }} \
Label Req {{8 1301 } {0 2048 } } \
Session Attribute {{16 cf07 } {1 1 4 5 } {R1_t0} } \
Sender Template {{12 0b07 } {1.1.1.1 0 87 } } \
Sender Tspec {{36 0c02 } Msg {0 0 7 } {Svc*  Tspec_Svc{{1 0 6 } {Para*{Token_Para {127 0 5 } {32000.0 1000.0 32000.0 0 2147483647 } } }} }} \
AdSpec {{48 0d02 } {0 0 10 } {{{1 0 8 } {{{4 0 1 } {1 } } {{6 0 1 } {12500000.0 } } {{8 0 1 } {0 } } {{10 0 1 } {1500 } } }} {{5 0 0 } {}} }} \
}

#ca0104540008ca0004540008080045c0008004230000ff2e3519c0a80001c0a8000210021dbeff00006c00100107010101010000000001010102000c0301c0a8000102000404000805010000753000080801000000120024090200000007050000067f00000546fa0000447a000046fa000000000000000005dc000c0a0701010102000000050008100100000000 ;#RSVP Resv
#ca0004540008ca0104540008080045c0008000e60000ff2e3856c0a80002c0a8000110021d6cff00006c00100107010101020000000001010101000c0301c0a8000202000404000805010000753000080801000000120024090200000007050000067f00000546fa0000447a000046fa000000000000000005dc000c0a0701010101000000570008100100000000 ;#RSVP Resv
#01005e000005c20056940001080045c000502606000001594e8964000001e000000502010030c800000200000000f89100000000000000000000ff000000000a120100000028640000016400000264000002fff600030001000400000001 ;#OSPF Hello w/ LLS
#ca0104540008ca0004540008080045c0003e00000000ff11b6ea010101010101010202860286002a28ef0001001e010101010000010000140000000004000004005ac0000401000401010101 ;# LDP Hello
#ca0104540008ca0004540008080045c000627a060000ff063ccb01010101010101020286a0b815b95835d0323798501010204f940000000100360101010100000400002c00000018010000148080050c0000000000000064010405dc0c0407020200000400000010896a000400000000 ;#LDP label mapping \
Ether {ca.01.04.54.00.08 ca.00.04.54.00.08 0800 } \
IP    {4 5 110000 00 98 7a06 000 0 255 6 3ccb 1.1.1.1 1.1.1.2 } \
TCP   {646 41144 15b95835 d0323798 5 000 0 } Flag {0 0 0 1 0 0 0 0 }  chksum{4128 4f94 0000 }\
LDP {1 54 1.1.1.1 0 } Msg{0 0400 44 00000018 } \
TLV*  {\
FEC_TLV{ \
Header {0 0 0100 20 } \
FEC_Element* {\
FEC VC {\
Type {128 } {1 0005 12 0 100 } \
List*{\
MTU  {{01 4 } 1500}\
VCCV {{0c 4 } {00000 1 1 1 00000 0 1 0 } } \
}List*\
}FEC_TLV \
}FEC_Element*\
}FEC_TLV \
{{0 0 0200 4 } {16 } } Label TLV\
{{1 0 096a 4 } {000000000000000000000000000 0 0 0 0 0 } } PW Status TLV\
} TLV*
#ca0104540008ca0004540008080045c0003a79fd0000ff063cfc01010101010101020286a0b815b957c3d032373850100e59811600000001000e0101010100000201000400000013 ;#LDP Keep_Alive
#0180c20000000025b4e66c010069424203000003027910000025b4e669800000000010000025b4e6698080010000140002000f000000400000000000000000000000000000000000000000000000000000000000000000000000ac36177f50283cd4b83821d8ab26de6200030d4080000025b4e66c0014a2278ac9 ;#MSTP
#c20156940001c20056940001080045c00060260100000159ca8164000001640000020204004cc8000002000000005357000000000000000000000000000100372201c8000002c8000002800000017ecd00300000000264000000ff0000000300000ac8000000ffff00000300000a ;#OSPF LSU 110 lsu 58 lsa 62 router_lsa 82 
#ca0104540008ca0004540008080045c000527a040000ff063cdd01010101010101020286a0b815b9580bd032376e50100e23f5760000000100260101010100000402001c000000170100000c8080050400000000000000640200000400000012 ;#LDP label withdraw
#ca0004540008ca0104540008080045c0005266230000ff0650be0101010201010101a0b80286d032376e15b9583550101020f34c0000000100260101010200000403001c000000180100000c8080050400000000000000640200000400000012 ;#LDP label release
#0180c20000000025b4e669818100e0010069424203000003027c10000025b4e669800000000010000025b4e6698080010000140002000f000000400000000000000000000000000000000000000000000000000000000000000000000000ac36177f50283cd4b83821d8ab26de620000000010000025b4e669801437d26658 ;#MSTP VLan
#0180c200000000179539f2120027424203000002023c21f5002498c7580000000bc0c1f500179539f20080120200140002000f000000000000000000 ;#RSTP
#ffffffffffff00219b1d61100806000108000604000100219b1d61100a8db4fb0000000000000a8db517000000000000000000000000000000000000 ;#ARP
#01005e000005c20056940001080045c0004c25ee000001594ea564000001e00000050201002cc800000200000000249c00000000000000000000ff000000000a1201000000280000000000000000fff600030001000400000001 ;#OSPF hello 90 option =82 tlv=8 
#c20056940001c20156940001080045c000541fd300000159d0bb64000002640000010202003464000002000000003e290000000000000000000005dc520200000008002b220164000002640000028000000199550030fff600030001000400000001 ;# OSPF DD 98 dd-58 lsa-66 options=lls=86 lls-tlv=90

set pkt [Char2Hex $pkt];set pkt_len [string length $pkt]
#set offset 0;set len [string length $pkt]; parsing_part pkt offset len Ether Header 1 
#set offset 62;set len 20; parsing_part pkt offset len OSPF LSA_Header 1; 
set offset 0;set len $pkt_len; set msg [parsing2 pkt offset len Ether Pkt]
#set offset 82;set len 8; parsing2 pkt offset len OSPF LLS_TLV
#set offset 0;set len [string length $pkt]; set msg [parsing2 parser_array pkt offset len Ether Header]
#set offset 58;set len 28; parsing2 pkt offset len OSPF DD

#------------------------------------------------------------------------------------------------------------------------------
#called by tlv_parsing2
proc get_tlv_vname {in} {set string [parser_record_format_cmd $in];# puts $string
regexp -nocase -all -line -- {(?:\[(\w+))?\s*\$([^\s\]]+)(?:\]\s*)?} $string -> v1 v2
return $v2
}
#puts [get_tlv_vname [get_parser_record LDP MTU_TLV 1]];#->::LDP_MTU_TLV_MTU\
puts [get_tlv_vname [get_parser_record OSPF LLS_TLV 1]];#->::OSPF_LLS_TLV_Value\
return
#------------------------------------------------------------------------------------------------------------------------------
#called by tlv_parsing2
proc get_tlv_tl_formator {in} {set string [parser_record_format_cmd $in];# puts $string
regexp -nocase -line -- {((?:\[(?:\w+))?\s*\$(?:[^\s\]]+)(?:\]\s*)?){2}} $string tl_formator v1 v2
return $tl_formator
}
#puts [get_tlv_tl_formator [get_parser_record OSPF LLS_TLV 1]];#->[Bin2Dec $::OSPF_LLS_TLV_Type] [Bin2Dec $::OSPF_LLS_TLV_Len]\
return
#------------------------------------------------------------------------------------------------------------------------------
#::parser_array(OSPF)(LLS_TLV)(1)                    = TLV {} {4 B16B16 ::OSPF_LLS_TLV_Type ::OSPF_LLS_TLV_Len } {} {[Bin2Dec $::OSPF_LLS_TLV_Type] [Bin2Dec $::OSPF_LLS_TLV_Len] $::OSPF_LLS_TLV_Value }
#called by parsing_part
proc tlv_parsing2 {pktIn offsetIn lenIn protocol message part} {
upvar $offsetIn offset  $pktIn pkt $lenIn len;set proc "tlv_parsing2"
set parser_record [get_parser_record $protocol $message $part]
set parser [parser_record_parser $parser_record]
set list_cmd [parser_record_list_cmd $parser_record]
set lenByte [lindex $list_cmd 0];set inclusive [lindex $list_cmd 1]
puts "--------------------------------------$proc:tl begin...offset=$offset,len=$len
parser=$parser,LenByte=$lenByte,inclusive=$inclusive\n"
set offset_old $offset;
if {[set tl [fixed_parsing pkt offset len $parser] ]==""} {
puts "--------------------------------------$proc:tl parsing null\n"
return ""
}
eval set tl \"[get_tlv_tl_formator $parser_record]\"
puts "tl=$tl
--------------------------------------$proc:tl parsing end...offset=$offset,len=$len\n"
set t [lindex $tl 0]; set l [lindex $tl 1]; set v_len [expr $l*$lenByte]
if {$inclusive==1} {set v_len [expr $v_len-($offset-$offset_old)]};
if {$v_len==0} {return $tl}
if {[set v [fixed_parsing pkt offset len "$v_len B[expr $v_len*8] [get_tlv_vname $parser_record]"]]==""} {return ""}
eval set tlv \"[parser_record_format_cmd $parser_record]\"
puts "tlv=$tlv
--------------------------------------$proc:end ...offset=$offset,len=$len\n"
return $tlv
}