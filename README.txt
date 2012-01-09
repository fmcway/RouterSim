This is a protocol parser that users can define new parser without programming.

Example:
To parser Ethernet protocol, define protocol structure as follow:
Protocol	Message	Part	Parser_Type	List_Num	FieldIndex	Field				Length	Format			Description
Ether		Pkt		1		Fixed					1			DMAC				48		Bin2mac	
Ether		Pkt		1		Fixed					2			SMAC				48		Bin2mac	
Ether		Pkt		1		Fixed					3			Type_Len			16		Bin2Hex2Char	Type>=0x0800
Ether		Pkt		2		Lookup					1			Ether Pkt Type_Len			

And lookup table if necessary:
Protocol	Message	Part	Field		Format	Value	Next_Protocol	Next_Message
Ether		Pkt		1		Type_Len	Hex		0800	IPv4			Pkt
Ether		Pkt		1		Type_Len	Hex		8100	802_1Q			Pkt
Ether		Pkt		1		Type_Len	Hex		0806	ARP				Pkt
Ether		Pkt		1		Type_Len	Hex		<=1500	LLC				Pkt

All the rest of work is done by parser.

Sample result:
{
Ether_Pkt_DMAC 	01.02.03.04.05.06 
Ether_Pkt_SMAC  	01.02.03.04.05.06 
Ether_Pkt_Type_Len 	0800 } 
{
IPv4_Header_Version 	4 
IPv4_Header_HLen 		6 
IPv4_Header_DSCP 		110000 
IPv4_Header_ECN 		00 
IPv4_Header_Len 		208 
IPv4_Header_ID 			0424 
IPv4_Header_Flags 		000 
IPv4_Header_Offset 		0 
IPv4_Header_TTL 		255 
IPv4_Header_PID 		46 
IPv4_Header_Checksum 	1d13 
IPv4_Header_SIP 		1.1.1.1 
IPv4_Header_DIP 		1.1.1.2 } 
{
IPv4_Header_Options 	94040000 }
