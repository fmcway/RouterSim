package require comm

array set host {
nms_client    127.0.0.1
OSPF_server   127.0.0.1
router_server 127.0.0.1
}

array set port {
nms_client    60000
OSPF_server   20000
router_server 10000
}

::comm::comm configure -port $port(nms_client)
set msg [list nms_client   -    0  		  OSPF_server rsh dump_log]
catch {::comm::comm send $port(OSPF_server) msg_comm $msg}

while {1} {
gets stdin cmd; if {$cmd=="exit"} {break}
set msg [list nms_client   -    0  		  OSPF_server rsh $cmd]
if {![catch {set out [::comm::comm send $port(OSPF_server) msg_comm $msg]}]} {
puts $out
}
}