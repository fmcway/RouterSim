 package require Tk
 option add *Button.padY 0        ;# to make it look better on Windows
 option add *Button.borderWidth 1
 #---------------------------------------------------- testing i18n
 package require msgcat
 namespace import msgcat::mc msgcat::mcset
 mcset de Start Los
 mcset de Stop  Halt
 mcset fr Start Allez
 mcset fr Stop  Arr¨ºtez
 mcset zh Start \u8DD1
 mcset zh Stop  \u505C
 msgcat::mclocale en ;# edit this line for display language
 #--------------------------------------------------------------- UI
 button .start -text [mc Start] -command Start
 label  .time -textvar time -width 9 -bg black -fg green
 set time 00:00.00
 button .stop -text [mc Stop] -command Stop
 eval pack [winfo children .] -side left -fill y
 #------------------------------------------------------- procedures
 proc every {ms body} {eval $body; after $ms [info level 0]}

 proc Start {} {
    if {$::time=="00:00.00"} {
        set ::time0 [clock clicks -milliseconds]
    }
    every 10 {
        set m [expr {[clock clicks -milliseconds] - $::time0}]
        set ::time [format %2.2d:%2.2d.%2.2d \
            [expr {$m/60000}] [expr {($m/1000)%60}] [expr {$m%1000/10}]]
    }
    .start config -state disabled
 }
 proc Stop {} {
    if {[llength [after info]]} {
        after cancel [after info]
    } else {set ::time 00:00.00}
    .start config -state normal
 }