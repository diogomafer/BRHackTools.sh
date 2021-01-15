#!/bin/bash 

exe() { echo "Running \"\$ $@\" in 5 seconds"; sleep 5 ; $@ ; } #Show and execute comand. Usage: exe eval 'ls -F | grep *.txt'

banner() #Show in a more beaultful mode
{
    echo "+------------------------------------------+"
    printf "| %-40s |\n" "`date`"
    echo "|                                          |"
    printf "|`tput bold` %-40s `tput sgr0`|\n" "$@"
    echo "+------------------------------------------+"
}

# Menu Option Wifiphisher
menuwifiphisher() {

    while :
    do

       banner "Chose an Option"
       echo "1 - Open Interface WifiPhisher"
       echo "2 - Free Wifi (Capture Facebook)"
       echo "0 - exit"

        read optionwifiphisher
        case $optionwifiphisher in
            1)
            exe sudo wifiphisher
            exe sudo systemctl start NetworkManager #Restart networkManager after closing

            ;;
            2)
	    read -p "Enter the name for the Fake Wifi(if blank default is: FREE): " essidwifihack

            read -p "Use Know Beacons? Y/N (Some Comum wifinames - blank Default is NO): " useknowbeacons

            case "$useknowbeacons" in #here we have a new case for select one submenu
                Y|y)
                useknowbeacons=-kB #Set the default content to -kB for use in atack script
                ;;
                N|n|"")
                ;;
                *)
                printf "Invalid Option, no use know beacons"
                ;;
            esac

	    essidwifihack=${essidwifihack:-"Copel Telecom Free Wifi"}

             exe sudo wifiphisher --essid "$essidwifihack" -p oauth-login $useknowbeacons

            ;;
            0)
            printf "Return to Initial Menu"
            break
            ;;
            *)
            printf "Invalid Option\n\n"
            ;;
        esac
    done
}

#menu for tshark (Wireshark non-Graphical)
menutshark() {

    read -p "Use an especific network card? type the mame of the card or enter to continue: " tsharknetworkcard

    [[ ! -z $tsharknetworkcard ]] && tsharknetworkcard="-i $tsharknetworkcard"  #if insert a card then ad to the comand

    printf "Need a especifc capture fetch filter? -(f) \n" 

    printf "\n
    Fetch Filters
    Filter:| Description
    host:| 4 Decimal digit dot separeted IP address
    net:| A range of decimal digit dot separeted IP address 
    srv net:| From a range of IP address 
    dst:| To range of IP address  
    mask:| To apply to IP address  
    arp:| Address Resolution Protocol 
    ether proto:| Ethernet type field 
    ether dst:| Ethernet MAC address of destination 
    broadcast:| Broadcast message across the network 
    multicast:| Ethernet Multicast Packet 
    tcp portrage:| Hypen (-) separeted range of TCP port numbers 
    dst port:| TCP destination port  
    tcp port:| TCP port number 
    ip:| All IPv4 traffic 
    pppoes:| All PPPOoE traffic
    vlan:| All Vlan port Number 
    port:| TCP port number 
    portocol:| You can Type the protocol name without \"quotes\" 
    ----:| ----
    not:| NOT the following 
    and:| Logical AND of the two adjacents parameters 
    or:| Logical Or of the two adjacent parameters 
    "| column -t -s ":" # run the atual print in a table format and with : as separator

    read -p "Please intert the filter without \"quotes\" or type ENTER to continue: " tsharkfetchfilter

    [[ ! -z $tsharkfetchfilter ]] && tsharkfetchfilter="-f \"$tsharkfetchfilter\""

    printf "Need a especifc capture yank filter? -(Y) \n" 

    printf "\n
    Yank Filters
    Filter:| Description
    frame.time:| 
    frame.time_relative:| Relative packet time stamp
    frame.len:| Lenght of the packet
    eth.addr:| 6 hex digit colon separeted ethernet MAC address
    eth.dst:| 6 hex digit colon separeted destination MAC address
    ip.addr:| 4 decimal digit dot separeted IP address
    ip.srv:| Sender's IP address
    ip.dst:| Reciver's IP address
    ip.len:| Length of the IP packet 
    tcp.srcport:| TCP source port
    tcp.port:| TCP port Number
    tcp.dstport:| TCP destination port
    udp.port:| UDP port number
    col.info:| Received Packet's content
    http.response.code:| HTTP Response code number
    http.request.method:| GET or POST
    && || >< == !:| Logical Operators
    "| column -t -s ":" # run the atual print in a table format and with : as separator

    read -p "Please intert the filter without \"quotes\" or type ENTER to continue: " tsharkyankfilter

    [[ ! -z $tsharkyankfilter ]] && tsharkyankfilter="-Y \"$tsharkyankfilter\"" 

    read -p "Use Monitor / Promiscuos mode? (-I). Type Y or enter to continue: " tsharkusemonitor

    case "$tsharkusemonitor" in 
        Y|y)
        tsharkusemonitor="-I" #if user type y then use monitor mode 
        ;;
        *)
        tsharkusemonitor="" 
        ;;
    esac

    read -p "Save pcapng output? (-w). Insert the path to the file or type enter to continue: " tsharkpcapoutput

    [[ ! -z $tsharkpcapoutput ]] && tsharkpcapoutput="-w \"$tsharkpcapoutput\"" 

    read -p "Especify a maximum number of packages(-c)(type a number or enter to unlimited): " tsharknumberofpackages

    if [[ ! -z $tsharknumberofpackages ]]
    then

        rechecknumber='^[0-9]+$'  # regular expression to check if its a number
        if  [[ $tsharknumberofpackages =~ $rechecknumber ]]  # If typed a number 
        then
            tsharknumberofpackages="-c $tsharknumberofpackages" 
        else
            tsharknumberofpackages=""  # Empty the content in case of are not numbers
            echo "The value insert its not a number running with unlimited packages"
        fi
    fi

    read -p "Show package contents(-x) Type Y or enter to continue: " tsharkshowpackagecontents

    case "$tsharkshowpackagecontents" in 
        Y|y)
        tsharkshowpackagecontents="-x" #show package contents
        ;;
        *)
        tsharkshowpackagecontents="" 
        ;;
    esac

    read -p "Show more information on packets(PacketTree)(Type Y or enter to continue): " tsharkshowpackagtree

    case "$tsharkshowpackagtree" in 
        Y|y)

           read -p "Type Especific Protocols (-O)(Comma separeted) or leave blank for all packages (-V): " tsharkshowpackagtree

            [[ ! -z $tsharkshowpackagtree ]] && tsharkshowpackagtree="-O \"$tsharkshowpackagtree\"" ||  tsharkshowpackagtree="-V" #show package contents
        ;;
        *)
        tsharkshowpackagtree="" 
        ;;
    esac

    exe eval sudo tshark --color -T tabs -z expert $tsharknetworkcard $tsharkfetchfilter $tsharkyankfilter $tsharkusemonitor $tsharkpcapoutput $tsharknumberofpackages $tsharkshowpackagecontents $tsharkshowpackagtree #run the script

}

searchallips(){

    read -p "Please insert the ip range (Syntax: 192.168.100.0/24) or press ENTER to use your gateway. WARNING! This tatic uses ping, so is highly detectable: " rangeip

    read -p "Type the path and file for log or type ENTER to do not log: " searchallipslog

   [[ -z $rangeip ]] && selectwificard

   rangeip=$(ip r | grep $selectedwificard | grep src | cut -d " " -f1) #if not insert a gateway use the default 

    [[ $searchallipslog ]] && searchallipslog="-oN $searchallipslog" 

    exe eval "sudo nmap -sn -PS22,3389 -PU161 $rangeip $searchallipslog"

    read -p "Type ENTER to continue" 

}

kismetmenu(){

  selectwificard #show an menu and return the response

    echo "Putting interface $selectedwificard into monitor mode"
    exe eval "sudo airmon-ng start $selectedwificard" #change to monitor mode
     
    read -p "Need some logging? By default we use no logging option (-n). Type Y if to logging or enter to continue: " kismetmenulogging

    case "$kismetmenulogging" in 
        Y|y)
        kismetmenulogging="" #use the default for kismet with log
        kismetmenuloggingmessage="Your log will be in $(pwd)"
        ;;
        *)
        kismetmenulogging="-n" 
        ;;
    esac

    exe eval "sudo kismet -c ${selectedwificard}mon $kismetmenulogging"

    echo "Putting interface $selectedwificard into normal mode"
    exe eval "sudo airmon-ng stop ${selectedwificard}mon" #change to normal mode

    echo $kismetmenuloggingmessage #Show logging message if exists"

}


    #CONTINUE REVISITING THE SCRIPT AFTER HERE!!!  






    slowhttptestmenu(){
    

    while [ -z "$slowhttptesttargeturl" ] #in loop unless the user inset a comand
    do
        read -p "Please intert the target absolute URL: " slowhttptesttargeturl 
    done

    while : #start an menu in a while to force the user to select one option
    do
    
        banner "Chose an Option:"
        printf "1 - Slow Read Test mode (-X)(Reading HTTP responses slowly) \n"
        printf "2 - Slow POST mode(-B)(Send unfinished HTTP message bodies) \n"
        printf "3 - SlowLoris mode(-H)(Send unfinished HTTP requests) \n"
        printf "4 - Range Header (-R) (Send malicious Range Request header data) \n"
        printf "0 - exit \n"

        read selectedoptionslowhttptestmenu
        case $selectedoptionslowhttptestmenu in
            1)
            read -p "Specify the start range of TCP: (-w)  or Type ENTER to use the default (512): " slowhttpcomandoption
            ${slowhttpcomandoption:=512}&>/dev/null # if the user not imput value use the default
            slowhttpapendcommand="$slowhttpapendcommand -w $slowhttpcomandoption" 
            unset slowhttpcomandoption #to garante dont pass the value to the next imput

            read -p "Specify the end range of TCP: (-y) or Type ENTER to use the default (1024): " slowhttpcomandoption
            ${slowhttpcomandoption:=1024}&>/dev/null # if the user not imput value use the default
            slowhttpapendcommand="$slowhttpapendcommand -y $slowhttpcomandoption" 
            unset slowhttpcomandoption #to garante dont pass the value to the next imput

            read -p "Specify the interval between read operations?(-n) or type ENTER to use the default(5): " slowhttpcomandoption
            ${slowhttpcomandoption:=5}&>/dev/null # if the user not imput value use the default
            slowhttpapendcommand="$slowhttpapendcommand -n $slowhttpcomandoption" 
            unset slowhttpcomandoption #to garante dont pass the value to the next imput

            read -p "Specify the number of times the resource wold be requested?(-k) or type ENTER to use the default (3): " slowhttpcomandoption
            ${slowhttpcomandoption:=3}&>/dev/null # if the user not imput value use the default
            slowhttpapendcommand="$slowhttpapendcommand -k $slowhttpcomandoption" 
            unset slowhttpcomandoption #to garante dont pass the value to the next imput

            break #to continue append comands outside the case
            ;;
            2)
            read -p "Specify the interval between fallow up data?: (-i) or type ENTER to use the default(110): " slowhttpcomandoption
            ${slowhttpcomandoption:=110}&>/dev/null # if the user not imput value use the default
            slowhttpapendcommand="$slowhttpapendcommand -i $slowhttpcomandoption" 
            unset slowhttpcomandoption #to garante dont pass the value to the next imput

            read -p "Specify the value of Content-Length? (-s) or type ENTER to use the default (8192): " slowhttpcomandoption
            ${slowhttpcomandoption:=8192}&>/dev/null # if the user not imput value use the default
            slowhttpapendcommand="$slowhttpapendcommand -s $slowhttpcomandoption" 
            unset slowhttpcomandoption #to garante dont pass the value to the next imput

            read -p "Specify the verb to use in HTTP request? (-t )or type ENTER to continue. " slowhttpcomandoption
            ${slowhttpcomandoption:=8192}&>/dev/null # if the user not imput value use the default
            slowhttpapendcommand="$slowhttpapendcommand -s $slowhttpcomandoption" 
            unset slowhttpcomandoption #to garante dont pass the value to the next imput

#
# #if dont insert omit the option for the comand
#
# Specify the maximum length of fallow up data? (-x) or type ENTER to use the default(10):
            ;;
            3)
#            Specify the interval between fallow up data?: (-i) or type ENTER to use the default(10):
#
# Specify the verb to use in HTTP request? (-t )or type ENTER to continue.
#
# #if dont insert omit the option for the comand
#
# Specify the maximum length of fallow up data? (-x) or type ENTER to use the default(24):
            ;;
            4)
#            Specify the verb to use in HTTP request? (-t )or type ENTER to continue.
#
# Specify the start value for Range Header Attack(-a) or type ENTER to use the default(10):
#
# Specify the limit value for Ranger Header Attack(-b) or type ENTER to use the default(3000)
            ;;
            0)
            break
            ;;
            *)
            echo "Invalid Option"
            ;;
        esac
    done


exe eval "slowhttptest -u $slowhttptesttargeturl $slowhttpapendcommand"


}


dirsearchmenu(){

    while [ -z "$targeturl" ] #in loop unless the user inset a comand
    do

        read -p "Please insert the target URL: " targeturl

        [ ! -z "$targeturl" ] && read -p "Please insert the extension (whitout \".\") to the search. Type enter to default (PHP): " dirsearchextension

        [ ! -z "$targeturl" ]  && read -p "Please instert a wordlist or tipe ENTER to use the default: " dirsearchwordlist 
        
	[ $dirsearchwordlist ] && dirsearchwordlist="-w $dirsearchwordlist" #create the comand to user wordlist 
    
    done








    exe eval sudo tshark --color -T tabs -z expert $tsharkfetchfilter $tsharkyankfilter $tsharkusemonitor $tsharkpcapoutput $tsharknumberofpackages $tsharkshowpackagecontents #run the script

}

dirsearchmenu(){

    while [ -z "$targeturl" ] #in loop unless the user inset a comand
    do

        read -p "Please insert the target URL: " targeturl

        [ ! -z "$targeturl" ] && read -p "Please insert the extension (whitout \".\") to the search. Type enter to default (PHP): " dirsearchextension

        [ ! -z "$targeturl" ]  && read -p "Please instert a wordlist or tipe ENTER to use the default: " dirsearchwordlist 
        
	[ $dirsearchwordlist ] && dirsearchwordlist="-w $dirsearchwordlist" #create the comand to user wordlist 
    
done

        dirsearchextension=${dirsearchextension:-php} #if not insert then set the default extension

        exe eval "dirsearch.py -u $targeturl -e $dirsearchextension -r $dirsearchwordlist --random-agents"

}

torghostmenu(){

    echo "WARNING!! Disable ipv6 before start, after end check the https://ipleak.net/ report or acess the site"
    echo "This program will fully anonymize the acess through Tor network"
    read -p "Press enter to start or type STOP to stop: " startorstop

    [ $startorstop ] && comandtorghost="-s" || comandtorghost="-x"

    echo "The network will restart, please check at the end if you are really out Tor Network"

    changemacadress #self explained :)

    exe eval "sudo torghost $comandtorghost"

    echo "WARNING! Check the result before to avoid errors!"
    exe eval "curl -s https://check.torproject.org/ | head | grep \"Tor.\""

    echo "WARNING!! Check the information below to avoid DNS Leaks or acess https://ipleak.net/ to verify"
    exe eval "curl https://ipleak.net/json/"

}

wifite2menu(){

    read -p "For best resultions type the path for a better wordlist or type enter to use the default" wifitewordlist

    [ ! -z "$wifitewordlist" ] && comandwifitewordlist="--dict $wifitewordlist"

    exe eval "sudo wifite $comandwifiteworllist --random-mac --verbose" 

    selectwificard 

    exe eval "sudo airmon-ng stop $wifitoativate" #reativate wificard
}


securepingmenu(){

    while [ -z "$targeturl" ] #in loop unless the user inset a comand
    do

        echo "Please insert the target URL"
        read targeturl

        echo "Runing \"nmap -sT -Pn $targeturl\" ( -sT for 3-way-handshake complete and -Pn for do not use ping )\""
        nmap -sT -Pn $targeturl

        echo ""

    done

}

changemacadress(){

    echo "To change the macadress please type the name of the card."
    echo "Our atual wifi cards are:\n"
    echo "Running \"ip a | grep state | cut -d: -f2\""
    ip a | grep state | cut -d: -f2 #show only wifi cards
    
    selectwificard

    while [ -z "$selectedwificard" ] #in loop unless the user inset a comand
    do

    echo "WARNING!!! CHECK IF THE MACADRESS REALLY CHANGE"

    echo "Runing \"sudo macchanger -r $ethernetcardtochange\""
    sudo macchanger -r $ethernetcardtochange

    echo "Runing \"sudo ip link set $ethernetcardtochange up\""
    sudo ip link set $ethernetcardtochange up
    done

}

respondermenu(){

    selectwificard  #show an menu and return the response

    echo "This program saves the HASHs in \"/opt/Responder-Master/logs\" if the atack works please check this directory  "
    echo "if a Hash is located use a program like john the ripper to decript"
    exe eval "sudo killall dnsmasq -9 "
    exe eval "sudo responder -vI $selectedwificard -wrf" 

}

jhontheripper(){

        echo "In Implementation process"
    #after this use jhon the reaper,
    # john SMB-NTLMv2-SSP-192.168.100.101.txt –wordlist=/usr/share/wordlists/rockyou.txt
    #or maybe hashcat? search the best
    #if use jhone the reaper, study chttps://github.com/SpiderLabs/KoreLogic-Rules/blob/master/kore-logic-rules-top7.txt seens to be good is from spiderlabs, so its good

    #i think jhonthereaper is best for cpu power and hashcat to gpu power?
}

selectwificard(){ #usage = call the function em then read the variable selectedwificard

    echo "Our atual wifi cards are:\n"
    echo "Running \"ip a | grep state | cut -d: -f2\""
    ip a | grep state | cut -d: -f2 #show only wifi cards


    while [ -z "$selectedwificard" ] #in loop unless the user inset a comand
    do

            echo "Please select one wificard"
            read selectedwificard

    done

    }


httrackmenu(){

    while [ -z "$COPYPAGE" ] #in loop unless the user inset a comand
    do

            echo "Please inset the page to copy with http://"
            read COPYPAGE


    done

      echo "Please inset the page destination, or type ENTER to use  "./" as the default"
      read PAGEDESTINATION

      test  -z $PAGEDESTINATION && PAGEDESTINATION="." #if not insert a page destination use the default

    echo $PAGEDESTINATION

    echo "Running \"httrack $COPYPAGE -O $PAGEDESTINATION -%!\""
    httrack $COPYPAGE -O $PAGEDESTINATION -%!

}

showmenu(){

    while :
    do
        

         banner "Chose an Option:"
         echo "1 - Wifi Hack Tools"
         echo "2 - DDoS, Network and Webserver Tools"
         echo "3 - TShark (Wireshark Non-Graphical)"
         echo "4 - Anonymize kali"
         echo "5 - Windows Network Hacking Tools "
         echo "0 - exit"

        read SELECTEDTOOL
        case $SELECTEDTOOL in
            1)
                while :
                do
                    banner "Chose an Option:"
                    echo "1 - Wifiphisher (Capture wifi credentials)"
                    echo "2 - Kismet (Wifi Network Surveillance tool with a web interface)"
                    echo "3 - Wifite2 (Automated Password Craking)"
                    echo "4 - Yersinia (Atack Network Protocols especially Cisco)"
                    echo "0 - exit"

                    read SELECTEDTOLLWIFIMENU
                    case $SELECTEDTOLLWIFIMENU in
                        1)
                        menuwifiphisher
                        ;;
                        2)
                        kismetmenu
                        ;;
                        3)
                        wifite2menu
                        ;;
                        4)
                        sudo yersinia -I
                        ;;
                        0)
                        break
                        ;;
                        *)
                        echo "Invalid Option"
                        ;;
                    esac
                done
            ;;
            2)
                while :
                do
                    banner "Chose an Option:"
                    echo "1 - Slowhttptest (Simple DDoS using SlowLoris technique)"
                    echo "2 - Dirsearch (Check hidden directories in websites)"
                    echo "3 - Dirburster (Graphical Interface to Check hidden directories in websites)"
                    echo "4 - Httrack (Download complete sites)"
                    echo "5 - Search all IPs in a network"
                    echo "6 - Secure ping (using nmap)" 
                    echo "0 - exit"

                    read SELECTTOLLWEBMENU
                    case $SELECTTOLLWEBMENU in
                        1)
                        slowhttptestmenu
                        ;;
                        2)
                        dirsearchmenu
                        ;;
                        3)
                        sudo dirbuster
                        ;;
                        4) httrackmenu
                        ;;
                        5)
                        searchallips
                        ;;
                        6)
                        securepingmenu
                        ;;
                        0)
                         break
                        ;;
                        *)
                        echo "Invalid Option"
                        ;;
                    esac
                done
            ;;
            3)
            menutshark
            ;;
            4)
            while :
            do

                banner "Chose an Option:"
                echo "1 - Torghost (Fully Anonymize kali)"
                echo "2 - Change MacAdress"
                echo "0 - exit"

                read SELECTTOLLANONYMIZEMENU
                case $SELECTTOLLANONYMIZEMENU in
                    1)
                    torghostmenu
                    ;;
                    2)
                    changemacadress
                    ;;
                    0)
                    break
                    ;;
                    *)
                    echo "Invalid Option"
                    ;;
                esac
            done
            ;;
            5)
            while :
            do

                banner "Chose an Option:"
                echo "1 - Responder (Locate windows credentials in network)"
                echo "0 - exit"

                read SELECTTOOLRESPONDERMENU
                case $SELECTTOOLRESPONDERMENU in
                    1)
                    respondermenu
                    ;;
                    0)
                    break
                    ;;
                    *)
                    echo "Invalid Option"
                    ;;
                esac
            done
            ;;
            0)
            banner "Bye"
            break
            ;;
            *)
            echo "Invalid Option"
            showmenu
            ;;
        esac
    done

}
showmenu #show de initial nem


