if { [catch { package require IRCServices 0.0.1 }] } { putloglev o * "\00304\[ProxyCheck - Error\]\003 ProxyCheck requires IRCServices package 0.0.1 (or higher) to work, Download from 'https://github.com/MalaGaM/TCL-PKG-IRCServices'. The loading of the script was canceled." ; return }

if { [catch { package require sqlite3 }] } { putloglev o * "\00304\[ProxyCheck - Error\]\003 ProxyCheck requires sqlite3 package to work, install with from 'apt install libsqlite3-tcl'. The loading of the script was canceled." ; return }

if { [catch { package require http }] } { putloglev o * "\00304\[ProxyCheck - Error\]\003 ProxyCheck requires http package to work, install with from 'apt install tcllib'. The loading of the script was canceled." ; return }

if { [catch { package require json }] } { putloglev o * "\00304\[ProxyCheck - Error\]\003 ProxyCheck requires json package to work, install with from 'apt install json'. The loading of the script was canceled." ; return }

if { [catch { package require dns }] } { putloglev o * "\00304\[ProxyCheck - Error\]\003 ProxyCheck requires dns package to work, install with from 'apt install tcllib'. The loading of the script was canceled." ; return }

if { [catch { package require ip }] } { putloglev o * "\00304\[ProxyCheck - Error\]\003 ProxyCheck requires ip package to work, install with from 'apt install tcllib'. The loading of the script was canceled." ; return }

try {
	package require tls
} on ok ver {
	putlog "::ProxyCheck TCL-TLS loaded: $ver"
	http::register https 443 ::tls::socket
} on error {

} {

}

if {[info commands ::ProxyCheck::uninstall] eq "::ProxyCheck::uninstall" } { ::ProxyCheck::uninstall }

namespace eval ::ProxyCheck {
	variable config
	variable ns	[namespace current]
	variable CONNECT_ID
	variable BOT_ID
	variable HTTP
	variable WHOIS
	variable INIT_SCRIPT
	set INIT_SCRIPT 1
	utimer 5 [list ::ProxyCheck::INIT_END]
	dict set WHOIS		BINARY				[lindex [split [exec which whois]] 0]
	set CONNECT_ID			{}
	set BOT_ID				{}

	set config(scriptname)	"ProxyServ Service"
	set config(version)		"1.1.20210521"
	set config(auteur)		"MalaGaM"
	set config(path_script)	[file dirname [info script]];
	set config(vars_list)	[list	\
		"uplink_host"		\
		"uplink_port"		\
		"uplink_password"	\
		"serverinfo_name"	\
		"serverinfo_descr"	\
		"serverinfo_id"		\
		"uplink_useprivmsg"	\
		"uplink_debug"		\
		"service_nick"		\
		"service_user"		\
		"service_host"		\
		"service_gecos"		\
		"service_modes"		\
		"service_channel"	\
		"service_chanmodes"	\
		"service_usermodes"	\
		"admin_password"	\
		"db_lang"			\
		"admin_console"		\
		"db_lang"			\
		"scriptname"		\
		"version"			\
		"auteur"
	];

}
proc ::ProxyCheck::INIT_END {} {
	variable INIT_SCRIPT
	set INIT_SCRIPT 0
	putlog "::ProxyCheck::INIT_END FIN INIT"
}
proc ::ProxyCheck::uninstall {args} {
	variable config
	variable CONNECT_ID
	putlog "Deallocation of resources from \002[set config(scriptname)]\002..."
	foreach binding [lsearch -inline -all -regexp [binds *[set ns [::tcl::string::range [namespace current] 2 end]]*] " \{?(::)?$ns"] {
		unbind [lindex $binding 0] [lindex $binding 1] [lindex $binding 2] [lindex $binding 4]
	}

	# Arrêt des timers en cours.
	foreach running_timer [timers] {
		if { [::tcl::string::match "*[namespace current]::*" [lindex $running_timer 1]] } { killtimer [lindex $running_timer 2] }
	}
	$CONNECT_ID destroy
	namespace delete ::ProxyCheck
}

proc ::ProxyCheck::SQL:BUILD:UPSERT { TABLE_NAME DICT_DATA {CONFLICT_NAME ""} } {
	set COLNAME	""
	set COLVAL	""
	set UPDATE	""
	foreach { COL_NAME COL_VALUE } $DICT_DATA {
		set CVALUE		[encoding convertfrom utf-8 $COL_VALUE]
		lappend COLNAME	$COL_NAME
		lappend COLVAL	$CVALUE
		lappend UPDATE	"$COL_NAME = '$CVALUE'"
	}
	set SQL_INSERT		"INSERT INTO $TABLE_NAME ("
	append SQL_INSERT	" " "`[join $COLNAME "`, `"]`"
	append SQL_INSERT	" " ") VALUES ( '[join $COLVAL "', '"]' )"
	if { $CONFLICT_NAME != "" } {
		append SQL_INSERT	" " "ON CONFLICT($CONFLICT_NAME) DO UPDATE SET"
		append SQL_INSERT	" " "[join $UPDATE ", "]"
	}


	return $SQL_INSERT
}
proc ::ProxyCheck::SQL:PROXYCHECK:GET { ID } {
	set columns [::ProxyCheck::SQL:QUERY "PRAGMA table_info(proxycheck_data)"]
	return $columns
}
proc ::ProxyCheck::SQL:PROXYCHECK:ADD { DICT_DATA } {
	return [::ProxyCheck::SQL:REPLACE:ADD $DICT_DATA proxycheck_data "asn"]
	set SQL_INSERT		[::ProxyCheck::SQL:BUILD:UPSERT proxycheck_data $DICT_DATA "asn"]
	return [::ProxyCheck::SQL:EXEC $SQL_INSERT]
}
proc ::ProxyCheck::SQL:WHOISDATA:ADD { DICT_DATA } {
	return [::ProxyCheck::SQL:REPLACE:ADD $DICT_DATA whois_data "INUM_START,INUM_END"]
	set SQL_INSERT		[::ProxyCheck::SQL:BUILD:UPSERT whois_data $DICT_DATA "INUM_START,INUM_END"]
	return [::ProxyCheck::SQL:EXEC $SQL_INSERT]
}
proc ::ProxyCheck::SQL:REPLACE:ADD { DICT_DATA SQL_TABLE SQL_UNIQUE } {
	set SQL_INSERT		[::ProxyCheck::SQL:BUILD:UPSERT $SQL_TABLE $DICT_DATA $SQL_UNIQUE]
	set SQL_DATA		[::ProxyCheck::SQL:EXEC $SQL_INSERT]
	if { $SQL_DATA == 0 } {
		set TMP			[dict filter $DICT_DATA key {*}[join [split $SQL_UNIQUE ,] { key }]]
		set SQL_WHERE_TMP	""
		foreach { N V } $TMP {
			append SQL_WHERE_TMP "$N = '$V'" " and "
		}
		set SQL_WHERE	[lindex $SQL_WHERE_TMP 0 end-1]
		set SQL_DATA	[lindex [::ProxyCheck::SQL:TABLE:SELECT $SQL_TABLE $SQL_WHERE] 1]
	}
	return $SQL_DATA
}
proc ::ProxyCheck::SQL:IANA:ADD { DICT_DATA } {
	return [::ProxyCheck::SQL:REPLACE:ADD $DICT_DATA iana_data "INUM_START,INUM_END"]
	set SQL_TABLE		"iana_data"
	set SQL_UNIQUE		"INUM_START,INUM_END"
	set SQL_INSERT		[::ProxyCheck::SQL:BUILD:UPSERT $SQL_TABLE $DICT_DATA $SQL_UNIQUE]
	set SQL_DATA		[::ProxyCheck::SQL:EXEC $SQL_INSERT]
	if { $SQL_DATA == 0 } {
		set TMP			[dict filter $DICT_DATA key {*}[join [split $SQL_UNIQUE ,] { key }]]
		set SQL_WHERE_TMP	""
		foreach { N V } $TMP {
			append SQL_WHERE_TMP "$N = '$V'" " and "
		}
		set SQL_WHERE	[lindex $SQL_WHERE_TMP 0 end-1]
		set SQL_DATA	[lindex [::ProxyCheck::SQL:TABLE:SELECT $SQL_TABLE $SQL_WHERE] 1]
	}
	return $SQL_DATA
}

proc ::ProxyCheck::SQL:CLOSE { } {
	::ProxyCheck_db close
}
proc ::ProxyCheck::SQL:OPEN { } {
	sqlite3 ::ProxyCheck_db [::ProxyCheck::FCT:Get:ScriptDir]db/ProxyCheck.db
}
proc ::ProxyCheck::SQL:EXEC { SQL_DATA } {
	::ProxyCheck::SQL:OPEN
	
	if { [catch {set SQL_RES			[::ProxyCheck_db eval $SQL_DATA]} err] } { 
		putlog "---------------------------------> $err"
	}
	set INSERT_ID	[::ProxyCheck_db last_insert_rowid];
	::ProxyCheck::SQL:CLOSE
	return $INSERT_ID

}
proc ::ProxyCheck::SQL:QUERY { SQL_DATA } {
	::ProxyCheck::SQL:OPEN
	set SQL_DATA	[::ProxyCheck_db eval $SQL_DATA]
	::ProxyCheck::SQL:CLOSE
	return $SQL_DATA
}
proc ::ProxyCheck::SQL:TABLE:SELECT { SQL_TABLE {WHERE ""} } {
	set COLS			[::ProxyCheck::SQL:TABLES:NAME $SQL_TABLE]
	set SQL_QUERY		"SELECT [join $COLS ", "]"
	set DATA			[list]
	set I				0
	append SQL_QUERY	" " "from $SQL_TABLE"
	if { $WHERE != "" } {
		append SQL_QUERY	" " "WHERE $WHERE"
	}
	append SQL_QUERY	" " "LIMIT 1"
	set SQL_DATA	[::ProxyCheck::SQL:QUERY $SQL_QUERY]
	foreach { COLSNAME } $COLS {
		lappend DATA $COLSNAME [lindex $SQL_DATA $I]
		incr I
	}
	return $DATA
}
proc ::ProxyCheck::SQL:TABLES:NAME { SQL_TABLE } {
	::ProxyCheck::SQL:OPEN
	set SQL_DATA	[::ProxyCheck_db eval "PRAGMA table_info($SQL_TABLE)"]
	set DATA		""
	::ProxyCheck::SQL:CLOSE
	foreach { - COLNAME - - - - } $SQL_DATA { lappend DATA $COLNAME }
	return $DATA
}

proc ::ProxyCheck::SQL:INIT { } {
	::ProxyCheck::SQL:EXEC "
	CREATE TABLE IF NOT EXISTS IP_relation_data (
	ID_IP_RELATION integer PRIMARY KEY AUTOINCREMENT,
	created_at timestamp  NOT NULL DEFAULT current_timestamp,
	ID_PROXYCHECK integer,
	ID_IANA integer ,
	ID_WHOIS integer,
	IP_DEC_START integer,
	IP_DEC_END integer,
	UNIQUE(IP_DEC_START,IP_DEC_END)
	);

	";
	::ProxyCheck::SQL:EXEC "
	CREATE TABLE IF NOT EXISTS proxycheck_data (
	ID_PROXYCHECK integer PRIMARY KEY AUTOINCREMENT,
	created_at timestamp  NOT NULL DEFAULT current_timestamp,
	asn varchar,
	provider varchar,
	continent varchar,
	country varchar,
	isocode varchar,
	region varchar,
	regioncode varchar,
	city varchar,
	latitude varchar,
	longitude varchar,
	proxy varchar,
	type varchar,
	risk integer,
	UNIQUE(asn)
	);
	
	";
	::ProxyCheck::SQL:EXEC "
	CREATE TABLE IF NOT EXISTS iana_data (
	ID_IANA integer PRIMARY KEY AUTOINCREMENT,
	created_at timestamp  NOT NULL DEFAULT current_timestamp,
	SERVER varchar,
	INUM_START varchar,
	INUM_END varchar,
	ORG varchar,
	STATUS varchar,
	CHANGED varchar,
	UNIQUE(INUM_START,INUM_END)
	);
	";
	::ProxyCheck::SQL:EXEC "
	CREATE TABLE IF NOT EXISTS whois_data (
	ID_WHOIS integer PRIMARY KEY AUTOINCREMENT,
	created_at timestamp  NOT NULL DEFAULT current_timestamp,
	SERVER varchar,
	INUM_START varchar,
	INUM_END varchar,
	UNIQUE(INUM_START,INUM_END)
	);
	";
}

proc ::ProxyCheck::INIT { } {
	variable config
	variable db
	::ProxyCheck::SQL:INIT

	################
	# ProxyCheck Source #
	################
	if { [file exists [::ProxyCheck::FCT:Get:ScriptDir]ProxyCheck.conf] } {
		source [::ProxyCheck::FCT:Get:ScriptDir]ProxyCheck.conf
		::ProxyCheck::FCT:Check:Config
	} else {
		if { [file exists [::ProxyCheck::FCT:Get:ScriptDir]ProxyCheck.Example.conf] } {
			putlog "Edit, configure and rename 'ProxyCheck.Example.conf' to 'ProxyCheck.conf' in '[::ProxyCheck::FCT:Get:ScriptDir]'"
			exit
		} else {
			putlog "Missing configuration file '[::ProxyCheck::FCT:Get:ScriptDir]ProxyCheck.conf'."
			exit
		}
	}
	if {![info exists config(idx)]} { ::ProxyCheck::FCT:Socket:Connexion }
	set config(putlog) "[set config(scriptname)] v[set config(version)] par [set config(auteur)]"
}
proc ::ProxyCheck::FCT:Get:ScriptDir { {DIR ""} } {
	variable config
	return "[file normalize $config(path_script)/$DIR]/"
}
proc ::ProxyCheck::FCT:Socket:Connexion {} {
	variable config
	variable CONNECT_ID
	variable BOT_ID

	if { $config(uplink_ssl) == 1		} { set config(uplink_port) "+$config(uplink_port)" }
	if { $config(serverinfo_id) != ""	} { set config(uplink_ts6) 1 } else { set config(uplink_ts6) 0 }

	set CONNECT_ID [::IRCServices::connection]; # Creer une instance services
	$CONNECT_ID connect $config(uplink_host) $config(uplink_port) $config(uplink_password) $config(uplink_ts6) $config(serverinfo_name) $config(serverinfo_id); # Connexion de l'instance service
	if { $config(uplink_debug) == 1} { $CONNECT_ID config logger 1; $CONNECT_ID config debug 1; }
	set BOT_ID [$CONNECT_ID bot]; #Creer une instance bot dans linstance services

	$BOT_ID create $config(service_nick) $config(service_user) $config(service_host) $config(service_gecos) $config(service_modes); # Creation d'un bot service
	$BOT_ID join $config(service_channel)
	$BOT_ID registerevent EOS {
		variable ::ProxyCheck::config
		[sid] mode $config(service_channel) $config(service_chanmodes)
		if { $config(service_usermodes) != "" } {
			[sid] mode $config(service_channel) $config(service_usermodes) $config(service_nick)
		}

	}
	$BOT_ID registerevent UID {
		
		# 001 UID ctcp 0 1620287716 IRCV3 215.ip-92-222-91.eu 001B3JC01 0 +iwxzG Epikuri-7194FAA0.ip-92-222-91.eu Epikuri-7194FAA0.ip-92-222-91.eu XN5b1w==
		set NICK	[lindex [header] 2]
		set IP		[lindex [header] 6]
		
		if { [::ProxyCheck::FCT:USER:IS:WEBCLIENT $IP] } {
			set IP		[msg]
			set MSG		[::ProxyCheck::FCT:CHECKUSER $IP $NICK "CONNECT" "WEBCLIENT-IRC"]
		} else {
			set MSG		[::ProxyCheck::FCT:CHECKUSER $IP $NICK "CONNECT"]
		}
		if { $::ProxyCheck::INIT_SCRIPT == 1 } { return 1 }
		::ProxyCheck::FCT:SENT:MSG $::ProxyCheck::config(service_channel) $MSG

	}
	$BOT_ID registerevent PRIVMSG {
		set cmd		[lindex [msg] 0]
		set data	[lrange [msg] 1 end]
		##########################
		#--> Commandes Privés <--#
		##########################
		# si [target] ne commence pas par # c'est un pseudo
		if { [string index [target] 0] != "#"} {
			if { [string tolower $cmd] == "help"	} {
				::ProxyCheck::IRC:CMD:PRIV:HELP [who2] [target] $cmd $data
			}
			if { [string tolower $cmd] == "ip"		} {
				::ProxyCheck::IRC:CMD:PRIV:IP [who2] [target] $cmd $data
			}
		}
		##########################
		#--> Commandes Salons <--#
		##########################
		# si [target] commence par # c'est un salon
		if { [string index [target] 0] == "#"} {
			if { [string tolower $cmd] == "!help"		} {
				# Received: :MalaGaM PRIVMSG #Eva :!help
				::ProxyCheck::IRC:CMD:PUB:HELP [who] [target] $cmd $data
			}
			if { [string tolower $cmd] == "!proxyserv"	} {
				::ProxyCheck::IRC:CMD:PUB:PROXYSERV [who] [target] $cmd $data
			}
		}
	}; # Creer un event sur PRIVMSG

}
proc ::ProxyCheck::FCT:Check:Config { } {
	variable config
	foreach CONF $config(vars_list) {
		if { ![info exists config($CONF)] } {
			putlog "\[ Error \] ProxyCheck Service configuration Incorrect ... '$CONF' : Missing parameter"
			exit
		}
		if { $config($CONF) == "" } {
			putlog "\[ Error \] Incorrect ProxyCheck Service configuration ... '$CONF' : Empty value"
			exit
		}
	}
}
proc ::ProxyCheck::FCT:SENT:NOTICE { DEST MSG } {
	variable BOT_ID
	$BOT_ID	notice $DEST [::ProxyCheck::FCT:apply_visuals $MSG]
}
proc ::ProxyCheck::FCT:SENT:PRIVMSG { DEST MSG } {
	variable BOT_ID
	$BOT_ID	privmsg $DEST [::ProxyCheck::FCT:apply_visuals $MSG]
}
proc ::ProxyCheck::FCT:SENT:MSG { DEST MSG } {
	variable config
	if { $config(uplink_useprivmsg) == 1 } {
		::ProxyCheck::FCT:SENT:PRIVMSG $DEST $MSG;
	} else {
		::ProxyCheck::FCT:SENT:NOTICE $DEST $MSG;
	}
}
proc ::ProxyCheck::FCT:SENT:MSG:TO:CHAN:LOG { MSG } {
	variable config
	::ProxyCheck::FCT:SENT:PRIVMSG $config(service_channel) $MSG;
}
proc ::ProxyCheck::FCT:API:GETKEY:RANDOM {} {
	variable config
	set NB_KEY		[llength $config(HTTP_APIKEY)];
	set RANDOM_KEY	[expr {int(rand()*$NB_KEY)}];
	return [lindex $config(HTTP_APIKEY) $RANDOM_KEY];
}
proc ::ProxyCheck::FCT:PROXYCHECK:GET { IP } {
	variable config
	variable HTTP
	set HTTP_QUERY		"$config(HTTP_API_URL)/"
	append HTTP_QUERY	$IP
	append HTTP_QUERY	"?key=[::ProxyCheck::FCT:API:GETKEY:RANDOM]"
	append HTTP_QUERY	"&vpn=1"
	append HTTP_QUERY	"&asn=1"
	append HTTP_QUERY	"&inf=1"
	append HTTP_QUERY	"&risk=1"
	append HTTP_QUERY	"&seen=1"
	append HTTP_QUERY	"&port=1"
	append HTTP_QUERY	"&days=$config(HTTP_DAYS)"
	set HTTP_DATA		[::ProxyCheck::FCT:HTTP:GET:DATA $HTTP_QUERY]
	if { [dict get $HTTP STATUS] != "ok" } { return -1 }
	set JSON_DATA		[json::json2dict $HTTP_DATA]
	if { [dict get $JSON_DATA status] == "ok" } {
		set PROXYCHECK_DATA [dict get $JSON_DATA $IP]
		set INSERT_ID		[::ProxyCheck::SQL:PROXYCHECK:ADD $PROXYCHECK_DATA]
		dict lappend PROXYCHECK_DATA PROXYCHECK_ID $INSERT_ID
		return $PROXYCHECK_DATA
	}
	return $JSON_DATA
}
proc ::ProxyCheck::FCT:CHECKUSER { IP {NICK ""} {METHODE "CONNECT"} {TYPE_CLIENT "CLIENT-IRC"} } {
	set IP				[::ProxyCheck::HOSTNAME:TO:IP $IP]
	
	if { [catch {set IP_DATA			[dict get [::ProxyCheck::FCT:CHECKIP $IP]]} err] } { putlog "---------------------------------> $err"}
	set PROXYCHECK_DATA {*}[dict get $IP_DATA PROXYCHECK_DATA]
	set asn				[dict get $PROXYCHECK_DATA asn]
	set provider		[dict get $PROXYCHECK_DATA provider]
	set country			[dict get $PROXYCHECK_DATA country]
	set isocode			[dict get $PROXYCHECK_DATA isocode]
	set proxy			[dict get $PROXYCHECK_DATA proxy]
	set type			[dict get $PROXYCHECK_DATA type]
	set risk			[dict get $PROXYCHECK_DATA risk]
	set cache			[expr {[dict get $IP_DATA CACHE]? Yes : No}]
	set HOSTINFO_DATA	{*}[dict get $IP_DATA HOSTINFO]
	set IP_ADRESS		[dict get $HOSTINFO_DATA IP_ADRESS]
	set HOSTNAME		[dict get $HOSTINFO_DATA HOSTNAME]
	set message			"<b><c03>>><b><c04> $NICK <c06>-"
	append message	" " "<c03>CACHE<c06>:<c14> $cache <c06>-"
	append message	" " "<c03>CLIENT<c06>:<c14> $TYPE_CLIENT <c06>-"
	append message	" " "<c03>IP<c06>:<c14> $IP_ADRESS <c06>-"
	append message	" " "<c03>HOSTNAME<c06>:<c14> $HOSTNAME <c06>-"
	append message	" " "<c03>ASN<c06>:<c14> $asn <c06>-"
	append message	" " "<c03>ORG<c06>:<c14> $provider <c06>-"
	append message	" " "<c03>SHTETI<c06>:<c14> $country <c06>-"
	append message	" " "<c03>KODI<c06>:<c14> $isocode <c06>-"
	append message	" " "<c03>Proxy<c06>:<b><c04> $proxy<b> <c06>-"
	append message	" " "<c03>Type<c06>:<c10> $type <c06>-"
	append message	" " "<c03>SCORE<c06>:<c10> $risk"
	return $message
}
proc ::ProxyCheck::GET:HOSTINFO { HOSTorIP } {
	dict append HOSTINFO IP_ADRESS	[::ProxyCheck::HOSTNAME:TO:IP $HOSTorIP]
	dict append HOSTINFO HOSTNAME	[::ProxyCheck::IP:TO:HOSTNAME $HOSTorIP]
	return $HOSTINFO
}
proc ::ProxyCheck::HOSTNAME:TO:IP { HOSTNAME } {
	if { [catch { set resolveip [exec resolveip $HOSTNAME] }] } { return $HOSTNAME }
	if { [regexp {^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$} $HOSTNAME] } {
		set IP [lindex $resolveip 3]
	} else {
		set IP [lindex $resolveip end]
	}
	return $IP
}
proc ::ProxyCheck::IP:TO:HOSTNAME { IP } {
	if { [catch { set resolveip [exec resolveip $IP] }] } { return $IP }
	if { ![regexp {^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$} $IP] } {
		set HOSTNAME [lindex $resolveip 3]
	} else {
		set HOSTNAME [lindex $resolveip end]
	}
	return $HOSTNAME
}
proc ::ProxyCheck::FCT:CHECKIP { IP } {
	set CACHED					1

	set HOSTINFO				[::ProxyCheck::GET:HOSTINFO $IP]

	# HOSTINFO :				IP_ADRESS 217.84.120.30 HOSTNAME pd954781e.dip0.t-ipconnect.de
	dict lappend DATA HOSTINFO $HOSTINFO

	set IP_ADRESS		 		[dict get $HOSTINFO IP_ADRESS]
	set IP_DECIMAL				[::ProxyCheck::FCT:IP:TO:DECIMAL $IP_ADRESS]

	# IP_RELATION_DATA :		ID_IP_RELATION {} created_at {} ID_PROXYCHECK {} ID_IANA {} ID_WHOIS {} IP_DEC_START {} IP_DEC_END {}
	set IP_RELATION_DATA		[::ProxyCheck::SQL:TABLE:SELECT IP_relation_data "IP_DEC_START <= $IP_DECIMAL AND IP_DEC_END >= $IP_DECIMAL"]

	set IP_RELATION_ID			[dict get $IP_RELATION_DATA ID_IP_RELATION]
	set ID_PROXYCHECK			[dict get $IP_RELATION_DATA ID_PROXYCHECK]
	set ID_IANA					[dict get $IP_RELATION_DATA ID_IANA]
	set ID_WHOIS				[dict get $IP_RELATION_DATA ID_WHOIS]

	if { $IP_RELATION_ID == "" } {
		set CACHED				0
		# IANA_DATA :			SERVER whois.ripe.net INUM_START 217.0.0.0 INUM_END 217.255.255.255 ORG {RIPE NCC} CHANGED 2000-06 STATUS ALLOCATED IANA_ID 8 - 240.654 ms
		set IANA_DATA			[::ProxyCheck::FCT:WHOIS:GETSERVER:FROM_IANA $IP_ADRESS]

		# SERVER_WHOIS :		whois.ripe.net
		set SERVER_WHOIS		[dict get $IANA_DATA SERVER]

		# WHOIS_DATA :			inetnum {217.80.0.0 - 217.86.127.255} netname DTAG-DIAL14 descr {Deutsche Telekom AG, Internet service provider} org ORG-DTAG1-RIPE country DE status {ASSIGNED PA} source RIPE organisation ORG-DTAG1-RIPE address {Darmstadt, Germany} remarks {abuse contact in case of Spam,} person {Security Team} route 217.80.0.0/12 origin AS3320 - 61.643 ms
		set WHOIS_DATA			[::ProxyCheck::FCT:WHOIS:GET $IP_ADRESS $SERVER_WHOIS]
		set WHOIS_DATA_EXTRACT	[::ProxyCheck::FCT:WHOIS:EXTRACT $WHOIS_DATA $SERVER_WHOIS]
		return "::ProxyCheck::FCT:WHOIS:EXTRACT $WHOIS_DATA $SERVER_WHOIS"
		

		# SERVER whois.ripe.net INUM_START 217.80.0.0 INUM_END 217.86.127.255 ID_WHOIS 17

		set PROXYCHECK_DATA		[::ProxyCheck::FCT:PROXYCHECK:GET $IP_ADRESS]

		# asn AS3320 provider {Deutsche Telekom AG} continent Europe country Germany isocode DE region Baden-WÃ¼rttemberg regioncode BW city Todtnau latitude 47.8257 longitude 7.9442 proxy no type Residential risk 0 PROXYCHECK_ID 17
		set ID_WHOIS			[dict get $WHOIS_DATA ID_WHOIS]
		set ID_PROXYCHECK		[dict get $PROXYCHECK_DATA PROXYCHECK_ID]
		set ID_IANA				[dict get $WHOIS_SERVER_DATA IANA_ID]
		
		set IP_DEC_START		[::ProxyCheck::FCT:IP:TO:DECIMAL [dict get $WHOIS_DATA INUM_START]]
		set IP_DEC_END			[::ProxyCheck::FCT:IP:TO:DECIMAL [dict get $WHOIS_DATA INUM_END]]
		set IP_RELATION_DATA	[list ID_WHOIS $ID_WHOIS ID_PROXYCHECK $ID_PROXYCHECK ID_IANA $ID_IANA IP_DEC_START $IP_DEC_START IP_DEC_END $IP_DEC_END]
		set SQL_INSERT			[::ProxyCheck::SQL:BUILD:UPSERT IP_relation_data $IP_RELATION_DATA "IP_DEC_START,IP_DEC_END"]
		set IP_RELATION_ID 		[::ProxyCheck::SQL:EXEC $SQL_INSERT]
	} else {
		# ID_IP_RELATION 7 created_at {2021-05-11 10:56:47} ID_PROXYCHECK 7 ID_IANA 9 ID_WHOIS 9 IP_DEC_START 1534697472 IP_DEC_END 1534701567
	}
	set PROXYCHECK_DATA		[::ProxyCheck::SQL:TABLE:SELECT proxycheck_data	"ID_PROXYCHECK=$ID_PROXYCHECK"]
	set IANA_DATA			[::ProxyCheck::SQL:TABLE:SELECT iana_data		"ID_IANA=$ID_IANA"]
	set WHOIS_DATA			[::ProxyCheck::SQL:TABLE:SELECT whois_data		"ID_WHOIS=$ID_WHOIS"]
	dict lappend DATA WHOIS_DATA $WHOIS_DATA
	dict lappend DATA PROXYCHECK_DATA $PROXYCHECK_DATA
	dict lappend DATA IANA_DATA $IANA_DATA
	dict lappend DATA IP_RELATION_DATA $IP_RELATION_DATA
	dict lappend DATA CACHE $CACHED
	return $DATA
}
proc ::ProxyCheck::FCT:WHOIS:EXTRACT { WHOIS_DATA WHOIS_SERVER } {
	
	set inetnum_start	""
	set inetnum_end		""
	if { [string match -nocase "whois.ripe.net" $WHOIS_SERVER] } {
		if { [::tcl::dict::exists $WHOIS_DATA inetnum] } {
			set inetnum_start	[lindex [::tcl::dict::get $WHOIS_DATA inetnum] 0]
			set inetnum_end		[lindex [::tcl::dict::get $WHOIS_DATA inetnum] 2]
		}
	}
	if { [string match -nocase "whois.apnic.net" $WHOIS_SERVER] } {
		if { [::tcl::dict::exists $WHOIS_DATA inetnum] } {
			set inetnum_start	[lindex [::tcl::dict::get $WHOIS_DATA inetnum] 0]
			set inetnum_end		[lindex [::tcl::dict::get $WHOIS_DATA inetnum] 2]
		}
	}
	if { [string match -nocase "whois.afrinic.net" $WHOIS_SERVER] } {
		if { [::tcl::dict::exists $WHOIS_DATA inetnum] } {
			set inetnum_start	[lindex [::tcl::dict::get $WHOIS_DATA inetnum] 0]
			set inetnum_end		[lindex [::tcl::dict::get $WHOIS_DATA inetnum] 2]
		}
	}
	if { [string match -nocase "whois.arin.net" $WHOIS_SERVER] } {
		if { [::tcl::dict::exists $WHOIS_DATA NetRange] } {
			set inetnum_start	[lindex [::tcl::dict::get $WHOIS_DATA NetRange] 0]
			set inetnum_end		[lindex [::tcl::dict::get $WHOIS_DATA NetRange] 2]
		}
	}
	if { [string match -nocase "whois.lacnic.net" $WHOIS_SERVER] } {
		if { [::tcl::dict::exists $WHOIS_DATA inetnum] } {
			set inetnum_start	[lindex [split [::tcl::dict::get $WHOIS_DATA inetnum] "/"] 0]
			set inetnum_end		[::ip::broadcastAddress [::tcl::dict::get $WHOIS_DATA inetnum]]
		}
	}

	set WHOIS_CONTENT		[list SERVER $WHOIS_SERVER INUM_START $inetnum_start INUM_END $inetnum_end]
	set INSERT_ID			[::ProxyCheck::SQL:WHOISDATA:ADD $WHOIS_CONTENT]
	lappend WHOIS_CONTENT	ID_WHOIS $INSERT_ID

	return $WHOIS_CONTENT

}
proc ::ProxyCheck::FCT:WHOIS:GETSERVER:FROM_IANA { IP } {
	variable WHOIS
	set W_SERV			""
	set W_INUM_START	""
	set W_INUM_END		""
	set W_ORG			""
	set W_CHANGED		""
	set W_STATUS		""
	set RE_SERV			{whois.*?:\s*(.+)$}
	set RE_INUM			{inetnum.*?:\s*(.+)$}
	set RE_ORG			{organisation.*?:\s*(.+)$}
	set RE_CHANGED		{changed.*?:\s*(.+)$}
	set RE_STATUS		{status.*?:\s*(.+)$}
	set HANDLER			[open "|[::tcl::dict::get $WHOIS BINARY] -h whois.iana.org $IP" r]
	set HANDLER_DATA	[read $HANDLER]
	close $HANDLER;
	foreach WHOIS_DATA [split $HANDLER_DATA \n] {
		regexp $RE_SERV		$WHOIS_DATA -> W_SERV
		if { [regexp $RE_INUM $WHOIS_DATA -> W_INUM] } {
			set W_INUM_START	[lindex $W_INUM 0]
			set W_INUM_END		[lindex $W_INUM 2]
		}
		regexp $RE_ORG		$WHOIS_DATA -> W_ORG
		regexp $RE_CHANGED	$WHOIS_DATA -> W_CHANGED
		regexp $RE_STATUS	$WHOIS_DATA -> W_STATUS
	}
	set SERVER_INFO		[list SERVER $W_SERV INUM_START $W_INUM_START INUM_END $W_INUM_END ORG $W_ORG CHANGED $W_CHANGED STATUS $W_STATUS]
	set INSERT_ID		[::ProxyCheck::SQL:IANA:ADD $SERVER_INFO]
	lappend SERVER_INFO	IANA_ID $INSERT_ID
	return $SERVER_INFO
}
proc ::ProxyCheck::FCT:WHOIS:GET { IP SERVER } {
	variable WHOIS
	set HANDLER			[open "|[::tcl::dict::get $WHOIS BINARY] -h $SERVER $IP" r]
	set HANDLER_DATA	[read $HANDLER]
	close $HANDLER;
	set WHOIS_DATA [dict create QUERY_SERVER $SERVER]
	set RE {^([a-zA-Z0-9_]*):\s+([a-zA-Z0-9_][a-zA-Z0-9_\s\-,\./]*)$}
	foreach WHOIS_DATA_TMP [split $HANDLER_DATA \n] {
		if { [regexp $RE $WHOIS_DATA_TMP -> W_NAME W_VALUE] } {
			putlog "$W_NAME ||| $W_VALUE"
			if { [::tcl::dict::exists $WHOIS_DATA $W_NAME] } {
				
				set WHOIS_DATA [::tcl::dict::append WHOIS_DATA $W_NAME $W_VALUE]
				putlog "1--> $WHOIS_DATA"
			} else {
				::tcl::dict::set WHOIS_DATA $W_NAME $W_VALUE
				putlog "2--> $WHOIS_DATA"
			}
			putlog "OK -> [::tcl::dict::get WHOIS_DATA $W_NAME]"
			
		}
	}
	return "-> [dict get WHOIS_DATA]"
}
proc ::ProxyCheck::FCT:IP:TO:DECIMAL { IP } {
	set res 0
	foreach i [split $IP .] {set res [expr {wide($res<<8 | $i)}]}
	set res
}
proc ::ProxyCheck::FCT:IP:RANGE:TO:BITS n {
	set res 0
	foreach i [split [string repeat 1 $n][string repeat 0 [expr {32-$n}]] ""] {
		set res [expr {$res<<1 | $i}]
	}
	set res
}

proc ::ProxyCheck::FCT:IP:MASK:MATCH {ip1 width ip2} {
	expr {([::ProxyCheck::FCT:IP:TO:DECIMAL $ip1] & [::ProxyCheck::FCT:IP:RANGE:TO:BITS $width]) == ([::ProxyCheck::FCT:IP:TO:DECIMAL $ip2] [::ProxyCheck::FCT:IP:RANGE:TO:BITS $width])}
}
proc ::ProxyCheck::FCT:IP:MASK:MATCH2 {mask ip} {
	foreach {ip0 width} [split $mask /] break
	if {$width eq ""} {return [string equal $mask $ip]}
	::ProxyCheck::FCT:IP:MASK:MATCH $ip0 $width $ip
}
proc ::ProxyCheck::FCT:USER:IS:WEBCLIENT { HOST } {
	variable config
	set LIST	[join $config(WEBIRC_HOSTSLIST) "|"]
	set RE		".*($LIST)\$"
	return [regexp -nocase $RE $HOST]
}
proc ::ProxyCheck::FCT:HTTP:GET:DATA { HTTP_URL } {
	variable ns
	variable HTTP
	variable config
	#variable config
	set HTTP_TOKEN -1
	::http::config -useragent $config(HTTP_USERAGENT)
	if { [catch {
		set HTTP_TOKEN	[::http::geturl $HTTP_URL -timeout $config(HTTP_TIMEOUT)]
	} HTTP_ERROR] } {
		putlog "[lindex [info level 0] 0] 'geturl' failed: $HTTP_ERROR"
		return -1
	}
	dict set HTTP		URL				$HTTP_URL
	dict set HTTP		NUMERIC_CODE	[::http::ncode $HTTP_TOKEN]
	dict set HTTP		ERROR			[::http::error $HTTP_TOKEN]
	dict set HTTP		META			[::http::meta $HTTP_TOKEN]
	dict set HTTP		DATA			[::http::data $HTTP_TOKEN]
	dict set HTTP		SIZE			[::http::size $HTTP_TOKEN]
	dict set HTTP		STATUS			[::http::status  $HTTP_TOKEN]
	if { $HTTP_TOKEN != -1 } { ::http::cleanup $HTTP_TOKEN; }
	switch -glob -- [::tcl::dict::get $HTTP NUMERIC_CODE] {
		30* {
			foreach {k v} [http::meta $HTTP_TOKEN] {
				if {[string tolower $k] eq "location"} {
					set url	$v
					putlog "Followed [::tcl::dict::get $HTTP NUMERIC_CODE] redirect to $url"
					return [::ProxyCheck::FCT:HTTP:GET:DATA $url]
					break
				}
			}
		}
		5* {
			putlog "Server error [::tcl::dict::get $HTTP NUMERIC_CODE], delaying 1s and trying again"
			after 1000
		}
		2* {
			return [::tcl::dict::get $HTTP DATA]
		}
		default {
			putlog "Fetching tclconfig failed: [::tcl::dict::get $HTTP NUMERIC_CODE] [::tcl::dict::get $HTTP ERROR] [::tcl::dict::get $HTTP DATA]"
			parray $token
			return 1
		}
	}
	return [http::data $HTTP_TOKEN]
}
#######################
#  --> Commandes <--  #
#######################
proc ::ProxyCheck::IRC:CMD:PRIV:HELP:IP { sender } {
	::ProxyCheck::FCT:SENT:MSG $sender  "<c04> .: <c12>Command for IP's Help<c04> :."
	::ProxyCheck::FCT:SENT:MSG $sender  "<c04> "
	::ProxyCheck::FCT:SENT:MSG $sender  "<c07> IP CHECK   - <c06>  Check an IP"
}
proc ::ProxyCheck::IRC:CMD:PUB:HELP:IP { sender } {
	::ProxyCheck::FCT:SENT:MSG $sender  "<c04> .: <c12>Command for IP's Help<c04> :."
	::ProxyCheck::FCT:SENT:MSG $sender  "<c04> "
	::ProxyCheck::FCT:SENT:MSG $sender  "<c07> IP CHECK   - <c06>  Check an IP"
}
proc ::ProxyCheck::IRC:CMD:PRIV:IP { sender destination cmd data } {
	set cmd		[lindex $data 0]
	set data	[lrange $data 1 end]
	switch -nocase $cmd {
		check	{
			::ProxyCheck::IRC:CMD:PRIV:IP:CHECK $sender $destination $cmd $data
		}
		default	{
			::ProxyCheck::IRC:CMD:PRIV:HELP:IP $sender
		}
	}
}
proc ::ProxyCheck::IRC:CMD:PUB:USER:CHECK  { sender destination cmd data } {
	if { $data == "" } {
		::ProxyCheck::FCT:SENT:MSG $destination  "<c04> .: <c12>Command for USER CHECK Help<c04> :."
		::ProxyCheck::FCT:SENT:MSG $destination  "<c04> "
		::ProxyCheck::FCT:SENT:MSG $destination  "<c07> USER CHECK <USERNAME>   - <c06>  Check an User informations"
		return 0
	}
	::ProxyCheck::FCT:SENT:MSG $destination "soon"
}
proc ::ProxyCheck::IRC:CMD:PUB:IP:CHECK { sender destination cmd data } {
	if { $data == "" } {
		::ProxyCheck::FCT:SENT:MSG $destination  "<c04> .: <c12>Command for IP CHECK Help<c04> :."
		::ProxyCheck::FCT:SENT:MSG $destination  "<c04> "
		::ProxyCheck::FCT:SENT:MSG $destination  "<c07> IP CHECK <IP>   - <c06>  Check an IP"
		return 0
	}
	::ProxyCheck::FCT:SENT:MSG $destination [::ProxyCheck::FCT:CHECKUSER $data "" "CMD" "IP:CHECK"]
}
proc ::ProxyCheck::IRC:CMD:PRIV:IP:CHECK { sender destination cmd data } {
	if { $data == "" } {
		::ProxyCheck::FCT:SENT:MSG $sender  "<c04> .: <c12>Command for IP CHECK Help<c04> :."
		::ProxyCheck::FCT:SENT:MSG $sender  "<c04> "
		::ProxyCheck::FCT:SENT:MSG $sender  "<c07> IP CHECK <IP>   - <c06>  Check an IP"
		return 0
	}
	::ProxyCheck::FCT:SENT:MSG $sender [::ProxyCheck::FCT:CHECKUSER $data "" "CMD" "IP:CHECK"]
}
proc ::ProxyCheck::IRC:CMD:PRIV:HELP { sender destination cmd data } {
	::ProxyCheck::IRC:CMD:PUB:HELP $sender $destination $cmd $data
}
proc ::ProxyCheck::IRC:CMD:PUB:HELP:USER { sender } {
	::ProxyCheck::FCT:SENT:MSG $sender  "<c04> .: <c12>Command for USER's Help<c04> :."
	::ProxyCheck::FCT:SENT:MSG $sender  "<c04> "
	::ProxyCheck::FCT:SENT:MSG $sender  "<c07> USER CHECK   - <c06>  Check an USER informations"
}
proc ::ProxyCheck::IRC:CMD:PUB:PROXYSERV { sender destination cmd data } {
	set cmd		[lindex $data 0]
	set data	[lrange $data 1 end]
	switch -nocase $cmd {
		user	{
			::ProxyCheck::IRC:CMD:PUB:USER $sender $destination $cmd $data
		}
		ip	{
			::ProxyCheck::IRC:CMD:PUB:IP $sender $destination $cmd $data
		}
		default	{
			::ProxyCheck::IRC:CMD:PUB:HELP $sender $destination $cmd $data
		}
	}
}
proc ::ProxyCheck::IRC:CMD:PUB:IP { sender destination cmd data } {
	set cmd		[lindex $data 0]
	set data	[lrange $data 1 end]
	switch -nocase $cmd {
		check	{
			::ProxyCheck::IRC:CMD:PUB:IP:CHECK $sender $destination $cmd $data
		}
		default	{
			::ProxyCheck::IRC:CMD:PUB:HELP:IP $destination
		}
	}
}

proc ::ProxyCheck::IRC:CMD:PUB:USER { sender destination cmd data } {
	set cmd		[lindex $data 0]
	set data	[lrange $data 1 end]
	switch -nocase $cmd {
		check	{
			::ProxyCheck::IRC:CMD:PUB:USER:CHECK $sender $destination $cmd $data
		}
		default	{
			::ProxyCheck::IRC:CMD:PUB:HELP:USER $destination
		}
	}
}
proc ::ProxyCheck::IRC:CMD:PUB:HELP { sender destination cmd data } {
	::ProxyCheck::FCT:SENT:MSG $destination  "<c04> .: <c12>Public Help<c04> :."
	::ProxyCheck::FCT:SENT:MSG $destination  "<c04> "
	::ProxyCheck::FCT:SENT:MSG $destination  "<c07> !help                  - <c06>  Show this help"
	::ProxyCheck::FCT:SENT:MSG $destination  "<c07> !ProxyServ user        - <c06>  Command for user"
	::ProxyCheck::FCT:SENT:MSG $destination  "<c07> !ProxyServ IP          - <c06>  Command for IP's"
	::ProxyCheck::FCT:SENT:MSG $destination  "<c04> "
	::ProxyCheck::FCT:SENT:MSG $destination  "<c04> .: <c12>Private help<c04> :."
	::ProxyCheck::FCT:SENT:MSG $destination  "<c04> "
	::ProxyCheck::FCT:SENT:MSG $destination  "<c07> /msg ProxyServ help    - <c06>  Show this help"
	::ProxyCheck::FCT:SENT:MSG $destination  "<c07> /msg ProxyServ IP      - <c06>  Command for IP's"
	::ProxyCheck::FCT:SENT:MSG $destination  "<c04> "
}
###############################################################################
### Substitution des symboles couleur/gras/soulignement/...
###############################################################################
# Modification de la fonction de MenzAgitat
# <cXX> : Ajouter un Couleur avec le code XX : <c01>; <c02,01>
# </c>  : Enlever la Couleur (refermer la deniere declaration <cXX>) : </c>
# <b>   : Ajouter le style Bold/gras
# </b>  : Enlever le style Bold/gras
# <u>   : Ajouter le style Underline/souligner
# </u>  : Enlever le style Underline/souligner
# <i>   : Ajouter le style Italic/Italique
# <s>   : Enlever les styles precedent
proc ::ProxyCheck::FCT:apply_visuals { data } {
	regsub -all -nocase {<c([0-9]{0,2}(,[0-9]{0,2})?)?>|</c([0-9]{0,2}(,[0-9]{0,2})?)?>} $data "\003\\1" data
	regsub -all -nocase {<b>|</b>} $data "\002" data
	regsub -all -nocase {<u>|</u>} $data "\037" data
	regsub -all -nocase {<i>|</i>} $data "\026" data
	return [regsub -all -nocase {<s>} $data "\017"]
}
proc ::ProxyCheck::FCT:Remove_visuals { data } {
	regsub -all -nocase {<c([0-9]{0,2}(,[0-9]{0,2})?)?>|</c([0-9]{0,2}(,[0-9]{0,2})?)?>} $data "" data
	regsub -all -nocase {<b>|</b>} $data "" data
	regsub -all -nocase {<u>|</u>} $data "" data
	regsub -all -nocase {<i>|</i>} $data "" data
	return [regsub -all -nocase {<s>} $data ""]
}
proc ::ProxyCheck::FCT:CHECK:IP { IP } {
	regsub -all -nocase {<c([0-9]{0,2}(,[0-9]{0,2})?)?>|</c([0-9]{0,2}(,[0-9]{0,2})?)?>} $data "" data
	regsub -all -nocase {<b>|</b>} $data "" data
	regsub -all -nocase {<u>|</u>} $data "" data
	regsub -all -nocase {<i>|</i>} $data "" data
	return [regsub -all -nocase {<s>} $data ""]
}
::ProxyCheck::INIT