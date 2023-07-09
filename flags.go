package main

import (
	"errors"
	"fmt"
	"os"
	"reflect"
	"time"

	flags "github.com/jessevdk/go-flags"
)

func dumpArkimeIni(filename string) {
	file, err := os.Create(filename)
	errorHandler(err)
	v := reflect.ValueOf(ArkimeOptions)
	typeOfV := v.Type()
	// values := make([]interface{}, v.NumField())
	file.Write([]byte("[default]\n"))
	for i := 0; i < v.NumField(); i++ {
		iniDefault, _ := getTagValue(ArkimeOptions, typeOfV.Field(i).Name, "ini-default")
		iniName, _ := getTagValue(ArkimeOptions, typeOfV.Field(i).Name, "ini-name")
		defaultValue, _ := getTagValue(GeneralOptions, typeOfV.Field(i).Name, "default")
		// file.Write([]byte(fmt.Sprintf("%s=%v\n", typeOfV.Field(i).Name, v.Field(i).Interface())))
		// True ini-default means the default value of the field should be written in the ini file. The non-default values should always be written regardless of the ini-default value.
		// in case of a false ini-default, only write the field if it's not the default value
		if defaultValue != v.Field(i).Interface() {
			file.Write([]byte(fmt.Sprintf("%s=%v\n", iniName, v.Field(i).Interface())))
			continue
		}
		if iniDefault == "true" {
			file.Write([]byte(fmt.Sprintf("%s=%v\n", iniName, defaultValue)))
		}

	}
}

// ArkimeOptions is the struct that holds the Arkime options. some of the options won't translate into the default ini file (ini-default=false)
var ArkimeOptions struct {
	Elasticsearch       string `long:"elasticsearch"          ini-name:"elasticsearch"          ini-default:"true"     env:"ARKIME_ELASTICSEARCH"          default:"http://127.0.0.1:9200"                                                            description:"Comma seperated list of elasticsearch host:port combinations.  If not using a\n \t ; elasticsearch VIP, a different elasticsearch node in the cluster can be specified\n \t ; for each Arkime node to help spread load on high volume clusters"`
	RotateIndex         string `long:"rotateIndex"            ini-name:"rotateIndex"            ini-default:"true"     env:"ARKIME_ROTATEINDEX"            default:"daily"                                                                            description:"How often to create a new elasticsearch index. hourly,hourly6,daily,weekly,monthly\n \t ; Changing the value will cause previous sessions to be unreachable"`
	CertFile            string `long:"certFile"               ini-name:"certFile"               ini-default:"false"    env:"ARKIME_CERTFILE"               default:""                                                                                 description:"Cert file to use, comment out to use http instead"`
	CaTrustFile         string `long:"caTrustFile"            ini-name:"caTrustFile"            ini-default:"false"    env:"ARKIME_CATRUSTFILE"            default:""                                                                                 description:"File with trusted roots/certs. WARNING! this replaces default roots\n \t ; Useful with self signed certs and can be set per node."`
	KeyFile             string `long:"keyFile"                ini-name:"keyFile"                ini-default:"false"    env:"ARKIME_KEYFILE"                default:""                                                                                 description:"Private key file to use, comment out to use http instead"`
	PasswordSecret      string `long:"passwordSecret"         ini-name:"passwordSecret"         ini-default:"true"     env:"ARKIME_PASSWORDSECRET"         default:"password"                                                                         description:"Password Hash and S2S secret - Must be in default section. Since elasticsearch\n \t ; is wide open by default, we encrypt the stored password hashes with this\n \t ; so a malicous person can't insert a working new account.  It is also used\n \t ; for secure S2S communication. Comment out for no user authentication.\n \t ; Changing the value will make all previously stored passwords no longer work.\n \t ; Make this RANDOM, you never need to type in"`
	ServerSecret        string `long:"serverSecret"           ini-name:"serverSecret"           ini-default:"false"    env:"ARKIME_SERVERSECRET"           default:""                                                                                 description:"Use a different password for S2S communication then passwordSecret.\n \t ; Must be in default section.  Make this RANDOM, you never need to type in"`
	HttpRealm           string `long:"httpRealm"              ini-name:"httpRealm"              ini-default:"true"     env:"ARKIME_HTTPREALM"              default:"Arkime"                                                                           description:"HTTP Digest Realm - Must be in default section.  Changing the value\n \t ; will make all previously stored passwords no longer work"`
	WebBasePath         string `long:"webBasePath"            ini-name:"webBasePath"            ini-default:"false"    env:"ARKIME_ WEBBASEPATH"           default:"/"                                                                                description:"The base path for Arkime web access.  Must end with a / or bad things will happen"`
	Interface           string `long:"interface"              ini-name:"interface"              ini-default:"true"     env:"ARKIME_INTERFACE"              default:"lo"                                                                               description:"Semicolon ';' seperated list of interfaces to listen on for traffic"`
	Bpf                 string `long:"bpf"                    ini-name:"bpf"                    ini-default:"false"    env:"ARKIME_BPF"                    default:"not port 9200"                                                                    description:"The bpf filter of traffic to ignore"`
	Yara                string `long:"yara"                   ini-name:"yara"                   ini-default:"false"    env:"ARKIME_YARA"                   default:"/dev/null"                                                                        description:"The yara file name"`
	WiseHost            string `long:"wiseHost"               ini-name:"wiseHost"               ini-default:"false"    env:"ARKIME_WISEHOST"               default:""                                                                                 description:"Host to connect to for wiseService"`
	AccessLogFile       string `long:"accessLogFile"          ini-name:"accessLogFile"          ini-default:"false"    env:"ARKIME_ACCESSLOGFILE"          default:""                                                                                 description:"Log viewer access requests to a different log file"`
	PcapDir             string `long:"pcapDir"                ini-name:"pcapDir"                ini-default:"true"     env:"ARKIME_PCAPDIR"                default:"/opt/arkime/raw"                                                                  description:"The directory to save raw pcap files to"`
	PcapDirAlgorithm    string `long:"pcapDirAlgorithm"       ini-name:"pcapDirAlgorithm"       ini-default:"true"     env:"ARKIME_PCAPDIRALGORITHM"       default:"round-robin"                                                                      description:"When pcapDir is a list of directories, this determines how Arkime chooses which directory to use for each new pcap file. Possible values: round-robin (rotate sequentially), max-free-percent (choose the directory on the filesystem with the highest percentage of available space), max-free-bytes (choose the directory on the filesystem with the highest number of available bytes)."`
	PcapDirTemplate     string `long:"pcapDirTemplate"        ini-name:"pcapDirTemplate"        ini-default:"false"    env:"ARKIME_PCAPDIRTEMPLATE"        default:""                                                                                 description:"When set, this strftime template is appended to pcapDir and allows multiple directories to be created based on time."`
	MaxFileSizeG        uint   `long:"maxFileSizeG"           ini-name:"maxFileSizeG"           ini-default:"true"     env:"ARKIME_MAXFILESIZEG"           default:"12"                                                                               description:"The max raw pcap file size in gigabytes, with a max value of 36G.\n \t ; The disk should have room for at least 10*maxFileSizeG"`
	MaxFileTimeM        uint   `long:"maxFileTimeM"           ini-name:"maxFileTimeM"           ini-default:"false"    env:"ARKIME_MAXFILETIMEM"           default:"0"                                                                                description:"The max time in minutes between rotating pcap files.  Default is 0, which means\n \t ; only rotate based on current file size and the maxFileSizeG variable"`
	TcpTimeout          uint   `long:"tcpTimeout"             ini-name:"tcpTimeout"             ini-default:"true"     env:"ARKIME_TCPTIMEOUT"             default:"600"                                                                              description:"TCP timeout value.  Arkime writes a session record after this many seconds\n \t ; of inactivity."`
	TcpSaveTimeout      uint   `long:"tcpSaveTimeout"         ini-name:"tcpSaveTimeout"         ini-default:"true"     env:"ARKIME_TCPSAVETIMEOUT"         default:"720"                                                                              description:"Arkime writes a session record after this many seconds, no matter if\n \t ; active or inactive"`
	TCPClosingTimeout   uint   `long:"tcpClosingTimeout"      ini-name:"tcpClosingTimeout"      ini-default:"true"     env:"ARKIME_TCPCLOSINGTIMEOUT"      default:"5"                                                                                description:"Delay before saving tcp sessions after close"`
	UdpTimeout          uint   `long:"udpTimeout"             ini-name:"udpTimeout"             ini-default:"true"     env:"ARKIME_UDPTIMEOUT"             default:"30"                                                                               description:"UDP timeout value.  Arkime assumes the UDP session is ended after this\n \t ; many seconds of inactivity."`
	IcmpTimeout         uint   `long:"icmpTimeout"            ini-name:"icmpTimeout"            ini-default:"true"     env:"ARKIME_ICMPTIMEOUT"            default:"10"                                                                               description:"ICMP timeout value.  Arkime assumes the ICMP session is ended after this\n \t ; many seconds of inactivity."`
	MaxStreams          uint   `long:"maxStreams"             ini-name:"maxStreams"             ini-default:"true"     env:"ARKIME_MAXSTREAMS"             default:"1000000"                                                                          description:"An aproximiate maximum number of active sessions Arkime/libnids will try\n \t ; and monitor"`
	MaxPackets          uint   `long:"maxPackets"             ini-name:"maxPackets"             ini-default:"true"     env:"ARKIME_MAXPACKETS"             default:"10000"                                                                            description:"Arkime writes a session record after this many packets"`
	FreeSpaceG          string `long:"freeSpaceG"             ini-name:"freeSpaceG"             ini-default:"true"     env:"ARKIME_FREESPACEG"             default:"5%"                                                                               description:"Delete pcap files when free space is lower then this in gigabytes OR it can be\n \t ; expressed as a percentage (ex: 5%).  This does NOT delete the session records in\n \t ; the database. It is recommended this value is between 5% and 10% of the disk.\n \t ; Database deletes are done by the db.pl expire script"`
	ViewPort            string `long:"viewPort"               ini-name:"viewPort"               ini-default:"true"     env:"ARKIME_VIEWPORT"               default:"8005"                                                                             description:"The port to listen on, by default 8005"`
	ViewHost            string `long:"viewHost"               ini-name:"viewHost"               ini-default:"false"    env:"ARKIME_VIEWHOST"               default:"localhost"                                                                        description:"The host/ip to listen on, by default 0.0.0.0 which is ALL"`
	ViewUrl             string `long:"viewUrl"                ini-name:"viewUrl"                ini-default:"false"    env:"ARKIME_VIEWURL"                default:"https://HOSTNAME:8005"                                                            description:"By default the viewer process is https://hostname:<viewPort> for each node."`
	GeoLite2Country     string `long:"geoLite2Country"        ini-name:"geoLite2Country"        ini-default:"true"     env:"ARKIME_GEOLITE2COUNTRY"        default:"/opt/arkime/etc/GeoLite2-Country.mmdb"                                            description:"Path of the maxmind geoip country file.  Download free version from:\n \t ;   https://updates.maxmind.com/app/update_secure?edition_id=GeoLite2-Country"`
	GeoLite2ASN         string `long:"geoLite2ASN"            ini-name:"geoLite2ASN"            ini-default:"true"     env:"ARKIME_GEOLITE2ASN"            default:"/opt/arkime/etc/GeoLite2-ASN.mmdb"                                                description:"Path of the maxmind geoip ASN file.  Download free version from:\n \t ;   https://updates.maxmind.com/app/update_secure?edition_id=GeoLite2-ASN"`
	RirFile             string `long:"rirFile"                ini-name:"rirFile"                ini-default:"true"     env:"ARKIME_RIRFILE"                default:"/opt/arkime/etc/ipv4-address-space.csv"                                           description:"Path of the rir assignments file\n \t ;  https://www.iana.org/assignments/ipv4-address-space/ipv4-address-space.csv"`
	OuiFile             string `long:"ouiFile"                ini-name:"ouiFile"                ini-default:"true"     env:"ARKIME_OUIFILE"                default:"/opt/arkime/etc/oui.txt"                                                          description:"Path of the OUI file from whareshark\n \t ;  https://raw.githubusercontent.com/wireshark/wireshark/master/manuf"`
	DropUser            string `long:"dropUser"               ini-name:"dropUser"               ini-default:"true"     env:"ARKIME_DROPUSER"               default:"nobody"                                                                           description:"User to drop privileges to. The pcapDir must be writable by this user or group below"`
	DropGroup           string `long:"dropGroup"              ini-name:"dropGroup"              ini-default:"true"     env:"ARKIME_DROPGROUP"              default:"daemon"                                                                           description:"Group to drop privileges to. The pcapDir must be writable by this group or user above"`
	LocalPcapIndex      string `long:"localPcapIndex"         ini-name:"localPcapIndex"         ini-default:"false"    env:"ARKIME_LOCALPCAPINDEX"         default:"false"                                                                            description:" enable pcap index on capture node instead of ES"                                                                                                                                                                                                                                                                                                                                                                                                                                     choice:"true" choice:"false"`
	DontSaveTags        string `long:"dontSaveTags"           ini-name:"dontSaveTags"           ini-default:"false"    env:"ARKIME_DONTSAVETAGS"           default:""                                                                                 description:"Semicolon ';' seperated list of tags which once capture sets for a session causes the\n \t ; remaining pcap from being saved for the session.  It is likely that the initial packets\n \t ; WILL be saved for the session since tags usually aren't set until after several packets\n \t ; Each tag can choiceally be followed by a :<num> which specifies how many total packets to save"`
	UserNameHeader      string `long:"userNameHeader"         ini-name:"userNameHeader"         ini-default:"false"    env:"ARKIME_USERNAMEHEADER"         default:"arkime_user"                                                                      description:"Header to use for determining the username to check in the database for instead of\n \t ; using http digest.  Use this if apache or something else is doing the auth.\n \t ; Set viewHost to localhost or use iptables\n \t ; Might need something like this in the httpd.conf\n \t ; RewriteRule .* - [E=ENV_RU:%{REMOTE_USER}]\n \t ; RequestHeader set ARKIME_USER %{ENV_RU}e"`
	ParseSMTP           string `long:"parseSMTP"              ini-name:"parseSMTP"              ini-default:"true"     env:"ARKIME_PARSESMTP"              default:"true"                                                                             description:"Should we parse extra smtp traffic info"                                                                                                                                                                                                                                                                                                                                                                                                                                              choice:"true" choice:"false"`
	ParseSMB            string `long:"parseSMB"               ini-name:"parseSMB"               ini-default:"true"     env:"ARKIME_PARSESMB"               default:"true"                                                                             description:"Should we parse extra smb traffic info"                                                                                                                                                                                                                                                                                                                                                                                                                                               choice:"true" choice:"false"`
	ParseQSValue        string `long:"parseQSValue"           ini-name:"parseQSValue"           ini-default:"true"     env:"ARKIME_PARSEQSVALUE"           default:"false"                                                                            description:"Should we parse HTTP QS Values"                                                                                                                                                                                                                                                                                                                                                                                                                                                       choice:"true" choice:"false"`
	SupportSha256       string `long:"supportSha256"          ini-name:"supportSha256"          ini-default:"true"     env:"ARKIME_SUPPORTSHA256"          default:"false"                                                                            description:"Should we calculate sha256 for bodies"                                                                                                                                                                                                                                                                                                                                                                                                                                                choice:"true" choice:"false"`
	MaxReqBody          uint   `long:"maxReqBody"             ini-name:"maxReqBody"             ini-default:"true"     env:"ARKIME_MAXREQBODY"             default:"64"                                                                               description:"Only index HTTP request bodies less than this number of bytes */"`
	ReqBodyOnlyUtf8     string `long:"reqBodyOnlyUtf8"        ini-name:"reqBodyOnlyUtf8"        ini-default:"true"     env:"ARKIME_REQBODYONLYUTF8"        default:"true"                                                                             description:"Only store request bodies that Utf-8?"                                                                                                                                                                                                                                                                                                                                                                                                                                                choice:"true" choice:"false"`
	SmtpIpHeaders       string `long:"smtpIpHeaders"          ini-name:"smtpIpHeaders"          ini-default:"true"     env:"ARKIME_SMTPIPHEADERS"          default:"X-Originating-IP:;X-Barracuda-Apparent-Source-IP:"                                description:"Semicolon ';' seperated list of SMTP Headers that have ips, need to have the terminating colon ':'"`
	ParsersDir          string `long:"parsersDir"             ini-name:"parsersDir"             ini-default:"true"     env:"ARKIME_PARSERSDIR"             default:"/opt/arkime/parsers"                                                              description:"Semicolon ';' seperated list of directories to load parsers from"`
	PluginsDir          string `long:"pluginsDir"             ini-name:"pluginsDir"             ini-default:"true"     env:"ARKIME_PLUGINSDIR"             default:"/opt/arkime/plugins"                                                              description:"Semicolon ';' seperated list of directories to load plugins from"`
	Plugins             string `long:"plugins"                ini-name:"plugins"                ini-default:"false"    env:"ARKIME_PLUGINS"                default:""                                                                                 description:"Semicolon ';' seperated list of plugins to load and the order to load in"`
	RootPlugins         string `long:"rootPlugins"            ini-name:"rootPlugins"            ini-default:"false"    env:"ARKIME_ROOTPLUGINS"            default:""                                                                                 description:"Plugins to load as root, usually just readers"`
	ViewerPlugins       string `long:"viewerPlugins"          ini-name:"viewerPlugins"          ini-default:"false"    env:"ARKIME_VIEWERPLUGINS"          default:""                                                                                 description:"Semicolon ';' seperated list of viewer plugins to load and the order to load in"`
	NetflowSNMPInput    uint   `long:"netflowSNMPInput"       ini-name:"netflowSNMPInput"       ini-default:"false"    env:"ARKIME_NETFLOWSNMPINPUT"       default:"1"                                                                                description:"NetFlowPlugin\n \t ; Input device id, 0 by default"`
	NetflowSNMPOutput   uint   `long:"netflowSNMPOutput"      ini-name:"netflowSNMPOutput"      ini-default:"false"    env:"ARKIME_NETFLOWSNMPOUTPUT"      default:"2"                                                                                description:"Outout device id, 0 by default"`
	NetflowVersion      uint   `long:"netflowVersion"         ini-name:"netflowVersion"         ini-default:"false"    env:"ARKIME_NETFLOWVERSION"         default:"1"                                                                                description:"Netflow version 1,5,7 supported, 7 by default"`
	NetflowDestinations string `long:"netflowDestinations"    ini-name:"netflowDestinations"    ini-default:"false"    env:"ARKIME_NETFLOWDESTINATIONS"    default:""                                                                                 description:"Semicolon ';' seperated list of netflow destinations"`
	SpiDataMaxIndices   uint   `long:"spiDataMaxIndices"      ini-name:"spiDataMaxIndices"      ini-default:"true"     env:"ARKIME_SPIDATAMAXINDICES"      default:"4"                                                                                description:"Specify the max number of indices we calculate spidata for.\n \t ; ES will blow up if we allow the spiData to search too many indices."`
	UploadCommand       string `long:"uploadCommand"          ini-name:"uploadCommand"          ini-default:"true"     env:"ARKIME_UPLOADCOMMAND"          default:"/opt/arkime/bin/capture --copy -n {NODE} -r {TMPFILE} -c {CONFIG} {TAGS}"         description:"Uncomment the following to allow direct uploads.  This is experimental"`
	TitleTemplate       string `long:"titleTemplate"          ini-name:"titleTemplate"          ini-default:"false"    env:"ARKIME_TITLETEMPLATE"          default:"_cluster_ - _page_ _-view_ _-expression_"                                         description:"Title Template\n \t ;  _cluster_=ES cluster name\n \t ;  _userId_=logged in User Id\n \t ;  _userName_=logged in User Name\n \t ;  _page_=internal page name\n \t ;  _expression_=current search expression if set, otherwise blank\n \t ;  _-expression_=\" - \" + current search expression if set, otherwise blank, prior spaces removed\n \t ;  _view_=current view if set, otherwise blank\n \t ;  _-view_=\" - \" + current view if set, otherwise blank, prior spaces removed"`
	PacketThreads       uint   `long:"packetThreads"          ini-name:"packetThreads"          ini-default:"true"     env:"ARKIME_PACKETTHREADS"          default:"2"                                                                                description:"Number of threads processing packets"`
	Includes            string `long:"includes"               ini-name:"includes"               ini-default:"false"    env:"ARKIME_INCLUDES"               default:""                                                                                 description:"ADVANCED - Semicolon ';' seperated list of files to load for config.  Files are loaded\n \t ; in order and can replace values set in this file or previous files."`
	PcapReadMethod      string `long:"pcapReadMethod"         ini-name:"pcapReadMethod"         ini-default:"true"     env:"ARKIME_PCAPREADMETHOD"         default:"libpcap"                                                                          description:"ADVANCED - Specify how packets are read from network cards:"`
	PcapWriteMethod     string `long:"pcapWriteMethod"        ini-name:"pcapWriteMethod"        ini-default:"true"     env:"ARKIME_PCAPWRITEMETHOD"        default:"simple"                                                                           description:"ADVANCED - How is pcap written to disk\n \t ;  simple=use O_DIRECT if available, writes in pcapWriteSize chunks,\n \t ;                    a file per packet thread.\n \t ;  simple-nodirect=don't use O_DIRECT.  Required for zfs and others"`
	PcapWriteSize       uint   `long:"pcapWriteSize"          ini-name:"pcapWriteSize"          ini-default:"true"     env:"ARKIME_PCAPWRITESIZE"          default:"262143"                                                                           description:"ADVANCED - Buffer size when writing pcap files.  Should be a multiple of the raid 5 or xfs\n \t ; stripe size.  Defaults to 256k"`
	DbBulkSize          uint   `long:"dbBulkSize"             ini-name:"dbBulkSize"             ini-default:"true"     env:"ARKIME_DBBULKSIZE"             default:"300000"                                                                           description:"ADVANCED - Number of bytes to bulk index at a time"`
	CompressES          string `long:"compressES"             ini-name:"compressES"             ini-default:"true"     env:"ARKIME_COMPRESSES"             default:"false"                                                                            description:"ADVANCED - Compress requests to ES, reduces ES bandwidth by ~80% at the cost\n \t ; of increased CPU. MUST have \"http.compression: true\" in elasticsearch.yml file"                                                                                                                                                                                                                                                                                                                 choice:"true" choice:"false"`
	MaxESConns          uint   `long:"maxESConns"             ini-name:"maxESConns"             ini-default:"true"     env:"ARKIME_MAXESCONNS"             default:"30"                                                                               description:"ADVANCED - Max number of connections to elastic search"`
	MaxESRequests       uint   `long:"maxESRequests"          ini-name:"maxESRequests"          ini-default:"true"     env:"ARKIME_MAXESREQUESTS"          default:"500"                                                                              description:"ADVANCED - Max number of es requests outstanding in q"`
	PacketsPerPoll      uint   `long:"packetsPerPoll"         ini-name:"packetsPerPoll"         ini-default:"true"     env:"ARKIME_PACKETSPERPOLL"         default:"50000"                                                                            description:"ADVANCED - Number of packets to ask libnids/libpcap to read per poll/spin\n \t ; Increasing may hurt stats and ES performance\n \t ; Decreasing may cause more dropped packets"`
	AntiSynDrop         string `long:"antiSynDrop"            ini-name:"antiSynDrop"            ini-default:"true"     env:"ARKIME_ANTISYNDROP"            default:"true"                                                                             description:"ADVANCED - Arkime will try to compensate for SYN packet drops by swapping\n \t ; the source and destination addresses when a SYN-acK packet was captured first.\n \t ; Probably useful to set it false, when running Arkime in wild due to SYN floods."                                                                                                                                                                                                                               choice:"true" choice:"false"`
	LogEveryXPackets    uint   `long:"logEveryXPackets"       ini-name:"logEveryXPackets"       ini-default:"true"     env:"ARKIME_LOGEVERYXPACKETS"       default:"100000"                                                                           description:"DEBUG - Write to stdout info every X packets.\n \t ; Set to -1 to never log status"`
	LogUnknownProtocols string `long:"logUnknownProtocols"    ini-name:"logUnknownProtocols"    ini-default:"true"     env:"ARKIME_LOGUNKNOWNPROTOCOLS"    default:"false"                                                                            description:"DEBUG - Write to stdout unknown protocols"        `
	LogESRequests       string `long:"logESRequests"          ini-name:"logESRequests"          ini-default:"true"     env:"ARKIME_LOGESREQUESTS"          default:"true"                                                                             description:"DEBUG - Write to stdout elastic search requests"  `
	LogFileCreation     string `long:"logFileCreation"        ini-name:"logFileCreation"        ini-default:"true"     env:"ARKIME_LOGFILECREATION"        default:"true"                                                                             description:"DEBUG - Write to stdout file creation information"`
	UserAuthIPs         string `long:"userAuthIps"            ini-name:"userAuthIps"            ini-default:"true"     env:"ARKIME_USERAUTHIPS"            default:"127.0.0.1,::1"                                                                    description:"IPs allow to be used for authenticated calls"     `
	UserAutoCreateTmpl  string `long:"userAutoCreateTmpl"     ini-name:"userAutoCreateTmpl"     ini-default:"false"    env:"ARKIME_USERAUTOCREATETMPL"     default:""                                                                                 description:"When using requiredAuthHeader to externalize provisioning of users to a system like LDAP/AD, this configuration parameter is used to define the JSON structure used to automatically create a arkime user in the arkime users database if one does not exist. The user will only be created if the requiredAuthHeader includes the expected value in requiredAuthHeaderVal, and is not automatically deleted if the auth headers are not present. Values can be populated into the creation JSON to dynamically populate fields into the user database, which are passed in as HTTP headers along with the user and auth headers. The example value below creates a user with a userId pulled from the http_auth_http_user HTTP header with a name pulled from the http_auth_mail user header. It is expected that these headers are passed in from an apache (or similar) instance that fronts the arkime viewer as described in the documentation supporting userNameHeader"`
	AuthClientID        string `long:"authClientId"           ini-name:"authClientId"           ini-default:"false"    env:"ARKIME_AUTHCLIENTID"           default:""                                                                                 description:"The OIDC client id"`
	AuthClientSecret    string `long:"authClientSecret"       ini-name:"authClientSecret"       ini-default:"false"    env:"ARKIME_AUTHCLIENTSECRET"       default:""                                                                                 description:"The OIDC Client Secret"`
	AuthDiscoveryURL    string `long:"authDiscoveryUrl"       ini-name:"authDiscoveryUrl"       ini-default:"false"    env:"ARKIME_AUTHDISCOVERYURL"       default:""                                                                                 description:"The OIDC discover wellknown URL."`
	AuthRedirectURL     string `long:"authRedirectURL"        ini-name:"authRedirectURL"        ini-default:"false"    env:"ARKIME_AUTHREDIRECTURL"        default:""                                                                                 description:"Comma separated list of redirect URLs. Maybe should end with /auth/login/callback"`
	AuthUserIDField     string `long:"authUserIdField"        ini-name:"authUserIdField"        ini-default:"false"    env:"ARKIME_AUTHUSERIDFIELD"        default:""                                                                                 description:"The field to use in the response from OIDC that contains the userId"`
}

// GeneralOptions are the options that are used by all Arkime components
var GeneralOptions struct {
	Help                   bool           `long:"help"  short:"h"        no-ini:"true"                                                                                                                                                 description:"Print this help to stdout"`
	DumpConfig             bool           `long:"dumpConfig"             no-ini:"true" ini-default:"false"    env:"ARKIME_DUMPCONFIG"                                                                                                  description:"generate an Arkime config file based on current inputs (flags, input config file and environment variables) and write to stdout."`
	SkipTlsVerifiction     bool           `long:"skipTlsVerifiction"     no-ini:"true" ini-default:"false"    env:"ARKIME_SKIPTLSVERIFICTION"                                                                                          description:"Skip TLS verification for Elasticsearch and Viewer"`
	NoConf                 string         `long:"noConf"                 no-ini:"true" ini-default:"false"    env:"ARKIME_NOCONF"                 default:"false"         choice:"true" choice:"false"                                 description:"Do not use any of the provided flags to generate a Config file, used when config file is directly mounted inside the container"`
	ConfigPath             flags.Filename `long:"configPath"             no-ini:"true" ini-default:"false"    env:"ARKIME_CONFIGPATH"             default:"/opt/arkime/etc/config.ini"                                                 description:"path to look for Arkime Config file"`
	Version                string         `long:"version"                no-ini:"true" ini-default:"false"    env:"ARKIME_VERSION"                default:"false"         choice:"true" choice:"false"                                 description:"print version and exit"`
	AutoInit               string         `long:"autoInit"               no-ini:"true" ini-default:"false"    env:"ARKIME_AUTOINIT"               default:"true"          choice:"true" choice:"false"                                 description:"atuomatically initialize Elastic indices if sequence_v2 and sequence_v1 were not present"`
	ForceInit              string         `long:"forceInit"              no-ini:"true" ini-default:"false"    env:"ARKIME_FORCEINIT"              default:"false"         choice:"true" choice:"false"                                 description:"force initialization of Arkime Elastic indices from scratch"`
	CreateAdminUser        string         `long:"createAdminUser"        no-ini:"true" ini-default:"false"    env:"ARKIME_CREATEADMINUSER"        default:"true"          choice:"true" choice:"false"                                 description:"create admin user at startup"`
	AdminCreds             string         `long:"adminCreds"             no-ini:"true" ini-default:"false"    env:"ARKIME_ADMINCREDS"             default:"admin:arkime"                                                               description:"Administrator Credentials"`
	EsHealthcheckInterval  time.Duration  `long:"esHealthcheckInterval"  no-ini:"true" ini-default:"false"    env:"ARKIME_ESHEALTHCHECKINTERVAL"  default:"60s"                                                                        description:"Interval to check Elastic avalability"`
	ViewerCheckInterval    time.Duration  `long:"viewerCheckInterval"    no-ini:"true" ini-default:"false"    env:"ARKIME_VIEWERCHECKINTERVAL"    default:"60s"                                                                        description:"Interval to check Viewer avalability"`
	CapturerCheckInterval  time.Duration  `long:"capturerCheckInterval"  no-ini:"true" ini-default:"false"    env:"ARKIME_CAPTURERCHECKINTERVAL"  default:"60s"                                                                        description:"Interval to check Capturer avalability"`
	ViewerLogLocation      flags.Filename `long:"viewerLogLocation"      no-ini:"true" ini-default:"false"    env:"ARKIME_VIEWERLOGLOCATION"      default:""                                                                           description:"Viewer log location, empty value pushes the log to container's stdout"`
	CapturerLogLocation    flags.Filename `long:"capturerLogLocation"    no-ini:"true" ini-default:"false"    env:"ARKIME_CAPTURERLOGLOCATION"    default:""                                                                           description:"Capturer log location, empty value pushes the log to container's stdout"`
	IPv4SpaceURL           string         `long:"ipv4SpaceURL"           no-ini:"true" ini-default:"false"    env:"ARKIME_IPV4SPACEURL"           default:"https://www.iana.org/assignments/ipv4-address-space/ipv4-address-space.csv" description:"Download IPv4 space on startup and push to rirFile location defined in ArkimeOptions. empty means disabled"`
	ManufURL               string         `long:"manufURL"               no-ini:"true" ini-default:"false"    env:"ARKIME_MANUFURL"               default:"https://raw.githubusercontent.com/wireshark/wireshark/master/manuf"         description:"Download MAC Vendor mapping on startup and push to ouiFile location defined in ArkimeOptions. empty means disabled"`
	GeoLite2CountryURL     string         `long:"geoLite2CountryURL"     no-ini:"true" ini-default:"false"    env:"ARKIME_GEOLITECOUNTRYURL"      default:"https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb"  description:"Download GeoLite2 Country mmdb on startup and push to geoLite2Country location defined in ArkimeOptions. empty means disabled"`
	GeoLite2ASNURL         string         `long:"geoLite2ASNURL"         no-ini:"true" ini-default:"false"    env:"ARKIME_GEOLITEASNURL"          default:"https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-ASN.mmdb"      description:"Download GeoLite2 ASN mmdb on startup and push to geoLite2ASN location defined in ArkimeOptions. empty means disabled"`
	GeoLiteRefreshInterval time.Duration  `long:"geoLiteRefreshInterval" no-ini:"true" ini-default:"false"    env:"ARKIME_GEOLITEREFRESHINTERVAL" default:"168h"                                                                       description:"Auto re-download interval for GeoLite2CountryURL and GeoLite2ASNURL"`
	insecure               string         // build the --insecure flag out of SkipTlsVerifiction
	// TODO: possibly handle daily script to remove old indices from Elasticsearch
}

func flagsProcess() {
	parser := flags.NewNamedParser("ARKIME", flags.PassDoubleDash|flags.PrintErrors)
	// iniParser := flags.NewIniParser(parser)
	parser.AddGroup("default", "Arkime Options", &ArkimeOptions)
	parser.AddGroup("general", "General Options", &GeneralOptions)
	parser.Parse()

	// process help options first
	if GeneralOptions.Help {
		parser.WriteHelp(os.Stdout)
		os.Exit(0)
	}
	// do not write
	if GeneralOptions.NoConf == "false" {
		dumpArkimeIni(string(GeneralOptions.ConfigPath))
	}
	if GeneralOptions.DumpConfig {
		dumpArkimeIni("/dev/stdout")
		os.Exit(0)
	}

	if GeneralOptions.SkipTlsVerifiction {
		GeneralOptions.insecure = "--insecure"
	} else {
		GeneralOptions.insecure = ""
	}

	// configDefault, _ := getTagValue(GeneralOptions, "Config", "default")
	// if string(GeneralOptions.WriteConfig) != configDefault {
	// 	DumpArkimeIni(string(GeneralOptions.WriteConfig))
	// 	os.Exit(0)
	// }

	// // check for config file choice and parse it
	// if string(GeneralOptions.Config) != configDefault {
	// 	// GeneralOptions.WriteConfig = ""
	// 	err := iniParser.ParseFile(string(GeneralOptions.Config))
	// 	if err != nil {
	// 		errorHandler(err)
	// 	}
	// 	return
	// 	//  re-parse the argument from command line to give them priority
	// 	// parser.Parse()
	// }

	// // choice to spit out an Arkime config file based on the parsed choices
	// writeConfigDefault, _ := getTagValue(GeneralOptions, "WriteConfig", "default")
	// parser.Parse()
	// log.Infof("Write Config File to: %s", GeneralOptions.WriteConfig)
	// iniParser.WriteFile(string(GeneralOptions.WriteConfig), flags.IniIncludeDefaults)
	// // if string(GeneralOptions.WriteConfig) != writeConfigDefault {
	// // 	os.Exit(0)
	// // }

	// if the user didn't change the default value of WriteConfig, it means
}

func getTagValue(myStruct interface{}, myField string, myTag string) (string, error) {
	t := reflect.TypeOf(myStruct)
	for i := 0; i < t.NumField(); i++ {
		// Get the field, returns https://golang.org/pkg/reflect/#StructField
		field := t.Field(i)
		if field.Name == myField {
			// Get the field tag value
			tag := field.Tag.Get(myTag)
			return tag, nil
		}
	}

	return "", errors.New("no tag found")
}
