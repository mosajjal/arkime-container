# Arkime (Moloch) Container Image and supervisor

Arkime is a large scale, open source, indexed packet capture and search tool ([website](https://arkime.com))

This tiny project aims to bring Arkime's powerful abilities to the cloud native world. `arkime-supervisor` is a Golang daemon running both capture and viewer functionality of Arkime and pulls logs from both viewer and capture processes into the containers `stdout`. It also handles initial Elasticsearch/Opensearch index creation, optionally adds default credentials and downloads necessery definition files to help Arkime work with no direct intraction with the container itself.

full list of options:

[//]: <> (start of command line options)
```
  ARKIME

default:
      --elasticsearch=                      Comma seperated list of
                                            elasticsearch host:port
                                            combinations.  If not using a
                                            ; elasticsearch VIP, a different
                                            elasticsearch node in the cluster
                                            can be specified
                                            ; for each Arkime node to help
                                            spread load on high volume clusters
                                            (default: http://127.0.0.1:9200)
                                            [$ARKIME_ELASTICSEARCH]
      --rotateIndex=                        How often to create a new
                                            elasticsearch index.
                                            hourly,hourly6,daily,weekly,monthly
                                            ; Changing the value will cause
                                            previous sessions to be unreachable
                                            (default: daily)
                                            [$ARKIME_ROTATEINDEX]
      --certFile=                           Cert file to use, comment out to
                                            use http instead [$ARKIME_CERTFILE]
      --caTrustFile=                        File with trusted roots/certs.
                                            WARNING! this replaces default roots
                                            ; Useful with self signed certs and
                                            can be set per node.
                                            [$ARKIME_CATRUSTFILE]
      --keyFile=                            Private key file to use, comment
                                            out to use http instead
                                            [$ARKIME_KEYFILE]
      --passwordSecret=                     Password Hash and S2S secret - Must
                                            be in default section. Since
                                            elasticsearch
                                            ; is wide open by default, we
                                            encrypt the stored password hashes
                                            with this
                                            ; so a malicous person can't insert
                                            a working new account.  It is also
                                            used
                                            ; for secure S2S communication.
                                            Comment out for no user
                                            authentication.
                                            ; Changing the value will make all
                                            previously stored passwords no
                                            longer work.
                                            ; Make this RANDOM, you never need
                                            to type in (default: password)
                                            [$ARKIME_PASSWORDSECRET]
      --serverSecret=                       Use a different password for S2S
                                            communication then passwordSecret.
                                            ; Must be in default section.  Make
                                            this RANDOM, you never need to type
                                            in [$ARKIME_SERVERSECRET]
      --httpRealm=                          HTTP Digest Realm - Must be in
                                            default section.  Changing the value
                                            ; will make all previously stored
                                            passwords no longer work (default:
                                            Arkime) [$ARKIME_HTTPREALM]
      --webBasePath=                        The base path for Arkime web
                                            access.  Must end with a / or bad
                                            things will happen (default: /)
                                            [$ARKIME_ WEBBASEPATH]
      --interface=                          Semicolon ';' seperated list of
                                            interfaces to listen on for traffic
                                            (default: lo) [$ARKIME_INTERFACE]
      --bpf=                                The bpf filter of traffic to ignore
                                            (default: not port 9200)
                                            [$ARKIME_BPF]
      --yara=                               The yara file name (default:
                                            /dev/null) [$ARKIME_YARA]
      --wiseHost=                           Host to connect to for wiseService
                                            [$ARKIME_WISEHOST]
      --accessLogFile=                      Log viewer access requests to a
                                            different log file
                                            [$ARKIME_ACCESSLOGFILE]
      --pcapDir=                            The directory to save raw pcap
                                            files to (default: /opt/arkime/raw)
                                            [$ARKIME_PCAPDIR]
      --maxFileSizeG=                       The max raw pcap file size in
                                            gigabytes, with a max value of 36G.
                                            ; The disk should have room for at
                                            least 10*maxFileSizeG (default: 12)
                                            [$ARKIME_MAXFILESIZEG]
      --maxFileTimeM=                       The max time in minutes between
                                            rotating pcap files.  Default is 0,
                                            which means
                                            ; only rotate based on current file
                                            size and the maxFileSizeG variable
                                            (default: 0) [$ARKIME_MAXFILETIMEM]
      --tcpTimeout=                         TCP timeout value.  Arkime writes a
                                            session record after this many
                                            seconds
                                            ; of inactivity. (default: 600)
                                            [$ARKIME_TCPTIMEOUT]
      --tcpSaveTimeout=                     Arkime writes a session record
                                            after this many seconds, no matter
                                            if
                                            ; active or inactive (default: 720)
                                            [$ARKIME_TCPSAVETIMEOUT]
      --udpTimeout=                         UDP timeout value.  Arkime assumes
                                            the UDP session is ended after this
                                            ; many seconds of inactivity.
                                            (default: 30) [$ARKIME_UDPTIMEOUT]
      --icmpTimeout=                        ICMP timeout value.  Arkime assumes
                                            the ICMP session is ended after this
                                            ; many seconds of inactivity.
                                            (default: 10) [$ARKIME_ICMPTIMEOUT]
      --maxStreams=                         An aproximiate maximum number of
                                            active sessions Arkime/libnids will
                                            try
                                            ; and monitor (default: 1000000)
                                            [$ARKIME_MAXSTREAMS]
      --maxPackets=                         Arkime writes a session record
                                            after this many packets (default:
                                            10000) [$ARKIME_MAXPACKETS]
      --freeSpaceG=                         Delete pcap files when free space
                                            is lower then this in gigabytes OR
                                            it can be
                                            ; expressed as a percentage (ex:
                                            5%).  This does NOT delete the
                                            session records in
                                            ; the database. It is recommended
                                            this value is between 5% and 10% of
                                            the disk.
                                            ; Database deletes are done by the
                                            db.pl expire script (default: 5%)
                                            [$ARKIME_FREESPACEG]
      --viewPort=                           The port to listen on, by default
                                            8005 (default: 8005)
                                            [$ARKIME_VIEWPORT]
      --viewHost=                           The host/ip to listen on, by
                                            default 0.0.0.0 which is ALL
                                            (default: localhost)
                                            [$ARKIME_VIEWHOST]
      --viewUrl=                            By default the viewer process is
                                            https://hostname:<viewPort> for
                                            each node. (default:
                                            https://HOSTNAME:8005)
                                            [$ARKIME_VIEWURL]
      --geoLite2Country=                    Path of the maxmind geoip country
                                            file.  Download free version from:
                                            ;
                                            https://updates.maxmind.com/app/upd-

                                            ate_secure?edition_id=GeoLite2-Coun-

                                            try (default:
                                            /opt/arkime/etc/GeoLite2-Country.mm-

                                            db) [$ARKIME_GEOLITE2COUNTRY]
      --geoLite2ASN=                        Path of the maxmind geoip ASN file.
                                            Download free version from:
                                            ;
                                            https://updates.maxmind.com/app/upd-

                                            ate_secure?edition_id=GeoLite2-ASN
                                            (default:
                                            /opt/arkime/etc/GeoLite2-ASN.mmdb)
                                            [$ARKIME_GEOLITE2ASN]
      --rirFile=                            Path of the rir assignments file
                                            ;
                                            https://www.iana.org/assignments/ip-

                                            v4-address-space/ipv4-address-space-

                                            .csv (default:
                                            /opt/arkime/etc/ipv4-address-space.-

                                            csv) [$ARKIME_RIRFILE]
      --ouiFile=                            Path of the OUI file from whareshark
                                            ;
                                            https://raw.githubusercontent.com/w-

                                            ireshark/wireshark/master/manuf
                                            (default: /opt/arkime/etc/oui.txt)
                                            [$ARKIME_OUIFILE]
      --dropUser=                           User to drop privileges to. The
                                            pcapDir must be writable by this
                                            user or group below (default:
                                            nobody) [$ARKIME_DROPUSER]
      --dropGroup=                          Group to drop privileges to. The
                                            pcapDir must be writable by this
                                            group or user above (default:
                                            daemon) [$ARKIME_DROPGROUP]
      --localPcapIndex=[true|false]         enable pcap index on capture node
                                            instead of ES (default: false)
                                            [$ARKIME_LOCALPCAPINDEX]
      --dontSaveTags=                       Semicolon ';' seperated list of
                                            tags which once capture sets for a
                                            session causes the
                                            ; remaining pcap from being saved
                                            for the session.  It is likely that
                                            the initial packets
                                            ; WILL be saved for the session
                                            since tags usually aren't set until
                                            after several packets
                                            ; Each tag can choiceally be
                                            followed by a :<num> which
                                            specifies how many total packets to
                                            save [$ARKIME_DONTSAVETAGS]
      --userNameHeader=                     Header to use for determining the
                                            username to check in the database
                                            for instead of
                                            ; using http digest.  Use this if
                                            apache or something else is doing
                                            the auth.
                                            ; Set viewHost to localhost or use
                                            iptables
                                            ; Might need something like this in
                                            the httpd.conf
                                            ; RewriteRule .* -
                                            [E=ENV_RU:%{REMOTE_USER}]
                                            ; RequestHeader set ARKIME_USER
                                            %{ENV_RU}e (default: arkime_user)
                                            [$ARKIME_USERNAMEHEADER]
      --parseSMTP=[true|false]              Should we parse extra smtp traffic
                                            info (default: true)
                                            [$ARKIME_PARSESMTP]
      --parseSMB=[true|false]               Should we parse extra smb traffic
                                            info (default: true)
                                            [$ARKIME_PARSESMB]
      --parseQSValue=[true|false]           Should we parse HTTP QS Values
                                            (default: false)
                                            [$ARKIME_PARSEQSVALUE]
      --supportSha256=[true|false]          Should we calculate sha256 for
                                            bodies (default: false)
                                            [$ARKIME_SUPPORTSHA256]
      --maxReqBody=                         Only index HTTP request bodies less
                                            than this number of bytes */
                                            (default: 64) [$ARKIME_MAXREQBODY]
      --config.reqBodyOnlyUtf8=[true|false] Only store request bodies that
                                            Utf-8? (default: true)
                                            [$ARKIME_CONFIG.REQBODYONLYUTF8]
      --smtpIpHeaders=                      Semicolon ';' seperated list of
                                            SMTP Headers that have ips, need to
                                            have the terminating colon ':'
                                            (default:
                                            X-Originating-IP:;X-Barracuda-Appar-

                                            ent-Source-IP:)
                                            [$ARKIME_SMTPIPHEADERS]
      --parsersDir=                         Semicolon ';' seperated list of
                                            directories to load parsers from
                                            (default: /opt/arkime/parsers)
                                            [$ARKIME_PARSERSDIR]
      --pluginsDir=                         Semicolon ';' seperated list of
                                            directories to load plugins from
                                            (default: /opt/arkime/plugins)
                                            [$ARKIME_PLUGINSDIR]
      --plugins=                            Semicolon ';' seperated list of
                                            plugins to load and the order to
                                            load in [$ARKIME_PLUGINS]
      --rootPlugins=                        Plugins to load as root, usually
                                            just readers [$ARKIME_ROOTPLUGINS]
      --viewerPlugins=                      Semicolon ';' seperated list of
                                            viewer plugins to load and the
                                            order to load in
                                            [$ARKIME_VIEWERPLUGINS]
      --netflowSNMPInput=                   NetFlowPlugin
                                            ; Input device id, 0 by default
                                            (default: 1)
                                            [$ARKIME_NETFLOWSNMPINPUT]
      --netflowSNMPOutput=                  Outout device id, 0 by default
                                            (default: 2)
                                            [$ARKIME_NETFLOWSNMPOUTPUT]
      --netflowVersion=                     Netflow version 1,5,7 supported, 7
                                            by default (default: 1)
                                            [$ARKIME_NETFLOWVERSION]
      --netflowDestinations=                Semicolon ';' seperated list of
                                            netflow destinations
                                            [$ARKIME_NETFLOWDESTINATIONS]
      --spiDataMaxIndices=                  Specify the max number of indices
                                            we calculate spidata for.
                                            ; ES will blow up if we allow the
                                            spiData to search too many indices.
                                            (default: 4)
                                            [$ARKIME_SPIDATAMAXINDICES]
      --uploadCommand=                      Uncomment the following to allow
                                            direct uploads.  This is
                                            experimental (default:
                                            /opt/arkime/bin/capture --copy -n
                                            {NODE} -r {TMPFILE} -c {CONFIG}
                                            {TAGS}) [$ARKIME_UPLOADCOMMAND]
      --titleTemplate=                      Title Template
                                            ;  _cluster_=ES cluster name
                                            ;  _userId_=logged in User Id
                                            ;  _userName_=logged in User Name
                                            ;  _page_=internal page name
                                            ;  _expression_=current search
                                            expression if set, otherwise blank
                                            ;  _-expression_=" - " + current
                                            search expression if set, otherwise
                                            blank, prior spaces removed
                                            ;  _view_=current view if set,
                                            otherwise blank
                                            ;  _-view_=" - " + current view if
                                            set, otherwise blank, prior spaces
                                            removed (default: _cluster_ -
                                            _page_ _-view_ _-expression_)
                                            [$ARKIME_TITLETEMPLATE]
      --packetThreads=                      Number of threads processing
                                            packets (default: 2)
                                            [$ARKIME_PACKETTHREADS]
      --includes=                           ADVANCED - Semicolon ';' seperated
                                            list of files to load for config.
                                            Files are loaded
                                            ; in order and can replace values
                                            set in this file or previous files.
                                            [$ARKIME_INCLUDES]
      --pcapReadMethod=                     ADVANCED - Specify how packets are
                                            read from network cards: (default:
                                            libpcap) [$ARKIME_PCAPREADMETHOD]
      --pcapWriteMethod=                    ADVANCED - How is pcap written to
                                            disk
                                            ;  simple=use O_DIRECT if
                                            available, writes in pcapWriteSize
                                            chunks,
                                            ;                    a file per
                                            packet thread.
                                            ;  simple-nodirect=don't use
                                            O_DIRECT.  Required for zfs and
                                            others (default: simple)
                                            [$ARKIME_PCAPWRITEMETHOD]
      --pcapWriteSize=                      ADVANCED - Buffer size when writing
                                            pcap files.  Should be a multiple
                                            of the raid 5 or xfs
                                            ; stripe size.  Defaults to 256k
                                            (default: 262143)
                                            [$ARKIME_PCAPWRITESIZE]
      --dbBulkSize=                         ADVANCED - Number of bytes to bulk
                                            index at a time (default: 300000)
                                            [$ARKIME_DBBULKSIZE]
      --compressES=[true|false]             ADVANCED - Compress requests to ES,
                                            reduces ES bandwidth by ~80% at the
                                            cost
                                            ; of increased CPU. MUST have
                                            "http.compression: true" in
                                            elasticsearch.yml file (default:
                                            false) [$ARKIME_COMPRESSES]
      --maxESConns=                         ADVANCED - Max number of
                                            connections to elastic search
                                            (default: 30) [$ARKIME_MAXESCONNS]
      --maxESRequests=                      ADVANCED - Max number of es
                                            requests outstanding in q (default:
                                            500) [$ARKIME_MAXESREQUESTS]
      --packetsPerPoll=                     ADVANCED - Number of packets to ask
                                            libnids/libpcap to read per
                                            poll/spin
                                            ; Increasing may hurt stats and ES
                                            performance
                                            ; Decreasing may cause more dropped
                                            packets (default: 50000)
                                            [$ARKIME_PACKETSPERPOLL]
      --antiSynDrop=[true|false]            ADVANCED - Arkime will try to
                                            compensate for SYN packet drops by
                                            swapping
                                            ; the source and destination
                                            addresses when a SYN-acK packet was
                                            captured first.
                                            ; Probably useful to set it false,
                                            when running Arkime in wild due to
                                            SYN floods. (default: true)
                                            [$ARKIME_ANTISYNDROP]
      --logEveryXPackets=                   DEBUG - Write to stdout info every
                                            X packets.
                                            ; Set to -1 to never log status
                                            (default: 100000)
                                            [$ARKIME_LOGEVERYXPACKETS]
      --logUnknownProtocols=[true|false]    DEBUG - Write to stdout unknown
                                            protocols (default: false)
                                            [$ARKIME_LOGUNKNOWNPROTOCOLS]
      --logESRequests=[true|false]          DEBUG - Write to stdout elastic
                                            search requests (default: true)
                                            [$ARKIME_LOGESREQUESTS]
      --logFileCreation=[true|false]        DEBUG - Write to stdout file
                                            creation information (default:
                                            true) [$ARKIME_LOGFILECREATION]

general:
  -h, --help                                Print this help to stdout
      --config=                             path to Arkime config file
                                            [$ARKIME_CONFIG]
      --writeConfig=                        generate an Arkime config file
                                            based on current inputs (flags,
                                            input config file and environment
                                            variables) and write to provided
                                            path. Empty input will disable the
                                            functionality (default:
                                            /opt/arkime/etc/config.ini)
                                            [$ARKIME_WRITECONFIG]
      --version=[true|false]                print version and exit (default:
                                            false) [$ARKIME_VERSION]
      --autoInit=[true|false]               atuomatically initialize Elastic
                                            indices if sequence_v2 and
                                            sequence_v1 were not present
                                            (default: true) [$ARKIME_AUTOINIT]
      --forceInit=[true|false]              force initialization of Arkime
                                            Elastic indices from scratch
                                            (default: false) [$ARKIME_FORCEINIT]
      --createAdminUser=[true|false]        create admin user at startup
                                            (default: true)
                                            [$ARKIME_CREATEADMINUSER]
      --adminCreds=                         Administrator Credentials (default:
                                            admin:arkime) [$ARKIME_ADMINCREDS]
      --esHealthcheckInterval=              Interval to check Elastic
                                            avalability (default: 60s)
                                            [$ARKIME_ESHEALTHCHECKINTERVAL]
      --viewerCheckInterval=                Interval to check Viewer
                                            avalability (default: 60s)
                                            [$ARKIME_VIEWERCHECKINTERVAL]
      --capturerCheckInterval=              Interval to check Capturer
                                            avalability (default: 60s)
                                            [$ARKIME_CAPTURERCHECKINTERVAL]
      --viewerLogLocation=                  Viewer log location, empty value
                                            pushes the log to container's
                                            stdout [$ARKIME_VIEWERLOGLOCATION]
      --capturerLogLocation=                Capturer log location, empty value
                                            pushes the log to container's
                                            stdout [$ARKIME_CAPTURERLOGLOCATION]
      --ipv4SpaceURL=                       Download IPv4 space on startup and
                                            push to rirFile location defined in
                                            ArkimeOptions. empty means disabled
                                            (default:
                                            https://www.iana.org/assignments/ip-

                                            v4-address-space/ipv4-address-space-

                                            .csv) [$ARKIME_IPV4SPACEURL]
      --manufURL=                           Download MAC Vendor mapping on
                                            startup and push to ouiFile
                                            location defined in ArkimeOptions.
                                            empty means disabled (default:
                                            https://raw.githubusercontent.com/w-

                                            ireshark/wireshark/master/manuf)
                                            [$ARKIME_MANUFURL]
      --geoLite2CountryURL=                 Download GeoLite2 Country mmdb on
                                            startup and push to geoLite2Country
                                            location defined in ArkimeOptions.
                                            empty means disabled (default:
                                            https://github.com/P3TERX/GeoLite.m-

                                            mdb/raw/download/GeoLite2-Country.m-

                                            mdb) [$ARKIME_GEOLITECOUNTRYURL]
      --geoLite2ASNURL=                     Download GeoLite2 ASN mmdb on
                                            startup and push to geoLite2ASN
                                            location defined in ArkimeOptions.
                                            empty means disabled (default:
                                            https://github.com/P3TERX/GeoLite.m-

                                            mdb/raw/download/GeoLite2-ASN.mmdb)
                                            [$ARKIME_GEOLITEASNURL]
      --geoLiteRefreshInterval=             Auto re-download interval for
                                            GeoLite2CountryURL and
                                            GeoLite2ASNURL (default: 168h)
                                            [$ARKIME_GEOLITEREFRESHINTERVAL]
```
[//]: <> (end of command line options)

## Run with a configuration file

`arkime-supervisor` can pass on a user-provided `ini` config file to the container, something like this:

```sh
docker run -it --rm -v $PWD/config.ini:/opt/arkime/etc/config.ini -v /opt/arkime/raw:/opt/arkime/raw --net host mosajjal/arkime:latest  --config=/opt/arkime/etc/config.ini
```

*IMPORTANT NOTE*: current implementation does not support anything otuside the `[default]` section for the `.ini` file and will throw an error if there's anything else other than the `[default]` section is present. 

## Run with command line arguments

`arkime-supervisor` also supports command line arguments as well as Environment variables to set most common commands into an Arkime-compatible `.ini` file on container's startup, so the user won't have to deal with managing an extra `ini` file dynamically.

```sh
docker run -it --rm -v /opt/arkime/raw:/opt/arkime/raw --net host mosajjal/arkime:latest --pcapWriteMethod=null --pcapDir=/tmp/ --passwordSecret=Passw0rd --elasticsearch=http://elasticsearch:9200 --interface=lo --forceInit=true --createAdminUser=true
```


by default, `arkime-supervisor` will download 4 files on startup: `ipv4-address-space.csv`, `manuf`, `GeoLite2-Country.mmdb` and `GeoLite2-ASN.mmdb`. `ipv4-address-space.csv`, `manuf` are considered static and not subject to many changes, so `arkime-supervisor` will not try to keep them up to date automatically, but `GeoLite2-Country.mmdb` and `GeoLite2-ASN.mmdb` can be re-fetched by setting geoLiteRefreshInterval to any positive time duration. Default is 1 week (168 hours). 

`arkime-supervisor` will check on viewer and capture process every 5 seconds to see if they're still running and if they've exited, it tries to restart them. 

