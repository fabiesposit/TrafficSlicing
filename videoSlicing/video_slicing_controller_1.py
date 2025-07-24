from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, udp
from ryu.ofproto import ether as ether_types
import json
import time
from ryu.lib import hub
import requests


class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

        # --- INIZIO AGGIUNTA PER STATISTICHE ---
        self.datapaths = {}
        self.flow_stats = {}  # Per memorizzare flussi e byte precedenti
        self.FLASK_SERVER_URL = 'http://127.0.0.1:5000/update_stats'
        self.monitor_thread = hub.spawn(self._monitor)
        # --- FINE AGGIUNTA PER STATISTICHE ---

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Memorizza datapath per monitoraggio stats
        self.datapaths[datapath.id] = datapath

        # Table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id is not None:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)


    # --- INIZIO AGGIUNTA PER STATISTICHE ---

    def _monitor(self):
        """Richiede periodicamente le statistiche di flusso dagli switch."""
        while True:
            for dp in self.datapaths.values():
                self._request_flow_stats(dp)
            hub.sleep(5)

    def _request_flow_stats(self, datapath):
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        dpid = ev.msg.datapath.id
        current_time = time.time()
        body = ev.msg.body

        stats_to_send = []

        for stat in body:
            if stat.priority != 10:
                continue  # Considera solo i flussi installati dall'app (priorità 10)

            match = stat.match
            src = match.get('eth_src')
            dst = match.get('eth_dst')
            eth_type = match.get('eth_type')
            ip_proto = match.get('ip_proto')
            udp_dst = match.get('udp_dst')
            byte_count = stat.byte_count

            if not src or not dst:
                continue  # Serve almeno eth_src e eth_dst

            # Chiave identificativa unica per il flusso
            key = (dpid, src, dst, eth_type, ip_proto, udp_dst)
            last = self.flow_stats.get(key)

            bandwidth_kbps = 0
            if last:
                time_diff = current_time - last['time']
                if time_diff > 0:
                    delta_bytes = byte_count - last['bytes']
                    bandwidth_kbps = (delta_bytes * 8) / (time_diff * 1000)

            # Salva stato corrente
            self.flow_stats[key] = {
                'bytes': byte_count,
                'time': current_time
            }

            # Crea statistica da inviare (anche traffico normale)
            stat_entry = {
                'dpid': dpid,
                'src': src,
                'dst': dst,
                'bandwidth_kbps': round(max(0, bandwidth_kbps), 2),
                'eth_type': eth_type,
                'ip_proto': ip_proto,
                'udp_dst': udp_dst  # può essere None per altri protocolli
            }
            stats_to_send.append(stat_entry)

        if stats_to_send:
            self.logger.info("Invio statistiche dei flussi al server Flask")
            hub.spawn(self._send_stats_to_flask, stats_to_send)

    def _send_stats_to_flask(self, stats):
        """Invia le statistiche a Flask in un greenthread separato."""
        try:
            requests.post(self.FLASK_SERVER_URL, data=json.dumps(stats),
                          headers={'Content-Type': 'application/json'})
        except requests.exceptions.RequestException as e:
            self.logger.error("Errore nell'invio delle statistiche al server: %s", e)

    # --- FINE AGGIUNTA PER STATISTICHE ---


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofp = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        dpid = datapath.id

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        eth_type = eth.ethertype
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        src = eth.src
        dst = eth.dst

        H1 = "00:00:00:00:00:01"
        H2 = "00:00:00:00:00:02"
        H3 = "00:00:00:00:00:03"
        H4 = "00:00:00:00:00:04"

        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port
        out_port = []  # Modifica solo qui: inizializzazione come lista vuota per coerenza
        is_video_traffic = False

        ip_pkt = pkt.get_protocol(ipv4.ipv4) 
        udp_pkt = pkt.get_protocol(udp.udp)

        # verifico che siano effettivamente pacchetti ip -udp e controllo porta per discriminare traffico video
        # in base a se traffico è video o broadcast o altro andiamo ad assegnare porte di uscita. 
        if ip_pkt and udp_pkt:
            if udp_pkt.dst_port == 9999:
                is_video_traffic = True

        # Nota: la riga "out_port = []" era ripetuta sotto, ho mantenuto solo quella iniziale
        if dpid == 1:
            if src == H1:
                if is_video_traffic:
                    if dst == H3 or dst == H4:
                        out_port.append(3)
                    elif dst == H2:
                        out_port.append(2)
                    else:
                        #traffico broadcast
                        out_port.append(2)
                        out_port.append(3)
                else:
                    if dst == H3 or dst == H4:
                        out_port.append(4)
                    elif dst == H2:
                        out_port.append(2)
                    else:
                        #traffico broadcast
                        out_port.append(2)
                        out_port.append(4) 
            elif src == H2:
                if is_video_traffic:
                    if dst == H3 or dst == H4:
                        out_port.append(3)
                    elif dst == H1:
                        out_port.append(1)
                    else:
                        #traffico broadcast
                        out_port.append(1)
                        out_port.append(3)
                else:
                    if dst == H3 or dst == H4:
                        out_port.append(4)
                    elif dst == H1:
                        out_port.append(1)
                    else:
                        #traffico broadcast
                        out_port.append(1)
                        out_port.append(4) 

            elif src == H3 or src == H4:
                if dst == H1:
                    out_port.append(1)
                elif dst == H2:
                    out_port.append(2)
                else:
                    #traffico broadcast
                    out_port.append(1)
                    out_port.append(2)

        elif dpid == 2:
            if in_port == 1:
                out_port.append(2)
            else:
                out_port.append(1)

        elif dpid == 3:
            if in_port == 1:
                out_port.append(2)
            else:
                out_port.append(1)

        elif dpid == 4:
            if src == H3:
                if is_video_traffic:
                    if dst == H1 or dst == H2:
                        out_port.append(1)
                    elif dst == H4:
                        out_port.append(4)
                    else:
                        #traffico broadcast
                        out_port.append(1)
                        out_port.append(4)
                else:
                    if dst == H1 or dst == H2:
                        out_port.append(2)
                    elif dst == H4:
                        out_port.append(4)
                    else:
                        #traffico broadcast
                        out_port.append(2)
                        out_port.append(4) 
            elif src == H4:
                if is_video_traffic:
                    if dst == H1 or dst == H2:
                        out_port.append(1)
                    elif dst == H3:
                        out_port.append(3)
                    else:
                        #traffico broadcast
                        out_port.append(1)
                        out_port.append(3)
                else:
                    if dst == H1 or dst == H2:
                        out_port.append(2)
                    elif dst == H3:
                        out_port.append(3)
                    else:
                        #traffico broadcast
                        out_port.append(2)
                        out_port.append(3) 

            elif src == H1 or src == H2:
                if dst == H3:
                    out_port.append(3)
                elif dst == H4:
                    out_port.append(4)
                else:
                    #traffico broadcast
                    out_port.append(3)
                    out_port.append(4)

        # Aggiorna mac_to_port per la destinazione solo se non è flood
        actions = []
        
        # La riga "out_port = []" era ripetuta qui, l'ho lasciata solo all'inizio del metodo

        ## ora devo creare i match, ossia le corrispondenze da dare allo switch per fargli capire quando arriva il pacchetto di quel tipo
        ## ossia che fa "match" cosa deve fare. Il cosa deve fare sono le actions, ossia semplicemente inviare pkt sulle porte nell'array out_port
        
        if is_video_traffic:
            # se il traffico è classificato come video, vuol dire che il pacchetto arrivato è ip - udp e ha porto dst 9999 e quindi creo match
            match= parser.OFPMatch(in_port=in_port, eth_src=src, eth_dst=dst,eth_type=ether_types.ETH_TYPE_IP, ip_proto=17, udp_dst=9999)
        else:
            # può capitare che il pacchetto arrivato sia ip (esempio icmp)...
            if eth_type==ether_types.ETH_TYPE_IP:
                ip_pkt = pkt.get_protocol(ipv4.ipv4)
                ## ...ma può non essere udp, devo verificarlo
                if ip_pkt.proto == 17:
                    udp_pkt = pkt.get_protocol(udp.udp)
                    # se è ip - udp non traffico video devo dare alla dest port semplicemente quella che arriva
                    match= parser.OFPMatch(in_port=in_port, eth_src=src, eth_dst=dst,eth_type=ether_types.ETH_TYPE_IP, ip_proto=17, udp_dst=udp_pkt.dst_port)
                else:
                    # se è ip ma non udp lascio il particolare protocollo senza assegnare udp alla regola
                    match=parser.OFPMatch(in_port=in_port, eth_src=src, eth_dst=dst,eth_type=ether_types.ETH_TYPE_IP, ip_proto=ip_pkt.proto)
            else:
                # pacchetti di altro tipo (es. ARP)
                match = parser.OFPMatch(in_port=in_port, eth_src=src, eth_dst=dst, eth_type= eth_type)

        # traffico unicast
        if len(out_port) == 1:
            self.mac_to_port[dpid][dst] = out_port[0]

        for porta in out_port:
            actions.append(parser.OFPActionOutput(porta))


        # Installa la regola nel flow table
        if msg.buffer_id != ofp.OFP_NO_BUFFER:
            self.add_flow(datapath, 10, match, actions, msg.buffer_id)
            return
        else:
            self.add_flow(datapath, 10, match, actions)

        # Invia il pacchetto
        data = None
        if msg.buffer_id == ofp.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath,
                                buffer_id=msg.buffer_id,
                                in_port=in_port,
                                actions=actions,
                                data=data)
        datapath.send_msg(out)