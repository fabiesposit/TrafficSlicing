from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp
from ryu.ofproto import ether as ether_types
from ryu.lib import hub

import requests
import json
import time


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
                continue  # Considera solo i flussi con priorità 10 (i tuoi)

            match = stat.match
            src = match.get('eth_src')
            dst = match.get('eth_dst')
            byte_count = stat.byte_count

            if not src or not dst:
                continue  # Ignora flussi senza src/dst

            key = (dpid, src, dst)
            last = self.flow_stats.get(key, None)

            bandwidth_kbps = 0
            if last:
                time_diff = current_time - last['time']
                if time_diff > 0:
                    delta_bytes = byte_count - last['bytes']
                    bandwidth_kbps = (delta_bytes * 8) / (time_diff * 1000)

            # Salva l'ultima statistica
            self.flow_stats[key] = {'bytes': byte_count, 'time': current_time}

            stats_to_send.append({
                'dpid': dpid,
                'src': src,
                'dst': dst,
                'bandwidth_kbps': round(max(0, bandwidth_kbps), 2)
            })

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

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        src = eth.src
        dst = eth.dst

        H1 = "00:00:00:00:00:01"
        H2 = "00:00:00:00:00:02"
        H3 = "00:00:00:00:00:03"
        H4 = "00:00:00:00:00:04"

        not_allowed = {
            (H1, H2), (H1, H4), (H2, H1), (H2, H3),
            (H3, H2), (H3, H4), (H4, H1), (H4, H3)
        }

        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        if (src, dst) in not_allowed:
            match = parser.OFPMatch(eth_src=src, eth_dst=dst)
            self.add_flow(datapath, 1, match, [])  # Drop
            return
        out_port=0
	    
        if dpid == 1:
            if src == H1:
                out_port = 3
                self.logger.info("entrato")
            elif src == H2:
                out_port = 4
            elif src == H3:
                out_port = 1
            elif src == H4:
                out_port = 2
        elif dpid == 2:
            if src == H1:
                out_port = 2
            else:
                out_port = 1

        elif dpid == 3:
            if src == H2:
                out_port = 2
            else:
                out_port = 1

        elif dpid == 4:
            if src == H1:
                out_port = 3
            elif src == H2:
                out_port = 4
            elif src == H3:
                out_port = 1
            elif src == H4:
                out_port = 2

        # Aggiorna mac_to_port per la destinazione solo se non è flood
        self.mac_to_port[dpid][dst] = out_port

        actions = [parser.OFPActionOutput(out_port)]
        
        # Crea un match più specifico per evitare conflitti
        match = parser.OFPMatch(in_port=in_port, eth_src=src, eth_dst=dst)

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
