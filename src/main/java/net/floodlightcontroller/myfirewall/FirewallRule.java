package net.floodlightcontroller.myfirewall;

import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.types.DatapathId;
import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.IpProtocol;
import org.projectfloodlight.openflow.types.MacAddress;
import org.projectfloodlight.openflow.types.OFPort;
import org.projectfloodlight.openflow.types.TransportPort;

import com.fasterxml.jackson.databind.annotation.JsonSerialize;

import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPacket;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.TCP;
import net.floodlightcontroller.packet.UDP;

@JsonSerialize(using = FirewallRuleSerializer.class)
public class FirewallRule implements Comparable<FirewallRule> {
    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        FirewallRule other = (FirewallRule) obj;
        if (action != other.action)
            return false;
        if (any_dl_dst != other.any_dl_dst)
            return false;
        if (any_dl_src != other.any_dl_src)
            return false;
        if (any_dl_type != other.any_dl_type)
            return false;
        if (any_dpid != other.any_dpid)
            return false;
        if (any_in_port != other.any_in_port)
            return false;
        if (any_nw_dst != other.any_nw_dst)
            return false;
        if (any_nw_proto != other.any_nw_proto)
            return false;
        if (any_nw_src != other.any_nw_src)
            return false;
        if (any_tp_dst != other.any_tp_dst)
            return false;
        if (any_tp_src != other.any_tp_src)
            return false;
        if (dl_dst == null) {
            if (other.dl_dst != null)
                return false;
        } else if (!dl_dst.equals(other.dl_dst))
            return false;
        if (dl_src == null) {
            if (other.dl_src != null)
                return false;
        } else if (!dl_src.equals(other.dl_src))
            return false;
        if (dl_type == null) {
            if (other.dl_type != null)
                return false;
        } else if (!dl_type.equals(other.dl_type))
            return false;
        if (dpid == null) {
            if (other.dpid != null)
                return false;
        } else if (!dpid.equals(other.dpid))
            return false;
        if (in_port == null) {
            if (other.in_port != null)
                return false;
        } else if (!in_port.equals(other.in_port))
            return false;
        if (nw_dst == null) {
            if (other.nw_dst != null)
                return false;
        } else if (!nw_dst.equals(other.nw_dst))
            return false;
        if (nw_proto == null) {
            if (other.nw_proto != null)
                return false;
        } else if (!nw_proto.equals(other.nw_proto))
            return false;
        if (nw_src == null) {
            if (other.nw_src != null)
                return false;
        } else if (!nw_src.equals(other.nw_src))
            return false;
        if (priority != other.priority)
            return false;
        if (ruleid != other.ruleid)
            return false;
        if (tp_dst == null) {
            if (other.tp_dst != null)
                return false;
        } else if (!tp_dst.equals(other.tp_dst))
            return false;
        if (tp_src == null) {
            if (other.tp_src != null)
                return false;
        } else if (!tp_src.equals(other.tp_src))
            return false;
        return true;
    }

    public int ruleid;              // 规则编号

    public DatapathId dpid;         // 交换机编号
    public OFPort in_port;          // 交换机端口
    public MacAddress dl_src;       // 源MAC地址
    public MacAddress dl_dst;       // 目的MAC
    public EthType dl_type;         // 链路层协议类型，ARP / IPv4
    public IPv4Address nw_src;      // 源IP
    public IPv4Address nw_dst;      // 目的IP
    public IpProtocol nw_proto;     // 网络层协议，TCP / UDP / ICMP
    public TransportPort tp_src;    // 源端口
    public TransportPort tp_dst;    // 目的端口

    // 判断上述变量是否为通配符
    public boolean any_dpid;
    public boolean any_in_port;
    public boolean any_dl_src;
    public boolean any_dl_dst;
    public boolean any_dl_type;
    public boolean any_nw_src;
    public boolean any_nw_dst;
    public boolean any_nw_proto;
    public boolean any_tp_src;
    public boolean any_tp_dst;

    public int priority = 0;        // 优先级

    public FirewallAction action;   // 行为

    public enum FirewallAction {
        DROP, ALLOW
    }

    /**
     * The default rule is to match on anything.
     */
    public FirewallRule() {
        this.dpid = DatapathId.NONE;
        this.in_port = OFPort.ANY;
        this.dl_src = MacAddress.NONE;
        this.dl_dst = MacAddress.NONE;
        this.dl_type = EthType.NONE;
        this.nw_src = IPv4Address.NONE;
        this.nw_dst = IPv4Address.NONE;
        this.nw_proto = IpProtocol.NONE;
        this.tp_src = TransportPort.NONE;
        this.tp_dst = TransportPort.NONE;
        this.any_dpid = true;
        this.any_in_port = true;
        this.any_dl_src = true;
        this.any_dl_dst = true;
        this.any_dl_type = true;
        this.any_nw_src = true;
        this.any_nw_dst = true;
        this.any_nw_proto = true;
        this.any_tp_src = true;
        this.any_tp_dst = true;
        this.priority = 0;
        this.action = FirewallAction.ALLOW;
        this.ruleid = 0;
    }

    @Override
    public int compareTo(FirewallRule rule) {
        return this.priority - rule.priority;
    }

    public boolean isSameAs(FirewallRule r) {
        return !(this.action != r.action || this.any_dl_type != r.any_dl_type
                || (this.any_dl_type == false && !this.dl_type.equals(r.dl_type)) || this.any_tp_src != r.any_tp_src
                || (this.any_tp_src == false && !this.tp_src.equals(r.tp_src)) || this.any_tp_dst != r.any_tp_dst
                || (this.any_tp_dst == false && !this.tp_dst.equals(r.tp_dst)) || this.any_dpid != r.any_dpid
                || (this.any_dpid == false && !this.dpid.equals(r.dpid)) || this.any_in_port != r.any_in_port
                || (this.any_in_port == false && !this.in_port.equals(r.in_port)) || this.any_nw_src != r.any_nw_src
                || (this.any_nw_src == false && !this.nw_src.equals(r.nw_src)) || this.any_dl_src != r.any_dl_src
                || (this.any_dl_src == false && !this.dl_src.equals(r.dl_src)) || this.any_nw_proto != r.any_nw_proto
                || (this.any_nw_proto == false && !this.nw_proto.equals(r.nw_proto)) || this.any_nw_dst != r.any_nw_dst
                || (this.any_nw_dst == false && !this.nw_dst.equals(r.nw_dst)) || this.any_dl_dst != r.any_dl_dst
                || (this.any_dl_dst == false && !this.dl_dst.equals(r.dl_dst)));
    }

    public boolean matchesThisPacket(DatapathId switchDpid, OFPort inPort, Ethernet packet, Match.Builder mb) {
        IPacket pkt = packet.getPayload();

        // dl_type type
        IPv4 pkt_ip = null;

        // nw_proto types
        TCP pkt_tcp = null;
        UDP pkt_udp = null;

        // tp_src and tp_dst (tp port numbers)
        TransportPort pkt_tp_src = TransportPort.NONE;
        TransportPort pkt_tp_dst = TransportPort.NONE;

        // switchID matches?
        if (any_dpid == false && !dpid.equals(switchDpid))
            return false;

        // in_port matches?
        if (any_in_port == false && !in_port.equals(inPort))
            return false;
        if (!OFPort.ANY.equals(this.in_port))
            mb.setExact(MatchField.IN_PORT, this.in_port);

        // mac address (src and dst) match?
        if (any_dl_src == false && !dl_src.equals(packet.getSourceMACAddress()))
            return false;
        if (!MacAddress.NONE.equals(this.dl_src))
            mb.setExact(MatchField.ETH_SRC, this.dl_src);
        if (any_dl_dst == false && !dl_dst.equals(packet.getDestinationMACAddress()))
            return false;
        if (!MacAddress.NONE.equals(this.dl_dst))
            mb.setExact(MatchField.ETH_DST, this.dl_dst);

        // dl_type check: ARP, IP

        // if this is not an ARP rule but the pkt is ARP,
        // return false match - no need to continue protocol specific check
        if (any_dl_type == false) {
            if (dl_type.equals(EthType.ARP)) {
                if (packet.getEtherType() != EthType.ARP) /* shallow check for equality is okay for EthType */
                    return false;
                else {
                    if (!EthType.NONE.equals(this.dl_type))
                        mb.setExact(MatchField.ETH_TYPE, this.dl_type);
                }
            } else if (dl_type.equals(EthType.IPv4)) {
                if (packet.getEtherType() != EthType.IPv4) /* shallow check for equality is okay for EthType */
                    return false;
                else {
                    if (!IpProtocol.NONE.equals(this.nw_proto))
                        mb.setExact(MatchField.IP_PROTO, this.nw_proto);
                    // IP packets, proceed with ip address check
                    pkt_ip = (IPv4) pkt;

                    // IP addresses (src and dst) match?
                    if (any_nw_src == false && !nw_src.equals(pkt_ip.getSourceAddress()))
                        return false;
                    if (!IPv4Address.NONE.equals(this.nw_src))
                        mb.setExact(MatchField.IPV4_SRC, nw_src);

                    if (any_nw_dst == false && !nw_dst.equals(pkt_ip.getDestinationAddress()))
                        return false;
                    if (!IPv4Address.NONE.equals(this.nw_dst))
                        mb.setExact(MatchField.IPV4_DST, nw_dst);

                    // nw_proto check
                    if (any_nw_proto == false) {
                        if (nw_proto.equals(IpProtocol.TCP)) {
                            if (!pkt_ip.getProtocol().equals(IpProtocol.TCP)) {
                                return false;
                            } else {
                                pkt_tcp = (TCP) pkt_ip.getPayload();
                                pkt_tp_src = pkt_tcp.getSourcePort();
                                pkt_tp_dst = pkt_tcp.getDestinationPort();
                            }
                        } else if (nw_proto.equals(IpProtocol.UDP)) {
                            if (!pkt_ip.getProtocol().equals(IpProtocol.UDP)) {
                                return false;
                            } else {
                                pkt_udp = (UDP) pkt_ip.getPayload();
                                pkt_tp_src = pkt_udp.getSourcePort();
                                pkt_tp_dst = pkt_udp.getDestinationPort();
                            }
                        } else if (nw_proto.equals(IpProtocol.ICMP)) {
                            if (!pkt_ip.getProtocol().equals(IpProtocol.ICMP)) {
                                return false;
                            } else {
                                // nothing more needed for ICMP
                            }
                        }
                        // wildcards.drop &= ~OFMatch.OFPFW_NW_PROTO;
                        if (!IpProtocol.NONE.equals(this.nw_proto)) {
                            mb.setExact(MatchField.IP_PROTO, this.nw_proto);
                        }

                        // TCP/UDP source and destination ports match?
                        if (pkt_tcp != null || pkt_udp != null) {
                            // does the source port match?
                            if (tp_src.getPort() != 0 && tp_src.getPort() != pkt_tp_src.getPort()) {
                                return false;
                            }
                            // wildcards.drop &= ~OFMatch.OFPFW_TP_SRC;
                            if (pkt_tcp != null) {
                                if (!TransportPort.NONE.equals(this.tp_src)) {
                                    mb.setExact(MatchField.TCP_SRC, this.tp_src);
                                }
                            } else {
                                if (!TransportPort.NONE.equals(this.tp_src)) {
                                    mb.setExact(MatchField.UDP_SRC, this.tp_src);
                                }
                            }

                            // does the destination port match?
                            if (tp_dst.getPort() != 0 && tp_dst.getPort() != pkt_tp_dst.getPort()) {
                                return false;
                            }
                            // wildcards.drop &= ~OFMatch.OFPFW_TP_DST;
                            if (pkt_tcp != null) {
                                if (!TransportPort.NONE.equals(this.tp_dst)) {
                                    mb.setExact(MatchField.TCP_DST, this.tp_dst);
                                }
                            } else {
                                if (!TransportPort.NONE.equals(this.tp_dst)) {
                                    mb.setExact(MatchField.UDP_DST, this.tp_dst);
                                }
                            }
                        }
                    }
                }
            } else {
                // non-IP packet - not supported - report no match
                return false;
            }
        }
        // wildcards.drop &= ~OFMatch.OFPFW_DL_TYPE;
        if (!EthType.NONE.equals(this.dl_type)) {
            mb.setExact(MatchField.ETH_TYPE, this.dl_type);
        }

        // all applicable checks passed
        return true;
    }
}
