package net.floodlightcontroller.myfirewall;

import java.io.IOException;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;

import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.IpProtocol;

public class FirewallRuleSerializer extends JsonSerializer<FirewallRule> {

    @Override
    public void serialize(FirewallRule rule, JsonGenerator jGen, SerializerProvider serializer)
            throws IOException, JsonProcessingException {
        String proto = "*";
        if (!(rule.any_dl_type && rule.any_nw_proto)) {
            if (rule.dl_type == EthType.ARP) { // or ARP=2054, IPv4=2048
                proto = "ARP";
            } else {
                if (rule.nw_proto == IpProtocol.TCP) {
                    proto = "TCP";
                } else if (rule.nw_proto == IpProtocol.UDP) {
                    proto = "UDP";
                } else if (rule.nw_proto == IpProtocol.ICMP) {
                    proto = "ICMP";
                }
            }
        }
        jGen.writeStartObject();
        jGen.writeNumberField("ruleid", rule.ruleid);
        jGen.writeStringField("dpid", rule.any_dpid ? "*" : rule.dpid.toString());
        jGen.writeStringField("in_port", rule.any_in_port ? "*" : String.valueOf(rule.in_port.getPortNumber()));
        jGen.writeStringField("dl_src", rule.any_dl_src ? "*" : rule.dl_src.toString());
        jGen.writeStringField("dl_dst", rule.any_dl_dst ? "*" : rule.dl_dst.toString());
        jGen.writeStringField("nw_src", rule.any_nw_src ? "*" : rule.nw_src.toString());
        jGen.writeStringField("nw_dst", rule.any_nw_dst ? "*" : rule.nw_dst.toString());
        jGen.writeStringField("tp_src", rule.any_tp_src ? "*" : String.valueOf(rule.tp_src.getPort()));
        jGen.writeStringField("tp_dst", rule.any_tp_dst ? "*" : String.valueOf(rule.tp_dst.getPort()));
        jGen.writeStringField("proto", proto);
        jGen.writeNumberField("priority", rule.priority);
        jGen.writeStringField("action", String.valueOf(rule.action));
        // jGen.writeNumberField("ruleid", rule.ruleid);
        // jGen.writeStringField("dpid", rule.dpid.toString());
        // jGen.writeNumberField("in_port", rule.in_port.getPortNumber());
        // jGen.writeStringField("dl_src", rule.dl_src.toString());
        // jGen.writeStringField("dl_dst", rule.dl_dst.toString());
        // jGen.writeNumberField("dl_type", rule.dl_type.getValue());
        // jGen.writeStringField("nw_src", rule.nw_src.toString());
        // jGen.writeStringField("nw_dst", rule.nw_dst.toString());
        // jGen.writeNumberField("nw_proto", rule.nw_proto.getIpProtocolNumber());
        // jGen.writeNumberField("tp_src", rule.tp_src.getPort());
        // jGen.writeNumberField("tp_dst", rule.tp_dst.getPort());
        // jGen.writeBooleanField("any_dpid", rule.any_dpid);
        // jGen.writeBooleanField("any_in_port", rule.any_in_port);
        // jGen.writeBooleanField("any_dl_src", rule.any_dl_src);
        // jGen.writeBooleanField("any_dl_dst", rule.any_dl_dst);
        // jGen.writeBooleanField("any_dl_type", rule.any_dl_type);
        // jGen.writeBooleanField("any_nw_src", rule.any_nw_src);
        // jGen.writeBooleanField("any_nw_dst", rule.any_nw_dst);
        // jGen.writeBooleanField("any_nw_proto", rule.any_nw_proto);
        // jGen.writeBooleanField("any_tp_src", rule.any_tp_src);
        // jGen.writeBooleanField("any_tp_dst", rule.any_tp_dst);
        // jGen.writeNumberField("priority", rule.priority);
        // jGen.writeStringField("action", String.valueOf(rule.action));
        jGen.writeEndObject();
    }
}