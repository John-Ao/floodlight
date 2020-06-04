package net.floodlightcontroller.myfirewall;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import org.projectfloodlight.openflow.protocol.*;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.action.OFActionOutput;
import org.projectfloodlight.openflow.types.*;

// import org.projectfloodlight.openflow.protocol.OFFactories;
import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFPacketIn;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.protocol.OFVersion;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;
// import org.projectfloodlight.openflow.types.DatapathId;
// import org.projectfloodlight.openflow.types.EthType;
// import org.projectfloodlight.openflow.types.IPv4Address;
// import org.projectfloodlight.openflow.types.IPv4AddressWithMask;
// import org.projectfloodlight.openflow.types.IpProtocol;
// import org.projectfloodlight.openflow.types.MacAddress;
// import org.projectfloodlight.openflow.types.Masked;
import org.projectfloodlight.openflow.types.OFPort;
// import org.projectfloodlight.openflow.types.TransportPort;
// import org.projectfloodlight.openflow.types.U64;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.myfirewall.FirewallRule.FirewallAction;

import java.util.ArrayList;

import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
// import net.floodlightcontroller.packet.TCP;
// import net.floodlightcontroller.packet.UDP;
import net.floodlightcontroller.restserver.IRestApiService;

import org.slf4j.Logger;

public class MyFirewall implements IOFMessageListener, IFloodlightModule {

	// service modules needed
	protected IFloodlightProviderService floodlightProvider;
	protected IRestApiService restApi;
	protected static Logger logger;

	static List<FirewallRule> rules;
	static int rule_id;
	static boolean enabled;

	@Override
	public String getName() {
		return "My Firewall";
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		Collection<Class<? extends IFloodlightService>> l = new ArrayList<Class<? extends IFloodlightService>>();
		l.add(IFloodlightProviderService.class);
		l.add(IRestApiService.class);
		return l;
	}

	@Override
	public void init(FloodlightModuleContext context) throws FloodlightModuleException {
		floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
		restApi = context.getServiceImpl(IRestApiService.class);
		rules = new ArrayList<FirewallRule>();
		rule_id = 0;
		enabled = true;
	}

	@Override
	public void startUp(FloodlightModuleContext context) {
		restApi.addRestletRoutable(new MyFirewallWebRoutable());
		floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
	}

	private String getEthName(Ethernet eth) {
		EthType t = eth.getEtherType();
		if (t.equals(EthType.ARP)) {
			return "ARP";
		} else if (t.equals(EthType.IPv4)) {
			IpProtocol proto = ((IPv4) eth.getPayload()).getProtocol();
			if (proto.equals(IpProtocol.TCP)) {
				return "TCP";
			} else if (proto.equals(IpProtocol.UDP)) {
				return "UDP";
			} else if (proto.equals(IpProtocol.ICMP)) {
				return "ICMP";
			} else {
				return "IPv4:" + proto.toString();
			}
		} else if (t.equals(EthType.LLDP)) {
			return "LLDP";
		}
		return eth.toString();
	}

	@Override
	public Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
		boolean drop = false;
		OFPacketIn pi = (OFPacketIn) msg;
		if (enabled && msg.getType() == OFType.PACKET_IN) {
			FirewallRule matched_rule = null;
			Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
			Match.Builder mb = sw.getOFFactory().buildMatch();
			synchronized (rules) {
				FirewallRule rule;
				for (int i = rules.size() - 1; i >= 0; --i) {
					rule = rules.get(i);
					if (rule.matchesThisPacket(sw.getId(),
							(pi.getVersion().compareTo(OFVersion.OF_12) < 0 ? pi.getInPort()
									: pi.getMatch().get(MatchField.IN_PORT)),
							eth, mb)) {
						matched_rule = rule;
						break;
					}
				}
			}
			if (matched_rule != null) {
				System.out.println("[" + getEthName(eth) + "] Rule " + matched_rule.ruleid + " matched, "
						+ String.valueOf(matched_rule.action));
			}
			// if (matched_rule != null && matched_rule.action == FirewallAction.DROP) {
			if (matched_rule == null || matched_rule.action == FirewallAction.DROP) {
				drop = true;
			}
		}
		if (!drop) {
			OFPacketOut.Builder pob = sw.getOFFactory().buildPacketOut();

			pob.setBufferId(pi.getBufferId()).setXid(pi.getXid())
					.setInPort((pi.getVersion().compareTo(OFVersion.OF_12) < 0 ? pi.getInPort()
							: pi.getMatch().get(MatchField.IN_PORT)));

			// set actions
			OFActionOutput.Builder actionBuilder = sw.getOFFactory().actions().buildOutput();
			actionBuilder.setPort(OFPort.FLOOD);
			pob.setActions(Collections.singletonList((OFAction) actionBuilder.build()));
			// set data if it is included in the packetin
			if (pi.getBufferId() == OFBufferId.NO_BUFFER) {
				byte[] packetData = pi.getData();
				pob.setData(packetData);
			}
			sw.write(pob.build());
		}
		return Command.CONTINUE;
	}

	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) {
		return false;
	}

	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) {
		return false;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		return null;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		return null;
	}
}
